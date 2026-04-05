#!/usr/bin/env python3
# ==============================================================================
#  PRODUCTION SNIFFER (v4.0 - Final)
# Deployed on: Gateway (192.168.56.1)
# Features: 
#   - Volume Filter (Fixes curl/web micro-bursts)
#   - Stability Filter (Fixes Ping False Positives)
#   - Priority Logic (Scan > DDoS > ML)
# ==============================================================================

import sys
import time
import json
from datetime import datetime
import logging
import joblib
import pandas as pd
import numpy as np
import requests
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ================= CONFIGURATION =================
CONFIG = {
    "INTERFACE": "wlp0s20f3",  
    "MODEL_PATH": "ids_ensemble_final.pkl",
    "API_URL": "http://127.0.0.1:8000/alert",
    
    # --- DETECTION THRESHOLDS ---
    "DOS_RATE_THRESHOLD": 50.0,       # >50 p/s on SINGLE port = DDoS
    "DDOS_MIN_PACKETS": 40,           # NEW FIX: Must have >40 packets to be a flood (Ignores curl)
    "SCAN_PORT_THRESHOLD": 2,         # >2 unique ports = Port Scan (Highest Priority)
    "SILENCE_THRESHOLD": 10.0,        # Ignore flows < 10 p/s (Noise Filter)
    
    "IGNORED_IPS": [
        "224.0.0.22", "239.255.255.250", "255.255.255.255", 
        "127.0.0.1", "0.0.0.0"
    ],
    
    "MANUAL_MAPPING": {
        0: "Benign", 1: "DOS-TCP-FLOOD", 2: "DOS-UDP-FLOOD", 
        3: "PortScan", 4: "Mirai-Botnet", 5: "DOS-ICMP-FLOOD"
    }
}

EXPECTED_FEATURES = [
     'flow_duration', 'header_length', 'protocol_type', 'duration', 'rate', 'srate', 'drate',
     'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
     'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count',
     'rst_count', 'http', 'https', 'dns', 'telnet', 'smtp', 'ssh', 'irc', 'tcp', 'udp', 'dhcp',
     'arp', 'icmp', 'ipv', 'llc', 'tot_sum', 'min', 'max', 'avg', 'std', 'tot_size', 'iat',
     'number', 'radius', 'covariance', 'variance', 'weight', 'magnitude'
]

def build_suricata_style_alert(flow, prediction, confidence, attack_type):
    if prediction == 0:
        return None
        
    # Determine severity based on attack_type mapped rules
    attack_lower = str(attack_type).lower()
    if "dos" in attack_lower or "flood" in attack_lower:
        severity = 1
    elif "portscan" in attack_lower or "network-scan" in attack_lower:
        severity = 2
    else:
        severity = 3
        
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": "alert",
        "src_ip": flow.get("src_ip"),
        "src_port": flow.get("src_port"),
        "dest_ip": flow.get("dest_ip"),
        "dest_port": flow.get("dest_port"),
        "proto": flow.get("proto"),
        "event_source": "NeuralGuard-AIDS",
        "detector": "AI_IDS",
        "alert": {
            "signature": f"AI Detected: {attack_type}",
            "category": "Anomalous Traffic",
            "severity": severity
        },
        "ml": {
            "model": "RandomForest+XGBoost",
            "prediction": "attack" if prediction == 1 else "normal",
            "confidence": float(confidence)
        },
        "attack_type": attack_type
    }

logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', level=logging.INFO)
logger = logging.getLogger("IDS_Core")

class FlowTracker:
    def __init__(self):
        self.flows = {}
        self.last_cleanup = time.time()

    def update(self, src, dst, packet):
        now = time.time()
        
        # Cleanup memory
        if now - self.last_cleanup > 2.0:
            self.flows = {k: v for k, v in self.flows.items() if (now - v['last']) < 5.0}
            self.last_cleanup = now

        proto = 'ICMP' if packet.haslayer(ICMP) else 'TCP/UDP'
        key = (src, dst, proto)

        if key not in self.flows:
            self.flows[key] = {
                'start': now, 'count': 0, 'last': now, 
                'ports': set(), 'syns': 0
            }
        
        f = self.flows[key]
        
        # Reset if flow gap > 3s
        if (now - f['start']) > 3.0:
            f['start'] = now
            f['count'] = 0
            f['ports'] = set()
            f['syns'] = 0

        f['count'] += 1
        f['last'] = now
        
        is_server_reply = False
        if packet.haslayer(TCP):
            if 'R' in packet[TCP].flags: return None
            if packet[TCP].sport in [80, 443, 8080, 22, 5000]: is_server_reply = True
            
            if not is_server_reply: 
                f['ports'].add(packet[TCP].dport)
            if 'S' in packet[TCP].flags: 
                f['syns'] += 1
                
        elif packet.haslayer(UDP):
            if packet[UDP].sport in [53]: is_server_reply = True
            if not is_server_reply: f['ports'].add(packet[UDP].dport)

        dur = now - f['start']
        safe_dur = dur if dur > 0.001 else 0.001
        rate = f['count'] / safe_dur
        
        return dur, rate, len(f['ports']), f['syns'], f['count']

class IDSEngine:
    def __init__(self):
        self.tracker = FlowTracker()
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self._load_resources()

    def _load_resources(self):
        try:
            if not os.path.exists(CONFIG['MODEL_PATH']): 
                logger.warning("⚠ Model file not found.")
                return

            data = joblib.load(CONFIG['MODEL_PATH'])
            if isinstance(data, dict):
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.label_encoder = data.get('label_encoder')
            else:
                self.model = data
            
            if hasattr(self.model, 'estimators_'):
                 for est in self.model.estimators_:
                     try: est.get_booster().feature_names = None
                     except: pass
        except Exception as e:
            pass

    def extract_features(self, packet, duration, rate):
        f = {k: 0.0 for k in EXPECTED_FEATURES}
        f['flow_duration'] = duration; f['duration'] = duration; f['rate'] = rate
        f['tot_size'] = float(len(packet))
        
        if IP in packet:
            f['header_length'] = float(packet[IP].ihl * 4)
            f['tcp'] = 1.0 if TCP in packet else 0.0
            f['udp'] = 1.0 if UDP in packet else 0.0
            f['icmp'] = 1.0 if ICMP in packet else 0.0
            
            if TCP in packet:
                flags = packet[TCP].flags
                f['syn_flag_number'] = 1.0 if 'S' in flags else 0.0
                f['ack_flag_number'] = 1.0 if 'A' in flags else 0.0
                f['rst_flag_number'] = 1.0 if 'R' in flags else 0.0
                f['fin_flag_number'] = 1.0 if 'F' in flags else 0.0

        return pd.DataFrame([f], columns=EXPECTED_FEATURES)

    def predict(self, packet):
        if not packet.haslayer(IP): return
        src, dst = packet[IP].src, packet[IP].dst
        
        if dst in CONFIG["IGNORED_IPS"] or dst.startswith("224.0.0."): return
        if src == dst: return 
        if packet.haslayer(TCP) and (packet[TCP].dport == 5000 or packet[TCP].sport == 5000): return

        result = self.tracker.update(src, dst, packet)
        if not result: return 
        
        dur, rate, unique_ports, syns, count = result

        # STABILITY FILTER (Ping Fix)
        if count < 5:
            return

        # SILENCE GATE
        if rate < CONFIG["SILENCE_THRESHOLD"] and unique_ports < 2:
            return

        final_label = "Benign"
        conf = 0.0

        # --- HEURISTIC LOGIC ---
        
        # 1. PORT SCAN
        if unique_ports >= CONFIG["SCAN_PORT_THRESHOLD"]:
            final_label, conf = "Recon (PortScan)", 0.99

        # 2. PING FLOOD
        elif packet.haslayer(ICMP) and rate > 20.0 and count > 20:
            final_label, conf = "DOS-ICMP-FLOOD", 0.99
            
        # 3. DOS FLOOD (THE CURL FIX IS HERE: Must have >40 packets)
        elif rate > CONFIG["DOS_RATE_THRESHOLD"] and count > CONFIG["DDOS_MIN_PACKETS"]:
            if packet.haslayer(TCP): 
                final_label, conf = "DOS-SYN-FLOOD" if syns > 5 else "DOS-TCP-FLOOD", 0.98
            elif packet.haslayer(UDP): 
                final_label, conf = "DOS-UDP-FLOOD", 0.98

        # --- ML FALLBACK ---
        else:
            if self.model and "Benign" in final_label:
                try:
                    input_df = self.extract_features(packet, dur, rate)
                    print(f"[DEBUG] Extracted features shape: {input_df.shape}")
                    if self.scaler:
                        input_data = self.scaler.transform(input_df)
                    else:
                        for c in ['flow_duration', 'rate', 'tot_size']: 
                            input_df[c] = np.log1p(input_df[c])
                        input_data = input_df

                    probs = self.model.predict_proba(input_data)[0]
                    pred_idx = np.argmax(probs)
                    ml_conf = np.max(probs)
                    
                    ml_label = "Unknown"
                    if self.label_encoder:
                        ml_label = self.label_encoder.inverse_transform([pred_idx])[0]
                    elif pred_idx in CONFIG["MANUAL_MAPPING"]:
                        ml_label = CONFIG["MANUAL_MAPPING"][pred_idx]
                    
                    # Ignore ML DOS predictions if packet volume is too low (curl micro-bursts)
                    if ("DOS" in ml_label or "DDoS" in ml_label) and count < CONFIG["DDOS_MIN_PACKETS"]:
                        pass
                    elif "Benign" not in ml_label:
                        final_label = ml_label
                        conf = ml_conf
                    print(f"[DEBUG] Prediction: {ml_label}, Confidence: {ml_conf:.2f}")
                except Exception as e:
                    pass

        print(f"[DEBUG] Final Label (Heuristics + ML): {final_label}")

        # 6. SEND ALERT
        if "Benign" not in final_label:
            # --- START: Suricata Alert Usage Example ---
            flow_data = {
                "src_ip": src,
                "src_port": packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0),
                "dest_ip": dst,
                "dest_port": packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0),
                "proto": "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else ("ICMP" if packet.haslayer(ICMP) else "Other"))
            }

            suricata_alert = build_suricata_style_alert(
                flow=flow_data,
                prediction=1,  # We know it's an attack if "Benign" is not in final_label
                confidence=conf,
                attack_type=final_label
            )

            self._alert(src, dst, final_label, conf, rate, unique_ports, suricata_alert=suricata_alert)

    def _alert(self, src, dst, label, conf, rate, ports, suricata_alert=None):
        color = "\033[91m" if "DOS" in label.upper() else "\033[93m"
        print(f"{color}[!] ALERT: {label} | Src: {src} -> {dst} | Rate: {rate:.1f} | Ports: {ports}\033[0m")
        
        # Map NeuralGuard labels to system standard DOS/RECON
        std_type = "UNKNOWN"
        label_lower = label.lower()
        if "dos" in label_lower or "flood" in label_lower:
            std_type = "DOS"
        elif "scan" in label_lower or "recon" in label_lower:
            std_type = "RECON"

        try:
            # We must send exactly what AIDSEvent pydantic model expects in main.py
            payload = {
                "source": "AIDS",
                "src_ip": src,
                "dest_ip": dst,
                "type": std_type,
                "subtype": label,
                "confidence": float(conf),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            requests.post(CONFIG["API_URL"], json=payload, timeout=0.5)
        except Exception as e:
            # print(f"Failed to send alert: {e}")
            pass

def test_model():
    print("[+] Loading Model...")
    engine = IDSEngine()
    
    if engine.model is None:
        print("Model not loaded")
        return
        
    print("[+] Model Loaded Successfully")
    print("[+] Running Test Inference...")
    
    f = {k: 0.0 for k in EXPECTED_FEATURES}
    input_df = pd.DataFrame([f], columns=EXPECTED_FEATURES)
    
    try:
        input_data = input_df.copy()
        if engine.scaler:
            input_data = engine.scaler.transform(input_df)
        else:
            for c in ['flow_duration', 'rate', 'tot_size']: 
                input_data[c] = np.log1p(input_df[c])

        probs = engine.model.predict_proba(input_data)[0]
        pred_idx = np.argmax(probs)
        conf = np.max(probs)
        
        ml_label = "Unknown"
        if engine.label_encoder:
            ml_label = engine.label_encoder.inverse_transform([pred_idx])[0]
        elif pred_idx in CONFIG["MANUAL_MAPPING"]:
            ml_label = CONFIG["MANUAL_MAPPING"][pred_idx]
            
        print(f"Prediction: {ml_label}")
        print(f"Confidence: {conf:.2f}")
        prob_str = "[" + ", ".join([f"{p:.2f}" for p in probs]) + "]"
        print(f"Probabilities: {prob_str}")
        
        if str(ml_label).lower() == "benign":
            print("[!] Warning: Output is always Benign. Possible model issue.")
            
    except Exception as e:
        print(f"[-] Prediction failed: {e}")

def main():
    if "--test-model" in sys.argv:
        test_model()
        sys.exit(0)

    print(f"[*] NEURALGUARD PRODUCTION IDS ACTIVE ON {CONFIG['INTERFACE']}")
    engine = IDSEngine()
    try:
        sniff(iface=CONFIG['INTERFACE'], prn=engine.predict, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\n[*] IDS Stopped.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
