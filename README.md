# Hybrid Intrusion Detection System

## 🚀 Overview

This project implements a **Hybrid Intrusion Detection System (HIDS)** designed for IoT environments by combining:

* **Signature-Based Intrusion Detection System (SIDS)** using Suricata
* **Anomaly-Based Intrusion Detection System (AIDS)** using Machine Learning

The system operates at the **network gateway level**, monitoring traffic between IoT devices and external networks to detect both **known and unknown attacks**.

---

## 🧠 Architecture

```
     Attacker
        ↓
Target / IoT Device
        ↓
Gateway IDS (172.20.0.2)
   ├── Suricata (SIDS)
   └── ML Engine (AIDS)
        ↓
   Alerts / Logs / Detection Output
```

---

## ⚔️ Attacks Simulated

The system is tested against real-world attack scenarios:

* Nmap aggressive scanning
* SQL Injection attacks
* DoS / Flood attacks
* Custom payload-based intrusions

---

## 📊 Detection Capabilities

### 🔹 SIDS (Suricata)

* Custom rule-based detection
* Protocol analysis (HTTP, TCP, etc.)
* Real-time alert generation

### 🔹 AIDS (Machine Learning)

* Detects anomalies beyond known signatures
* Lightweight model suitable for IoT constraints
* Works alongside Suricata for hybrid detection

---

## 🧩 Key Features

* Hybrid detection (Signature + Anomaly)
* Real-time monitoring
* Custom Suricata rules
* Modular architecture
* Designed for IoT environments

---

## 🛠️ Tech Stack

* Suricata
* Python
* Scikit-learn
* Docker
* Linux Networking

---

## ⚡ Quick Start

```bash
git clone https://github.com/Alexander-50/HYBRID-INTRUSION-DETECTION-SYSTEM.git
cd HYBRID-INTRUSION-DETECTION-SYSTEM

pip install -r requirements.txt

# Run Suricata (SIDS)
sudo suricata -c SIDS/suricata.yaml -i <interface>

# Run ML Detection (AIDS)
python3 AIDS_module/detection_script.py
```

---

## 📁 Project Structure

```
SIDS_module/        # Suricata rules, configs, detection
AIDS_module/        # Machine learning model and detection logic
Vuln_Login/         # Vulnerable web application for testing
suricata_backup/    # Backup configs (logs excluded)
scripts/            # Integration / helper scripts
```

---

## 📸 Demo (To Be Added)

* Suricata alerts (eve.json samples)
* Attack execution logs
* Detection outputs

---

## 🧠 Real-World Use Case

This system can be deployed at an IoT gateway to detect:

* Unauthorized scanning
* Exploitation attempts
* Abnormal device behavior

---

## ⚠️ Note

Logs, PCAP files, and runtime data are excluded from this repository to maintain a clean and lightweight structure.

---


