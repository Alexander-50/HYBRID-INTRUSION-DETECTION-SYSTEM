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
Gateway IDS 
   ├── Suricata (SIDS)
   └── ML Engine (AIDS)
        ↓  (OR Logic)
   Alerts / Logs / Detection Output 
```

---

## ⚔️ Attacks Simulated

The system is tested against real-world attack scenarios:

* Nmap aggressive scanning
* vaious types of SQL Injection attacks
* Flood based DoS attacks
   * TCP flood
   * UDP flood
   * TCP-SYN flood
   * TCP-ACK flood
   * TCP-FIN flood  
* Custom payload-based intrusions

---

## 📊 Detection Capabilities

### 🔹 SIDS (Suricata)
* Custom rule creation and detection for wide range of attacks
* Protocol analysis (HTTP, TCP, etc.)
* Real-time alert generation

### 🔹 AIDS (Machine Learning)

* Detects anomalies beyond known signatures
* Lightweight Ensemble model suitable for IoT constraints as well as lower False Positive Rate
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
python3 AIDS_module/sniffer.py
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


<img width="1826" height="995" alt="Screenshot from 2026-03-27 17-50-45" src="https://github.com/user-attachments/assets/571af33e-9b10-43d8-9256-57a4d43d3d0a" />

                                                  CUSTOM-BUILT DASHBOARD PREVIEW SHOWING REAL TIME ALERT GENERATION



---
<img width="1843" height="999" alt="Screenshot from 2026-03-25 13-55-31" src="https://github.com/user-attachments/assets/2add9a6d-50d7-444e-8ccb-bed32caaebba" />

                                                           VULNERABLE WEBSITE FOR SQLI TESTING
---

---

---
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

IF U ARE INTERESTED TO KNOW MORE DETAILS ON THIS RESEARCH PROJECT OR FOR COLLABORATION CONTACT :
 pbalexander69@gmail.com  
 Alexander P.B   
 Cybersecurity Researcher 

