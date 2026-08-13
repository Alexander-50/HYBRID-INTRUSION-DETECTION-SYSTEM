# 🛡️ Hybrid Intrusion Detection System

> **A Hybrid Intrusion Detection System for IoT environments that combines Signature-Based Detection, Machine-Learning-Based Anomaly Detection, and AND-based event correlation.**

![Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![Suricata](https://img.shields.io/badge/SIDS-Suricata-red)
![Python](https://img.shields.io/badge/ML-Python-yellow)
![Scikit Learn](https://img.shields.io/badge/ML-Scikit--learn-orange)
![Docker](https://img.shields.io/badge/Infrastructure-Docker-2496ED)
![IoT](https://img.shields.io/badge/Environment-IoT-purple)

---

## 📌 Overview

The **Hybrid Intrusion Detection System (IDS)** is a network-level security monitoring system designed for **IoT environments**.

The project combines two complementary detection mechanisms:

- 🔴 **Signature-Based Intrusion Detection System (SIDS)** using **Suricata**
- 🟠 **Anomaly-Based Intrusion Detection System (AIDS)** using **Machine Learning**

Network traffic is analyzed independently by both detection engines. Their detection events are then passed to a **correlation layer**, where **AND-based correlation logic** is used to identify attacks detected by both detection mechanisms.

The resulting events are presented through a **custom-built real-time monitoring dashboard**, providing visibility into individual detections as well as correlated attacks.

---

# 🎯 Objectives

The project was built to demonstrate how **signature-based detection and machine-learning-based anomaly detection can work together within an IoT network security architecture**.

### Key objectives

* Detect known attack patterns using Suricata.
* Detect anomalous network behavior using Machine Learning.
* Develop custom Suricata rules for attack detection.
* Implement an AND-based correlation mechanism between SIDS and AIDS detections.
* Generate unified security events from correlated detections.
* Monitor attack activity through a custom-built dashboard.
* Evaluate the system against multiple network and application-layer attack scenarios.
* Provide a centralized detection architecture suitable for IoT gateway environments.

---

# 🏗️ System Architecture

The system operates at the **network gateway level**, allowing traffic between external networks and IoT devices to be inspected by both detection mechanisms.

![Hybrid IDS Architecture](https://github.com/user-attachments/assets/557e896a-4ee1-4776-8f1d-270e89c3ffc6)

## Detection Flow

```text
                    External / Attacker Network
                              │
                              ▼
                    ┌─────────────────────┐
                    │     IoT Gateway     │
                    │                     │
                    │   Network Traffic   │
                    └──────────┬──────────┘
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
        ┌───────────────────┐     ┌───────────────────┐
        │     Suricata      │     │    ML Detector    │
        │       SIDS        │     │       AIDS        │
        │                   │     │                   │
        │ Signature-Based   │     │ Anomaly-Based     │
        │ Detection         │     │ Detection         │
        └─────────┬─────────┘     └─────────┬─────────┘
                  │                         │
                  │     Detection Events    │
                  └────────────┬────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Correlation Engine│
                    │                     │
                    │    SIDS ──┐        │
                    │            ├──► AND ───► Correlated
                    │    AIDS ──┘             Attack
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Alert Processing   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Dashboard      │
                    │                     │
                    │ • SIDS Alerts       │
                    │ • AIDS Alerts       │
                    │ • Correlations      │
                    │ • Attack Type       │
                    │ • Severity          │
                    │ • Source / Target   │
                    │ • Event Details     │
                    └─────────────────────┘
```

---

# 🔀 Hybrid Detection & Correlation

The core of the system is the interaction between the **SIDS** and **AIDS** detection layers.

Rather than relying on a single detection mechanism, the system evaluates network activity through both approaches.

### 🔴 SIDS

Suricata analyzes network traffic against signatures and custom rules to identify **known attack patterns**.

### 🟠 AIDS

The Machine Learning component analyzes network traffic characteristics to identify **abnormal or anomalous behavior**.

### 🔗 Correlation

The outputs of both detection mechanisms are passed to the correlation layer.

The system applies **AND-based correlation logic** to identify events where the relevant SIDS and AIDS conditions are satisfied.

```text
              SIDS Detection
                    │
                    │
                    ▼
                 ┌─────┐
                 │ AND │──────► Correlated Attack
                 └─────┘
                    ▲
                    │
                    │
              AIDS Detection
```

This creates a detection pipeline based on:

> **Signature Detection + Behavioral Anomaly Detection → Correlated Security Event**

The correlation layer allows the system to distinguish between isolated detection events and attacks supported by both detection mechanisms.

---

# 🔴 Signature-Based IDS — Suricata

The **SIDS module** uses **Suricata** as the signature-based detection engine.

Custom Suricata rules were developed specifically for the attack scenarios used in this project, including **SQL Injection and multiple DoS/flood-based attacks**.

## Custom Detection Rules

The project includes custom signatures for detecting:

### 💉 SQL Injection

Custom Suricata rules were created to identify SQL Injection patterns within HTTP requests, including variations of malicious SQL payloads.

### 🌊 Denial-of-Service Attacks

Custom rules were developed for multiple flood-based attack patterns, including:

- TCP Flood
- UDP Flood
- TCP SYN Flood
- TCP ACK Flood
- TCP FIN Flood

These rules were tested against controlled attack traffic generated within the lab environment.

## Capabilities

- Custom Suricata rule development
- SQL Injection detection
- DoS/flood attack detection
- Protocol-aware inspection
- HTTP traffic analysis
- TCP traffic analysis
- Real-time alert generation
- Custom attack-pattern detection
- Integration with the hybrid correlation layer

The custom rules form the **SIDS component of the hybrid detection pipeline**, with their alerts subsequently correlated with the ML-based AIDS output.
---

# 🟠 Anomaly-Based IDS — Machine Learning

The **AIDS module** complements Suricata by using Machine Learning to identify abnormal network behavior.

Instead of relying exclusively on predefined attack signatures, the ML detection layer evaluates network traffic characteristics and identifies anomalous behavior.

## Capabilities

* Network traffic feature analysis
* ML-based anomaly detection
* Ensemble-based detection
* Detection of abnormal traffic behavior
* Integration with the hybrid detection pipeline
* Designed with IoT environments and resource constraints in consideration

The AIDS layer provides a second detection perspective that complements conventional signature-based inspection.

---

# ⚔️ Attack Scenarios

The completed system was evaluated against multiple attack scenarios covering **network reconnaissance, application-layer attacks, and flood-based DoS traffic**.

## 🔎 Network Reconnaissance

### Nmap Aggressive Scanning

The system was tested against aggressive Nmap scanning to evaluate its ability to identify reconnaissance activity and abnormal scanning behavior.

---

## 💉 SQL Injection

The project includes a deliberately vulnerable web application used as a controlled target for SQL Injection testing.

Multiple SQL Injection payload variations were used to evaluate the detection capabilities of the system.

---

## 🌊 Flood-Based DoS Attacks

The system was tested against several flood-based traffic patterns:

* TCP Flood
* UDP Flood
* TCP SYN Flood
* TCP ACK Flood
* TCP FIN Flood

These scenarios were used to evaluate detection of high-volume and abnormal network traffic patterns.

---

## 🧪 Custom Payload-Based Intrusions

Custom payload-based intrusion scenarios were also used to evaluate the ability of the detection layers to identify traffic outside simple predefined test cases.

---

# 📊 Real-Time Monitoring Dashboard

A **custom-built dashboard** was developed as the visualization and monitoring layer of the system.

The dashboard provides a centralized view of the security events generated by the detection pipeline.

![Real-Time Alert Dashboard](https://github.com/user-attachments/assets/571af33e-9b10-43d8-9256-57a4d43d3d0a)

### Dashboard Visibility

The dashboard provides visibility into:

* 🔴 SIDS detections
* 🟠 AIDS detections
* 🔗 Correlated attack events
* ⚠️ Attack severity
* 🌐 Source and destination information
* 🕒 Event timestamps
* 📋 Detection details
* 📈 Attack activity
* 🔍 Detection correlations

The dashboard makes it possible to observe individual detection events and their resulting correlations in real time.

> **Custom-built dashboard demonstrating real-time alert generation and security-event correlation.**

---

# 🌐 Vulnerable Web Application

A deliberately vulnerable web application was developed as part of the controlled testing environment.

The application provides a safe target for simulating application-layer attacks and validating the IDS detection pipeline.

![Vulnerable Web Application](https://github.com/user-attachments/assets/2add9a6d-50d7-444e-8ccb-bed32caaebba)

### Testing Purpose

The application was used to:

* Simulate SQL Injection attacks.
* Generate realistic HTTP attack traffic.
* Validate Suricata signatures.
* Produce network traffic for ML analysis.
* Validate the hybrid detection and correlation pipeline.

> **Deliberately vulnerable web application used for controlled SQL Injection testing.**

---

# 🛠️ Technology Stack

## Detection

* **Suricata**
* Custom IDS rules
* Network traffic analysis

## Machine Learning

* **Python**
* **Scikit-learn**
* Ensemble-based ML detection

## Infrastructure

* **Linux**
* IOT device
* Windows 
* Networking

## Testing

* **Nmap**
* Controlled DoS/flood traffic 
* SQL Injection payloads
* Custom attack payloads
* Vulnerable web application

---

# 📁 Repository Structure

```text
HYBRID-INTRUSION-DETECTION-SYSTEM/
│
├── SIDS_module/
│   ├── Suricata configuration
│   ├── Custom rules
│   └── Signature-based detection
│
├── AIDS_module/
│   ├── Machine learning model
│   ├── Feature processing
│   └── Network traffic detection
│
├── Vuln_Login/
│   └── Vulnerable web application
│
├── suricata_backup/
│   └── Backup configuration files
│
├── scripts/
│   └── Integration and helper scripts
│
├── requirements.txt
└── README.md
```

> **Note:** Runtime logs, PCAP files, generated alerts and other runtime data are excluded from the repository to keep the project lightweight and maintain a clean source tree.

---

# ⚡ Quick Start

## 1. Clone the Repository

```bash
git clone https://github.com/Alexander-50/HYBRID-INTRUSION-DETECTION-SYSTEM.git
cd HYBRID-INTRUSION-DETECTION-SYSTEM
```

## 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

## 3. Start the Suricata Detection Layer

Replace `<interface>` with the network interface being monitored.

```bash
sudo suricata -c SIDS/suricata.yaml -i <interface>
```

## 4. Start the ML Detection Layer

```bash
python3 AIDS_module/sniffer.py
```

> **Lab note:** Interface names, permissions, configuration paths and model paths may vary depending on the deployment environment.

---

# 🧪 Testing Workflow

The system was tested using a controlled attack-generation and detection workflow.

```text
                    ┌──────────────────┐
                    │ Configure System │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Generate Attack  │
                    │     Traffic      │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Network Traffic  │
                    │     Analysis     │
                    └────────┬─────────┘
                             │
                  ┌──────────┴──────────┐
                  ▼                     ▼
            ┌───────────┐         ┌───────────┐
            │  Suricata │         │    ML     │
            │   SIDS    │         │   AIDS    │
            └─────┬─────┘         └─────┬─────┘
                  │                     │
                  └──────────┬──────────┘
                             ▼
                    ┌──────────────────┐
                    │    AND-Based     │
                    │    Correlation   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Correlated Attack│
                    │      Event       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Dashboard     │
                    └──────────────────┘
```

---

# 🌍 Real-World Use Case

The architecture is applicable to environments where IoT devices communicate through a centralized network gateway.

A gateway-based IDS can provide centralized visibility into traffic without requiring a dedicated IDS agent to be installed on every individual IoT device.

### Potential Security Monitoring Scenarios

* Unauthorized network scanning
* Suspicious connection attempts
* Exploitation attempts
* Abnormal device communication
* Flood-based network attacks
* Malicious HTTP requests
* Unexpected traffic behavior

The hybrid architecture provides multiple perspectives on the same network activity, allowing security events to be evaluated through both **signature-based** and **behavior-based** detection.

---

# 🔬 Project Highlights

### 🛡️ Hybrid Detection

Combines two fundamentally different detection approaches:

**Signature-Based Detection + Machine Learning-Based Anomaly Detection**

### 🔗 AND-Based Correlation

Detection events from SIDS and AIDS are correlated to identify attacks supported by both detection mechanisms.

### ⚡ Real-Time Monitoring

Detection events are processed and displayed through a custom monitoring dashboard.

### 🧩 Modular Architecture

The SIDS, AIDS, correlation, testing and visualization components are organized into separate modules.

### 🧪 Multi-Vector Testing

The system was tested against reconnaissance, SQL Injection, multiple flood-based DoS attacks and custom payload-based intrusions.

### 🌐 IoT-Focused Design

The architecture is designed around centralized monitoring of IoT network traffic at the gateway level.

---

# 📌 Project Status

## ✅ Completed

The Hybrid Intrusion Detection System has been implemented and tested as a functional cybersecurity research project.

The completed implementation includes:

* ✅ Suricata-based SIDS
* ✅ Custom Suricata rules
* ✅ ML-based AIDS
* ✅ Network traffic analysis
* ✅ AND-based detection correlation
* ✅ Attack-event generation
* ✅ Real-time monitoring dashboard
* ✅ Vulnerable web application for controlled testing
* ✅ Multiple attack simulations
* ✅ IoT gateway-oriented architecture

---

# 🔐 Security & Ethical Use

This project is intended for:

* Cybersecurity research
* IDS/IPS experimentation
* IoT security research
* Security education
* Controlled penetration-testing environments
* Network detection engineering

All attack simulations and testing should be performed only against systems for which you have explicit authorization.

---

# 👤 Researcher

## Alexander P.B

**Cybersecurity Researcher**

📧 **Email:** [pbalexander69@gmail.com](mailto:pbalexander69@gmail.com)

Interested in the implementation, research methodology, or potential collaboration?

Feel free to get in touch.

---

<p align="center">
  <b>Hybrid Detection • IoT Security • Network Monitoring • Machine Learning • Security Analytics</b>
</p>
```
