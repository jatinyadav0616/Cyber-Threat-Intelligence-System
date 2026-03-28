# 🔐 Cyber Threat Intelligence System (CTIS)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![ML](https://img.shields.io/badge/Machine%20Learning-Random%20Forest-green?style=for-the-badge&logo=scikit-learn)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Threat%20Detection-red?style=for-the-badge&logo=shield)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Accuracy](https://img.shields.io/badge/Accuracy-97.67%25-success?style=for-the-badge)

**An AI-powered real-time network threat detection and intelligence system**

Built by [Jatin Yadav](https://www.linkedin.com/in/jatin-yadav-72612b257/)

</div>

---

## 📌 What is CTIS?

CTIS is a full-stack **Cyber Threat Intelligence System** that monitors network traffic in real time, classifies threats using Machine Learning, scores attacker IPs by risk level, detects coordinated attack campaigns, and auto-generates professional Threat Intelligence Reports — just like a real Security Operations Center (SOC).

> 💡 This project combines **Supervised ML + Unsupervised Anomaly Detection** to create a dual-layer AI security engine.

---

## 🎯 Features

| Feature | Description |
|--------|-------------|
| 🤖 **AI Threat Classifier** | Random Forest with 97.67% accuracy across 8 threat types |
| 🔍 **Anomaly Detection** | Isolation Forest flags unknown/zero-day style threats |
| 📊 **Risk Scoring Engine** | Scores every attacker IP from 0–100 in real time |
| 🕵️ **Campaign Detection** | Identifies coordinated multi-IP attack campaigns |
| 📄 **TIR Generator** | Auto-generates Threat Intelligence Reports with unique IDs |
| 🖥️ **Live SOC Dashboard** | Real-time color-coded terminal dashboard |

---

## 🚨 Threats Detected

```
┌─────────────────────────────────────────────────────┐
│  THREAT TYPE          RISK SCORE    SEVERITY        │
├─────────────────────────────────────────────────────┤
│  Zero-Day Exploit        95/100     🔴 CRITICAL     │
│  Data Exfiltration       90/100     🔴 CRITICAL     │
│  Privilege Escalation    85/100     🔴 CRITICAL     │
│  Malware C2 Beacon       80/100     🔴 CRITICAL     │
│  DDoS Attack             70/100     🟡 HIGH         │
│  Brute Force             65/100     🟡 HIGH         │
│  SQL Injection           60/100     🟡 HIGH         │
│  Port Scan               40/100     🔵 MEDIUM       │
│  Normal Traffic           5/100     🟢 SAFE         │
└─────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

```python
Language     : Python 3.8+
ML Models    : Random Forest Classifier (Supervised)
             : Isolation Forest (Unsupervised)
Libraries    : scikit-learn, pandas, numpy
Dataset      : NSL-KDD style (3,000 network events)
Features     : 11 behavioral + network features
```

---

## ⚡ Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/jatinyadav0616/Cyber-Threat-Intelligence-System.git
cd Cyber-Threat-Intelligence-System
```

### 2. Install dependencies
```bash
pip install scikit-learn pandas numpy
```

### 3. Run CTIS
```bash
python ctis.py
```

### 4. Launch Live SOC Dashboard
```
Press ENTER when prompted → Live dashboard starts
```

---

## 📸 Output Preview

### 🔹 Phase 1 — AI Training & Analysis
```
[1/6] Ingesting network event logs...      ✓ 3,000 entries loaded
[2/6] Anomaly detection (Isolation Forest) ✓ 450 anomalies flagged
[3/6] Training AI classifier...            ✓ Accuracy: 97.67%
[4/6] Computing IP risk scores...          ✓ 1,398 critical IPs
[5/6] Detecting attack campaigns...        ✓ 8 campaigns found
[6/6] Generating Threat Intel Report...    ✓ TIR ready
```

### 🔹 Phase 2 — Threat Intelligence Report
```
╔══════════════════════════════════════════════════╗
║         THREAT INTELLIGENCE REPORT (TIR)        ║
║         Report ID : TIR-5661A127                ║
║         Analyst   : AI Engine | Jatin Yadav     ║
╚══════════════════════════════════════════════════╝

Total Events : 3,000  |  Malicious : 71.3%
Campaigns    : 8      |  Accuracy  : 97.67%
```

### 🔹 Phase 3 — Live SOC Dashboard
```
🖥️  LIVE SOC DASHBOARD — REAL-TIME THREAT MONITOR
══════════════════════════════════════════════════
TIME      SRC IP             PORT   THREAT           RISK   STATUS
11:13:18  45.155.82.200       80    ZERO DAY          95    🚨 CRITICAL
11:13:19  23.129.179.124      53    BRUTE FORCE       85    🚨 CRITICAL
11:13:20  140.114.59.247     443    NORMAL             5    ✅ SAFE
11:13:21  198.98.134.187     443    DDOS              85    🚨 CRITICAL
```

---

## 🧠 How It Works

```
Network Logs (3,000 events)
         │
         ▼
┌─────────────────────┐
│  Isolation Forest   │  ← Flags anomalies (unsupervised)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Random Forest      │  ← Classifies threat type (97.67% accuracy)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Risk Scoring       │  ← Scores each IP 0-100
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Campaign Detector  │  ← Groups coordinated attacks
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  TIR + SOC Dashboard│  ← Report + Live monitoring
└─────────────────────┘
```

---

## 📁 Project Structure

```
Cyber-Threat-Intelligence-System/
├── ctis.py           ← Main system (all-in-one)
├── README.md         ← This file
└── threat_report.txt ← Auto-generated after each run
```

---

## 🎓 About the Developer

**Jatin Yadav**
- 🎓 B.Tech Computer Engineering + Minor in Cybersecurity
- 🏛️ Shri Vishwakarma Skill University, Palwal, Haryana
- 🏅 NDA-153 & INAC-115 Recommended
- 💼 Ex Python Developer Intern @ Trackila Smart Innovations
- 🔐 Fortinet Certified — Introduction to the Threat Landscape 3.0

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/jatin-yadav-72612b257/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/jatinyadav0616)

---

## 🚀 Future Enhancements

- [ ] Live packet capture using **Scapy**
- [ ] Web dashboard using **Flask + Chart.js**
- [ ] Email alerts for CRITICAL threats
- [ ] Integration with real **SIEM tools**
- [ ] Deploy as a **background service**
- [ ] Connect to real **CICIDS2017 dataset**

---

## 📜 License

This project is open source under the [MIT License](LICENSE).

---

<div align="center">

⭐ **Star this repo if you found it useful!** ⭐

*Built with ❤️ for cybersecurity, defence research, and open source*

</div>
