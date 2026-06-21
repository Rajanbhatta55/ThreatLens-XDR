
<p align="center">
  <img src="https://img.shields.io/badge/ThreatLens-XDR-000000?style=for-the-badge">
</p>

<p align="center">
  <b>Next-Generation Log Intelligence & Threat Detection Platform</b><br>
  Autonomous Threat Hunting • Incident Correlation • Digital Forensics • SIEM Integration
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Deployment-CLI%20%7C%20Agent%20%7C%20API-black?style=flat-square">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Integrated-red?style=flat-square">
  <img src="https://img.shields.io/badge/Sigma-Rules-blueviolet?style=flat-square">
  <img src="https://img.shields.io/badge/Encryption-AES--256-green?style=flat-square">
</p>

---

## 🧠 Overview

**ThreatLens-XDR** is an enterprise-grade security analytics engine designed to transform raw system logs into **actionable threat intelligence in real time**.

Built for:
- SOC Analysts (Tier 1–3)
- Incident Response Teams
- Threat Hunters
- Digital Forensics Investigators

### 🔐 Core Mission
> Detect attacks early, reconstruct attacker behavior, and reduce incident response time from hours to seconds.

---

## ⚙️ Platform Capabilities

### 🔍 Real-Time Threat Detection
- Brute force & credential stuffing detection  
- Lateral movement identification  
- Privilege escalation tracking  
- Suspicious PowerShell / LOLBin execution  
- DNS tunneling detection  
- Persistence mechanism discovery  
- Defense evasion tracking  

---

### 🔗 Attack Correlation Engine (XDR Core)
ThreatLens reconstructs:
- Multi-stage attack chains  
- Kill chain progression (Initial Access → Exfiltration)  
- Cross-host attack relationships  
- User behavior anomalies  

---

### 🧾 Digital Forensics Module
- Automated forensic PDF report generation  
- Attack timeline reconstruction  
- Evidence bundling (JSON / CSV / HTML)  
- SOC-ready incident packaging  

---

### 🔐 Security & Integrity Layer
- AES-256 encryption for sensitive reports  
- RSA-2048 digital signatures  
- SHA-256 chain-of-custody validation  
- Tamper-proof evidence tracking  

---

### 🔌 Enterprise Integrations
- Wazuh SIEM ingestion  
- Windows Event Log streaming agent  
- SQLite threat warehouse  
- API-ready SOC integration  

---

## 🧩 System Architecture

```text
Log Sources (EVTX / JSON / Syslog)
                │
                ▼
        Parsing Layer
                │
                ▼
 Threat Detection Engine
 (Sigma + YAML + Plugins)
                │
                ▼
 Attack Correlation Engine (XDR)
                │
                ▼
 Reporting Layer
 (JSON / HTML / PDF / Timeline)
                │
                ▼
        SOC / SIEM Analysts
```


### Reports & Export

```bash
threatlens scan logs/ -o report.json -f json
threatlens scan logs/ -o report.csv  -f csv
threatlens scan logs/ -o report.html -f html
threatlens scan logs/ -o report.md   -f md
threatlens scan logs/ --timeline timeline.html

# Print a quick severity breakdown of an existing JSON report without re-scanning
threatlens summary report.json

# Disable a noisy built-in detector by class name or substring
threatlens scan logs/ --exclude BruteForceDetector --exclude lateral
```
