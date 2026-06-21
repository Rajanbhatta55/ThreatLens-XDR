<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red?style=flat-square">
  <img src="https://img.shields.io/badge/Sigma-compatible-blueviolet?style=flat-square">
</p>

<h1 align="center">ThreatLens-XDR</h1>

<p align="center">
<b>Advanced Log Analysis, Threat Hunting & Digital Forensics CLI</b><br>
Detect multi-stage attacks, correlate incidents, build forensic reports, encrypt evidence, and integrate with SIEMs.
</p>

---

## 🚀 Overview

ThreatLens-XDR is a defensive cybersecurity CLI platform for:

- Threat hunting
- Incident response
- Digital forensics
- SIEM log analysis
- Attack chain correlation

It transforms raw logs into actionable security intelligence mapped to MITRE ATT&CK.

---

## ⚙️ Key Features

### 🔍 Threat Detection
- Brute-force / password spray detection  
- Lateral movement detection  
- Privilege escalation tracking  
- Suspicious process execution  
- Credential dumping detection  
- DNS tunneling detection  
- Persistence & defense evasion detection  

---

### 🔗 Incident Correlation
- Multi-stage attack chain reconstruction  
- Event correlation into incidents  
- SQLite-based forensic storage  

---

### 🧾 Forensics & Reporting
- Forensic PDF report generation  
- Timeline reconstruction  
- JSON / HTML / CSV reports  
- Weekly automated email reports  

---

### 🔐 Security Features
- AES-256 encryption (reports & evidence)  
- RSA-2048 digital signatures  
- SHA-256 hash chain verification  
- Evidence integrity validation  

---

### 🔌 Integrations
- Wazuh API integration  
- Windows Event Log streaming agent  
- SQLite threat database  
- SIEM-ready outputs  

---

## 📦 Installation

```bash
git clone https://github.com/your-repo/ThreatLens-XDR.git
cd ThreatLens-XDR

python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

pip install -e .
