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

It is built for:
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
ThreatLens automatically reconstructs:
- Multi-stage attack chains
- Kill chain progression (Initial Access → Exfiltration)
- Cross-host attack relationships
- User behavior anomalies

---

### 🧾 Digital Forensics Module
- Automated forensic PDF report generation
- Attack timeline reconstruction
- Evidence bundling (JSON / CSV / HTML)
- Incident case packaging for SOC workflows

---

### 🔐 Security & Integrity Layer
- AES-256 encryption for sensitive reports
- RSA-2048 digital signatures
- SHA-256 chain-of-custody validation
- Tamper-proof forensic evidence tracking

---

### 🔌 Enterprise Integrations
- Wazuh SIEM ingestion
- Windows Event Log streaming agent
- SQLite-based threat warehouse
- API-ready architecture for SOC pipelines

---

## 🧩 System Architecture

            +----------------------+
            |  Log Sources         |
            | (EVTX / JSON / Syslog|
            +----------+-----------+
                       |
                       v
            +----------------------+
            |  Parsing Layer       |
            +----------+-----------+
                       |
                       v
    +--------------------------------------+
    | Detection & Threat Intelligence Core |
    |  - Sigma Rules                      |
    |  - Custom YAML Rules               |
    |  - Python Plugins                  |
    +----------------+---------------------+
                     |
                     v
    +--------------------------------------+
    | Attack Correlation Engine (XDR)     |
    +----------------+---------------------+
                     |
                     v
    +--------------------------------------+
    | Reporting & Export Layer            |
    | JSON / HTML / PDF / Timeline        |
    +--------------------------------------+
                     |
                     v
            SOC / SIEM / Analysts

---

## 📦 Installation

```bash
git clone https://github.com/your-org/ThreatLens-XDR.git
cd ThreatLens-XDR

python -m venv .venv
source .venv/bin/activate   # Linux / macOS
.venv\Scripts\activate      # Windows

pip install -e .
⚡ Quick Start
threatlens scan logs/security.json
🧠 Core Operations
🔎 Threat Detection
threatlens scan logs/
threatlens scan logs/ --min-severity high --verbose
threatlens scan logs/ --custom-rules rules/
threatlens scan logs/ --timeline attack_timeline.html
📊 Reporting & Intelligence
threatlens summary report.json
threatlens rules
📡 SIEM Integration (Wazuh)
threatlens wazuh-pull \
  --url https://wazuh:55000 \
  --user analyst \
  --password secret
🪟 Endpoint Telemetry (Windows Agent)
threatlens windows-agent-listen \
  --output windows-agent-logs.jsonl
🔗 Incident Correlation (XDR Engine)
threatlens seed-db --database threatlens.db
threatlens correlate --database threatlens.db
🧾 Forensic Report Generation
threatlens forensic-report \
  --database threatlens.db \
  --output incident_report.pdf
🔐 Security Operations
Encrypt Evidence (AES-256)
threatlens encrypt-report report.pdf --key-file aes.key
Decrypt Evidence
threatlens decrypt-report report.pdf.enc --key-file aes.key
Sign Reports (RSA-2048)
threatlens sign-report report.pdf --private-key private.pem
Verify Chain of Custody
threatlens verify-chain --database threatlens.db
📧 Automation & SOC Reporting
threatlens weekly-report \
  --database threatlens.db \
  --smtp-host smtp.gmail.com
📂 Supported Data Sources
JSON / NDJSON logs
Windows EVTX logs
Linux Syslog (RFC 3164 / 5424)
SIEM exports (Wazuh compatible)
🛡 MITRE ATT&CK Coverage

ThreatLens maps detections to:

Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Exfiltration
Command & Control
🔐 Security Model

ThreatLens is built strictly for defensive security:

❌ No exploitation modules
❌ No offensive payloads
❌ No network attack features
✅ Log analysis only
✅ Authorized forensic use only
📊 Example Detection Output
[HIGH] Credential Attack Detected
MITRE: T1110 - Brute Force
Source IP: 192.168.1.10
Target Account: ADMIN
Event Count: 34 failed login attempts
Confidence: 96%
🧪 Development
pip install -e ".[dev]"
pytest tests/
🏢 Product Vision

ThreatLens-XDR is designed to evolve into a full-scale:

🔹 SOC Automation Platform
🔹 Threat Intelligence Engine
🔹 XDR (Extended Detection & Response) System
🔹 Digital Forensics Suite
