<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=750&amp;lines=CIPHER+SIEM;Security+Information+%26+Event+Management;Syslog+%7C+Windows+Event+%7C+Apache+%7C+CEF;12+Sigma-like+Rules+%7C+4+Correlation+Engines" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![Sigma](https://img.shields.io/badge/Rules-Sigma--like-F97316?style=for-the-badge)](https://github.com/SigmaHQ/sigma)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Multi-source log ingestion, Sigma-like detection rules, temporal correlation, and MITRE ATT&CK-mapped alerting — at zero licensing cost.**

<br/>

[![Rules](https://img.shields.io/badge/Detection_Rules-12_YAML-64ffda?style=flat-square)](.)
[![Parsers](https://img.shields.io/badge/Log_Parsers-4_Formats-64ffda?style=flat-square)](.)
[![Correlation](https://img.shields.io/badge/Correlation-4_Attack_Patterns-64ffda?style=flat-square)](.)
[![Cost](https://img.shields.io/badge/License_Cost-%240-22c55e?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Problem Statement

Commercial SIEMs (Splunk, QRadar, Sentinel) cost **$50,000–$500,000/year**, pricing out small teams. CIPHER SIEM provides:

- **Multi-format log ingestion** — Syslog RFC 3164/5424, Windows Event Log, Apache/Nginx CLF, CEF
- **Sigma-like YAML rules** — same structure as industry-standard Sigma, drop-in extensible
- **Temporal correlation** — detects multi-event attack chains within a 5-minute sliding window
- **MITRE ATT&CK mapping** on every alert — tactic and technique IDs

| Feature | Details |
|---------|---------|
| **Log Sources** | Syslog, Windows Event, Apache/Nginx, CEF |
| **Detection Rules** | 12 Sigma-like YAML rules |
| **Correlation Rules** | Brute force, lateral movement, privilege escalation, data staging |
| **Correlation Window** | 5-minute sliding window |
| **MITRE Techniques** | T1110, T1059.001, T1003, T1053, T1543, T1021, T1074, T1068… |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Syslog │ Windows Event │ Apache/Nginx │ CEF
       │  POST /api/ingest
       ▼
┌──────────────────────────────────┐
│      Log Parser Router           │
│  RFC3164/5424│JSON│CLF│CEF       │
└──────────────┬───────────────────┘
               │  Normalized Event
    ┌──────────┴──────────┐
    ▼                     ▼
┌──────────────┐  ┌────────────────────────┐
│ YAML Rule    │  │ Event Correlator        │
│ Engine       │  │ Brute force (≥5 fails)  │
│ 12 rules     │  │ Lateral move (≥3 hosts) │
│ any/all/expr │  │ Privilege escalation    │
│ conditions   │  │ Data staging            │
└──────┬───────┘  └──────────┬─────────────┘
       └──────────┬───────────┘
                  │
       ┌──────────▼──────────┐
       │   Alert Manager     │
       │   Dedup (5 min)     │
       └──────────┬──────────┘
                  │
       ┌──────────▼──────────┐
       │  Dashboard + API    │
       └─────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Detection Rules

<details>
<summary><b>🔐 Authentication Rules (3 rules)</b></summary>

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| auth-001 | Multiple Failed Logins | HIGH | T1110 |
| auth-002 | SSH Root Login Attempt | CRITICAL | T1078 |
| auth-003 | Account Lockout | HIGH | T1110.001 |

</details>

<details>
<summary><b>⚙️ Process Rules (5 rules)</b></summary>

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| proc-001 | Suspicious PowerShell | HIGH | T1059.001 |
| proc-002 | Credential Dumping | CRITICAL | T1003 |
| proc-003 | Scheduled Task Creation | HIGH | T1053 |
| proc-004 | Service Installation | HIGH | T1543.003 |
| proc-005 | System Discovery Commands | MEDIUM | T1033 |

</details>

<details>
<summary><b>🌐 Network Rules (4 rules)</b></summary>

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| net-001 | Suspicious Outbound Port | HIGH | T1571 |
| net-002 | TOR Exit Node Traffic | HIGH | T1090.003 |
| net-003 | DNS Tunneling Indicator | MEDIUM | T1048.003 |
| net-004 | Web Application Attack | HIGH | T1190 |

</details>

### Log Format Examples

```bash
# Syslog RFC 3164
<34>Nov 15 10:23:15 webserver01 sshd[1234]: Failed password for root from 185.220.101.45

# Windows Event Log (JSON)
{"EventID": 4625, "Computer": "DC01", "SubjectUserName": "john"}

# Apache Combined Log
192.168.1.10 - - [01/Jan/2024] "GET /admin HTTP/1.1" 403 512 "-" "sqlmap/1.7"

# CEF
CEF:0|Vendor|Product|1.0|100|Login Failure|8|src=192.168.1.50 dst=10.0.0.1
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/cipher-siem.git
cd cipher-siem

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5006
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/cipher-siem.git
cd cipher-siem
docker build -t cipher-siem .
docker run -p 5006:5006 cipher-siem
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Ingest single log
POST /api/ingest
{"source": "syslog", "raw": "<34>Nov 15 10:23:15 ..."}

# Ingest batch (up to 200)
POST /api/ingest/batch
[{"source": "windows_event", "EventID": 4625, ...}]

# Get events
GET /api/events?source=syslog

# Get alerts
GET /api/alerts

# Update alert
PATCH /api/alert/<id>
{"status": "closed"}

# Stats
GET /api/stats
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
cipher-siem/
├── app.py                          # Flask application & REST API
├── wsgi.py                         # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── parsers/
│   ├── syslog_parser.py            # RFC 3164 + RFC 5424
│   ├── windows_event_parser.py     # Windows Event Log
│   ├── apache_parser.py            # Apache/Nginx CLF
│   └── cef_parser.py               # CEF format
│
├── core/
│   ├── rule_engine.py              # Sigma-like YAML engine
│   ├── correlator.py               # 4 temporal correlators
│   └── alert_manager.py            # Dedup & management
│
├── rules/
│   ├── authentication_rules.yaml   # 3 rules
│   ├── process_rules.yaml          # 5 rules
│   └── network_rules.yaml          # 4 rules
│
├── templates/                      # Dashboard, Events, Alerts
├── static/                         # CSS + JavaScript
└── tests/                          # 16 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)



> *"SIEM shouldn't cost a fortune. YAML rules and temporal correlation can cover the MITRE ATT&CK framework at zero licensing cost."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/cipher-siem?style=social)](https://github.com/RohitKumarReddySakam/cipher-siem)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
