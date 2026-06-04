# Malak-Cyber

**Malak-Cyber** is a Windows-first security reconnaissance and vulnerability assessment tool designed for authorized security testing. It combines passive reconnaissance, active enumeration, web security assessment, CVE correlation, risk scoring, and offline HTML report generation into a single workflow.

> **Disclaimer:** This tool is intended strictly for authorized security assessments. Only scan systems that you own or have explicit written permission to test.

---
## Features

### Active Enumeration

* Nmap-powered port scanning
* Service discovery
* Web crawling
* Sensitive path probing
* Host and service enumeration

### Vulnerability Assessment

* Security header analysis
* Cookie security review
* TLS/SSL configuration checks
* URL parameter inspection
* CVE correlation and mapping
* Risk rating and prioritization

### Passive Reconnaissance

* WHOIS lookups
* DNS enumeration
* Passive subdomain discovery
* Certificate Transparency checks
* IP intelligence gathering
* Search engine dork checklist generation
* Technology fingerprinting

### Reporting

* Fully offline HTML and PDF report generation
* Self-contained reports with inline CSS
* No external CDN dependencies
* Professional risk summaries and findings

---

# Requirements
* Python 3.10 or newer
* Nmap
Download Nmap:
https://nmap.org/download
Ensure `nmap.exe` is installed and available in your system `PATH`.
---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/DanyalMunir0326/Malak-Cyber
cd Malak-Cyber
```

## 2. Create venv & Install Dependencies

For Linux
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
For Windows
```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
---

## 3.Run The Tool

```bash
python malak-cyber.py
```
---

# User Input

When the scanner starts, it prompts for only three inputs:

1. Analyst Name
2. Target
3. Scan Mode

Example:

```text
Enter your name: Alice
Enter target: example.com
Select scan mode: Full Assessment
```

---

# Scan Modes

## Full Assessment

Performs a complete security assessment including:

* Passive reconnaissance
* Active reconnaissance
* Enumeration
* Web vulnerability checks
* CVE correlation
* Risk analysis
* HTML report generation

---

## Passive Recon Only

Performs:

* WHOIS lookups
* DNS enumeration
* Passive subdomain discovery
* Certificate Transparency analysis
* Technology fingerprinting
* IP intelligence gathering
* Dork checklist generation

No active scanning is performed.

---

## Active Recon + Enumeration

Performs:

* Nmap port scanning
* Service detection
* Web crawling
* Sensitive path probing
* Service enumeration

---

## Vulnerability Assessment Only

Performs:

* Security header analysis
* Cookie security checks
* TLS/SSL review
* Parameter assessment
* CVE correlation
* Risk scoring

---

# Reports

Reports are automatically saved in:

```text
reports/
```

Naming format:

```text
Malak-Cyber-<analyst_name>-<timestamp>.html
```

Example:

```text
reports/Malak-Cyber-John-20260602-143522.html
```

---

# Operational Notes

* All terminal output uses the Rich library after dependency checks complete.
* Every HTTP request uses a 10-second timeout.
* Failed checks are logged as warnings and do not stop execution.
* Reports are generated locally and work completely offline.
* No external CSS, JavaScript, or CDN resources are required.

---

# Example Workflow

```text
Start Scanner
      │
      ▼
Enter Analyst Name
      │
      ▼
Enter Target
      │
      ▼
Choose Scan Mode
      │
      ▼
Reconnaissance
      │
      ▼
Enumeration
      │
      ▼
Vulnerability Assessment
      │
      ▼
CVE Correlation
      │
      ▼
Risk Rating
      │
      ▼
Generate HTML Report
```

---

# Project Structure

```text
Malak-cyber/
│
├── malak-cyber.py
├── run.bat
├── requirements.txt
│
├── reports/
│   └── Generated HTML Reports
│
└── README.md
```

---

# Security & Ethics

Malak-Scanner is intended for:

* Security professionals
* Penetration testers
* Security researchers
* Blue team analysts
* Students practicing in authorized lab environments

Do not use this tool against systems, networks, or applications without explicit authorization.

Unauthorized scanning may violate laws, regulations, organizational policies, or service agreements.

---

# License

Use responsibly and ethically.

The authors assume no liability for misuse, damages, or legal consequences resulting from the use of this software.
# Malak-Cyber
