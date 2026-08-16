# SentinelX-Advanced-SIEM-Automated-Threat-Detection-System
SentinelX is a Python-based SIEM-style security monitoring and threat detection system that analyzes security logs, identifies suspicious activity, correlates events by source IP, generates alerts and incidents, calculates risk scores, and produces automated security reports.
# SentinelX 🛡️

SentinelX is a Python-based SIEM-style security monitoring and automated threat detection system designed for log analysis and security event correlation.

## Features

- Log ingestion from .log, .txt, and .csv files
- Security event parsing and severity classification
- IP address and timestamp extraction
- Brute-force detection
- Failed-login correlation
- Access-denied spike detection
- High-activity detection
- Critical security event detection
- Automated security alerts
- Incident generation and status management
- Risk scoring (0–100)
- IOC extraction
- MITRE ATT&CK technique mapping
- Log search and security statistics
- Trusted IP management
- TXT, JSON, CSV, and HTML report generation
- Real-time log monitoring mode

## How It Works

Log File
   ↓
Log Parser
   ↓
Event Classification
   ↓
Threat Detection
   ↓
Event Correlation
   ↓
Risk Scoring
   ↓
Alerts & Incidents
   ↓
Security Reports

## Technologies

- Python
- Regular Expressions
- SIEM Concepts
- Log Analysis
- Threat Detection
- Event Correlation
- MITRE ATT&CK

## Usage

`bash
python SentinelX_Phase5_Final.py
