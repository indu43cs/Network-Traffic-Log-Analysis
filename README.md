# Network Traffic Log Analysis using Wireshark & Python

## Overview

This project is a lightweight Network Forensics and SOC-style Traffic Analysis tool developed using Python, Scapy, and Wireshark packet captures.

The system analyzes `.pcap` network capture files to detect suspicious activities such as:

- Port scanning
- DNS anomalies
- Possible data exfiltration
- Suspicious communication patterns

The project simulates basic SOC Tier-1 analyst workflows including:

- Traffic inspection
- Alert triage
- Event filtering
- Threat detection
- Incident investigation

---

# Objectives

- Understand network packet analysis
- Learn PCAP forensic investigation
- Detect indicators of compromise (IOCs)
- Simulate real-world SOC workflows
- Build foundational network forensic tooling using Python

---

# Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Scapy | Packet parsing and PCAP analysis |
| Pandas | Data organization and reporting |
| Wireshark | Packet capture and traffic inspection |
| VS Code | Development environment |

---

# Project Structure

```text
Network Traffic Log Analysis/
│
├── captures/          # Sample .pcap files
├── src/               # Python analysis scripts
├── reports/           # Generated reports
├── notes/             # Learning notes and observations
├── requirements.txt   # Python dependencies
├── README.md          # Project documentation
└── .venv/             # Virtual environment
# Features

## 1. PCAP File Loading

Reads and parses `.pcap` files using Scapy.

### Extracted Information

- Source IP
- Destination IP
- Protocol
- Source Port
- Destination Port

---

## 2. Port Scan Detection

Detects suspicious reconnaissance activity where:

```text
One source IP -> multiple destination ports -> within short time window
```

### Detection Logic

- Time Window: 60 seconds
- Threshold: 10 unique destination ports

### Example Detection

```text
192.168.1.5 scanned ports:
21, 22, 80, 443, 8080
```

---

## 3. DNS Anomaly Detection

Detects suspicious DNS activity including:

- High-frequency DNS queries
- Random-looking domain names
- Numeric-heavy domains
- Potential malware beaconing patterns

### Example Suspicious Domains

```text
a8d91xq72kz.example.com
login9384759384.badsite.test
```

---

## 4. Data Exfiltration Detection

Detects potential unauthorized outbound data transfer.

### Detection Logic

```text
Private/Internal IP
        ↓
External/Public IP
        ↓
Large packet transfer
```

### Possible Indicators

- Insider threat
- Malware communication
- Unauthorized uploads
- Data leakage

---

# Installation

## Clone Repository

```bash
git clone <your-repository-url>
cd "Network Traffic Log Analysis"
```

---

## Create Virtual Environment

```bash
python -m venv .venv
```

---

## Activate Virtual Environment

### Windows

```powershell
.\.venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Requirements

```text
scapy
pandas
```

---

# Running the Project

## Sample PCAP File

Download sample PCAP files from:

https://wiki.wireshark.org/SampleCaptures

Place files inside:

```text
captures/
```

### Example

```text
captures/dns.cap
```

---

# Usage

## 1. Load and Inspect Packets

```powershell
python src\load_pcap.py captures\dns.cap
```

---

## 2. Detect Port Scans

```powershell
python src\detect_port_scans.py captures\dns.cap
```

---

## 3. Detect DNS Anomalies

```powershell
python src\detect_dns_anomalies.py captures\dns.cap
```

---

## 4. Detect Possible Data Exfiltration

```powershell
python src\detect_exfiltration.py captures\dns.cap
```

---

# Example Output

## Port Scan Detection

```text
Loaded 38 packets from captures\dns.cap
No port scan activity found.
```

---

## DNS Analysis

```text
Loaded 38 packets from captures\dns.cap
Found 38 DNS queries.

No high-frequency DNS sources found.

Random-looking DNS queries:
192.168.170.8 queried 104.9.192.66.in-addr.arpa
```

---

## Exfiltration Detection

```text
Loaded 38 packets from captures\dns.cap
No possible data exfiltration found.
```

---

# Forensic Relevance

This project demonstrates foundational concepts in:

- Network Forensics
- Incident Response
- Threat Hunting
- SOC Operations
- Traffic Analysis
- IOC Detection

The system provides a simplified simulation of real-world security monitoring and forensic investigation workflows.

---

# Future Improvements

- Unified reporting engine
- PDF/CSV forensic reports
- TLS fingerprinting (JA3)
- Real-time packet monitoring
- Machine learning anomaly detection
- SIEM integration
- Threat intelligence feeds
- Interactive dashboard

---

# Learning Outcomes

Through this project, the following concepts were explored:

- PCAP analysis
- Packet inspection
- DNS analysis
- Network anomaly detection
- Rule-based threat detection
- Python-based forensic automation
- SOC investigation workflows