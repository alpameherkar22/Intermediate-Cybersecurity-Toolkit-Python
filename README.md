# Intermediate Cybersecurity Toolkit (Python)

A modular collection of custom-built cybersecurity and network utility tools developed using Python 3.12+. This repository covers various aspects of security auditing, vulnerability scanning, traffic analysis, and low-level socket communication.

---

## 🛠️ Toolkit Modules

| Module | Tool Name | Description |
| :--- | :--- | :--- |
| **08** | Multi-Threaded Port Scanner | Concurrent TCP port scanner using thread pools for fast service discovery. |
| **09** | HTTP Header Analyzer | Security header audit tool checking for CSP, HSTS, X-Frame-Options, and more. |
| **10** | Web Directory Brute-Forcer | Multi-threaded HTTP path discovery tool using custom wordlists. |
| **11** | Network Mapper | Local subnet scanner identifying active hosts via ARP and ICMP pings. |
| **12** | Interactive Network Honeypot | Lightweight TCP honeypot tracking attacker IPs, timestamps, and logging payloads. |
| **13** | Automated Log Analyzer | Regex-based log parser that extracts traffic stats and flags brute-force attempts. |
| **14** | Advanced Port Scanner & Banner Grabber | Multi-threaded port scanner with active service fingerprinting and banner retrieval. |
| **15** | Automated SQL Injection Scanner | HTTP request fuzzer checking query parameters for error-based SQL vulnerabilities. |
| **16** | Encrypted Reverse Shell | Secure C2-style utility featuring TLS/SSL socket wrapping and self-signed certificates. |

---

## ⚙️ Prerequisites & Environment
* **Python Version:** Python 3.12+
* **Dependencies:** Standard library modules (`socket`, `ssl`, `subprocess`, `argparse`, `re`, `threading`) plus `requests`.

---

## 🚀 Usage Note
These tools are built for educational, defensive testing, and authorized security assessment purposes only.