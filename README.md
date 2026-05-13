# GoldenEye – CEH Lab DoS/DDoS Security Research Tool

**For educational & authorized lab use only** – simulate attacks, detect anomalies, apply defenses, and log everything.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green)
![Bash](https://img.shields.io/badge/bash-5.1+-green)

## 📌 Features

| Category       | Capabilities                                                                 |
|----------------|------------------------------------------------------------------------------|
| **Attack**     | SYN, UDP, ICMP, HTTP floods, Slowloris (multi‑threaded DDoS simulation)     |
| **Detection**  | Real‑time packet analysis (Scapy/tcpdump) with rate‑based alerts            |
| **Defense**    | iptables hardening, SYN cookies, rate limiting, IP blocking, blackhole      |
| **Monitor**    | Process, connection & file integrity monitoring (malicious activity)        |
| **Logging**    | JSON + plain text logs, session summaries, report generation                |

## 🧪 Lab Environment

- **3 Ubuntu VMs** (attacker, target, monitor) on private `192.168.56.0/24`
- Target runs Apache2 (`sudo systemctl start apache2`)
- All operations require `sudo` (raw packets, iptables)

## 📦 Installation

### Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y tcpdump jq iproute2 iptables procps hping3 curl apache2-utils inotify-tools
