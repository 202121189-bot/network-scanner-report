# 🌐 Network Scanner & Report

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Nmap](https://img.shields.io/badge/Nmap-7.x-green.svg)
![Domain](https://img.shields.io/badge/Domain-Network%20Security-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A network reconnaissance tool built with **Python + Nmap** that discovers live hosts, detects open ports, identifies running services, and generates a professional HTML/JSON/CSV report.

## ✨ Features

- 🔍 **Host Discovery** — find live hosts on any network (ping scan)
- 🚪 **Port Scanning** — detect open TCP/UDP ports
- 🛠️ **Service Detection** — identify services, products, and versions
- 🖥️ **OS Detection** — best-effort operating system fingerprinting
- 📊 **Multi-format Report** — HTML, JSON, CSV
- 📈 **Summary Dashboard** — live hosts, open ports, statistics

## 🛠️ Requirements

- Python 3.8+
- **Nmap** installed and in PATH
- `python-nmap` library
- `jinja2` library

### Install dependencies

```bash
pip install -r requirements.txt