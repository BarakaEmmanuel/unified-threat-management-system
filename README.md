# Linux Unified Threat Management (UTM) Stack

A lightweight, hybrid User and Entity Behavior Analytics (UEBA) and Layer 4 automated firewall application for Linux systems. 

This project integrates Machine Learning anomaly detection (Isolation Forest) with direct kernel-level `iptables` rule management to identify malicious behavioral patterns, prevent data exfiltration (DLP), and enforce bidirectional network blocking in real time.

---

## Architecture Overview

The system operates across a decoupled multi-layered architecture:
* **Layer 1 Rust Based Sniffer and Moving Target Defense(`collector.rs,bridge.rs`)**: Uses a rust based sniffer to intercept and filter packets and route traffic going in and out through a virtual TUN Bridge that obscures the original IP address and MAC Address.
* **Layer 2 / Machine Learning (`ueba_engine.py`)**: Uses an Unsupervised `Isolation Forest` model trained on local baseline packet data to detect behavioral anomalies, oversized payloads, and blacklisted destination interactions.
* **Layer 3 The Graphic User Interface(`gui_main.py`)**: A graphical interface that allows monitoring and management of traffic and the system as a whole.
* **Layer 4 Kernel Firewall (`firewall_driver.py`)**: Controls network traffic dynamically by attaching a custom `UTM_FILTER` chain to both `INPUT` and `OUTPUT` `iptables` chains for bidirectional blocking.
* **Reconciliation Daemon (`utm_daemon.py`)**: A background service that periodically synchronizes dynamic SQLite firewall rules with kernel `iptables` and handles automated rule expiration (TTL cleanup).
* **Control Dashboard (`gui_main.py`)**: Interactive GUI interface providing real-time log monitoring, traffic simulation tools, and dynamic rule management (Whitelist / Blacklist / Auto-Block).
* **Unified Orchestrator (`utm`)**: A Bash wrapper handling privilege escalation checks, virtual environment setup, background daemon execution, and graceful process teardown.

---

## Prerequisites

* **OS**: Linux (Ubuntu/Debian recommended with `iptables` support)
* **Python**: `Python 3.8+`
* **System Packages**:
  ```bash
  sudo apt update
  sudo apt install -y iptables python3-tk python3-venv
  ```
This system intercepts, filters and analyses network traffic and builds a model of the users baseline behaviour.
Traffic that does not fit within this baseline is flagged and blocked keeping the system secure.

## Languages used

* **Rust**
* **Python**

## Project Structure
## 📁 Project Structure

```text
├── Cargo.toml           # Rust package configuration
├── Cargo.lock           # Rust dependency lockfile
├── src/
│   └── bin/
│       ├── collector.rs # High-performance packet capture engine
│       └── bridge.rs    # IPC/Stream bridge between collector and UEBA
├── utm                  # Unified Bash execution wrapper
├── utm_daemon.py        # Background Layer 4 reconciliation loop & TTL handler
├── firewall_driver.py   # Low-level iptables wrapper (bidirectional filtering)
├── ueba_engine.py       # Isolation Forest ML detection & DLP engine
├── gui_main.py          # Dashboard GUI application
├── database.py          # SQLite database interface & schema definitions
├── requirements.txt     # Python package dependencies
└── README.md            # Project documentation
```

## Running the system
In order to activate and run this system, run the following command in your Terminal
sudo ./utm

