<p align="center">
  <img src="assets/5G-GIBBON_logo.png" alt="5G-Gibbon Logo" width="400">
</p>

<h1 align="center"></h1>
<p align="center">
  <strong>Advanced 5G/4G LTE Core Network Security Testing Toolkit</strong>
</p>
<p align="center">
  <em>Red Team & Blue Team capabilities for mobile network infrastructure</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/5G-NR%20%7C%20NGAP%20%7C%20SBI%20%7C%20PFCP-orange.svg" alt="5G Support">
  <img src="https://img.shields.io/badge/4G-LTE%20%7C%20S1AP%20%7C%20Diameter-purple.svg" alt="4G Support">
</p>

---

**Author:** NET - Gaspberry

A comprehensive **5G and 4G/LTE** core network security testing framework for authorized penetration testing and security audits.

**Supports:** 5G NR (NGAP, SBI, PFCP, GTP-U) + 4G LTE (S1AP, Diameter, GTP)

---

## Quick Start (6 Steps)

### 1. Download the Toolkit

```bash
git clone https://github.com/Suffix30/5G-Gibbon.git
cd 5G-Gibbon
```

### 2. Install Requirements

```bash
# Linux/WSL (Recommended)
chmod +x setup.sh
./setup.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Load the Toolkit

```bash
source venv/bin/activate
python run.py
```

### 4. Scan for Targets

```bash
# From interactive menu: Select [1] Discovery
# Or directly:
sudo python run.py discover --network 10.0.0.0/24
```

### 5. Target Point of Interest

The toolkit auto-detects 5G components (UPF, AMF, SMF, NRF, etc.) and displays them.

### 6. Run Against Target

```bash
# Full security audit
sudo python run.py audit

# Red team attack
sudo python run.py ultra-red

# Blue team defense
sudo python run.py ultra-blue
```

---

## Usage Modes

### Interactive Mode (Recommended for first-time users)

```bash
python run.py
```

Shows a menu-driven interface with all options.

### Direct Command Mode (Power users)

```bash
python run.py <command> [options]
```

| Command                | Description                        |
| ---------------------- | ---------------------------------- |
| `discover`           | Scan network for 5G/4G components  |
| `audit`              | Run comprehensive security audit   |
| `keys standard`      | Standard key extraction            |
| `keys maximum`       | Maximum extraction (all methods)   |
| `attack billing`     | Billing fraud attack               |
| `attack nested`      | Nested GTP-U tunnel attack         |
| `async scan`         | Async network scan (10x faster)    |
| `async teid`         | Async TEID enumeration (5x faster) |
| `timing teid-oracle` | TEID oracle timing attack          |
| `fuzz gtp`           | Advanced GTP protocol fuzzing      |
| `report html`        | Generate HTML security report      |
| `dashboard`          | Start real-time dashboard          |
| `ultra-red`          | Full red team framework            |
| `ultra-blue`         | Full blue team defense             |
| `lte rogue-enb`      | Register rogue eNodeB to MME       |
| `lte hss-probe`      | Probe HSS via Diameter CER         |
| `lte imsi-enum`      | Enumerate valid IMSIs              |
| `lte auth-vectors`   | Extract auth vectors from HSS      |
| `lte assessment`     | Full 4G/LTE security assessment    |

Run `python run.py --help` for all commands.

---

## Requirements

- Python 3.8+
- Linux/WSL (recommended for raw socket access)
- Root/sudo (for network operations)

---

## Folder Structure

```
5G-Gibbon/
├── run.py              # Main entry point
├── setup.sh            # Setup script
├── requirements.txt    # Dependencies
├── docs/               # Documentation
├── core/               # CLI, config, async utilities
├── discovery/          # Network scanning (sync + async)
├── enumeration/        # TEID/SEID enumeration (sync + async)
├── key_extraction/     # Key extraction modules
├── attacks/            # Attack modules (sync + async)
├── defense/            # Blue team / remediation
├── red_team/           # Red team framework
├── analysis/           # Packet analysis
├── audit/              # Security audit
├── protocol/           # Protocol definitions (HTTP/2, SCTP)
├── tunneling/          # GTP-U tunneling
└── utils/              # Utilities
```

---

## Docker Usage

```bash
# Build and run dashboard
docker-compose up -d gibbon-dashboard

# Run toolkit in container
docker-compose run gibbon --help
docker-compose run gibbon discover --network 10.0.0.0/24
```

---

## Documentation

| Guide                                   | Description                                          |
| --------------------------------------- | ---------------------------------------------------- |
| [Installation Guide](docs/INSTALLATION.md) | System requirements, platform setup, troubleshooting |
| [User Guide](docs/USER_GUIDE.md)           | CLI commands, workflows, configuration               |
| [Honeypot Guide](docs/HONEYPOT.md)         | Deploy and use the honeypot network                  |
| [Reporting Guide](docs/REPORTING.md)       | Generate HTML, JSON, topology reports                |
| [Docker Guide](docs/DOCKER.md)             | Container deployment, docker-compose                 |
| [Architecture](docs/ARCHITECTURE.md)       | Technical overview for developers                    |

---

## Attack Coverage

### 5G NR Attacks

| Attack Vector        | Details                   |
| -------------------- | ------------------------- |
| TEID Enumeration     | Sync + Async modes        |
| Nested GTP-U Tunnels | Multi-layer encapsulation |
| Billing Fraud        | Sync + Async modes        |
| Battery Drain        | UE power exhaustion       |
| Session Hijacking    | PDU session takeover      |
| Key Extraction       | 4 extraction methods      |
| Rogue gNodeB         | NGAP registration         |
| PFCP Attacks         | Session manipulation      |
| DPI Bypass           | Tunnel obfuscation        |
| Timing Attacks       | TEID/Session oracle       |
| Side-Channel         | Error/Traffic analysis    |
| Protocol Fuzzing     | GTP/PFCP/NGAP             |
| HTTP/2 SBI           | NRF/UDM/AMF exploitation  |

### 4G LTE Attacks

| Attack Vector             | Protocol |
| ------------------------- | -------- |
| Rogue eNodeB Registration | S1AP     |
| Initial UE Injection      | S1AP     |
| Forced Handover           | S1AP     |
| S1 Interface Reset        | S1AP     |
| HSS Diameter Probe        | CER/CEA  |
| IMSI Enumeration          | AIR/AIA  |
| Cancel Location           | CLR/CLA  |
| Auth Vector Extraction    | AIR/AIA  |
| Purge UE                  | PUR/PUA  |
| S1AP/Diameter Flood       | DoS      |

## Defense Modules

| Module              | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| IDS Signatures      | Generate Snort/Suricata/iptables rules for 5G attack detection |
| Honeypot Network    | Deploy fake UPF/SMF/NRF to detect attackers                    |
| Anomaly Detector    | Real-time traffic anomaly detection with baseline learning     |
| Security Audit      | Compliance checking (GSMA 5G, 3GPP, NIST)                      |
| DPI Rules           | Deep packet inspection firewall rules                          |
| Blue Team Framework | Full defensive monitoring and remediation                      |

## Analysis Modules

| Module             | Description                                     |
| ------------------ | ----------------------------------------------- |
| Traffic Analyzer   | Deep protocol parsing (GTP-U, PFCP, NGAP, SBI)  |
| Session Tracker    | Track UE registrations, PDU sessions, handovers |
| Packet Capture     | Real-time packet capture and analysis           |
| Rate Limit Testing | Detect rate limiting thresholds                 |

## Reporting

| Feature          | Command                           |
| ---------------- | --------------------------------- |
| HTML Report      | `python run.py report html`     |
| JSON Export      | `python run.py report json`     |
| Network Topology | `python run.py report topology` |
| Live Dashboard   | `python run.py dashboard`       |

**[View Example Reports →](examples/)**

---

## Warning

This toolkit is for **AUTHORIZED SECURITY TESTING ONLY**.
Unauthorized use against networks you don't own is illegal.

---

## License

For authorized security research and penetration testing only.
