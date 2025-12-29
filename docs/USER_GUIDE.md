[← Back to README](../README.md) | [Installation](INSTALLATION.md) | [Honeypot](HONEYPOT.md) | [Reporting](REPORTING.md) | [Docker](DOCKER.md) | [Architecture](ARCHITECTURE.md)

---

# User Guide

## Getting Started

### Start the Toolkit

```bash
# Activate virtual environment first
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\Activate   # Windows

# Launch interactive mode
python run.py

# Or use direct commands
python run.py --help
```

---

## Interactive Mode

When you run `python run.py` without arguments, you get a menu-driven interface:

```
╔══════════════════════════════════════════════════════════════════╗
║                    5G-GIBBON SECURITY TOOLKIT                    ║
╚══════════════════════════════════════════════════════════════════╝

[1] Discovery        - Scan for 5G/4G network components
[2] Enumeration      - Enumerate TEIDs, SEIDs, sessions
[3] Key Extraction   - Extract subscriber keys
[4] Attacks          - Run attack modules
[5] Defense          - Blue team / defensive tools
[6] Reporting        - Generate reports
[7] 4G/LTE           - 4G-specific attacks
[8] Utilities        - Configuration, settings
[0] Exit

Select option:
```

Navigate by entering the number and pressing Enter.

---

## Command Line Mode

For automation and scripting, use direct commands:

### Discovery

```bash
# Scan a network for 5G/4G components
sudo python run.py discover --network 10.0.0.0/24

# Quick discovery (faster, less thorough)
sudo python run.py discover quick --network 10.0.0.0/24

# Async scan (10x faster)
sudo python run.py async scan --network 10.0.0.0/24
```

### Enumeration

```bash
# Enumerate TEIDs on a UPF
python run.py enumerate teid --target 10.0.0.10 --start 0 --end 10000

# Enumerate SEIDs on an SMF
python run.py enumerate seid --target 10.0.0.20 --start 0 --end 1000

# Async enumeration (5x faster)
python run.py async teid --target 10.0.0.10 --start 0 --end 10000
```

### Attacks

```bash
# Billing fraud attack
python run.py attack billing --target 10.0.0.10 --count 100

# Nested GTP tunnel attack
python run.py attack nested --target 10.0.0.10 --depth 3

# PFCP session manipulation
python run.py attack pfcp --target 10.0.0.20

# Rogue gNodeB registration
python run.py attack rogue --target 10.0.0.5

# Timing attacks
python run.py timing teid-oracle --target 10.0.0.10

# Protocol fuzzing
python run.py fuzz gtp --target 10.0.0.10 --cases 100
```

### 4G/LTE Attacks

```bash
# Register rogue eNodeB to MME
python run.py lte rogue-enb --mme 10.0.0.40

# Probe HSS via Diameter
python run.py lte hss-probe --hss 10.0.0.50

# Enumerate valid IMSIs
python run.py lte imsi-enum --hss 10.0.0.50 --count 1000

# Extract authentication vectors
python run.py lte auth-vectors --hss 10.0.0.50 --imsi 001010123456789

# Full 4G assessment
python run.py lte assessment --mme 10.0.0.40 --hss 10.0.0.50
```

### Key Extraction

```bash
# Standard extraction
python run.py keys standard

# Maximum extraction (all methods)
python run.py keys maximum

# Nuclear extraction (aggressive)
python run.py keys nuclear
```

### Defense

```bash
# Generate IDS signatures
python run.py defense ids --output ids_rules.txt

# Start honeypot network
python run.py defense honeypot --duration 3600

# Run anomaly detection
python run.py defense anomaly --interface eth0 --duration 300

# Security audit
python run.py defense audit
```

### Reporting

```bash
# Generate HTML report
python run.py report html --output my_report.html

# Generate JSON export
python run.py report json --output results.json

# Generate network topology
python run.py report topology --output topology.html

# Start live dashboard
python run.py dashboard --port 8080
```

### Red Team / Blue Team

```bash
# Full red team engagement
sudo python run.py ultra-red

# Full blue team defense
sudo python run.py ultra-blue
```

---

## Typical Workflow

### 1. Discovery Phase

```bash
# Find all 5G/4G components on the network
sudo python run.py discover --network 10.0.0.0/24
```

Output shows detected components:
- UPF (User Plane Function) - Port 2152
- SMF (Session Management Function) - Port 8805
- AMF (Access and Mobility Management) - Port 38412
- NRF (Network Repository Function) - Port 80
- MME (Mobility Management Entity) - Port 36412 (4G)
- HSS (Home Subscriber Server) - Port 3868 (4G)

### 2. Enumeration Phase

```bash
# Enumerate active TEIDs on discovered UPF
python run.py async teid --target 10.0.0.10 --start 0 --end 10000
```

### 3. Attack Phase

```bash
# Run billing fraud attack on UPF
python run.py attack billing --target 10.0.0.10

# Or run full red team assessment
sudo python run.py ultra-red
```

### 4. Reporting Phase

```bash
# Generate comprehensive HTML report
python run.py report html --output assessment_report.html
```

---

## Configuration

Edit `core/config.py` to set default targets:

```python
TEST_CONFIG = {
    "upf_ip": "10.0.0.10",
    "smf_ip": "10.0.0.20",
    "amf_ip": "10.0.0.5",
    "nrf_ip": "10.0.0.30",
    "mme_ip": "10.0.0.40",
    "hss_ip": "10.0.0.50",
}
```

---

## Tips

1. **Always use sudo** for network operations (discovery, attacks)
2. **Start with discovery** to map the network before attacking
3. **Use async modes** for faster scanning (10x speed improvement)
4. **Generate reports** to document findings
5. **Check the dashboard** for real-time monitoring

---

## Next Steps

- [HONEYPOT.md](HONEYPOT.md) - Set up defensive honeypots
- [REPORTING.md](REPORTING.md) - Understand report formats
- [DOCKER.md](DOCKER.md) - Run in containers

