[← Back to README](../README.md) | [Installation](INSTALLATION.md) | [User Guide](USER_GUIDE.md) | [Reporting](REPORTING.md) | [Docker](DOCKER.md) | [Architecture](ARCHITECTURE.md)

---

# Honeypot Setup Guide

## Overview

The 5G-Gibbon honeypot network deploys fake 5G core components to detect and log attacker activities. It captures:

- Attack techniques used
- Source IP addresses
- Protocol-level details
- Timestamps and patterns

---

## Honeypot Components

| Honeypot | Protocol | Port | Emulates |
|----------|----------|------|----------|
| GTP Honeypot | GTP-U | 2152 | User Plane Function (UPF) |
| PFCP Honeypot | PFCP | 8805 | Session Management Function (SMF) |
| SBI Honeypot | HTTP | 7777 | Network Repository Function (NRF) |

---

## Quick Start

### Start All Honeypots

```bash
# From CLI
python run.py defense honeypot --duration 3600

# Or in interactive mode
python run.py
# Select [5] Defense → [2] Honeypot
```

### Run Indefinitely

```bash
# Runs until Ctrl+C
python run.py defense honeypot --duration 0
```

---

## Programmatic Usage

```python
from defense.honeypot import Honeypot5GOrchestrator

# Create orchestrator
orchestrator = Honeypot5GOrchestrator(bind_ip="0.0.0.0")

# Add all honeypots
orchestrator.add_all()

# Or add specific honeypots
orchestrator.add_gtp_honeypot(port=2152)
orchestrator.add_pfcp_honeypot(port=8805)
orchestrator.add_sbi_honeypot(port=7777)

# Start
orchestrator.start_all()

# Let it run...
import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

# Stop and get results
orchestrator.stop_all()

# Get statistics
stats = orchestrator.get_statistics()
print(f"Total attacks: {stats['total_attacks']}")
print(f"By type: {stats['by_attack_type']}")
print(f"Top attackers: {stats['by_source_ip']}")

# Export events
orchestrator.export_all("honeypot_events.json")
```

---

## Attack Detection

The honeypots detect and classify these attack types:

### GTP Honeypot Detects

| Attack Type | Description |
|-------------|-------------|
| TEID_PROBE | TEID enumeration attempts |
| DATA_INJECTION | Malicious data in GTP tunnels |
| TUNNEL_ATTACK | GTP tunnel manipulation |
| PROTOCOL_FUZZING | Malformed GTP packets |
| LARGE_PACKET_ATTACK | Oversized packets |
| RECONNAISSANCE | General scanning |

### PFCP Honeypot Detects

| Attack Type | Description |
|-------------|-------------|
| HEARTBEAT_PROBE | PFCP heartbeat scanning |
| ASSOCIATION_ATTEMPT | Unauthorized association requests |
| SESSION_ESTABLISHMENT | Fake session creation |
| SESSION_MODIFICATION | Session tampering |
| SESSION_DELETION | Session teardown attacks |
| VERSION_DISCOVERY | Protocol version probing |

### SBI Honeypot Detects

| Attack Type | Description |
|-------------|-------------|
| NF_DISCOVERY_PROBE | NRF discovery scanning |
| ROGUE_NF_REGISTRATION | Fake NF registration attempts |
| SUBSCRIBER_DATA_THEFT | UDM data access attempts |
| AUTH_ATTACK | Authentication attacks |
| SESSION_MANIPULATION | SMF session attacks |
| NF_DEREGISTRATION_ATTACK | NF lifecycle attacks |

---

## Output Files

When the honeypot stops, it generates:

### 1. JSON Event Log (`honeypot_all_events.json`)

```json
{
  "statistics": {
    "total_attacks": 47,
    "by_attack_type": {
      "TEID_PROBE": 23,
      "DATA_INJECTION": 12,
      "NF_DISCOVERY_PROBE": 8
    },
    "by_source_ip": {
      "192.168.1.100": 35,
      "10.0.0.200": 12
    }
  },
  "events": [
    {
      "timestamp": "2025-01-15T10:30:45",
      "source_ip": "192.168.1.100",
      "source_port": 54321,
      "honeypot_type": "UPF",
      "protocol": "GTP-U",
      "attack_type": "TEID_PROBE",
      "raw_data_hex": "30ff0008...",
      "decoded_info": {"teid": 256, "message_type": 1}
    }
  ]
}
```

### 2. HTML Report (`honeypot_report.html`)

Visual report with:
- Attack statistics
- Timeline of attacks
- Top attackers
- Remediation recommendations

### 3. Topology Report (`honeypot_topology.html`)

Interactive visualization showing:
- Attacker → Honeypot connections
- Attack flow direction
- Compromised paths

---

## Deployment Scenarios

### Standalone Detection

Deploy the honeypot on unused IP addresses in your 5G network to detect lateral movement.

```bash
# Bind to specific IP
python -c "
from defense.honeypot import run_honeypot_network
run_honeypot_network(bind_ip='10.0.0.250', duration=0)
"
```

### Alongside Real Components

Run honeypots on alternate ports next to real 5G functions:

```python
from defense.honeypot import Honeypot5GOrchestrator

orchestrator = Honeypot5GOrchestrator()
orchestrator.add_gtp_honeypot(port=2153)   # Real UPF on 2152
orchestrator.add_pfcp_honeypot(port=8806)  # Real SMF on 8805
orchestrator.start_all()
```

### Docker Deployment

```bash
docker-compose up -d gibbon-honeypot
```

---

## Integration with Other Tools

### Feed to SIEM

Export events and ingest into your SIEM:

```bash
# Export to JSON
python -c "
from defense.honeypot import Honeypot5GOrchestrator
o = Honeypot5GOrchestrator()
o.export_all('/var/log/honeypot/events.json')
"
```

### Generate IDS Rules

After capturing attacks, generate detection rules:

```bash
python run.py defense ids --output /etc/suricata/rules/5g_honeypot.rules
```

---

## Tips

1. **Run as root** for binding to privileged ports (<1024)
2. **Use dedicated IPs** that aren't used by real components
3. **Monitor the logs** - high volume may indicate active attack
4. **Export regularly** to preserve evidence
5. **Generate reports** to share with security team

---

## Next Steps

- [REPORTING.md](REPORTING.md) - Understand honeypot reports
- [USER_GUIDE.md](USER_GUIDE.md) - Full CLI reference

