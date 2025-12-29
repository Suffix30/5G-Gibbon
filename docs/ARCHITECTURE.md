[← Back to README](../README.md) | [Installation](INSTALLATION.md) | [User Guide](USER_GUIDE.md) | [Honeypot](HONEYPOT.md) | [Reporting](REPORTING.md) | [Docker](DOCKER.md)

---

# Architecture Overview

## Project Structure

```
5G-Gibbon/
├── run.py                 # Main entry point
├── requirements.txt       # Python dependencies
├── setup.sh              # Linux setup script
├── install.py            # Cross-platform installer
├── Dockerfile            # Container definition
├── docker-compose.yml    # Multi-container setup
├── Makefile              # Common commands
│
├── core/                 # Core framework
│   ├── cli.py           # Command-line interface (Rich UI)
│   ├── config.py        # Configuration and constants
│   ├── results_db.py    # SQLite result storage
│   ├── logger_config.py # Logging configuration
│   ├── resource_manager.py  # Socket lifecycle management
│   ├── progress_tracker.py  # Progress bars
│   ├── response_verifier.py # Packet verification
│   ├── async_utils.py   # Async rate limiting, retry logic
│   ├── streaming.py     # Memory-efficient data streaming
│   └── adaptive_rate.py # Dynamic rate limiting
│
├── discovery/            # Network scanning
│   ├── network_discovery.py  # Component discovery
│   ├── network_scanner.py    # Port scanning
│   ├── quick_discovery.py    # Fast scan mode
│   └── async_scanner.py      # Async scanning (10x faster)
│
├── enumeration/          # TEID/SEID enumeration
│   ├── teid_seid_enumeration.py  # Standard enumeration
│   ├── enhanced_enumeration.py   # Advanced techniques
│   └── async_enumeration.py      # Async enumeration
│
├── attacks/              # Attack modules
│   ├── billing_fraud.py        # GTP billing bypass
│   ├── nested_tunnel_testing.py # Multi-layer GTP tunnels
│   ├── pfcp_attacks.py         # PFCP session manipulation
│   ├── ngap_injection.py       # NGAP message injection
│   ├── ue_to_ue_injection.py   # UE traffic injection
│   ├── rogue_gnodeb.py         # Rogue gNodeB registration
│   ├── advanced_gnb_registration.py # Advanced gNB attacks
│   ├── timing_attacks.py       # Timing-based attacks
│   ├── side_channel.py         # Side-channel analysis
│   ├── advanced_fuzzing.py     # Protocol fuzzing
│   ├── async_attacks.py        # Async attack variants
│   └── lte_attacks.py          # 4G/LTE attacks (S1AP, Diameter)
│
├── key_extraction/       # Key extraction
│   ├── ngap_key_extraction.py    # NGAP-based extraction
│   ├── key_extraction_stress.py  # Stress testing
│   ├── nuclear_key_extraction.py # Aggressive extraction
│   └── maximum_extraction.py     # All methods combined
│
├── protocol/             # Protocol implementations
│   ├── protocol_layers.py   # Scapy layer definitions
│   ├── sctp_proper.py       # SCTP implementation
│   ├── sctp_enhanced.py     # Enhanced SCTP (multi-homing)
│   ├── http2_sbi.py         # HTTP/2 for SBI
│   ├── s1ap.py              # 4G S1AP protocol
│   └── diameter.py          # 4G Diameter protocol
│
├── defense/              # Blue team / defensive
│   ├── ultra_blue_team.py   # Full defense framework
│   ├── ids_signatures.py    # IDS rule generation
│   ├── honeypot.py          # Fake 5G components
│   ├── anomaly_detector.py  # Traffic anomaly detection
│   ├── security_audit.py    # Compliance checking
│   └── dpi_recommendations.txt # DPI config examples
│
├── analysis/             # Traffic analysis
│   ├── packet_capture.py    # PCAP capture
│   ├── pcap_analyzer.py     # PCAP parsing
│   ├── traffic_analyzer.py  # Deep protocol analysis
│   ├── session_tracker.py   # Session monitoring
│   └── rate_limit_testing.py # Rate limit detection
│
├── red_team/             # Red team framework
│   └── ultra_red_team.py    # Full attack suite
│
├── audit/                # Security audit
│   └── security_audit.py    # Audit orchestration
│
├── tunneling/            # GTP tunneling
│   └── gtpu_tunneling.py    # Tunnel management
│
├── reporting/            # Report generation
│   ├── html_report.py       # HTML reports
│   ├── visualization.py     # Network topology
│   ├── dashboard.py         # Real-time dashboard
│   └── __init__.py
│
├── utils/                # Utilities
│   └── performance_monitor.py # Performance tracking
│
├── tests/                # Test suite
│   └── test_toolkit.py      # Comprehensive tests
│
├── reports/              # Generated reports
│   ├── demo_report.html
│   ├── demo_topology.html
│   └── demo_report.json
│
└── results/              # Session data
    └── 5g_gibbon.db         # SQLite database
```

---

## Core Components

### CLI (`core/cli.py`)

The command-line interface uses [Rich](https://rich.readthedocs.io/) for a modern terminal UI. It supports:

- **Interactive mode**: Menu-driven navigation
- **Direct mode**: Command-line arguments for scripting

Key classes:
- `InteractiveMode`: Menu system
- `setup_argparse()`: Argument parsing
- `run_direct_mode()`: CLI execution

### Results Database (`core/results_db.py`)

SQLite database for persistent storage:

- `attack_results`: Attack outcomes
- `discovered_components`: Found 5G/4G elements
- `extracted_keys`: Captured subscriber keys
- `audit_findings`: Security findings

### Async Utilities (`core/async_utils.py`)

Provides high-performance async operations:

- `AsyncRateLimiter`: Token bucket rate limiting
- `async_retry_with_backoff`: Exponential backoff
- `AdaptiveRateLimiter`: Dynamic rate adjustment

---

## Protocol Stack

### 5G Protocols

| Protocol | Layer | Port | Module |
|----------|-------|------|--------|
| GTP-U | User Plane | 2152/UDP | `protocol/protocol_layers.py` |
| PFCP | Control Plane | 8805/UDP | `protocol/protocol_layers.py` |
| NGAP | Access Network | 38412/SCTP | `protocol/sctp_enhanced.py` |
| SBI | Service-Based | 80,443/HTTP2 | `protocol/http2_sbi.py` |

### 4G Protocols

| Protocol | Layer | Port | Module |
|----------|-------|------|--------|
| GTP | User Plane | 2152/UDP | `protocol/protocol_layers.py` |
| S1AP | Access Network | 36412/SCTP | `protocol/s1ap.py` |
| Diameter | Core | 3868/TCP | `protocol/diameter.py` |

---

## Attack Flow

```
Discovery → Enumeration → Exploitation → Reporting
    ↓            ↓              ↓            ↓
 Find 5G     Find TEIDs    Run attacks   Generate
 components   & SEIDs       & extract     HTML/JSON
                             keys         reports
```

### Typical Attack Chain

1. `discovery/network_discovery.py` - Find UPF, SMF, AMF
2. `enumeration/async_enumeration.py` - Enumerate active TEIDs
3. `attacks/billing_fraud.py` - Inject traffic
4. `key_extraction/maximum_extraction.py` - Extract keys
5. `reporting/html_report.py` - Document findings

---

## Reporting System

### Data Classes

```python
@dataclass
class Finding:
    title: str
    severity: SeverityLevel  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    affected_component: str
    evidence: str
    remediation: str

@dataclass
class AttackResult:
    attack_type: str
    target: str
    success: bool
    timestamp: str
    duration: float
    details: Dict
    attack_events: List[AttackEvent]

@dataclass
class AttackEvent:
    timestamp: str
    phase: str          # Reconnaissance, Enumeration, Exploitation
    technique: str
    command: str
    payload: str
    response: str
    success: bool
    evidence: Dict
```

### Report Types

- **HTML**: Full visual report with charts
- **JSON**: Machine-readable export
- **Topology**: D3.js network visualization

---

## Defense System

### Honeypot Architecture

```
Honeypot5GOrchestrator
    ├── GTPHoneypot (port 2152)
    ├── PFCPHoneypot (port 8805)
    └── SBIHoneypot (port 7777)
```

Each honeypot:
- Listens for connections
- Parses protocol-specific packets
- Classifies attack type
- Logs to AttackEvent
- Optionally sends fake responses

### IDS Integration

`defense/ids_signatures.py` generates:
- Snort rules
- Suricata rules
- iptables rules

---

## Extending the Toolkit

### Add New Attack

1. Create `attacks/my_attack.py`:

```python
def run_my_attack(target_ip: str, **kwargs) -> dict:
    # Attack logic
    return {"success": True, "details": {...}}
```

2. Register in `core/cli.py`:
   - Add to menu
   - Add argparse subparser
   - Add handler in `run_direct_mode()`

### Add New Protocol

1. Create `protocol/my_protocol.py`
2. Define Scapy layers
3. Add to `protocol/__init__.py`

### Add New Report Type

1. Extend `ReportGenerator` in `reporting/html_report.py`
2. Add `generate_my_format()` method

---

## Dependencies

| Package | Purpose |
|---------|---------|
| scapy | Packet crafting/parsing |
| rich | Terminal UI |
| h2 | HTTP/2 support |
| flask | Dashboard web server |
| psutil | System monitoring |

See `requirements.txt` for full list.

