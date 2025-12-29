[← Back to README](../README.md) | [Installation](INSTALLATION.md) | [User Guide](USER_GUIDE.md) | [Honeypot](HONEYPOT.md) | [Docker](DOCKER.md) | [Architecture](ARCHITECTURE.md)

---

# Reporting Guide

## Overview

5G-Gibbon generates three types of reports:

| Report Type | Format | Purpose |
|-------------|--------|---------|
| HTML Report | `.html` | Human-readable security assessment |
| JSON Export | `.json` | Machine-readable data for integration |
| Topology | `.html` | Interactive network visualization |

All reports share the same data and can be navigated between using tabs.

---

## Generating Reports

### From CLI

```bash
# HTML security report
python run.py report html --output my_report.html

# JSON export
python run.py report json --output results.json

# Network topology visualization
python run.py report topology --output topology.html

# Session report (from all stored data)
# In interactive mode: Reporting → Session Report
```

### From Code

```python
from reporting.html_report import ReportGenerator, Finding, SeverityLevel, AttackResult

report = ReportGenerator()

# Set metadata
report.set_metadata(
    title="5G Security Assessment",
    assessment_type="Penetration Test",
    target_network="10.0.0.0/24",
    start_time="2025-01-15 09:00:00",
    end_time="2025-01-15 17:00:00"
)

# Add findings
report.add_finding(Finding(
    title="TEID Enumeration Possible",
    severity=SeverityLevel.HIGH,
    description="UPF responds to sequential TEID probes",
    affected_component="UPF (10.0.0.10)",
    evidence="156 active TEIDs discovered",
    remediation="Implement TEID randomization"
))

# Generate reports
report.generate_html("assessment.html")
report.generate_json("assessment.json")
```

---

## Report Contents

### HTML Report Sections

1. **Header** - Title, target network, assessment period
2. **Executive Summary** - Severity counts, key metrics
3. **Security Findings** - Vulnerabilities with severity, evidence, remediation
4. **Scan Results** - Discovered ports and services
5. **Attack Results** - Attacks performed with full attack logs
6. **Recommendations** - Prioritized remediation steps

### Attack Logs

Each attack result includes a detailed attack log showing:

| Field | Description |
|-------|-------------|
| Timestamp | When the attack step occurred |
| Phase | Reconnaissance, Enumeration, Exploitation, etc. |
| Technique | Specific attack technique used |
| Command | Exact command executed |
| Payload | Data sent to target |
| Response | Target's response |
| Success | Whether the step succeeded |
| Evidence | Artifacts captured |

---

## Topology Report

The topology visualization shows:

- **Nodes** - Network components (UPF, SMF, AMF, etc.)
- **Links** - Connections between components
- **Attack Paths** - Red arrows showing exploitation flow
- **Compromised Nodes** - Highlighted in red

### Interactive Features

- **Hover** on nodes for quick info (name, IP, type)
- **Click** on nodes for detailed panel (ports, vulns, attack logs)
- **Click** sidebar items to navigate to that node
- **Zoom/Pan** to explore the network
- **Print** button for PDF export

---

## Live Dashboard

Start a real-time monitoring dashboard:

```bash
python run.py dashboard --port 8080
```

Then open `http://localhost:8080` in your browser.

The dashboard shows:
- Live attack events
- Statistics charts
- Recent findings
- Active connections

---

## Session Reports

All attacks and scans are stored in a SQLite database (`results/5g_gibbon.db`). Generate a report from all session data:

### From Interactive Mode

```
python run.py
→ [6] Reporting
→ [4] Session Report
```

### From Code

```python
from core.results_db import ResultsDatabase

db = ResultsDatabase()

# View statistics
stats = db.get_statistics()
print(f"Total attacks: {stats['total_attacks']}")

# Generate HTML report from all data
db.generate_html_report("session_report.html")

# Generate JSON
db.generate_json_report("session_report.json")
```

---

## Exporting to PDF

1. Open the HTML report in a browser
2. Click the **Export PDF** button (top-right)
3. Or use **Print → Save as PDF**

The report has print-optimized CSS that:
- Removes navigation elements
- Adjusts fonts for paper
- Prevents page breaks in the middle of sections

---

## Report Customization

### Change Output Directory

```python
from reporting.html_report import ReportGenerator

report = ReportGenerator(output_dir="my_reports")
report.generate_html("assessment.html")
# Saved to: my_reports/assessment.html
```

### Add Custom Findings

```python
from reporting.html_report import Finding, SeverityLevel

# Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
finding = Finding(
    title="Custom Finding Title",
    severity=SeverityLevel.CRITICAL,
    description="Detailed description of the issue",
    affected_component="Component Name (IP)",
    evidence="What you observed",
    remediation="How to fix it",
    cvss_score=9.8,
    cwe_id="CWE-287"
)
```

### Add Attack Events

```python
from reporting.html_report import AttackResult, AttackEvent

attack = AttackResult(
    attack_type="My Custom Attack",
    target="10.0.0.10",
    success=True,
    timestamp="2025-01-15 10:30:00",
    duration=45.5,
    details={"packets_sent": 1000, "responses": 500},
    attack_events=[
        AttackEvent(
            timestamp="2025-01-15 10:30:00",
            phase="Reconnaissance",
            technique="Port Scan",
            command="nmap -sU 10.0.0.10",
            response="2152/udp open",
            success=True,
            evidence={"ports": [2152]}
        )
    ]
)
```

---

## File Locations

| File | Location |
|------|----------|
| Generated reports | `reports/` folder |
| Session database | `results/5g_gibbon.db` |
| Demo reports | `reports/demo_*.html` |

---

## Troubleshooting

### Reports are empty
Run some attacks/scans first, then generate reports.

### PDF looks wrong
Use Chrome/Edge for best PDF export. Firefox may have issues.

### Charts not showing
Ensure you have internet access (Chart.js loads from CDN).

---

## Next Steps

- [USER_GUIDE.md](USER_GUIDE.md) - Run attacks to populate reports
- [HONEYPOT.md](HONEYPOT.md) - Honeypot-specific reports

