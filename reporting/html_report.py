#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    title: str
    severity: SeverityLevel
    description: str
    affected_component: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None

@dataclass
class ScanResult:
    target: str
    port: int
    service: str
    state: str
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class AttackEvent:
    timestamp: str
    phase: str
    technique: str
    command: str = ""
    payload: str = ""
    response: str = ""
    success: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackResult:
    attack_type: str
    target: str
    success: bool
    timestamp: str
    duration: float
    details: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    attack_events: List[AttackEvent] = field(default_factory=list)

@dataclass
class ReportMetadata:
    title: str
    assessment_type: str
    target_network: str
    start_time: str
    end_time: str
    analyst: str = "5G-Gibbon Toolkit"
    version: str = "1.0.0"

class ReportGenerator:
    def __init__(
        self,
        output_dir: str = "reports",
        template_dir: Optional[str] = None
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir = Path(template_dir) if template_dir else None
        
        self.metadata: Optional[ReportMetadata] = None
        self.findings: List[Finding] = []
        self.scan_results: List[ScanResult] = []
        self.attack_results: List[AttackResult] = []
    
    def set_metadata(
        self,
        title: str,
        assessment_type: str,
        target_network: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ):
        self.metadata = ReportMetadata(
            title=title,
            assessment_type=assessment_type,
            target_network=target_network,
            start_time=start_time or datetime.now().isoformat(),
            end_time=end_time or datetime.now().isoformat()
        )
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
    
    def add_scan_result(self, result: ScanResult):
        self.scan_results.append(result)
    
    def add_attack_result(self, result: AttackResult):
        self.attack_results.append(result)
        for f in result.findings:
            self.findings.append(f)
    
    def generate_html(self, filename: str = "report.html") -> str:
        html = self._build_html_report()
        
        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        
        logger.info(f"Report generated: {output_path}")
        return str(output_path)
    
    def generate_json(self, filename: str = "report.json") -> str:
        data = {
            "metadata": asdict(self.metadata) if self.metadata else {},
            "summary": self._get_summary(),
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "scan_results": [asdict(r) for r in self.scan_results],
            "attack_results": [self._attack_to_dict(r) for r in self.attack_results]
        }
        
        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {output_path}")
        return str(output_path)
    
    def _get_summary(self) -> Dict[str, Any]:
        severity_counts = {s.value: 0 for s in SeverityLevel}
        for f in self.findings:
            severity_counts[f.severity.value] += 1
        
        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "total_scans": len(self.scan_results),
            "total_attacks": len(self.attack_results),
            "successful_attacks": sum(1 for a in self.attack_results if a.success)
        }
    
    def _finding_to_dict(self, f: Finding) -> Dict:
        d = asdict(f)
        d["severity"] = f.severity.value
        return d
    
    def _attack_to_dict(self, a: AttackResult) -> Dict:
        d = asdict(a)
        d["findings"] = [self._finding_to_dict(f) for f in a.findings]
        return d
    
    def _build_html_report(self) -> str:
        summary = self._get_summary()
        
        css = self._get_css()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.metadata.title if self.metadata else '5G Security Assessment Report'}</title>
    <style>{css}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        {self._build_header()}
        {self._build_executive_summary(summary)}
        {self._build_findings_section()}
        {self._build_scan_results_section()}
        {self._build_attack_results_section()}
        {self._build_recommendations()}
        {self._build_footer()}
    </div>
    {self._build_charts_script(summary)}
</body>
</html>"""
        
        return html
    
    def _get_css(self) -> str:
        return """
:root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #12121a;
    --bg-tertiary: #1a1a25;
    --text-primary: #e0e0e8;
    --text-secondary: #a0a0b0;
    --accent-cyan: #00d4ff;
    --accent-magenta: #ff00ff;
    --accent-green: #00ff88;
    --severity-critical: #ff0040;
    --severity-high: #ff4444;
    --severity-medium: #ffaa00;
    --severity-low: #44aaff;
    --severity-info: #888899;
    --border-color: #2a2a3a;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
}

header {
    border-bottom: 2px solid var(--accent-cyan);
    padding-bottom: 2rem;
    margin-bottom: 3rem;
    background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
    padding: 2rem;
    border-radius: 8px;
}

header h1 {
    font-size: 2.5rem;
    background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
}

header .meta {
    color: var(--text-secondary);
    font-size: 0.9rem;
}

.report-nav {
    display: flex;
    gap: 10px;
    margin-bottom: 1.5rem;
}

.nav-tab {
    padding: 8px 20px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.9rem;
    transition: all 0.2s;
}

.nav-tab:hover {
    background: var(--bg-secondary);
    color: var(--accent-cyan);
    border-color: var(--accent-cyan);
}

.nav-tab.active {
    background: var(--accent-cyan);
    color: var(--bg-primary);
    border-color: var(--accent-cyan);
    font-weight: bold;
}

.section {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
}

.section h2 {
    color: var(--accent-cyan);
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    font-size: 1.3rem;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.summary-card {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
    border-left: 3px solid var(--accent-cyan);
}

.summary-card.critical { border-left-color: var(--severity-critical); }
.summary-card.high { border-left-color: var(--severity-high); }
.summary-card.medium { border-left-color: var(--severity-medium); }
.summary-card.low { border-left-color: var(--severity-low); }

.summary-card.clickable {
    cursor: pointer;
    transition: all 0.2s ease;
}

.summary-card.clickable:hover {
    transform: translateY(-3px);
    box-shadow: 0 5px 20px rgba(0, 212, 255, 0.3);
}

.summary-card.clickable:active {
    transform: translateY(0);
}

.report-actions {
    position: fixed;
    top: 20px;
    right: 20px;
    display: flex;
    gap: 0.5rem;
    z-index: 1000;
    background: rgba(10, 10, 15, 0.95);
    padding: 10px 15px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
}

.export-btn {
    background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--bg-secondary) 100%);
    border: 1px solid var(--accent-cyan);
    color: var(--accent-cyan);
    padding: 0.5rem 1rem;
    border-radius: 6px;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 6px;
}

.export-btn:hover {
    background: var(--accent-cyan);
    color: var(--bg-primary);
    box-shadow: 0 0 15px rgba(0, 212, 255, 0.4);
}

@media print {
    .report-actions { display: none; }
}

.finding-card.highlight {
    animation: highlightPulse 2s ease-out;
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
}

@keyframes highlightPulse {
    0% { box-shadow: 0 0 30px rgba(0, 212, 255, 0.8); }
    100% { box-shadow: none; }
}

.filter-bar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
}

.filter-btn {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    padding: 0.4rem 1rem;
    border-radius: 20px;
    cursor: pointer;
    font-size: 0.8rem;
    transition: all 0.2s ease;
}

.filter-btn:hover, .filter-btn.active {
    background: var(--accent-cyan);
    color: var(--bg-primary);
    border-color: var(--accent-cyan);
}

.filter-btn.critical:hover, .filter-btn.critical.active { background: var(--severity-critical); border-color: var(--severity-critical); }
.filter-btn.high:hover, .filter-btn.high.active { background: var(--severity-high); border-color: var(--severity-high); }
.filter-btn.medium:hover, .filter-btn.medium.active { background: var(--severity-medium); border-color: var(--severity-medium); }
.filter-btn.low:hover, .filter-btn.low.active { background: var(--severity-low); border-color: var(--severity-low); }

.finding-card.hidden {
    display: none;
}

.summary-card .number {
    font-size: 2rem;
    font-weight: bold;
    color: var(--accent-green);
}

.summary-card .label {
    color: var(--text-secondary);
    font-size: 0.85rem;
}

.finding {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 1rem;
    border-left: 4px solid var(--severity-info);
}

.finding.critical { border-left-color: var(--severity-critical); }
.finding.high { border-left-color: var(--severity-high); }
.finding.medium { border-left-color: var(--severity-medium); }
.finding.low { border-left-color: var(--severity-low); }

.finding h3 {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.finding h3 .title { color: var(--text-primary); }

.severity-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: bold;
    text-transform: uppercase;
}

.severity-badge.critical { background: var(--severity-critical); color: white; }
.severity-badge.high { background: var(--severity-high); color: white; }
.severity-badge.medium { background: var(--severity-medium); color: black; }
.severity-badge.low { background: var(--severity-low); color: white; }
.severity-badge.info { background: var(--severity-info); color: white; }

.finding .description { color: var(--text-secondary); margin-bottom: 0.5rem; }
.finding .component { color: var(--accent-cyan); font-size: 0.85rem; }

.evidence {
    background: var(--bg-primary);
    padding: 0.75rem;
    border-radius: 4px;
    margin-top: 0.5rem;
    font-family: monospace;
    font-size: 0.85rem;
    overflow-x: auto;
    border: 1px solid var(--border-color);
}

.remediation {
    background: rgba(0, 255, 136, 0.1);
    border: 1px solid var(--accent-green);
    padding: 0.75rem;
    border-radius: 4px;
    margin-top: 0.5rem;
}

.remediation::before {
    content: "Remediation: ";
    color: var(--accent-green);
    font-weight: bold;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}

th {
    background: var(--bg-tertiary);
    color: var(--accent-cyan);
}

tr:hover { background: var(--bg-tertiary); }

.status-open { color: var(--accent-green); }
.status-closed { color: var(--severity-critical); }
.status-filtered { color: var(--severity-medium); }

.attack-result {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 1rem;
}

.attack-result.success { border-left: 4px solid var(--accent-green); }
.attack-result.failed { border-left: 4px solid var(--severity-critical); }

.attack-log {
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-color);
}

.attack-log h4 {
    color: var(--severity-critical);
    margin-bottom: 1rem;
}

.attack-event {
    background: rgba(0, 0, 0, 0.2);
    padding: 0.8rem;
    margin-bottom: 0.8rem;
    border-radius: 0 4px 4px 0;
}

.event-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
}

.event-phase {
    font-weight: bold;
    text-transform: uppercase;
    font-size: 0.75rem;
}

.event-time {
    color: var(--text-secondary);
    font-size: 0.75rem;
}

.event-technique {
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.event-command code {
    background: var(--bg-primary);
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    color: var(--accent-green);
    display: block;
    overflow-x: auto;
}

.event-payload pre, .event-response pre {
    background: var(--bg-primary);
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    overflow-x: auto;
    max-height: 60px;
    margin: 0.3rem 0;
}

.event-payload pre { color: var(--severity-medium); }
.event-response pre { color: var(--text-secondary); }

.event-status {
    font-size: 0.7rem;
    font-weight: bold;
    margin-top: 0.5rem;
}

.event-success { color: var(--accent-green); }
.event-failed { color: var(--severity-critical); }

.event-evidence {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin-top: 0.3rem;
}

.chart-container {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 1rem;
    margin: 1rem 0;
}

footer {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
    border-top: 1px solid var(--border-color);
    margin-top: 2rem;
}

@media print {
    * {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
        box-sizing: border-box !important;
    }
    
    @page {
        size: A4 portrait;
        margin: 10mm;
    }
    
    html, body {
        width: 100% !important;
        height: auto !important;
        margin: 0 !important;
        padding: 0 !important;
        background: white !important;
        color: #1a1a1a !important;
        font-size: 9pt !important;
        line-height: 1.3 !important;
        overflow: visible !important;
    }
    
    .container {
        max-width: 100% !important;
        width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
    }
    
    .report-actions, .filter-bar, .export-btn, .chart-container, canvas {
        display: none !important;
    }
    
    header {
        background: #2a2a35 !important;
        color: white !important;
        padding: 10px !important;
        margin-bottom: 10px !important;
        page-break-after: avoid;
        page-break-inside: avoid;
    }
    
    header h1 {
        font-size: 16pt !important;
        margin: 0 0 5px 0 !important;
    }
    
    header p {
        font-size: 8pt !important;
        margin: 2px 0 !important;
    }
    
    .section {
        background: white !important;
        border: 1px solid #ccc !important;
        border-radius: 0 !important;
        padding: 8px !important;
        margin-bottom: 8px !important;
        page-break-inside: auto !important;
        page-break-before: auto !important;
        overflow: visible !important;
    }
    
    h2 {
        color: #1a1a1a !important;
        border-bottom: 1px solid #00a0c0 !important;
        padding-bottom: 3px !important;
        margin: 0 0 8px 0 !important;
        font-size: 12pt !important;
        page-break-after: avoid !important;
        page-break-inside: avoid !important;
    }
    
    .summary-grid {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 5px !important;
        margin-bottom: 10px !important;
    }
    
    .summary-card {
        background: white !important;
        border: 1px solid #ccc !important;
        padding: 5px 10px !important;
        text-align: center !important;
        flex: 1 1 80px !important;
        min-width: 60px !important;
    }
    
    .summary-card .number {
        font-size: 14pt !important;
        font-weight: bold !important;
        color: #1a1a1a !important;
    }
    
    .summary-card .label {
        font-size: 7pt !important;
        color: #666 !important;
    }
    
    .summary-card.critical { border-left: 3px solid #ff0040 !important; }
    .summary-card.high { border-left: 3px solid #ff4444 !important; }
    .summary-card.medium { border-left: 3px solid #cc8800 !important; }
    .summary-card.low { border-left: 3px solid #0088cc !important; }
    
    .finding, .finding-card {
        background: white !important;
        border: 1px solid #ddd !important;
        border-left: 3px solid #666 !important;
        padding: 6px !important;
        margin-bottom: 6px !important;
        page-break-inside: avoid !important;
        break-inside: avoid !important;
    }
    
    .finding.critical, .finding-card.critical { border-left-color: #ff0040 !important; }
    .finding.high, .finding-card.high { border-left-color: #ff4444 !important; }
    .finding.medium, .finding-card.medium { border-left-color: #cc8800 !important; }
    .finding.low, .finding-card.low { border-left-color: #0088cc !important; }
    
    .finding h3, .finding-card h3 {
        font-size: 10pt !important;
        margin: 0 0 4px 0 !important;
    }
    
    .finding p, .finding-card p {
        font-size: 8pt !important;
        margin: 2px 0 !important;
    }
    
    .severity-badge {
        padding: 1px 5px !important;
        border-radius: 2px !important;
        font-size: 7pt !important;
        font-weight: bold !important;
    }
    
    .severity-badge.critical { background: #ff0040 !important; color: white !important; }
    .severity-badge.high { background: #ff4444 !important; color: white !important; }
    .severity-badge.medium { background: #cc8800 !important; color: white !important; }
    .severity-badge.low { background: #0088cc !important; color: white !important; }
    
    table {
        width: 100% !important;
        border-collapse: collapse !important;
        font-size: 8pt !important;
        page-break-inside: auto;
    }
    
    th, td {
        border: 1px solid #ccc !important;
        padding: 4px !important;
        text-align: left !important;
        background: white !important;
        color: #1a1a1a !important;
        word-wrap: break-word !important;
        max-width: 150px !important;
    }
    
    th {
        background: #e8e8e8 !important;
        font-weight: bold !important;
    }
    
    .attack-result {
        background: white !important;
        border: 1px solid #ccc !important;
        padding: 6px !important;
        margin-bottom: 6px !important;
        page-break-inside: auto !important;
    }
    
    .attack-result h3 {
        font-size: 10pt !important;
        margin: 0 0 4px 0 !important;
        page-break-after: avoid !important;
    }
    
    .attack-result > ul {
        page-break-before: avoid !important;
    }
    
    .attack-log {
        background: #f5f5f5 !important;
        border: 1px solid #ddd !important;
        padding: 6px !important;
        margin-top: 6px !important;
        page-break-inside: auto !important;
    }
    
    .attack-log h4 {
        font-size: 9pt !important;
        margin: 0 0 4px 0 !important;
        page-break-after: avoid !important;
    }
    
    .attack-event {
        background: white !important;
        border: 1px solid #eee !important;
        border-left: 2px solid #666 !important;
        padding: 4px !important;
        margin-bottom: 4px !important;
        page-break-inside: avoid !important;
        font-size: 7pt !important;
    }
    
    .event-header {
        font-size: 7pt !important;
    }
    
    .event-technique {
        font-size: 8pt !important;
    }
    
    .event-command code {
        display: block !important;
        background: #f0f0f0 !important;
        color: #1a1a1a !important;
        padding: 3px !important;
        font-size: 7pt !important;
        word-wrap: break-word !important;
        white-space: pre-wrap !important;
    }
    
    .event-payload pre, .event-response pre {
        background: #f0f0f0 !important;
        color: #1a1a1a !important;
        padding: 3px !important;
        font-size: 6pt !important;
        max-height: none !important;
        word-wrap: break-word !important;
        white-space: pre-wrap !important;
        overflow: visible !important;
    }
    
    pre, code {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        overflow: visible !important;
    }
    
    footer {
        margin-top: 10px !important;
        padding-top: 5px !important;
        border-top: 1px solid #ccc !important;
        font-size: 7pt !important;
        color: #666 !important;
        page-break-before: avoid;
    }
    
    a { color: #0066cc !important; text-decoration: none !important; }
    
    .hidden { display: none !important; }
    
    ul { 
        padding-left: 15px !important; 
        margin: 4px 0 !important;
    }
    
    li {
        font-size: 8pt !important;
        margin: 2px 0 !important;
    }
}
"""
    
    def _build_header(self) -> str:
        if not self.metadata:
            return "<header><h1>5G Security Assessment Report</h1></header>"
        
        return f"""
<header>
    <div class="report-nav">
        <a href="demo_report.html" class="nav-tab active">Document View</a>
        <a href="demo_topology.html" class="nav-tab">Topology View</a>
        <a href="demo_report.json" class="nav-tab" download>JSON Export</a>
    </div>
    <h1>{self.metadata.title}</h1>
    <div class="meta">
        <p><strong>Assessment Type:</strong> {self.metadata.assessment_type}</p>
        <p><strong>Target Network:</strong> {self.metadata.target_network}</p>
        <p><strong>Period:</strong> {self.metadata.start_time} - {self.metadata.end_time}</p>
        <p><strong>Generated by:</strong> {self.metadata.analyst} v{self.metadata.version}</p>
    </div>
</header>"""
    
    def _build_executive_summary(self, summary: Dict) -> str:
        sc = summary["severity_breakdown"]
        
        return f"""
<div class="report-actions">
    <button onclick="exportReport('pdf')" class="export-btn">PDF</button>
    <button onclick="exportReport('html')" class="export-btn">Save</button>
    <button onclick="window.print()" class="export-btn">Print</button>
</div>
<div class="section">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="summary-card critical clickable" onclick="navigateToSeverity('critical')" data-severity="critical">
            <div class="number">{sc.get('critical', 0)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card high clickable" onclick="navigateToSeverity('high')" data-severity="high">
            <div class="number">{sc.get('high', 0)}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card medium clickable" onclick="navigateToSeverity('medium')" data-severity="medium">
            <div class="number">{sc.get('medium', 0)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card low clickable" onclick="navigateToSeverity('low')" data-severity="low">
            <div class="number">{sc.get('low', 0)}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-card clickable" onclick="navigateToSection('scan-results')">
            <div class="number">{summary['total_scans']}</div>
            <div class="label">Scans</div>
        </div>
        <div class="summary-card clickable" onclick="navigateToSection('attack-results')">
            <div class="number">{summary['successful_attacks']}/{summary['total_attacks']}</div>
            <div class="label">Successful Attacks</div>
        </div>
    </div>
    <div class="chart-container">
        <canvas id="severityChart" width="400" height="200"></canvas>
    </div>
</div>"""
    
    def _build_findings_section(self) -> str:
        if not self.findings:
            return ""
        
        sorted_findings = sorted(
            self.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
        )
        
        findings_html = ""
        for i, f in enumerate(sorted_findings):
            evidence_html = f'<div class="evidence">{f.evidence}</div>' if f.evidence else ""
            remediation_html = f'<div class="remediation">{f.remediation}</div>' if f.remediation else ""
            cvss_html = f' (CVSS: {f.cvss_score})' if f.cvss_score else ""
            cwe_html = f' [{f.cwe_id}]' if f.cwe_id else ""
            
            findings_html += f"""
<div class="finding finding-card {f.severity.value}" id="finding-{i}" data-severity="{f.severity.value}">
    <h3>
        <span class="title">{f.title}{cvss_html}{cwe_html}</span>
        <span class="severity-badge {f.severity.value}">{f.severity.value}</span>
    </h3>
    <p class="description">{f.description}</p>
    <p class="component">Affected: {f.affected_component}</p>
    {evidence_html}
    {remediation_html}
</div>"""
        
        return f"""
<div class="section" id="findings-section">
    <h2>Security Findings ({len(self.findings)})</h2>
    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterFindings('all')">All</button>
        <button class="filter-btn critical" onclick="filterFindings('critical')">Critical</button>
        <button class="filter-btn high" onclick="filterFindings('high')">High</button>
        <button class="filter-btn medium" onclick="filterFindings('medium')">Medium</button>
        <button class="filter-btn low" onclick="filterFindings('low')">Low</button>
    </div>
    {findings_html}
</div>"""
    
    def _build_scan_results_section(self) -> str:
        if not self.scan_results:
            return ""
        
        rows = ""
        for r in self.scan_results:
            state_class = f"status-{r.state.lower()}"
            vulns = ", ".join(r.vulnerabilities) if r.vulnerabilities else "-"
            rows += f"""
<tr>
    <td>{r.target}</td>
    <td>{r.port}</td>
    <td>{r.service}</td>
    <td class="{state_class}">{r.state}</td>
    <td>{r.banner[:50] if r.banner else '-'}</td>
    <td>{vulns}</td>
</tr>"""
        
        return f"""
<div class="section" id="scan-results">
    <h2>Scan Results ({len(self.scan_results)})</h2>
    <table>
        <thead>
            <tr>
                <th>Target</th>
                <th>Port</th>
                <th>Service</th>
                <th>State</th>
                <th>Banner</th>
                <th>Vulnerabilities</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</div>"""
    
    def _build_attack_results_section(self) -> str:
        if not self.attack_results:
            return ""
        
        results_html = ""
        for a in self.attack_results:
            status_class = "success" if a.success else "failed"
            status_text = "Success" if a.success else "Failed"
            
            details_items = "".join(
                f"<li><strong>{k}:</strong> {v}</li>"
                for k, v in a.details.items()
            )
            
            events_html = ""
            if a.attack_events:
                phase_colors = {
                    'Reconnaissance': '#00d4ff',
                    'Enumeration': '#ffaa00',
                    'Exploitation': '#ff0040',
                    'Persistence': '#ff6600',
                    'Exfiltration': '#ff00ff',
                    'Lateral Movement': '#ff6600'
                }
                
                events_html = '<div class="attack-log"><h4>Attack Log</h4>'
                for e in a.attack_events:
                    color = phase_colors.get(e.phase, '#666')
                    events_html += f'''
                    <div class="attack-event" style="border-left: 3px solid {color};">
                        <div class="event-header">
                            <span class="event-phase" style="color: {color};">{e.phase}</span>
                            <span class="event-time">{e.timestamp}</span>
                        </div>
                        <div class="event-technique">{e.technique}</div>
                        {f'<div class="event-command"><code>{e.command}</code></div>' if e.command else ''}
                        {f'<div class="event-payload"><strong>Payload:</strong> <pre>{e.payload[:200]}{"..." if len(e.payload) > 200 else ""}</pre></div>' if e.payload else ''}
                        {f'<div class="event-response"><strong>Response:</strong> <pre>{e.response[:200]}{"..." if len(e.response) > 200 else ""}</pre></div>' if e.response else ''}
                        <div class="event-status {"event-success" if e.success else "event-failed"}">{"SUCCESS" if e.success else "FAILED"}</div>
                        {f'<div class="event-evidence"><strong>Evidence:</strong> {", ".join(f"{k}: {v}" for k, v in e.evidence.items())}</div>' if e.evidence else ''}
                    </div>'''
                events_html += '</div>'
            
            results_html += f"""
<div class="attack-result {status_class}">
    <h3>{a.attack_type} - <span class="{status_class}">{status_text}</span></h3>
    <p><strong>Target:</strong> {a.target}</p>
    <p><strong>Time:</strong> {a.timestamp} (Duration: {a.duration:.2f}s)</p>
    <ul>{details_items}</ul>
    {events_html}
</div>"""
        
        return f"""
<div class="section" id="attack-results">
    <h2>Attack Results ({len(self.attack_results)})</h2>
    {results_html}
</div>"""
    
    def _build_recommendations(self) -> str:
        recs = [
            "Implement network segmentation between 5G core components",
            "Enable mutual TLS for all SBI interfaces",
            "Deploy rate limiting on GTP-U and PFCP interfaces",
            "Enable logging and monitoring on all 5G network functions",
            "Implement TEID/SEID randomization to prevent enumeration",
            "Deploy DPI solutions for GTP tunnel inspection",
            "Regular security assessments using 5G-specific tools"
        ]
        
        recs_html = "".join(f"<li>{r}</li>" for r in recs)
        
        return f"""
<div class="section">
    <h2>General Recommendations</h2>
    <ul>{recs_html}</ul>
</div>"""
    
    def _build_footer(self) -> str:
        return f"""
<footer>
    <p>Generated by 5G-Gibbon Security Toolkit</p>
    <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</footer>"""
    
    def _build_charts_script(self, summary: Dict) -> str:
        sc = summary["severity_breakdown"]
        
        return f"""
<script>
const ctx = document.getElementById('severityChart').getContext('2d');
const severityLabels = ['critical', 'high', 'medium', 'low', 'info'];
const chart = new Chart(ctx, {{
    type: 'doughnut',
    data: {{
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{{
            data: [{sc.get('critical', 0)}, {sc.get('high', 0)}, {sc.get('medium', 0)}, {sc.get('low', 0)}, {sc.get('info', 0)}],
            backgroundColor: ['#ff0040', '#ff4444', '#ffaa00', '#44aaff', '#888899'],
            borderColor: '#1a1a25',
            borderWidth: 2
        }}]
    }},
    options: {{
        responsive: true,
        onClick: (e, elements) => {{
            if (elements.length > 0) {{
                const index = elements[0].index;
                navigateToSeverity(severityLabels[index]);
            }}
        }},
        plugins: {{
            legend: {{
                position: 'right',
                labels: {{ color: '#e0e0e8' }},
                onClick: (e, legendItem, legend) => {{
                    navigateToSeverity(severityLabels[legendItem.index]);
                }}
            }}
        }}
    }}
}});

function navigateToSeverity(severity) {{
    const section = document.getElementById('findings-section');
    if (section) {{
        section.scrollIntoView({{ behavior: 'smooth' }});
        filterFindings(severity);
        
        document.querySelectorAll('.finding-card[data-severity="' + severity + '"]').forEach((el, i) => {{
            if (i === 0) {{
                setTimeout(() => {{
                    el.classList.add('highlight');
                    setTimeout(() => el.classList.remove('highlight'), 2000);
                }}, 500);
            }}
        }});
    }}
}}

function navigateToSection(sectionId) {{
    const section = document.getElementById(sectionId);
    if (section) {{
        section.scrollIntoView({{ behavior: 'smooth' }});
        section.classList.add('highlight');
        setTimeout(() => section.classList.remove('highlight'), 2000);
    }}
}}

function filterFindings(severity) {{
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    
    if (severity === 'all') {{
        document.querySelector('.filter-btn:first-child').classList.add('active');
        document.querySelectorAll('.finding-card').forEach(el => el.classList.remove('hidden'));
    }} else {{
        document.querySelector('.filter-btn.' + severity).classList.add('active');
        document.querySelectorAll('.finding-card').forEach(el => {{
            if (el.dataset.severity === severity) {{
                el.classList.remove('hidden');
            }} else {{
                el.classList.add('hidden');
            }}
        }});
    }}
}}

function exportReport(format) {{
    if (format === 'pdf') {{
        window.print();
    }} else if (format === 'html') {{
        const blob = new Blob([document.documentElement.outerHTML], {{ type: 'text/html' }});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'security_report_' + new Date().toISOString().split('T')[0] + '.html';
        a.click();
        URL.revokeObjectURL(url);
    }}
}}
</script>"""

def generate_attack_report(
    attacks: List[Dict[str, Any]],
    title: str = "5G Attack Assessment",
    output_file: str = "attack_report.html"
) -> str:
    gen = ReportGenerator()
    gen.set_metadata(
        title=title,
        assessment_type="Penetration Test",
        target_network="5G Core Network"
    )
    
    for attack in attacks:
        findings = []
        if attack.get("success"):
            findings.append(Finding(
                title=f"{attack['type']} Vulnerability",
                severity=SeverityLevel.HIGH,
                description=f"Successfully exploited {attack['type']} on {attack['target']}",
                affected_component=attack.get("component", "Unknown"),
                evidence=str(attack.get("details", {}))
            ))
        
        result = AttackResult(
            attack_type=attack.get("type", "Unknown"),
            target=attack.get("target", "Unknown"),
            success=attack.get("success", False),
            timestamp=attack.get("timestamp", datetime.now().isoformat()),
            duration=attack.get("duration", 0.0),
            details=attack.get("details", {}),
            findings=findings
        )
        gen.add_attack_result(result)
    
    return gen.generate_html(output_file)

def generate_scan_report(
    scan_results: List[Dict[str, Any]],
    title: str = "5G Network Scan Report",
    output_file: str = "scan_report.html"
) -> str:
    gen = ReportGenerator()
    gen.set_metadata(
        title=title,
        assessment_type="Network Reconnaissance",
        target_network="5G Infrastructure"
    )
    
    for result in scan_results:
        sr = ScanResult(
            target=result.get("target", "Unknown"),
            port=result.get("port", 0),
            service=result.get("service", "Unknown"),
            state=result.get("state", "Unknown"),
            banner=result.get("banner", ""),
            vulnerabilities=result.get("vulnerabilities", [])
        )
        gen.add_scan_result(sr)
        
        if result.get("state") == "open":
            gen.add_finding(Finding(
                title=f"Open {result.get('service', 'Unknown')} Port",
                severity=SeverityLevel.INFO,
                description=f"Port {result.get('port')} is open on {result.get('target')}",
                affected_component=result.get("target", "Unknown")
            ))
    
    return gen.generate_html(output_file)

if __name__ == "__main__":
    gen = ReportGenerator()
    gen.set_metadata(
        title="5G Core Security Assessment",
        assessment_type="Red Team Engagement",
        target_network="10.0.0.0/24"
    )
    
    gen.add_finding(Finding(
        title="GTP-U TEID Enumeration",
        severity=SeverityLevel.HIGH,
        description="TEIDs are predictable and can be enumerated",
        affected_component="UPF (10.0.0.10)",
        evidence="Found 50 active TEIDs in range 0x1000-0x1050",
        remediation="Implement TEID randomization",
        cvss_score=7.5,
        cwe_id="CWE-330"
    ))
    
    gen.add_finding(Finding(
        title="Missing PFCP Authentication",
        severity=SeverityLevel.CRITICAL,
        description="PFCP interface accepts unauthenticated session requests",
        affected_component="SMF (10.0.0.20)",
        evidence="Session establishment request accepted without authentication",
        remediation="Enable PFCP over TLS with mutual authentication",
        cvss_score=9.8,
        cwe_id="CWE-306"
    ))
    
    gen.add_scan_result(ScanResult(
        target="10.0.0.10",
        port=2152,
        service="GTP-U",
        state="open",
        banner="GTP-U UPF"
    ))
    
    gen.add_attack_result(AttackResult(
        attack_type="TEID Enumeration",
        target="10.0.0.10:2152",
        success=True,
        timestamp=datetime.now().isoformat(),
        duration=45.2,
        details={"teids_found": 50, "range": "0x1000-0x1050"}
    ))
    
    report_path = gen.generate_html("demo_report.html")
    print(f"Demo report generated: {report_path}")

