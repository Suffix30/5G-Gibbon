#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

class NodeType(Enum):
    UPF = "upf"
    AMF = "amf"
    SMF = "smf"
    NRF = "nrf"
    AUSF = "ausf"
    UDM = "udm"
    PCF = "pcf"
    NSSF = "nssf"
    GNODEB = "gnodeb"
    UE = "ue"
    UNKNOWN = "unknown"
    ATTACKER = "attacker"

class LinkType(Enum):
    GTPU = "gtp-u"
    PFCP = "pfcp"
    NGAP = "ngap"
    SBI = "sbi"
    NAS = "nas"
    UNKNOWN = "unknown"

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
class NetworkNode:
    id: str
    ip: str
    node_type: NodeType
    label: str = ""
    ports: List[int] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    attack_events: List[AttackEvent] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.label:
            self.label = f"{self.node_type.value.upper()}\n{self.ip}"

@dataclass
class NetworkLink:
    source: str
    target: str
    link_type: LinkType
    port: int = 0
    label: str = ""
    is_compromised: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    attack_events: List[AttackEvent] = field(default_factory=list)

class TopologyMapper:
    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self.links: List[NetworkLink] = []
    
    def add_node(self, node: NetworkNode):
        self.nodes[node.id] = node
    
    def add_link(self, link: NetworkLink):
        self.links.append(link)
    
    def detect_node_type(self, ip: str, ports: List[int]) -> NodeType:
        port_mappings = {
            2152: NodeType.UPF,
            8805: NodeType.SMF,
            38412: NodeType.AMF,
            80: NodeType.NRF,
            443: NodeType.NRF,
            29510: NodeType.NRF,
            29518: NodeType.AMF,
            29502: NodeType.SMF,
            29509: NodeType.UDM,
            29512: NodeType.PCF,
        }
        
        for port in ports:
            if port in port_mappings:
                return port_mappings[port]
        
        return NodeType.UNKNOWN
    
    def build_from_scan_results(self, scan_results: List[Dict[str, Any]]):
        host_ports: Dict[str, List[int]] = {}
        
        for result in scan_results:
            ip = result.get("target", "")
            port = result.get("port", 0)
            
            if ip not in host_ports:
                host_ports[ip] = []
            if port and port not in host_ports[ip]:
                host_ports[ip].append(port)
        
        for ip, ports in host_ports.items():
            node_type = self.detect_node_type(ip, ports)
            node = NetworkNode(
                id=ip,
                ip=ip,
                node_type=node_type,
                ports=ports
            )
            self.add_node(node)
        
        self._infer_links()
    
    def _infer_links(self):
        upfs = [n for n in self.nodes.values() if n.node_type == NodeType.UPF]
        smfs = [n for n in self.nodes.values() if n.node_type == NodeType.SMF]
        amfs = [n for n in self.nodes.values() if n.node_type == NodeType.AMF]
        nrfs = [n for n in self.nodes.values() if n.node_type == NodeType.NRF]
        
        for smf in smfs:
            for upf in upfs:
                self.add_link(NetworkLink(
                    source=smf.id,
                    target=upf.id,
                    link_type=LinkType.PFCP,
                    port=8805,
                    label="PFCP"
                ))
        
        for amf in amfs:
            for smf in smfs:
                self.add_link(NetworkLink(
                    source=amf.id,
                    target=smf.id,
                    link_type=LinkType.SBI,
                    port=29502,
                    label="N11/SBI"
                ))
        
        for nrf in nrfs:
            for node in self.nodes.values():
                if node.node_type in [NodeType.AMF, NodeType.SMF, NodeType.UPF]:
                    self.add_link(NetworkLink(
                        source=node.id,
                        target=nrf.id,
                        link_type=LinkType.SBI,
                        port=29510,
                        label="NRF Registration"
                    ))
    
    def mark_compromised(self, node_id: str, link_source: Optional[str] = None, link_target: Optional[str] = None):
        if node_id in self.nodes:
            self.nodes[node_id].vulnerabilities.append("compromised")
        
        if link_source and link_target:
            for link in self.links:
                if link.source == link_source and link.target == link_target:
                    link.is_compromised = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "ip": n.ip,
                    "type": n.node_type.value,
                    "label": n.label,
                    "ports": n.ports,
                    "vulnerabilities": n.vulnerabilities,
                    "metadata": n.metadata,
                    "attack_events": [
                        {
                            "timestamp": e.timestamp,
                            "phase": e.phase,
                            "technique": e.technique,
                            "command": e.command,
                            "payload": e.payload,
                            "response": e.response,
                            "success": e.success,
                            "evidence": e.evidence
                        }
                        for e in n.attack_events
                    ]
                }
                for n in self.nodes.values()
            ],
            "links": [
                {
                    "source": l.source,
                    "target": l.target,
                    "type": l.link_type.value,
                    "port": l.port,
                    "label": l.label,
                    "compromised": l.is_compromised,
                    "attack_events": [
                        {
                            "timestamp": e.timestamp,
                            "phase": e.phase,
                            "technique": e.technique,
                            "command": e.command,
                            "payload": e.payload,
                            "response": e.response,
                            "success": e.success,
                            "evidence": e.evidence
                        }
                        for e in l.attack_events
                    ]
                }
                for l in self.links
            ]
        }

class NetworkVisualizer:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_html(
        self,
        topology: TopologyMapper,
        filename: str = "topology.html",
        title: str = "5G Network Topology",
        target_network: str = "",
        analyst: str = "5G-Gibbon"
    ) -> str:
        data = topology.to_dict()
        
        stats = {
            "total_nodes": len(data["nodes"]),
            "compromised": sum(1 for n in data["nodes"] if n.get("vulnerabilities")),
            "total_vulns": sum(len(n.get("vulnerabilities", [])) for n in data["nodes"]),
            "total_links": len(data["links"]),
            "attack_paths": sum(1 for l in data["links"] if l.get("compromised"))
        }
        
        html = self._build_html(data, title, target_network, analyst, stats)
        
        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        
        logger.info(f"Topology visualization generated: {output_path}")
        return str(output_path)
    
    def generate_svg(
        self,
        topology: TopologyMapper,
        filename: str = "topology.svg"
    ) -> str:
        svg = self._build_svg(topology)
        
        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(svg)
        
        return str(output_path)
    
    def _build_html(self, data: Dict, title: str, target_network: str, analyst: str, stats: Dict) -> str:
        nodes_json = json.dumps(data["nodes"])
        links_json = json.dumps(data["links"])
        findings_json = json.dumps([
            {"id": n["id"], "node": n["label"] or n["type"], "ip": n["ip"], "vulns": n.get("vulnerabilities", [])}
            for n in data["nodes"] if n.get("vulnerabilities")
        ])
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-tertiary: #1a1a25;
            --text-primary: #e0e0e8;
            --text-secondary: #a0a0b0;
            --accent-cyan: #00d4ff;
            --accent-magenta: #ff00ff;
            --accent-green: #00ff88;
            --accent-red: #ff0040;
            --accent-yellow: #ffaa00;
            --node-upf: #00d4ff;
            --node-amf: #ff00ff;
            --node-smf: #00ff88;
            --node-nrf: #ffaa00;
            --node-gnb: #44aaff;
            --node-ue: #888899;
            --node-attacker: #ff0040;
            --link-gtpu: #00d4ff;
            --link-pfcp: #00ff88;
            --link-ngap: #ff00ff;
            --link-sbi: #ffaa00;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            overflow: hidden;
        }}
        
        #header {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 60px;
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            border-bottom: 2px solid var(--accent-cyan);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            z-index: 100;
        }}
        
        #header h1 {{
            font-size: 1.3rem;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        #header .meta {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        
        .report-nav {{
            display: flex;
            gap: 8px;
        }}
        
        .nav-tab {{
            padding: 6px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.8rem;
            transition: all 0.2s;
        }}
        
        .nav-tab:hover {{
            background: var(--bg-secondary);
            color: var(--accent-cyan);
            border-color: var(--accent-cyan);
        }}
        
        .nav-tab.active {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
            border-color: var(--accent-cyan);
            font-weight: bold;
        }}
        
        #stats-bar {{
            position: fixed;
            top: 60px;
            left: 0;
            right: 0;
            height: 50px;
            background: var(--bg-secondary);
            display: flex;
            justify-content: center;
            gap: 30px;
            align-items: center;
            border-bottom: 1px solid #2a2a3a;
            z-index: 100;
        }}
        
        .stat-item {{
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 1.4rem;
            font-weight: bold;
        }}
        
        .stat-value.compromised {{ color: var(--accent-red); }}
        .stat-value.normal {{ color: var(--accent-cyan); }}
        .stat-value.warning {{ color: var(--accent-yellow); }}
        
        .stat-label {{
            font-size: 0.7rem;
            color: var(--text-secondary);
        }}
        
        #sidebar {{
            position: fixed;
            top: 110px;
            left: 0;
            width: 320px;
            bottom: 0;
            background: var(--bg-secondary);
            border-right: 1px solid #2a2a3a;
            overflow-y: auto;
            z-index: 100;
            padding: 15px;
        }}
        
        #sidebar h3 {{
            color: var(--accent-cyan);
            font-size: 0.9rem;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #2a2a3a;
        }}
        
        .finding-item {{
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 10px;
            margin-bottom: 10px;
            border-left: 3px solid var(--accent-red);
        }}
        
        .finding-node {{
            font-weight: bold;
            color: var(--text-primary);
            margin-bottom: 4px;
        }}
        
        .finding-ip {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        
        .finding-vulns {{
            font-size: 0.75rem;
        }}
        
        .finding-vulns li {{
            color: var(--accent-red);
            margin-left: 15px;
            margin-top: 3px;
        }}
        
        #container {{
            position: fixed;
            top: 110px;
            left: 320px;
            right: 0;
            bottom: 0;
        }}
        
        svg {{
            width: 100%;
            height: 100%;
        }}
        
        .node {{
            cursor: pointer;
        }}
        
        .node circle {{
            stroke-width: 2px;
            transition: all 0.3s ease;
        }}
        
        .node:hover circle {{
            stroke-width: 4px;
            filter: drop-shadow(0 0 10px currentColor);
        }}
        
        .node.compromised circle {{
            stroke: #ff0040;
            stroke-width: 4px;
            animation: pulse 1s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ stroke-opacity: 1; }}
            50% {{ stroke-opacity: 0.5; }}
        }}
        
        .node text {{
            fill: var(--text-primary);
            font-size: 10px;
            text-anchor: middle;
            pointer-events: none;
        }}
        
        .link {{
            stroke-opacity: 0.6;
            stroke-width: 2px;
        }}
        
        .link.compromised {{
            stroke: #ff0040 !important;
            stroke-width: 3px;
        }}
        
        .link-label {{
            fill: var(--text-primary);
            font-size: 8px;
            opacity: 0.7;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
            font-size: 11px;
        }}
        
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
        
        #tooltip {{
            position: absolute;
            background: var(--bg-secondary);
            border: 1px solid var(--accent-cyan);
            padding: 12px 15px;
            border-radius: 6px;
            font-size: 11px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            max-width: 350px;
            box-shadow: 0 4px 20px rgba(0, 212, 255, 0.2);
            z-index: 1000;
        }}
        
        #controls {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--bg-secondary);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #2a2a3a;
            z-index: 100;
        }}
        
        #controls button {{
            background: var(--bg-primary);
            border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan);
            padding: 5px 10px;
            margin: 2px;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
        }}
        
        #controls button:hover {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
        }}
    </style>
</head>
<body>
    <div id="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>{title}</h1>
            <div class="report-nav">
                <a href="demo_report.html" class="nav-tab">Document View</a>
                <a href="demo_topology.html" class="nav-tab active">Topology View</a>
                <a href="demo_report.json" class="nav-tab" download>JSON Export</a>
            </div>
        </div>
        <div class="meta">
            <div>Target: {target_network or 'Network Assessment'}</div>
            <div>Generated: {timestamp} | Analyst: {analyst}</div>
        </div>
    </div>
    
    <div id="stats-bar">
        <div class="stat-item">
            <div class="stat-value normal">{stats['total_nodes']}</div>
            <div class="stat-label">NODES DISCOVERED</div>
        </div>
        <div class="stat-item">
            <div class="stat-value compromised">{stats['compromised']}</div>
            <div class="stat-label">COMPROMISED</div>
        </div>
        <div class="stat-item">
            <div class="stat-value warning">{stats['total_vulns']}</div>
            <div class="stat-label">VULNERABILITIES</div>
        </div>
        <div class="stat-item">
            <div class="stat-value compromised">{stats['attack_paths']}</div>
            <div class="stat-label">ATTACK PATHS</div>
        </div>
    </div>
    
    <div id="sidebar">
        <h3>Compromised Nodes</h3>
        <div id="findings-list"></div>
        
        <h3 style="margin-top: 20px;">Legend</h3>
        <div class="legend-item"><span class="legend-color" style="background: var(--node-upf);"></span>UPF</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--node-amf);"></span>AMF</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--node-smf);"></span>SMF</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--node-nrf);"></span>NRF</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--node-gnb);"></span>gNodeB</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--node-attacker);"></span>Attacker</div>
        
        <h3 style="margin-top: 20px;">Interfaces</h3>
        <div class="legend-item"><span class="legend-color" style="background: var(--link-gtpu);"></span>GTP-U (5G)</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--link-pfcp);"></span>PFCP (5G)</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--link-ngap);"></span>NGAP (5G)</div>
        <div class="legend-item"><span class="legend-color" style="background: var(--link-sbi);"></span>SBI (5G)</div>
        <div class="legend-item"><span class="legend-color" style="background: #666666;"></span>S1AP/Diameter (4G)</div>
        
        <h3 style="margin-top: 20px;">Status</h3>
        <div class="legend-item"><span class="legend-color" style="background: var(--accent-red); border: 2px dashed #ff0040;"></span>Attack Path</div>
        <div class="legend-item"><span class="legend-color" style="border: 2px solid var(--accent-red);"></span>Compromised Node</div>
    </div>
    
    <div id="container"></div>
    
    <div id="tooltip"></div>
    
    <div id="controls">
        <button onclick="resetZoom()">Reset View</button>
        <button onclick="toggleLabels()">Toggle Labels</button>
        <button onclick="window.print()">Print Report</button>
    </div>
    
    <script>
        const nodes = {nodes_json};
        const links = {links_json};
        const findings = {findings_json};
        
        const findingsList = document.getElementById('findings-list');
        findings.forEach(f => {{
            const div = document.createElement('div');
            div.className = 'finding-item';
            div.dataset.nodeId = f.id;
            div.innerHTML = `
                <div class="finding-node">${{f.node}}</div>
                <div class="finding-ip">${{f.ip}}</div>
                <ul class="finding-vulns">
                    ${{f.vulns.map(v => '<li>' + v + '</li>').join('')}}
                </ul>
            `;
            div.addEventListener('click', () => focusNode(f.id));
            findingsList.appendChild(div);
        }});
        
        if (findings.length === 0) {{
            findingsList.innerHTML = '<div style="color: #00ff88; padding: 10px;">No compromised nodes detected</div>';
        }}
        
        let selectedNode = null;
        let detailPanel = null;
        
        const width = document.getElementById('container').clientWidth;
        const height = document.getElementById('container').clientHeight;
        
        const nodeColors = {{
            'upf': '#00d4ff',
            'amf': '#ff00ff',
            'smf': '#00ff88',
            'nrf': '#ffaa00',
            'gnodeb': '#44aaff',
            'ue': '#888899',
            'attacker': '#ff0040',
            'unknown': '#666666'
        }};
        
        const linkColors = {{
            'gtp-u': '#00d4ff',
            'pfcp': '#00ff88',
            'ngap': '#ff00ff',
            'sbi': '#ffaa00',
            'nas': '#44aaff',
            'unknown': '#666666'
        }};
        
        const svg = d3.select('#container')
            .append('svg')
            .attr('width', width)
            .attr('height', height);
        
        const defs = svg.append('defs');
        
        defs.append('marker')
            .attr('id', 'arrow-attack')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 35)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#ff0040');
        
        defs.append('marker')
            .attr('id', 'arrow-normal')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 35)
            .attr('refY', 0)
            .attr('markerWidth', 5)
            .attr('markerHeight', 5)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-4L8,0L0,4')
            .attr('fill', '#666');
        
        const g = svg.append('g');
        
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => g.attr('transform', event.transform));
        
        svg.call(zoom);
        
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(150))
            .force('charge', d3.forceManyBody().strength(-500))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(60));
        
        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('class', d => 'link' + (d.compromised ? ' compromised' : ''))
            .attr('marker-end', d => d.compromised ? 'url(#arrow-attack)' : 'url(#arrow-normal)')
            .style('stroke', d => linkColors[d.type] || linkColors.unknown);
        
        const linkLabels = g.append('g')
            .selectAll('text')
            .data(links)
            .enter()
            .append('text')
            .attr('class', 'link-label')
            .text(d => d.label);
        
        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .enter()
            .append('g')
            .attr('class', d => 'node' + (d.vulnerabilities.includes('compromised') ? ' compromised' : ''))
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        node.append('circle')
            .attr('r', 25)
            .style('fill', d => nodeColors[d.type] || nodeColors.unknown)
            .style('stroke', d => d.vulnerabilities.length ? '#ff0040' : nodeColors[d.type])
            .style('cursor', 'pointer')
            .on('mouseover', showTooltip)
            .on('mouseout', hideTooltip)
            .on('click', (event, d) => {{
                event.stopPropagation();
                selectNode(d);
            }});
        
        node.append('text')
            .attr('dy', 4)
            .text(d => d.type.toUpperCase());
        
        node.append('text')
            .attr('dy', 45)
            .style('font-size', '9px')
            .text(d => d.ip);
        
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            linkLabels
                .attr('x', d => (d.source.x + d.target.x) / 2)
                .attr('y', d => (d.source.y + d.target.y) / 2);
            
            node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        function showTooltip(event, d) {{
            const tooltip = document.getElementById('tooltip');
            const status = d.vulnerabilities.length > 0 ? 
                '<span style="color: #ff0040;">!</span>' : 
                '<span style="color: #00ff88;">OK</span>';
            
            tooltip.innerHTML = `
                <strong style="color: #00d4ff;">${{d.label || d.type.toUpperCase()}}</strong><br>
                <span style="color: #a0a0b0;">${{d.ip}}</span> ${{status}}<br>
                <span style="font-size: 10px; color: #666;">Click for details</span>
            `;
            tooltip.style.left = (event.pageX + 15) + 'px';
            tooltip.style.top = (event.pageY - 15) + 'px';
            tooltip.style.opacity = 1;
        }}
        
        function hideTooltip() {{
            document.getElementById('tooltip').style.opacity = 0;
        }}
        
        function resetZoom() {{
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity.translate(0, 0).scale(1)
            );
        }}
        
        let labelsVisible = true;
        function toggleLabels() {{
            labelsVisible = !labelsVisible;
            node.selectAll('text').style('opacity', labelsVisible ? 1 : 0);
            linkLabels.style('opacity', labelsVisible ? 0.7 : 0);
        }}
        
        function focusNode(nodeId) {{
            const targetNode = nodes.find(n => n.id === nodeId);
            if (!targetNode) return;
            
            const scale = 1.5;
            const x = width / 2 - targetNode.x * scale;
            const y = height / 2 - targetNode.y * scale;
            
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity.translate(x, y).scale(scale)
            );
            
            node.selectAll('circle')
                .style('stroke-width', d => d.id === nodeId ? 4 : 2)
                .style('filter', d => d.id === nodeId ? 'drop-shadow(0 0 10px #00d4ff)' : 'none');
            
            document.querySelectorAll('.finding-item').forEach(el => {{
                el.style.background = el.dataset.nodeId === nodeId ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 255, 255, 0.03)';
                el.style.borderLeftColor = el.dataset.nodeId === nodeId ? '#00d4ff' : '#ff0040';
            }});
            
            selectNode(targetNode);
        }}
        
        function selectNode(d) {{
            if (selectedNode === d.id) {{
                closeDetailPanel();
                return;
            }}
            selectedNode = d.id;
            
            node.selectAll('circle')
                .style('stroke-width', n => n.id === d.id ? 4 : 2)
                .style('filter', n => n.id === d.id ? 'drop-shadow(0 0 10px #00d4ff)' : 'none');
            
            showDetailPanel(d);
        }}
        
        function showDetailPanel(d) {{
            closeDetailPanel();
            
            detailPanel = document.createElement('div');
            detailPanel.id = 'detail-panel';
            detailPanel.style.cssText = `
                position: fixed; bottom: 100px; right: 20px; width: 380px;
                max-height: calc(100vh - 200px); overflow-y: auto;
                background: rgba(10, 10, 15, 0.98); border: 1px solid #1a1a2a;
                border-radius: 8px; padding: 20px; z-index: 1000;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
                font-family: 'JetBrains Mono', monospace; color: #e0e0e0;
                animation: slideIn 0.3s ease-out;
            `;
            
            const connectedLinks = links.filter(l => l.source.id === d.id || l.target.id === d.id);
            const connectedNodes = connectedLinks.map(l => {{
                const other = l.source.id === d.id ? l.target : l.source;
                return {{ node: other, link: l }};
            }});
            
            const attackPaths = connectedLinks.filter(l => l.compromised);
            
            const severity = d.vulnerabilities.length >= 3 ? 'CRITICAL' : 
                             d.vulnerabilities.length >= 2 ? 'HIGH' : 
                             d.vulnerabilities.length === 1 ? 'MEDIUM' : 'LOW';
            const severityColor = severity === 'CRITICAL' ? '#ff0040' : 
                                  severity === 'HIGH' ? '#ff6600' : 
                                  severity === 'MEDIUM' ? '#ffaa00' : '#00ff88';
            
            const status = d.vulnerabilities.length > 0 ? 
                `<span style="color: ${{severityColor}}; font-weight: bold;">${{severity}}</span>` : 
                '<span style="color: #00ff88; font-weight: bold;">SECURE</span>';
            
            const svcMap = {{2152: 'GTP-U', 8805: 'PFCP', 38412: 'NGAP', 36412: 'S1AP', 3868: 'Diameter', 27017: 'MongoDB', 80: 'HTTP', 443: 'HTTPS', 2123: 'GTPv2-C'}};
            
            const ports = d.ports && d.ports.length > 0 ?
                d.ports.map(p => `<span style="background: #1a1a2a; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block;">${{p}}${{svcMap[p] ? ' (' + svcMap[p] + ')' : ''}}</span>`).join(' ') : 'None detected';
            
            let vulnsSection = '';
            if (d.vulnerabilities.length > 0) {{
                vulnsSection = `
                    <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #2a2a3a;">
                        <div style="color: #ff0040; font-weight: bold; margin-bottom: 8px;">VULNERABILITIES (${{d.vulnerabilities.length}})</div>
                        <ul style="margin: 0; padding: 0; list-style: none;">
                            ${{d.vulnerabilities.map(v => `<li style="margin: 6px 0; padding: 8px 12px; background: rgba(255, 0, 64, 0.1); border-left: 3px solid #ff0040; border-radius: 0 4px 4px 0;">${{v}}</li>`).join('')}}
                        </ul>
                    </div>`;
            }}
            
            let connectionsSection = '';
            if (connectedNodes.length > 0) {{
                connectionsSection = `
                    <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #2a2a3a;">
                        <div style="color: #00d4ff; font-weight: bold; margin-bottom: 8px;">CONNECTIONS (${{connectedNodes.length}})</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                            ${{connectedNodes.map(c => {{
                                const isAttack = c.link.compromised;
                                const style = isAttack ? 'background: rgba(255, 0, 64, 0.2); border: 1px solid #ff0040;' : 'background: #1a1a2a; border: 1px solid #333;';
                                return `<span style="${{style}} padding: 4px 8px; border-radius: 4px; font-size: 11px;">${{c.node.label || c.node.type}}${{isAttack ? ' ⚠' : ''}}</span>`;
                            }}).join('')}}
                        </div>
                    </div>`;
            }}
            
            let attackPathsSection = '';
            if (attackPaths.length > 0) {{
                attackPathsSection = `
                    <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #2a2a3a;">
                        <div style="color: #ff6600; font-weight: bold; margin-bottom: 8px;">ATTACK PATHS (${{attackPaths.length}})</div>
                        <div style="font-size: 11px; color: #a0a0b0;">
                            ${{attackPaths.map(l => `<div style="margin: 4px 0; padding: 4px 8px; background: rgba(255, 102, 0, 0.1); border-radius: 4px;">${{l.label || 'Unknown'}} (${{l.source.label || l.source.type}} → ${{l.target.label || l.target.type}})</div>`).join('')}}
                        </div>
                    </div>`;
            }}
            
            let metadataSection = '';
            if (d.metadata && Object.keys(d.metadata).length > 0) {{
                metadataSection = `
                    <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #2a2a3a;">
                        <div style="color: #a0a0b0; font-weight: bold; margin-bottom: 8px;">METADATA</div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 4px; font-size: 11px;">
                            ${{Object.entries(d.metadata).map(([k, v]) => `<span style="color: #666;">${{k}}:</span><span>${{v}}</span>`).join('')}}
                        </div>
                    </div>`;
            }}
            
            let recommendationsSection = '';
            if (d.vulnerabilities.length > 0) {{
                const recs = [];
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('rate limit'))) recs.push('Implement rate limiting on this interface');
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('authentication') || v.toLowerCase().includes('unauthenticated'))) recs.push('Enable authentication mechanisms');
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('mongodb') || v.toLowerCase().includes('exposed'))) recs.push('Restrict network access, enable auth');
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('enumeration'))) recs.push('Randomize identifiers, add delays');
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('injection') || v.toLowerCase().includes('hijack'))) recs.push('Validate all input, use encryption');
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('encryption') || v.toLowerCase().includes('eea0'))) recs.push('Enforce strong encryption (EEA1/EEA2)');
                if (d.vulnerabilities.some(v => v.toLowerCase().includes('rogue') || v.toLowerCase().includes('certificate'))) recs.push('Implement certificate validation');
                if (recs.length === 0) recs.push('Review security configuration');
                
                recommendationsSection = `
                    <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #2a2a3a;">
                        <div style="color: #00ff88; font-weight: bold; margin-bottom: 8px;">RECOMMENDATIONS</div>
                        <ul style="margin: 0; padding: 0 0 0 16px; font-size: 11px; color: #a0a0b0;">
                            ${{recs.map(r => `<li style="margin: 4px 0;">${{r}}</li>`).join('')}}
                        </ul>
                    </div>`;
            }}
            
            const allEvents = [
                ...(d.attack_events || []),
                ...connectedLinks.filter(l => l.attack_events).flatMap(l => l.attack_events || [])
            ].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            
            let attackLogSection = '';
            if (allEvents.length > 0) {{
                const phaseColors = {{
                    'Reconnaissance': '#00d4ff',
                    'Enumeration': '#ffaa00',
                    'Exploitation': '#ff0040',
                    'Persistence': '#ff6600',
                    'Exfiltration': '#ff00ff',
                    'Lateral Movement': '#ff6600'
                }};
                
                attackLogSection = `
                    <div style="margin-top: 16px; padding-top: 16px; border-top: 2px solid #ff0040;">
                        <div style="color: #ff0040; font-weight: bold; margin-bottom: 12px; font-size: 13px;">
                            ATTACK LOG (${{allEvents.length}} events)
                        </div>
                        <div style="max-height: 300px; overflow-y: auto;">
                            ${{allEvents.map((e, i) => `
                                <div style="margin-bottom: 12px; padding: 10px; background: rgba(255, 0, 64, 0.05); border-left: 3px solid ${{phaseColors[e.phase] || '#666'}}; border-radius: 0 4px 4px 0;">
                                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                                        <span style="color: ${{phaseColors[e.phase] || '#666'}}; font-weight: bold; font-size: 11px;">${{e.phase.toUpperCase()}}</span>
                                        <span style="color: #666; font-size: 10px;">${{e.timestamp}}</span>
                                    </div>
                                    <div style="color: #e0e0e0; font-size: 12px; margin-bottom: 6px;">${{e.technique}}</div>
                                    ${{e.command ? `<div style="margin-top: 8px;"><span style="color: #666; font-size: 10px;">COMMAND:</span><pre style="margin: 4px 0; padding: 6px; background: #0a0a0f; border-radius: 4px; font-size: 10px; overflow-x: auto; color: #00ff88;">${{e.command}}</pre></div>` : ''}}
                                    ${{e.payload ? `<div style="margin-top: 6px;"><span style="color: #666; font-size: 10px;">PAYLOAD:</span><pre style="margin: 4px 0; padding: 6px; background: #0a0a0f; border-radius: 4px; font-size: 10px; overflow-x: auto; color: #ffaa00; max-height: 60px;">${{e.payload.length > 200 ? e.payload.substring(0, 200) + '...' : e.payload}}</pre></div>` : ''}}
                                    ${{e.response ? `<div style="margin-top: 6px;"><span style="color: #666; font-size: 10px;">RESPONSE:</span><pre style="margin: 4px 0; padding: 6px; background: #0a0a0f; border-radius: 4px; font-size: 10px; overflow-x: auto; color: #a0a0b0; max-height: 60px;">${{e.response.length > 200 ? e.response.substring(0, 200) + '...' : e.response}}</pre></div>` : ''}}
                                    <div style="margin-top: 6px; display: flex; align-items: center; gap: 8px;">
                                        <span style="color: ${{e.success ? '#00ff88' : '#ff0040'}}; font-size: 10px; font-weight: bold;">${{e.success ? 'SUCCESS' : 'FAILED'}}</span>
                                        ${{Object.keys(e.evidence || {{}}).length > 0 ? `<span style="color: #666; font-size: 10px;">Evidence: ${{Object.keys(e.evidence).join(', ')}}</span>` : ''}}
                                    </div>
                                </div>
                            `).join('')}}
                        </div>
                    </div>`;
            }}
            
            detailPanel.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #2a2a3a;">
                    <div>
                        <div style="color: #00d4ff; font-size: 16px; font-weight: bold;">${{d.label || d.type.toUpperCase()}}</div>
                        <div style="font-size: 11px; color: #666; margin-top: 2px;">${{d.type.toUpperCase()}} Network Function</div>
                    </div>
                    <button onclick="closeDetailPanel()" style="background: none; border: 1px solid #333; color: #888; padding: 4px 10px; cursor: pointer; border-radius: 4px; font-size: 16px;">×</button>
                </div>
                
                <div style="display: grid; grid-template-columns: 100px 1fr; gap: 8px; font-size: 12px;">
                    <span style="color: #666;">IP Address:</span><span style="color: #00d4ff; font-family: monospace;">${{d.ip}}</span>
                    <span style="color: #666;">Severity:</span><span>${{status}}</span>
                    <span style="color: #666;">Connections:</span><span>${{connectedNodes.length}} nodes</span>
                    <span style="color: #666;">Attack Paths:</span><span style="color: ${{attackPaths.length > 0 ? '#ff6600' : '#00ff88'}};">${{attackPaths.length}} detected</span>
                </div>
                
                <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #2a2a3a;">
                    <div style="color: #a0a0b0; font-weight: bold; margin-bottom: 8px;">OPEN PORTS</div>
                    <div>${{ports}}</div>
                </div>
                
                ${{vulnsSection}}
                ${{attackPathsSection}}
                ${{connectionsSection}}
                ${{metadataSection}}
                ${{recommendationsSection}}
                ${{attackLogSection}}
            `;
            
            document.body.appendChild(detailPanel);
        }}
        
        function closeDetailPanel() {{
            if (detailPanel) {{
                detailPanel.remove();
                detailPanel = null;
            }}
            selectedNode = null;
            node.selectAll('circle')
                .style('stroke-width', 2)
                .style('filter', 'none');
            document.querySelectorAll('.finding-item').forEach(el => {{
                el.style.background = 'rgba(255, 255, 255, 0.03)';
            }});
        }}
        
        svg.on('click', () => closeDetailPanel());
        
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {{
                from {{ transform: translateY(20px); opacity: 0; }}
                to {{ transform: translateY(0); opacity: 1; }}
            }}
            .finding-item {{ cursor: pointer; transition: all 0.2s ease; }}
            .finding-item:hover {{ background: rgba(0, 212, 255, 0.1) !important; }}
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>"""
    
    def _build_svg(self, topology: TopologyMapper) -> str:
        width = 800
        height = 600
        
        node_positions = self._calculate_positions(topology, width, height)
        
        node_colors = {
            NodeType.UPF: "#00d4ff",
            NodeType.AMF: "#ff00ff",
            NodeType.SMF: "#00ff88",
            NodeType.NRF: "#ffaa00",
            NodeType.GNODEB: "#44aaff",
            NodeType.UE: "#888899",
            NodeType.ATTACKER: "#ff0040",
            NodeType.UNKNOWN: "#666666",
        }
        
        svg_elements = []
        svg_elements.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">')
        svg_elements.append(f'<rect width="{width}" height="{height}" fill="#0a0a0f"/>')
        
        for link in topology.links:
            if link.source in node_positions and link.target in node_positions:
                x1, y1 = node_positions[link.source]
                x2, y2 = node_positions[link.target]
                color = "#ff0040" if link.is_compromised else "#666666"
                stroke_dasharray = "5,5" if link.is_compromised else "none"
                svg_elements.append(
                    f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                    f'stroke="{color}" stroke-width="2" stroke-dasharray="{stroke_dasharray}"/>'
                )
        
        for node_id, (x, y) in node_positions.items():
            node = topology.nodes[node_id]
            color = node_colors.get(node.node_type, "#666666")
            
            svg_elements.append(f'<circle cx="{x}" cy="{y}" r="25" fill="{color}" stroke="#fff" stroke-width="2"/>')
            svg_elements.append(
                f'<text x="{x}" y="{y+4}" text-anchor="middle" fill="#fff" font-size="10" font-family="monospace">'
                f'{node.node_type.value.upper()}</text>'
            )
            svg_elements.append(
                f'<text x="{x}" y="{y+40}" text-anchor="middle" fill="#888" font-size="8" font-family="monospace">'
                f'{node.ip}</text>'
            )
        
        svg_elements.append('</svg>')
        
        return '\n'.join(svg_elements)
    
    def _calculate_positions(
        self,
        topology: TopologyMapper,
        width: int,
        height: int
    ) -> Dict[str, Tuple[int, int]]:
        positions = {}
        
        type_order = [
            NodeType.UE,
            NodeType.GNODEB,
            NodeType.AMF,
            NodeType.SMF,
            NodeType.UPF,
            NodeType.NRF,
            NodeType.UDM,
            NodeType.PCF,
            NodeType.AUSF,
            NodeType.NSSF,
            NodeType.ATTACKER,
            NodeType.UNKNOWN
        ]
        
        grouped: Dict[NodeType, List[NetworkNode]] = {}
        for node in topology.nodes.values():
            if node.node_type not in grouped:
                grouped[node.node_type] = []
            grouped[node.node_type].append(node)
        
        y_step = height // (len(grouped) + 1)
        current_y = y_step
        
        for node_type in type_order:
            if node_type in grouped:
                nodes_in_group = grouped[node_type]
                x_step = width // (len(nodes_in_group) + 1)
                
                for i, node in enumerate(nodes_in_group):
                    positions[node.id] = (x_step * (i + 1), current_y)
                
                current_y += y_step
        
        return positions

def visualize_from_scan(
    scan_results: List[Dict[str, Any]],
    output_file: str = "topology.html"
) -> str:
    mapper = TopologyMapper()
    mapper.build_from_scan_results(scan_results)
    
    viz = NetworkVisualizer()
    return viz.generate_html(mapper, output_file)

if __name__ == "__main__":
    mapper = TopologyMapper()
    
    mapper.add_node(NetworkNode("upf1", "10.0.0.10", NodeType.UPF, ports=[2152]))
    mapper.add_node(NetworkNode("smf1", "10.0.0.20", NodeType.SMF, ports=[8805, 29502]))
    mapper.add_node(NetworkNode("amf1", "10.0.0.30", NodeType.AMF, ports=[38412, 29518]))
    mapper.add_node(NetworkNode("nrf1", "10.0.0.40", NodeType.NRF, ports=[29510]))
    mapper.add_node(NetworkNode("gnb1", "10.0.0.50", NodeType.GNODEB, ports=[38412]))
    mapper.add_node(NetworkNode("attacker", "192.168.1.100", NodeType.ATTACKER))
    
    mapper.add_link(NetworkLink("gnb1", "amf1", LinkType.NGAP, 38412, "N2"))
    mapper.add_link(NetworkLink("amf1", "smf1", LinkType.SBI, 29502, "N11"))
    mapper.add_link(NetworkLink("smf1", "upf1", LinkType.PFCP, 8805, "N4"))
    mapper.add_link(NetworkLink("gnb1", "upf1", LinkType.GTPU, 2152, "N3", is_compromised=True))
    
    mapper.mark_compromised("upf1")
    
    viz = NetworkVisualizer()
    path = viz.generate_html(mapper, "demo_topology.html")
    print(f"Demo topology generated: {path}")

