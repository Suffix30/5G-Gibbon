#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import struct
import logging
import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class HoneypotType(Enum):
    UPF = "upf"
    AMF = "amf"
    SMF = "smf"
    NRF = "nrf"
    GNODEB = "gnb"


@dataclass
class AttackEvent:
    timestamp: str
    source_ip: str
    source_port: int
    honeypot_type: str
    protocol: str
    attack_type: str
    raw_data: bytes
    decoded_info: Dict = field(default_factory=dict)


class HoneypotBase:
    def __init__(self, bind_ip: str = "0.0.0.0", log_callback: Optional[Callable] = None):
        self.bind_ip = bind_ip
        self.events: List[AttackEvent] = []
        self.running = False
        self.threads: List[threading.Thread] = []
        self.log_callback = log_callback or self._default_log
        
    def _default_log(self, event: AttackEvent):
        logger.warning(f"[ATTACK] {event.honeypot_type} from {event.source_ip}:{event.source_port} - {event.attack_type}")
    
    def start(self):
        raise NotImplementedError("Subclasses must implement start()")
    
    def stop(self):
        raise NotImplementedError("Subclasses must implement stop()")
    
    def record_event(self, source: tuple, honeypot_type: str, protocol: str, 
                     attack_type: str, raw_data: bytes, decoded: Optional[Dict] = None):
        event = AttackEvent(
            timestamp=datetime.now().isoformat(),
            source_ip=source[0],
            source_port=source[1],
            honeypot_type=honeypot_type,
            protocol=protocol,
            attack_type=attack_type,
            raw_data=raw_data,
            decoded_info=decoded or {}
        )
        self.events.append(event)
        self.log_callback(event)
        return event
    
    def export_events(self, filename: str = "honeypot_events.json"):
        data = []
        for e in self.events:
            d = {
                "timestamp": e.timestamp,
                "source_ip": e.source_ip,
                "source_port": e.source_port,
                "honeypot_type": e.honeypot_type,
                "protocol": e.protocol,
                "attack_type": e.attack_type,
                "raw_data_hex": e.raw_data.hex() if e.raw_data else "",
                "decoded_info": e.decoded_info
            }
            data.append(d)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(data)} events to {filename}")
        return filename


class GTPHoneypot(HoneypotBase):
    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 2152, **kwargs):
        super().__init__(bind_ip, **kwargs)
        self.port = port
        self.sock = None
        
    def _parse_gtp_header(self, data: bytes) -> Dict:
        if len(data) < 8:
            return {"error": "too_short"}
        
        flags = data[0]
        msg_type = data[1]
        length = struct.unpack("!H", data[2:4])[0]
        teid = struct.unpack("!I", data[4:8])[0]
        
        return {
            "version": (flags >> 5) & 0x07,
            "pt_flag": (flags >> 4) & 0x01,
            "e_flag": (flags >> 2) & 0x01,
            "s_flag": (flags >> 1) & 0x01,
            "pn_flag": flags & 0x01,
            "message_type": msg_type,
            "length": length,
            "teid": teid
        }
    
    def _classify_attack(self, gtp_info: Dict, data: bytes) -> str:
        msg_type = gtp_info.get("message_type", 0)
        _teid = gtp_info.get("teid", 0)
        
        if msg_type == 1:
            return "TEID_PROBE"
        elif msg_type == 255:
            if b'\x45\x00' in data[8:]:
                return "DATA_INJECTION"
            return "TUNNEL_ATTACK"
        elif gtp_info.get("version", 0) != 1:
            return "PROTOCOL_FUZZING"
        elif len(data) > 1400:
            return "LARGE_PACKET_ATTACK"
        else:
            return "RECONNAISSANCE"
    
    def _generate_response(self, gtp_info: Dict) -> bytes:
        if gtp_info.get("message_type") == 1:
            response = struct.pack("!BBHI",
                0x32,
                0x02,
                6,
                gtp_info.get("teid", 0)
            )
            response += struct.pack("!BBH", 0x0e, 0x00, 0)
            return response
        return b""
    
    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_ip, self.port))
        self.sock.settimeout(1.0)
        
        logger.info(f"[GTP Honeypot] Listening on {self.bind_ip}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                gtp_info = self._parse_gtp_header(data)
                attack_type = self._classify_attack(gtp_info, data)
                
                self.record_event(
                    source=addr,
                    honeypot_type="UPF",
                    protocol="GTP-U",
                    attack_type=attack_type,
                    raw_data=data,
                    decoded=gtp_info
                )
                
                response = self._generate_response(gtp_info)
                if response:
                    self.sock.sendto(response, addr)
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"GTP Honeypot error: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


class PFCPHoneypot(HoneypotBase):
    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 8805, **kwargs):
        super().__init__(bind_ip, **kwargs)
        self.port = port
        self.sock = None
        
    def _parse_pfcp_header(self, data: bytes) -> Dict:
        if len(data) < 8:
            return {"error": "too_short"}
        
        flags = data[0]
        msg_type = data[1]
        length = struct.unpack("!H", data[2:4])[0]
        
        seid = 0
        if flags & 0x01:
            if len(data) >= 16:
                seid = struct.unpack("!Q", data[4:12])[0]
        
        seq = struct.unpack("!I", data[-4:])[0] >> 8 if len(data) >= 4 else 0
        
        return {
            "version": (flags >> 5) & 0x07,
            "mp_flag": (flags >> 1) & 0x01,
            "s_flag": flags & 0x01,
            "message_type": msg_type,
            "length": length,
            "seid": seid,
            "sequence": seq
        }
    
    def _classify_attack(self, pfcp_info: Dict) -> str:
        msg_type = pfcp_info.get("message_type", 0)
        
        if msg_type in [1, 2]:
            return "HEARTBEAT_PROBE"
        elif msg_type in [5, 6]:
            return "ASSOCIATION_ATTEMPT"
        elif msg_type in [50, 51]:
            return "SESSION_ESTABLISHMENT"
        elif msg_type in [52, 53]:
            return "SESSION_MODIFICATION"
        elif msg_type in [54, 55]:
            return "SESSION_DELETION"
        elif msg_type == 15:
            return "VERSION_DISCOVERY"
        else:
            return "UNKNOWN_OPERATION"
    
    def _generate_response(self, pfcp_info: Dict) -> bytes:
        msg_type = pfcp_info.get("message_type", 0)
        
        if msg_type == 1:
            response = struct.pack("!BBH", 0x20, 0x02, 12)
            response += struct.pack("!I", int(time.time()))
            response += struct.pack("!I", pfcp_info.get("sequence", 0) << 8)
            return response
        
        return b""
    
    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_ip, self.port))
        self.sock.settimeout(1.0)
        
        logger.info(f"[PFCP Honeypot] Listening on {self.bind_ip}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                pfcp_info = self._parse_pfcp_header(data)
                attack_type = self._classify_attack(pfcp_info)
                
                self.record_event(
                    source=addr,
                    honeypot_type="SMF",
                    protocol="PFCP",
                    attack_type=attack_type,
                    raw_data=data,
                    decoded=pfcp_info
                )
                
                response = self._generate_response(pfcp_info)
                if response:
                    self.sock.sendto(response, addr)
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"PFCP Honeypot error: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


class SBIHoneypot(HoneypotBase):
    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 7777, **kwargs):
        super().__init__(bind_ip, **kwargs)
        self.port = port
        self.sock = None
        
    def _parse_http_request(self, data: bytes) -> Dict:
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if not lines:
                return {"error": "empty"}
            
            first_line = lines[0].split(' ')
            method = first_line[0] if len(first_line) > 0 else ""
            path = first_line[1] if len(first_line) > 1 else ""
            
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
            
            return {
                "method": method,
                "path": path,
                "headers": headers,
                "user_agent": headers.get("user-agent", "unknown")
            }
        except Exception:
            return {"error": "parse_failed"}
    
    def _classify_attack(self, http_info: Dict) -> str:
        path = http_info.get("path", "")
        method = http_info.get("method", "")
        
        if "nnrf-disc" in path:
            return "NF_DISCOVERY_PROBE"
        elif "nnrf-nfm" in path and method == "PUT":
            return "ROGUE_NF_REGISTRATION"
        elif "nudm-sdm" in path:
            return "SUBSCRIBER_DATA_THEFT"
        elif "nausf" in path or "authentication" in path:
            return "AUTH_ATTACK"
        elif "nsmf" in path:
            return "SESSION_MANIPULATION"
        elif method == "DELETE":
            return "NF_DEREGISTRATION_ATTACK"
        else:
            return "SBI_RECONNAISSANCE"
    
    def _generate_fake_nf_list(self) -> str:
        fake_nfs = {
            "nfInstances": [
                {"nfInstanceId": "fake-amf-001", "nfType": "AMF", "nfStatus": "REGISTERED"},
                {"nfInstanceId": "fake-smf-001", "nfType": "SMF", "nfStatus": "REGISTERED"},
                {"nfInstanceId": "fake-upf-001", "nfType": "UPF", "nfStatus": "REGISTERED"},
            ]
        }
        return json.dumps(fake_nfs)
    
    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_ip, self.port))
        self.sock.listen(10)
        self.sock.settimeout(1.0)
        
        logger.info(f"[SBI Honeypot] Listening on {self.bind_ip}:{self.port}")
        
        while self.running:
            try:
                conn, addr = self.sock.accept()
                conn.settimeout(5.0)
                
                try:
                    data = conn.recv(4096)
                    if data:
                        http_info = self._parse_http_request(data)
                        attack_type = self._classify_attack(http_info)
                        
                        self.record_event(
                            source=addr,
                            honeypot_type="NRF",
                            protocol="SBI/HTTP",
                            attack_type=attack_type,
                            raw_data=data,
                            decoded=http_info
                        )
                        
                        if "nnrf-disc" in http_info.get("path", ""):
                            body = self._generate_fake_nf_list()
                            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                        else:
                            response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                        
                        conn.send(response.encode())
                finally:
                    conn.close()
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"SBI Honeypot error: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


class Honeypot5GOrchestrator:
    def __init__(self, bind_ip: str = "0.0.0.0"):
        self.bind_ip = bind_ip
        self.honeypots: Dict[str, HoneypotBase] = {}
        self.threads: Dict[str, threading.Thread] = {}
        self.all_events: List[AttackEvent] = []
        
    def _unified_callback(self, event: AttackEvent):
        self.all_events.append(event)
        logger.warning(
            f"[{event.timestamp}] ATTACK DETECTED\n"
            f"  Type: {event.attack_type}\n"
            f"  Source: {event.source_ip}:{event.source_port}\n"
            f"  Target: {event.honeypot_type} ({event.protocol})\n"
            f"  Details: {event.decoded_info}"
        )
    
    def add_gtp_honeypot(self, port: int = 2152):
        hp = GTPHoneypot(self.bind_ip, port, log_callback=self._unified_callback)
        self.honeypots["gtp"] = hp
        return self
    
    def add_pfcp_honeypot(self, port: int = 8805):
        hp = PFCPHoneypot(self.bind_ip, port, log_callback=self._unified_callback)
        self.honeypots["pfcp"] = hp
        return self
    
    def add_sbi_honeypot(self, port: int = 7777):
        hp = SBIHoneypot(self.bind_ip, port, log_callback=self._unified_callback)
        self.honeypots["sbi"] = hp
        return self
    
    def add_all(self):
        self.add_gtp_honeypot()
        self.add_pfcp_honeypot()
        self.add_sbi_honeypot()
        return self
    
    def start_all(self):
        logger.info("="*50)
        logger.info("5G HONEYPOT NETWORK STARTING")
        logger.info("="*50)
        
        for name, hp in self.honeypots.items():
            t = threading.Thread(target=hp.start, daemon=True)
            t.start()
            self.threads[name] = t
        
        logger.info(f"Started {len(self.honeypots)} honeypots")
        return self
    
    def stop_all(self):
        logger.info("Stopping all honeypots...")
        for hp in self.honeypots.values():
            hp.stop()
        
        for t in self.threads.values():
            t.join(timeout=2)
        
        logger.info("All honeypots stopped")
    
    def get_statistics(self) -> Dict:
        by_type = {}
        by_source = {}
        by_honeypot = {}
        
        for event in self.all_events:
            by_type[event.attack_type] = by_type.get(event.attack_type, 0) + 1
            by_source[event.source_ip] = by_source.get(event.source_ip, 0) + 1
            by_honeypot[event.honeypot_type] = by_honeypot.get(event.honeypot_type, 0) + 1
        
        return {
            "total_attacks": len(self.all_events),
            "by_attack_type": by_type,
            "by_source_ip": dict(sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:10]),
            "by_honeypot": by_honeypot
        }
    
    def export_all(self, filename: str = "honeypot_all_events.json"):
        data = []
        for e in self.all_events:
            d = {
                "timestamp": e.timestamp,
                "source_ip": e.source_ip,
                "source_port": e.source_port,
                "honeypot_type": e.honeypot_type,
                "protocol": e.protocol,
                "attack_type": e.attack_type,
                "raw_data_hex": e.raw_data.hex() if e.raw_data else "",
                "decoded_info": e.decoded_info
            }
            data.append(d)
        
        with open(filename, 'w') as f:
            json.dump({
                "statistics": self.get_statistics(),
                "events": data
            }, f, indent=2)
        
        return filename
    
    def generate_html_report(self, filename: str = "honeypot_report.html"):
        from reporting.html_report import (
            ReportGenerator, Finding, SeverityLevel, AttackResult,
            AttackEvent as ReportAttackEvent
        )
        
        report = ReportGenerator()
        report.set_metadata(
            title="5G Honeypot Attack Report",
            assessment_type="Honeypot Analysis",
            target_network=self.bind_ip,
            start_time=self.all_events[0].timestamp if self.all_events else datetime.now().isoformat(),
            end_time=self.all_events[-1].timestamp if self.all_events else datetime.now().isoformat()
        )
        
        stats = self.get_statistics()
        attack_types = stats.get("by_attack_type", {})
        
        for attack_type, count in attack_types.items():
            severity = SeverityLevel.CRITICAL if count > 10 else (
                SeverityLevel.HIGH if count > 5 else SeverityLevel.MEDIUM
            )
            
            finding = Finding(
                title=f"{attack_type} Detected",
                severity=severity,
                description=f"Honeypot detected {count} instances of {attack_type}",
                affected_component="Honeypot Network",
                evidence=f"Total occurrences: {count}",
                remediation=self._get_recommendation(attack_type)
            )
            report.add_finding(finding)
        
        for source_ip, count in stats.get("by_source_ip", {}).items():
            events_from_ip = [e for e in self.all_events if e.source_ip == source_ip]
            
            attack_events = []
            for e in events_from_ip[:10]:
                attack_events.append(ReportAttackEvent(
                    timestamp=e.timestamp,
                    phase="Attack",
                    technique=e.attack_type,
                    command=f"{e.protocol} packet to {e.honeypot_type}",
                    payload=e.raw_data.hex()[:100] if e.raw_data else "N/A",
                    response="Honeypot response sent",
                    success=True,
                    evidence={"decoded_info": str(e.decoded_info)[:200]}
                ))
            
            result = AttackResult(
                attack_type=f"Attacks from {source_ip}",
                target=self.bind_ip,
                success=True,
                timestamp=events_from_ip[0].timestamp if events_from_ip else datetime.now().isoformat(),
                duration=0.0,
                details={
                    "total_attacks": count,
                    "attack_types": list(set(e.attack_type for e in events_from_ip)),
                    "protocols_used": list(set(e.protocol for e in events_from_ip)),
                    "first_seen": events_from_ip[0].timestamp if events_from_ip else "N/A",
                    "last_seen": events_from_ip[-1].timestamp if events_from_ip else "N/A"
                },
                attack_events=attack_events
            )
            report.add_attack_result(result)
        
        report.generate_html(filename)
        logger.info(f"HTML report generated: {filename}")
        return filename
    
    def generate_topology_report(self, filename: str = "honeypot_topology.html"):
        from reporting.visualization import (
            NetworkVisualizer, TopologyMapper, NetworkNode, NetworkLink,
            NodeType, LinkType, AttackEvent as TopoAttackEvent
        )
        
        mapper = TopologyMapper()
        
        honeypot_nodes = {
            "UPF": ("upf_honeypot", NodeType.UPF, 2152),
            "SMF": ("smf_honeypot", NodeType.SMF, 8805),
            "NRF": ("nrf_honeypot", NodeType.NRF, 7777),
        }
        
        for hp_type, (node_id, node_type, port) in honeypot_nodes.items():
            events = [e for e in self.all_events if e.honeypot_type == hp_type]
            
            attack_events = []
            for e in events[:20]:
                attack_events.append(TopoAttackEvent(
                    timestamp=e.timestamp,
                    phase="Honeypot Trap",
                    technique=e.attack_type,
                    command=f"{e.protocol} from {e.source_ip}:{e.source_port}",
                    payload=e.raw_data.hex()[:50] if e.raw_data else "",
                    response="Honeypot captured",
                    success=True,
                    evidence={"decoded_info": str(e.decoded_info)[:100]}
                ))
            
            node = NetworkNode(
                id=node_id,
                ip=self.bind_ip,
                node_type=node_type,
                label=f"{hp_type} Honeypot",
                ports=[port],
                vulnerabilities=[],
                metadata={
                    "attacks_received": len(events),
                    "unique_attackers": len(set(e.source_ip for e in events)),
                    "attack_types": list(set(e.attack_type for e in events))[:5],
                    "status": "compromised" if events else "active"
                },
                attack_events=attack_events
            )
            mapper.add_node(node)
        
        attacker_ips = set(e.source_ip for e in self.all_events)
        for idx, attacker_ip in enumerate(list(attacker_ips)[:10]):
            attacker_events = [e for e in self.all_events if e.source_ip == attacker_ip]
            
            attacker_node = NetworkNode(
                id=f"attacker_{idx}",
                ip=attacker_ip,
                node_type=NodeType.UNKNOWN,
                label=f"Attacker\n{attacker_ip}",
                ports=[],
                vulnerabilities=[],
                metadata={
                    "total_attacks": len(attacker_events),
                    "attack_types": list(set(e.attack_type for e in attacker_events)),
                    "status": "compromised"
                }
            )
            mapper.add_node(attacker_node)
            
            for e in attacker_events:
                hp_type = e.honeypot_type
                target_id = honeypot_nodes.get(hp_type, ("unknown", None, 0))[0]
                if target_id in [n.id for n in mapper.nodes.values()]:
                    link = NetworkLink(
                        source=f"attacker_{idx}",
                        target=target_id,
                        link_type=LinkType.UNKNOWN,
                        is_compromised=True,
                        metadata={"attack_type": e.attack_type, "protocol": e.protocol}
                    )
                    mapper.add_link(link)
        
        visualizer = NetworkVisualizer()
        visualizer.generate_html(
            mapper, 
            filename, 
            target_network=self.bind_ip,
            analyst="5G-Gibbon Honeypot"
        )
        logger.info(f"Topology report generated: {filename}")
        return filename
    
    def _get_recommendation(self, attack_type: str) -> str:
        recommendations = {
            "TEID_PROBE": "Implement TEID randomization and rate limiting on GTP-U interfaces",
            "DATA_INJECTION": "Deploy deep packet inspection and validate inner tunnel contents",
            "TUNNEL_ATTACK": "Enable GTP-U tunnel validation and implement ingress filtering",
            "PROTOCOL_FUZZING": "Deploy protocol validators and implement input sanitization",
            "LARGE_PACKET_ATTACK": "Configure maximum packet size limits and fragmentation handling",
            "RECONNAISSANCE": "Implement network segmentation and enhanced monitoring",
            "HEARTBEAT_PROBE": "Configure strict PFCP association policies",
            "ASSOCIATION_ATTEMPT": "Require mutual authentication for PFCP associations",
            "SESSION_ESTABLISHMENT": "Implement session validation and authorization checks",
            "SESSION_MODIFICATION": "Log and audit all session modifications",
            "SESSION_DELETION": "Implement session ownership verification",
            "NF_DISCOVERY_PROBE": "Restrict NRF access and implement OAuth2 for SBI",
            "ROGUE_NF_REGISTRATION": "Enforce certificate-based NF authentication",
            "SUBSCRIBER_DATA_THEFT": "Implement strict access controls on UDM interfaces",
            "AUTH_ATTACK": "Enable rate limiting and anomaly detection on AUSF",
            "SESSION_MANIPULATION": "Implement session integrity checks",
            "NF_DEREGISTRATION_ATTACK": "Require authorization for NF lifecycle operations",
            "SBI_RECONNAISSANCE": "Implement API gateway with rate limiting",
        }
        return recommendations.get(attack_type, "Review security policies and implement defense in depth")


def run_honeypot_network(bind_ip: str = "0.0.0.0", duration: int = 0, generate_report: bool = True):
    orchestrator = Honeypot5GOrchestrator(bind_ip)
    orchestrator.add_all().start_all()
    
    try:
        if duration > 0:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        orchestrator.stop_all()
        stats = orchestrator.get_statistics()
        logger.info(f"\nFinal Statistics:\n{json.dumps(stats, indent=2)}")
        orchestrator.export_all()
        
        if generate_report and orchestrator.all_events:
            orchestrator.generate_html_report()
            orchestrator.generate_topology_report()
    
    return orchestrator


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="5G Honeypot Network")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind IP address")
    parser.add_argument("--duration", type=int, default=0, help="Run duration (0=forever)")
    args = parser.parse_args()
    
    run_honeypot_network(args.bind, args.duration)

