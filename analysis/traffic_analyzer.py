#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import struct
import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Protocol(Enum):
    GTP_U = "GTP-U"
    GTP_C = "GTP-C"
    PFCP = "PFCP"
    NGAP = "NGAP"
    NAS = "NAS"
    SBI = "SBI"
    UNKNOWN = "UNKNOWN"


class GTPMessageType(Enum):
    ECHO_REQUEST = 1
    ECHO_RESPONSE = 2
    ERROR_INDICATION = 26
    END_MARKER = 254
    G_PDU = 255


class PFCPMessageType(Enum):
    HEARTBEAT_REQUEST = 1
    HEARTBEAT_RESPONSE = 2
    PFD_MANAGEMENT_REQUEST = 3
    ASSOCIATION_SETUP_REQUEST = 5
    ASSOCIATION_SETUP_RESPONSE = 6
    ASSOCIATION_UPDATE_REQUEST = 7
    ASSOCIATION_RELEASE_REQUEST = 9
    SESSION_ESTABLISHMENT_REQUEST = 50
    SESSION_ESTABLISHMENT_RESPONSE = 51
    SESSION_MODIFICATION_REQUEST = 52
    SESSION_MODIFICATION_RESPONSE = 53
    SESSION_DELETION_REQUEST = 54
    SESSION_DELETION_RESPONSE = 55
    SESSION_REPORT_REQUEST = 56


@dataclass
class PacketInfo:
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: Protocol
    size: int
    raw_data: bytes
    parsed: Dict = field(default_factory=dict)


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)


@dataclass
class FlowStatistics:
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0
    last_seen: float = 0
    message_types: Dict[str, int] = field(default_factory=dict)
    avg_packet_size: float = 0
    packets_per_second: float = 0
    
    def update(self, packet: PacketInfo, msg_type: Optional[str] = None):
        if self.first_seen == 0:
            self.first_seen = packet.timestamp
        self.last_seen = packet.timestamp
        self.packets += 1
        self.bytes += packet.size
        
        if msg_type:
            self.message_types[msg_type] = self.message_types.get(msg_type, 0) + 1
        
        self.avg_packet_size = self.bytes / self.packets
        duration = self.last_seen - self.first_seen
        if duration > 0:
            self.packets_per_second = self.packets / duration


class ProtocolParser:
    @staticmethod
    def parse_gtp_u(data: bytes) -> Dict:
        if len(data) < 8:
            return {"error": "too_short", "valid": False}
        
        flags = data[0]
        version = (flags >> 5) & 0x07
        pt = (flags >> 4) & 0x01
        e = (flags >> 2) & 0x01
        s = (flags >> 1) & 0x01
        pn = flags & 0x01
        
        msg_type = data[1]
        length = struct.unpack("!H", data[2:4])[0]
        teid = struct.unpack("!I", data[4:8])[0]
        
        result = {
            "valid": version == 1 and pt == 1,
            "version": version,
            "pt_flag": pt,
            "e_flag": e,
            "s_flag": s,
            "pn_flag": pn,
            "message_type": msg_type,
            "message_type_name": GTPMessageType(msg_type).name if msg_type in [e.value for e in GTPMessageType] else f"TYPE_{msg_type}",
            "length": length,
            "teid": teid,
            "header_length": 8
        }
        
        offset = 8
        if e or s or pn:
            if len(data) >= 12:
                result["sequence_number"] = struct.unpack("!H", data[8:10])[0]
                result["n_pdu_number"] = data[10]
                result["next_extension"] = data[11]
                result["header_length"] = 12
                offset = 12
        
        if msg_type == 255 and len(data) > offset:
            inner = data[offset:]
            if len(inner) >= 20 and (inner[0] >> 4) == 4:
                result["inner_ip_src"] = ".".join(str(b) for b in inner[12:16])
                result["inner_ip_dst"] = ".".join(str(b) for b in inner[16:20])
                result["inner_protocol"] = inner[9]
                result["has_inner_ip"] = True
        
        return result
    
    @staticmethod
    def parse_pfcp(data: bytes) -> Dict:
        if len(data) < 8:
            return {"error": "too_short", "valid": False}
        
        flags = data[0]
        version = (flags >> 5) & 0x07
        mp = (flags >> 1) & 0x01
        s = flags & 0x01
        
        msg_type = data[1]
        length = struct.unpack("!H", data[2:4])[0]
        
        result = {
            "valid": version == 1,
            "version": version,
            "mp_flag": mp,
            "s_flag": s,
            "message_type": msg_type,
            "message_type_name": PFCPMessageType(msg_type).name if msg_type in [e.value for e in PFCPMessageType] else f"TYPE_{msg_type}",
            "length": length
        }
        
        if s:
            if len(data) >= 16:
                result["seid"] = struct.unpack("!Q", data[4:12])[0]
                result["sequence_number"] = struct.unpack("!I", data[12:16])[0] >> 8
        else:
            if len(data) >= 8:
                result["sequence_number"] = struct.unpack("!I", data[4:8])[0] >> 8
        
        return result
    
    @staticmethod
    def parse_ngap(data: bytes) -> Dict:
        if len(data) < 4:
            return {"error": "too_short", "valid": False}
        
        pdu_type = (data[0] >> 5) & 0x07
        procedure_code = data[1]
        criticality = (data[2] >> 6) & 0x03
        
        pdu_names = {0: "InitiatingMessage", 1: "SuccessfulOutcome", 2: "UnsuccessfulOutcome"}
        
        procedure_names = {
            0: "AMFConfigurationUpdate",
            10: "HandoverCancel",
            12: "HandoverPreparation",
            13: "HandoverResourceAllocation",
            14: "InitialContextSetup",
            15: "InitialUEMessage",
            20: "NGReset",
            21: "NGSetup",
            25: "PDUSessionResourceModify",
            26: "PDUSessionResourceModifyIndication",
            27: "PDUSessionResourceRelease",
            28: "PDUSessionResourceSetup",
            46: "UEContextRelease",
            47: "UEContextReleaseRequest",
        }
        
        return {
            "valid": True,
            "pdu_type": pdu_type,
            "pdu_type_name": pdu_names.get(pdu_type, f"PDU_{pdu_type}"),
            "procedure_code": procedure_code,
            "procedure_name": procedure_names.get(procedure_code, f"PROC_{procedure_code}"),
            "criticality": criticality
        }
    
    @staticmethod
    def parse_sbi(data: bytes) -> Dict:
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if not lines or ' ' not in lines[0]:
                return {"valid": False, "error": "not_http"}
            
            first_line = lines[0].split(' ')
            
            if first_line[0] in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                method = first_line[0]
                path = first_line[1] if len(first_line) > 1 else ""
                
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip().lower()] = v.strip()
                
                api_type = "unknown"
                if "nnrf" in path:
                    api_type = "NRF"
                elif "namf" in path:
                    api_type = "AMF"
                elif "nsmf" in path:
                    api_type = "SMF"
                elif "nudm" in path:
                    api_type = "UDM"
                elif "nausf" in path:
                    api_type = "AUSF"
                elif "npcf" in path:
                    api_type = "PCF"
                
                return {
                    "valid": True,
                    "type": "request",
                    "method": method,
                    "path": path,
                    "api_type": api_type,
                    "content_type": headers.get("content-type", ""),
                    "host": headers.get("host", "")
                }
            elif "HTTP" in first_line[0]:
                status = int(first_line[1]) if len(first_line) > 1 else 0
                return {
                    "valid": True,
                    "type": "response",
                    "status_code": status,
                    "status_text": " ".join(first_line[2:]) if len(first_line) > 2 else ""
                }
            
            return {"valid": False, "error": "not_http"}
        except Exception as e:
            return {"valid": False, "error": str(e)}


class Traffic5GAnalyzer:
    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.flows: Dict[FlowKey, FlowStatistics] = {}
        self.protocol_stats: Dict[Protocol, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "bytes": 0, "messages": {}})
        self.teid_map: Dict[int, Dict] = {}
        self.seid_map: Dict[int, Dict] = {}
        self.parser = ProtocolParser()
        
    def analyze_packet(self, packet: PacketInfo) -> Dict:
        self.packets.append(packet)
        
        parsed = self._parse_packet(packet)
        packet.parsed = parsed
        
        flow_key = FlowKey(
            src_ip=packet.source_ip,
            dst_ip=packet.dest_ip,
            src_port=packet.source_port,
            dst_port=packet.dest_port,
            protocol=packet.protocol.value
        )
        
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStatistics()
        
        msg_type = parsed.get("message_type_name") or parsed.get("procedure_name") or parsed.get("method")
        self.flows[flow_key].update(packet, msg_type)
        
        stats = self.protocol_stats[packet.protocol]
        stats["count"] += 1
        stats["bytes"] += packet.size
        if msg_type:
            stats["messages"][msg_type] = stats["messages"].get(msg_type, 0) + 1
        
        if packet.protocol == Protocol.GTP_U and "teid" in parsed:
            teid = parsed["teid"]
            if teid not in self.teid_map:
                self.teid_map[teid] = {"first_seen": packet.timestamp, "packets": 0, "bytes": 0}
            self.teid_map[teid]["packets"] += 1
            self.teid_map[teid]["bytes"] += packet.size
            self.teid_map[teid]["last_seen"] = packet.timestamp
            self.teid_map[teid]["endpoints"] = (packet.source_ip, packet.dest_ip)
        
        if packet.protocol == Protocol.PFCP and "seid" in parsed:
            seid = parsed["seid"]
            if seid not in self.seid_map:
                self.seid_map[seid] = {"first_seen": packet.timestamp, "packets": 0, "bytes": 0}
            self.seid_map[seid]["packets"] += 1
            self.seid_map[seid]["bytes"] += packet.size
            self.seid_map[seid]["last_seen"] = packet.timestamp
        
        return parsed
    
    def _parse_packet(self, packet: PacketInfo) -> Dict:
        if packet.protocol == Protocol.GTP_U:
            return self.parser.parse_gtp_u(packet.raw_data)
        elif packet.protocol == Protocol.PFCP:
            return self.parser.parse_pfcp(packet.raw_data)
        elif packet.protocol == Protocol.NGAP:
            return self.parser.parse_ngap(packet.raw_data)
        elif packet.protocol == Protocol.SBI:
            return self.parser.parse_sbi(packet.raw_data)
        return {}
    
    def detect_protocol(self, data: bytes, src_port: int, dst_port: int) -> Protocol:
        if dst_port == 2152 or src_port == 2152:
            return Protocol.GTP_U
        elif dst_port == 8805 or src_port == 8805:
            return Protocol.PFCP
        elif dst_port == 38412 or src_port == 38412:
            return Protocol.NGAP
        elif dst_port in [80, 443, 7777, 8080] or src_port in [80, 443, 7777, 8080]:
            return Protocol.SBI
        
        if len(data) >= 2:
            if data[0] in [0x30, 0x32, 0x34, 0x36]:
                return Protocol.GTP_U
            if (data[0] >> 5) == 1 and data[1] in range(1, 60):
                return Protocol.PFCP
        
        return Protocol.UNKNOWN
    
    def get_flow_analysis(self) -> List[Dict]:
        results = []
        for flow_key, stats in self.flows.items():
            results.append({
                "source": f"{flow_key.src_ip}:{flow_key.src_port}",
                "destination": f"{flow_key.dst_ip}:{flow_key.dst_port}",
                "protocol": flow_key.protocol,
                "packets": stats.packets,
                "bytes": stats.bytes,
                "duration": stats.last_seen - stats.first_seen,
                "pps": stats.packets_per_second,
                "avg_size": stats.avg_packet_size,
                "message_types": stats.message_types
            })
        return sorted(results, key=lambda x: x["bytes"], reverse=True)
    
    def get_teid_analysis(self) -> Dict:
        active_teids = {t: info for t, info in self.teid_map.items() if info["packets"] > 1}
        
        return {
            "total_teids": len(self.teid_map),
            "active_teids": len(active_teids),
            "top_by_traffic": sorted(
                [(t, info) for t, info in self.teid_map.items()],
                key=lambda x: x[1]["bytes"],
                reverse=True
            )[:20],
            "teid_range": {
                "min": min(self.teid_map.keys()) if self.teid_map else 0,
                "max": max(self.teid_map.keys()) if self.teid_map else 0
            }
        }
    
    def get_seid_analysis(self) -> Dict:
        return {
            "total_seids": len(self.seid_map),
            "top_by_traffic": sorted(
                [(s, info) for s, info in self.seid_map.items()],
                key=lambda x: x[1]["bytes"],
                reverse=True
            )[:20]
        }
    
    def get_protocol_breakdown(self) -> Dict:
        total_packets = sum(s["count"] for s in self.protocol_stats.values())
        total_bytes = sum(s["bytes"] for s in self.protocol_stats.values())
        
        breakdown = {}
        for proto, stats in self.protocol_stats.items():
            breakdown[proto.value] = {
                "packets": stats["count"],
                "bytes": stats["bytes"],
                "packet_percentage": (stats["count"] / total_packets * 100) if total_packets > 0 else 0,
                "byte_percentage": (stats["bytes"] / total_bytes * 100) if total_bytes > 0 else 0,
                "message_distribution": stats["messages"]
            }
        
        return breakdown
    
    def detect_anomalies(self) -> List[Dict]:
        anomalies = []
        
        for flow_key, stats in self.flows.items():
            if stats.packets_per_second > 1000:
                anomalies.append({
                    "type": "high_rate_flow",
                    "severity": "HIGH",
                    "flow": f"{flow_key.src_ip} -> {flow_key.dst_ip}",
                    "rate": stats.packets_per_second,
                    "description": "Unusually high packet rate detected"
                })
            
            if stats.avg_packet_size > 1400:
                anomalies.append({
                    "type": "large_packets",
                    "severity": "MEDIUM",
                    "flow": f"{flow_key.src_ip} -> {flow_key.dst_ip}",
                    "avg_size": stats.avg_packet_size,
                    "description": "Large average packet size"
                })
        
        if self.teid_map:
            teid_values = list(self.teid_map.keys())
            if len(teid_values) > 10:
                sequential = sum(1 for i in range(len(teid_values)-1) if teid_values[i+1] - teid_values[i] == 1)
                if sequential > len(teid_values) * 0.5:
                    anomalies.append({
                        "type": "teid_enumeration",
                        "severity": "HIGH",
                        "description": f"Sequential TEID pattern detected ({sequential} sequential TEIDs)"
                    })
        
        return anomalies
    
    def generate_report(self) -> Dict:
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_packets": len(self.packets),
                "total_flows": len(self.flows),
                "protocols_seen": list(self.protocol_stats.keys()),
                "active_teids": len(self.teid_map),
                "active_seids": len(self.seid_map)
            },
            "protocol_breakdown": self.get_protocol_breakdown(),
            "top_flows": self.get_flow_analysis()[:10],
            "teid_analysis": self.get_teid_analysis(),
            "seid_analysis": self.get_seid_analysis(),
            "anomalies": self.detect_anomalies()
        }
    
    def export_report(self, filename: str = "traffic_analysis_report.json"):
        report = self.generate_report()
        
        def convert(obj):
            if isinstance(obj, Protocol):
                return obj.value
            if isinstance(obj, tuple):
                return list(obj)
            return str(obj)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=convert)
        
        logger.info(f"Report exported to {filename}")
        return filename


def demo_traffic_analysis():
    import random
    
    logger.info("Running traffic analysis demo...")
    
    analyzer = Traffic5GAnalyzer()
    
    for i in range(100):
        teid = random.randint(1, 50)
        gtp_data = struct.pack("!BBHI", 0x30, 255, 100, teid)
        gtp_data += b'\x45\x00' + bytes(98)
        
        packet = PacketInfo(
            timestamp=time.time() + i * 0.01,
            source_ip=f"10.0.0.{random.randint(1, 10)}",
            dest_ip="192.168.1.1",
            source_port=random.randint(10000, 60000),
            dest_port=2152,
            protocol=Protocol.GTP_U,
            size=len(gtp_data),
            raw_data=gtp_data
        )
        analyzer.analyze_packet(packet)
    
    for i in range(20):
        seid = random.randint(1, 10)
        pfcp_data = struct.pack("!BBHQBBH", 0x21, 50, 20, seid, 0, 0, i)
        
        packet = PacketInfo(
            timestamp=time.time() + i * 0.05,
            source_ip="10.0.0.100",
            dest_ip="192.168.1.2",
            source_port=8805,
            dest_port=8805,
            protocol=Protocol.PFCP,
            size=len(pfcp_data),
            raw_data=pfcp_data
        )
        analyzer.analyze_packet(packet)
    
    report = analyzer.generate_report()
    
    logger.info("\n" + "="*50)
    logger.info("TRAFFIC ANALYSIS REPORT")
    logger.info("="*50)
    logger.info(f"Total Packets: {report['summary']['total_packets']}")
    logger.info(f"Total Flows: {report['summary']['total_flows']}")
    logger.info(f"Active TEIDs: {report['summary']['active_teids']}")
    logger.info(f"Active SEIDs: {report['summary']['active_seids']}")
    
    if report['anomalies']:
        logger.warning(f"\nAnomalies Detected: {len(report['anomalies'])}")
        for a in report['anomalies']:
            logger.warning(f"  [{a['severity']}] {a['type']}: {a['description']}")
    
    analyzer.export_report()
    
    return analyzer


def get_protocol_breakdown(analyzer: Traffic5GAnalyzer) -> List[Tuple[str, int, float]]:
    proto_breakdown = analyzer.get_protocol_breakdown()
    total = proto_breakdown.get("total_packets", 1)
    breakdown = []
    for proto, count in proto_breakdown.items():
        if proto != "total_packets" and isinstance(count, int):
            percentage = (count / total) * 100 if total > 0 else 0.0
            breakdown.append((proto, count, percentage))
    return sorted(breakdown, key=lambda x: x[1], reverse=True)


if __name__ == "__main__":
    demo_traffic_analysis()

