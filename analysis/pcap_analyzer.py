#!/usr/bin/env python3 
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.contrib.gtp import GTPHeader
import logging
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

GTPU_PORT = 2152
PFCP_PORT = 8805
NGAP_SCTP_PORT = 38412
HTTP2_SBI_PORT = 7777

PROTOCOL_SIGNATURES = {
    "GTP-U": {"ports": [2152], "transport": "UDP"},
    "PFCP": {"ports": [8805], "transport": "UDP"},
    "NGAP": {"ports": [38412], "transport": "SCTP"},
    "SBI/HTTP2": {"ports": [7777, 80, 443], "transport": "TCP"},
    "Diameter": {"ports": [3868], "transport": "SCTP"},
    "S1AP": {"ports": [36412], "transport": "SCTP"},
}

class PcapAnalyzer:
    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.packets = []
        self.analysis = {
            "file": pcap_file,
            "timestamp": datetime.now().isoformat(),
            "total_packets": 0,
            "protocol_breakdown": {},
            "5g_components_detected": [],
            "security_findings": [],
            "attack_indicators": [],
            "sessions": {},
            "timeline": [],
        }
    
    def load_pcap(self, pcap_file=None):
        if pcap_file:
            self.pcap_file = pcap_file
        
        if not self.pcap_file or not os.path.exists(self.pcap_file):
            logger.error(f"PCAP file not found: {self.pcap_file}")
            return False
        
        try:
            self.packets = rdpcap(self.pcap_file)
            self.analysis["total_packets"] = len(self.packets)
            logger.info(f"Loaded {len(self.packets)} packets from {self.pcap_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}")
            return False
    
    def detect_nested_gtp(self, pkt):
        try:
            if pkt.haslayer(GTPHeader):
                payload = bytes(pkt[GTPHeader].payload)
                gtp_signature = b'\x30'
                if gtp_signature in payload[:20]:
                    return True
                if b'\x32' in payload[:5] or b'\x30' in payload[:5]:
                    return True
            return False
        except:
            return False
    
    def detect_rogue_gnodeb_attempt(self, pkt):
        try:
            if pkt.haslayer(SCTP) or (pkt.haslayer(UDP) and pkt[UDP].dport == 38412):
                payload = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
                if b'\x00\x15' in payload[:10]:
                    return True
            return False
        except:
            return False
    
    def detect_teid_enumeration(self, packets_window):
        try:
            teids = set()
            for pkt in packets_window:
                if pkt.haslayer(GTPHeader):
                    teids.add(pkt[GTPHeader].teid)
            
            if len(teids) > 10:
                teid_list = sorted(list(teids))
                sequential_count = 0
                for i in range(1, len(teid_list)):
                    if teid_list[i] - teid_list[i-1] == 1:
                        sequential_count += 1
                if sequential_count > 5:
                    return True, teid_list
            return False, []
        except:
            return False, []
    
    def analyze_packet(self, pkt, idx):
        result = {
            "index": idx,
            "time": float(pkt.time) if hasattr(pkt, 'time') else 0,
            "protocols": [],
            "src": None,
            "dst": None,
            "flags": [],
        }
        
        if pkt.haslayer(IP):
            result["src"] = pkt[IP].src
            result["dst"] = pkt[IP].dst
        
        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            
            if sport == GTPU_PORT or dport == GTPU_PORT:
                result["protocols"].append("GTP-U")
                if pkt.haslayer(GTPHeader):
                    result["teid"] = pkt[GTPHeader].teid
                    result["gtp_type"] = pkt[GTPHeader].gtp_type
                    
                    if self.detect_nested_gtp(pkt):
                        result["flags"].append("NESTED_GTP")
                        result["attack_type"] = "Russian Nesting Doll"
            
            if sport == PFCP_PORT or dport == PFCP_PORT:
                result["protocols"].append("PFCP")
        
        if pkt.haslayer(SCTP):
            sport = pkt[SCTP].sport if hasattr(pkt[SCTP], 'sport') else 0
            dport = pkt[SCTP].dport if hasattr(pkt[SCTP], 'dport') else 0
            
            if sport == NGAP_SCTP_PORT or dport == NGAP_SCTP_PORT:
                result["protocols"].append("NGAP")
                
                if self.detect_rogue_gnodeb_attempt(pkt):
                    result["flags"].append("ROGUE_GNODEB_ATTEMPT")
                    result["attack_type"] = "Rogue gNodeB Registration"
        
        return result
    
    def run_full_analysis(self):
        if not self.packets:
            logger.error("No packets loaded")
            return None
        
        logger.info("=== Starting Full PCAP Analysis ===")
        
        protocol_counts = {}
        attack_packets = []
        sessions = {}
        
        for idx, pkt in enumerate(self.packets):
            result = self.analyze_packet(pkt, idx)
            
            for proto in result["protocols"]:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            if result.get("flags"):
                attack_packets.append(result)
                self.analysis["attack_indicators"].append({
                    "packet": idx,
                    "type": result.get("attack_type", "Unknown"),
                    "flags": result["flags"],
                    "src": result["src"],
                    "dst": result["dst"],
                })
            
            if result.get("teid"):
                teid = result["teid"]
                if teid not in sessions:
                    sessions[teid] = {"packets": 0, "first_seen": result["time"], "last_seen": result["time"]}
                sessions[teid]["packets"] += 1
                sessions[teid]["last_seen"] = result["time"]
        
        self.analysis["protocol_breakdown"] = protocol_counts
        self.analysis["sessions"] = {str(k): v for k, v in sessions.items()}
        
        is_enum, enum_teids = self.detect_teid_enumeration(self.packets)
        if is_enum:
            self.analysis["security_findings"].append({
                "type": "TEID_ENUMERATION_DETECTED",
                "severity": "HIGH",
                "description": f"Sequential TEID probing detected: {len(enum_teids)} TEIDs scanned",
                "teids_sample": enum_teids[:20],
            })
        
        upf_ips = set()
        amf_ips = set()
        for pkt in self.packets:
            if pkt.haslayer(IP):
                if pkt.haslayer(UDP) and (pkt[UDP].sport == 2152 or pkt[UDP].dport == 2152):
                    upf_ips.add(pkt[IP].dst if pkt[UDP].dport == 2152 else pkt[IP].src)
                if pkt.haslayer(SCTP):
                    amf_ips.add(pkt[IP].dst)
        
        for ip in upf_ips:
            self.analysis["5g_components_detected"].append({"type": "UPF", "ip": ip})
        for ip in amf_ips:
            self.analysis["5g_components_detected"].append({"type": "AMF/SMF", "ip": ip})
        
        logger.info(f"Analysis complete:")
        logger.info(f"  Total packets: {self.analysis['total_packets']}")
        logger.info(f"  Protocols: {protocol_counts}")
        logger.info(f"  Attack indicators: {len(self.analysis['attack_indicators'])}")
        logger.info(f"  Security findings: {len(self.analysis['security_findings'])}")
        
        return self.analysis
    
    def generate_report(self, output_file=None):
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"pcap_analysis_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.analysis, f, indent=2, default=str)
        
        logger.info(f"Report saved to: {output_file}")
        return output_file
    
    def print_summary(self):
        print("\n" + "=" * 60)
        print("PCAP ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"File: {self.analysis['file']}")
        print(f"Total Packets: {self.analysis['total_packets']}")
        print()
        
        print("Protocol Breakdown:")
        for proto, count in self.analysis["protocol_breakdown"].items():
            print(f"  {proto}: {count} packets")
        print()
        
        if self.analysis["5g_components_detected"]:
            print("5G Components Detected:")
            for comp in self.analysis["5g_components_detected"]:
                print(f"  {comp['type']}: {comp['ip']}")
            print()
        
        if self.analysis["attack_indicators"]:
            print(f"⚠️  ATTACK INDICATORS FOUND: {len(self.analysis['attack_indicators'])}")
            for attack in self.analysis["attack_indicators"][:5]:
                print(f"  Packet #{attack['packet']}: {attack['type']} ({attack['src']} -> {attack['dst']})")
            print()
        
        if self.analysis["security_findings"]:
            print("🚨 SECURITY FINDINGS:")
            for finding in self.analysis["security_findings"]:
                print(f"  [{finding['severity']}] {finding['type']}")
                print(f"    {finding['description']}")
            print()
        
        print("=" * 60)

def analyze_live_capture(interface, duration=30, output_file=None):
    from scapy.all import sniff
    
    logger.info(f"Starting live capture on {interface} for {duration}s...")
    
    packets = sniff(iface=interface, timeout=duration)
    
    if output_file:
        wrpcap(output_file, packets)
        logger.info(f"Saved {len(packets)} packets to {output_file}")
    
    analyzer = PcapAnalyzer()
    analyzer.packets = packets
    analyzer.analysis["file"] = f"live_capture_{interface}"
    analyzer.analysis["total_packets"] = len(packets)
    
    return analyzer.run_full_analysis()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py <pcap_file>")
        print("       python pcap_analyzer.py --live <interface> [duration]")
        sys.exit(1)
    
    if sys.argv[1] == "--live":
        iface = sys.argv[2] if len(sys.argv) > 2 else "eth0"
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 30
        result = analyze_live_capture(iface, duration)
    else:
        analyzer = PcapAnalyzer(sys.argv[1])
        if analyzer.load_pcap():
            analyzer.run_full_analysis()
            analyzer.print_summary()
            analyzer.generate_report()

