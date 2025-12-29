#!/usr/bin/env python3 
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.sendrecv import sniff
from scapy.utils import wrpcap, rdpcap
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.contrib.gtp import GTPHeader
import logging
from datetime import datetime
from core.config import TEST_CONFIG

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def capture_gtp_traffic(duration=30, output_file=None, iface=None, filter_str="udp port 2152"):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"gtp_capture_{timestamp}.pcap"
    
    logger.info(f"Starting GTP-U packet capture for {duration}s")
    logger.info(f"Interface: {iface}")
    logger.info(f"Filter: {filter_str}")
    logger.info(f"Output: {output_file}")
    
    try:
        packets = sniff(iface=iface, filter=filter_str, timeout=duration, store=True)
        
        if packets:
            wrpcap(output_file, packets)
            logger.info(f"✓ Captured {len(packets)} packets")
            logger.info(f"✓ Saved to {output_file}")
            return output_file, packets
        else:
            logger.warning("No packets captured")
            return None, []
    except Exception as e:
        logger.error(f"Capture failed: {e}")
        return None, []

def analyze_gtp_packets(pcap_file):
    logger.info(f"Analyzing {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
        
        stats = {
            "total_packets": len(packets),
            "gtp_packets": 0,
            "nested_gtp": 0,
            "unique_teids": set(),
            "unique_ips": set(),
            "gtp_types": {},
            "packet_sizes": [],
            "tunneled_protocols": {}
        }
        
        for pkt in packets:
            if pkt.haslayer(GTPHeader):
                stats["gtp_packets"] += 1
                gtp = pkt[GTPHeader]
                stats["unique_teids"].add(gtp.teid)
                
                gtp_type = gtp.gtp_type
                stats["gtp_types"][gtp_type] = stats["gtp_types"].get(gtp_type, 0) + 1
                
                stats["packet_sizes"].append(len(pkt))
                
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    if b'GTP' in payload or (len(payload) > 8 and payload[0] in [0x30, 0x32, 0x34]):
                        stats["nested_gtp"] += 1
                
                if pkt.haslayer(IP):
                    inner_ip = pkt[IP]
                    if inner_ip != pkt.getlayer(IP, 1):
                        stats["unique_ips"].add(inner_ip.src)
                        stats["unique_ips"].add(inner_ip.dst)
                        
                        if inner_ip.proto == 1:
                            stats["tunneled_protocols"]["ICMP"] = stats["tunneled_protocols"].get("ICMP", 0) + 1
                        elif inner_ip.proto == 6:
                            stats["tunneled_protocols"]["TCP"] = stats["tunneled_protocols"].get("TCP", 0) + 1
                        elif inner_ip.proto == 17:
                            stats["tunneled_protocols"]["UDP"] = stats["tunneled_protocols"].get("UDP", 0) + 1
        
        logger.info("\n=== Capture Analysis ===")
        logger.info(f"Total packets: {stats['total_packets']}")
        logger.info(f"GTP packets: {stats['gtp_packets']}")
        logger.info(f"Nested GTP-U: {stats['nested_gtp']}")
        logger.info(f"Unique TEIDs: {len(stats['unique_teids'])}")
        logger.info(f"Unique IPs: {len(stats['unique_ips'])}")
        
        logger.info("\nGTP Message Types:")
        for gtp_type, count in sorted(stats["gtp_types"].items()):
            type_name = {1: "Echo Request", 2: "Echo Response", 26: "Error Indication", 255: "G-PDU"}.get(gtp_type, f"Type {gtp_type}")
            logger.info(f"  {type_name}: {count}")
        
        if stats["tunneled_protocols"]:
            logger.info("\nTunneled Protocols:")
            for proto, count in stats["tunneled_protocols"].items():
                logger.info(f"  {proto}: {count}")
        
        if stats["packet_sizes"]:
            avg_size = sum(stats["packet_sizes"]) / len(stats["packet_sizes"])
            logger.info(f"\nAverage packet size: {avg_size:.0f} bytes")
        
        return stats
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return None

def verify_tunnel_forwarding(pcap_file, expected_teid, expected_inner_ip):
    logger.info(f"Verifying tunnel forwarding for TEID {expected_teid}")
    
    try:
        packets = rdpcap(pcap_file)
        
        found_outer = False
        found_decapsulated = False
        
        for pkt in packets:
            if pkt.haslayer(GTPHeader):
                if pkt[GTPHeader].teid == expected_teid:
                    found_outer = True
                    logger.info(f"✓ Found outer tunnel with TEID {expected_teid}")
                    
                    if pkt.haslayer(IP):
                        layers = []
                        layer_num = 1
                        while True:
                            ip_layer = pkt.getlayer(IP, layer_num)
                            if ip_layer:
                                layers.append((ip_layer.src, ip_layer.dst))
                                layer_num += 1
                            else:
                                break
                        
                        if len(layers) > 1:
                            logger.info(f"  IP layers: {layers}")
                            if expected_inner_ip in [ip for pair in layers for ip in pair]:
                                found_decapsulated = True
                                logger.info(f"✓ Found inner IP {expected_inner_ip}")
        
        if found_outer and found_decapsulated:
            logger.info("✓✓ Tunnel forwarding VERIFIED")
            return True
        elif found_outer:
            logger.warning("⚠ Outer tunnel found but inner IP not verified")
            return False
        else:
            logger.warning("✗ Tunnel not found in capture")
            return False
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False

def live_gtp_monitor(duration=60, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    logger.info(f"Starting live GTP-U monitor for {duration}s")
    
    packet_count = 0
    teid_set = set()
    
    def packet_handler(pkt):
        nonlocal packet_count, teid_set
        packet_count += 1
        
        if pkt.haslayer(GTPHeader):
            teid = pkt[GTPHeader].teid
            gtp_type = pkt[GTPHeader].gtp_type
            teid_set.add(teid)
            
            type_name = {1: "EchoReq", 2: "EchoResp", 26: "Error", 255: "Data"}.get(gtp_type, f"Type{gtp_type}")
            
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                logger.info(f"[{packet_count}] {src} -> {dst} | TEID: {teid} | Type: {type_name}")
    
    try:
        sniff(iface=iface, filter="udp port 2152", prn=packet_handler, timeout=duration, store=0)
        
        logger.info(f"\n=== Monitor Summary ===")
        logger.info(f"Total packets: {packet_count}")
        logger.info(f"Unique TEIDs: {len(teid_set)}")
        logger.info(f"TEIDs seen: {sorted(list(teid_set))[:20]}")
    except Exception as e:
        logger.error(f"Monitor failed: {e}")

if __name__ == "__main__":
    logger.info("=== Packet Capture & Analysis Suite ===\n")
    
    logger.info("Test 1: Capture GTP traffic (10s)")
    pcap_file, packets = capture_gtp_traffic(duration=10)
    
    if pcap_file:
        logger.info("\nTest 2: Analyze captured traffic")
        analyze_gtp_packets(pcap_file)
        
        logger.info("\nTest 3: Verify tunnel forwarding")
        verify_tunnel_forwarding(pcap_file, TEST_CONFIG["outer_teid"], TEST_CONFIG["amf_ip"])

