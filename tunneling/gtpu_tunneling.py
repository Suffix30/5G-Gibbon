#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.contrib.gtp import GTPHeader
import logging
from core.config import TEST_CONFIG, validate_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def craft_gtpu_tunnel(outer_src_ip, outer_dst_ip, outer_teid, inner_src_ip, inner_dst_ip, inner_teid, inner_payload):
    try:
        inner_gtpu = GTPHeader(teid=inner_teid, gtp_type=255) / IP(src=inner_src_ip, dst=inner_dst_ip) / UDP(sport=2152, dport=2152) / Raw(load=inner_payload)
        outer_packet = IP(src=outer_src_ip, dst=outer_dst_ip) / UDP(sport=2152, dport=2152) / GTPHeader(teid=outer_teid, gtp_type=255) / inner_gtpu
        return outer_packet
    except Exception as e:
        logger.error(f"Failed to craft GTP-U tunnel: {e}")
        return None

def send_tunnel(outer_src, outer_dst, outer_teid, inner_src, inner_dst, inner_teid, payload, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    try:
        tunnel_pkt = craft_gtpu_tunnel(outer_src, outer_dst, outer_teid, inner_src, inner_dst, inner_teid, payload)
        if tunnel_pkt:
            send(tunnel_pkt, iface=iface, verbose=0)
            logger.info(f"Sent GTP-U tunnel: TEID {outer_teid} -> {inner_teid}")
            return True
        else:
            logger.error("Failed to craft tunnel packet")
            return False
    except Exception as e:
        logger.error(f"Failed to send tunnel: {e}")
        return False

if __name__ == "__main__":
    logger.info("Starting GTP-U tunneling test")
    payload = b'\x00' * 100
    send_tunnel(
        TEST_CONFIG["outer_src"],
        TEST_CONFIG["upf_ip"],
        TEST_CONFIG["outer_teid"],
        TEST_CONFIG["inner_src"],
        TEST_CONFIG["amf_ip"],
        TEST_CONFIG["inner_teid"],
        payload
    )

