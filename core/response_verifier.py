#!/usr/bin/env python3
import logging
import time
from typing import Dict, Any, Optional
from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.contrib.gtp import GTPHeader

logger = logging.getLogger(__name__)
 
class ResponseVerifier:
    def __init__(self, timeout=5.0):
        self.timeout = timeout
        self.captured_responses = []
    
    def verify_gtp_response(self, packet, expected_teid: Optional[int] = None, 
                            expected_type: Optional[int] = None,
                            expected_src: Optional[str] = None) -> Dict[str, Any]:
        if not packet:
            return {"success": False, "reason": "no_response"}
        
        result: Dict[str, Any] = {
            "success": False,
            "has_ip": False,
            "has_udp": False,
            "has_gtp": False,
            "teid_match": False,
            "type_match": False,
            "src_match": False,
            "gtp_type": None,
            "teid": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None
        }
        
        if packet.haslayer(IP):
            result["has_ip"] = True
            result["src_ip"] = packet[IP].src
            result["dst_ip"] = packet[IP].dst
            
            if expected_src and packet[IP].src == expected_src:
                result["src_match"] = True
        
        if packet.haslayer(UDP):
            result["has_udp"] = True
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport
        
        if packet.haslayer(GTPHeader):
            result["has_gtp"] = True
            gtp = packet[GTPHeader]
            result["gtp_type"] = gtp.gtp_type
            result["teid"] = gtp.teid
            
            if expected_teid is not None and gtp.teid == expected_teid:
                result["teid_match"] = True
            
            if expected_type is not None and gtp.gtp_type == expected_type:
                result["type_match"] = True
                result["success"] = True
            
            if expected_type is None:
                if gtp.gtp_type in [2, 26, 255]:
                    result["success"] = True
        
        return result
    
    def verify_pfcp_response(self, packet, expected_seid: Optional[int] = None,
                             expected_src: Optional[str] = None) -> Dict[str, Any]:
        if not packet:
            return {"success": False, "reason": "no_response"}
        
        result: Dict[str, Any] = {
            "success": False,
            "has_ip": False,
            "has_udp": False,
            "src_ip": None,
            "dst_ip": None,
            "msg_type": None,
            "seid": None,
            "seid_match": False,
            "src_match": False
        }
        
        if packet.haslayer(IP):
            result["has_ip"] = True
            result["src_ip"] = packet[IP].src
            result["dst_ip"] = packet[IP].dst
            
            if expected_src and packet[IP].src == expected_src:
                result["src_match"] = True
        
        if packet.haslayer(UDP):
            result["has_udp"] = True
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport
        
        if not packet.haslayer(Raw):
            result["reason"] = "no_payload"
            return result
        
        try:
            payload = bytes(packet[Raw])
            if len(payload) < 4:
                result["reason"] = "invalid_length"
                return result
            
            version = (payload[0] >> 5) & 0x07
            msg_type = payload[1]
            is_response = (msg_type & 0x01) == 0
            
            result["version"] = version
            result["msg_type"] = msg_type
            result["is_response"] = is_response
            result["length"] = len(payload)
            
            if len(payload) >= 12 and (payload[0] & 0x01):
                seid = int.from_bytes(payload[4:12], 'big')
                result["seid"] = seid
                if expected_seid is not None and seid == expected_seid:
                    result["seid_match"] = True
            
            valid_response_types = [2, 6, 34, 36, 38, 52, 54]
            result["success"] = is_response and (msg_type in valid_response_types)
            
            return result
        except Exception as e:
            logger.debug(f"PFCP verification error: {e}")
            result["reason"] = str(e)
            return result
    
    def verify_ngap_response(self, packet, expected_src: Optional[str] = None) -> Dict[str, Any]:
        if not packet:
            return {"success": False, "reason": "no_response"}
        
        result: Dict[str, Any] = {
            "success": False,
            "has_ip": False,
            "has_sctp": False,
            "src_ip": None,
            "dst_ip": None,
            "pdu_type": None,
            "procedure_code": None,
            "src_match": False
        }
        
        if packet.haslayer(IP):
            result["has_ip"] = True
            result["src_ip"] = packet[IP].src
            result["dst_ip"] = packet[IP].dst
            
            if expected_src and packet[IP].src == expected_src:
                result["src_match"] = True
        
        if packet.haslayer(SCTP):
            result["has_sctp"] = True
            result["src_port"] = packet[SCTP].sport
            result["dst_port"] = packet[SCTP].dport
        
        if not packet.haslayer(Raw):
            result["reason"] = "no_payload"
            return result
        
        try:
            payload = bytes(packet[Raw])
            
            if len(payload) < 2:
                result["reason"] = "too_short"
                return result
            
            pdu_type = (payload[0] >> 5) & 0x07
            procedure_code = payload[1] if len(payload) > 1 else 0
            
            result["pdu_type"] = pdu_type
            result["procedure_code"] = procedure_code
            result["length"] = len(payload)
            
            setup_response_codes = [0x15, 0x0E, 0x00]
            result["is_setup_response"] = procedure_code == 0x15
            result["success"] = pdu_type == 1 or procedure_code in setup_response_codes
            
            return result
        except Exception as e:
            logger.debug(f"NGAP verification error: {e}")
            result["reason"] = str(e)
            return result
    
    def wait_for_response(self, sniff_func, response_handler, timeout=None):
        timeout = timeout or self.timeout
        start_time = time.time()
        responses = []
        
        def capture_handler(pkt):
            if time.time() - start_time > timeout:
                return False
            
            result = response_handler(pkt)
            if result and result.get("success"):
                responses.append({"packet": pkt, "verification": result})
                return True
            
            return False
        
        try:
            sniff_func(capture_handler, timeout=timeout)
        except Exception as e:
            logger.debug(f"Response capture error: {e}")
        
        return responses

