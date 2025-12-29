#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import send
import struct
import logging
from core.config import TEST_CONFIG, validate_config
from protocol.protocol_layers import craft_ngap_setup_request

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SCTPChunk:
    CHUNK_DATA = 0
    CHUNK_INIT = 1
    CHUNK_INIT_ACK = 2
    CHUNK_SACK = 3
    CHUNK_HEARTBEAT = 4
    CHUNK_HEARTBEAT_ACK = 5
    CHUNK_ABORT = 6
    CHUNK_SHUTDOWN = 7
    CHUNK_SHUTDOWN_ACK = 8
    CHUNK_ERROR = 9
    CHUNK_COOKIE_ECHO = 10
    CHUNK_COOKIE_ACK = 11
    CHUNK_SHUTDOWN_COMPLETE = 14

def craft_sctp_header(src_port, dst_port, vtag, checksum=0):
    return struct.pack('!HHII', src_port, dst_port, vtag, checksum)

def craft_sctp_chunk(chunk_type, flags, data):
    length = len(data) + 4
    padding = (4 - (length % 4)) % 4
    chunk = struct.pack('!BBH', chunk_type, flags, length) + data + (b'\x00' * padding)
    return chunk

def craft_sctp_init(initiate_tag, a_rwnd=65535, num_outbound_streams=10, num_inbound_streams=65535, initial_tsn=1):
    init_data = struct.pack('!IIHHI', initiate_tag, a_rwnd, num_outbound_streams, num_inbound_streams, initial_tsn)
    return craft_sctp_chunk(SCTPChunk.CHUNK_INIT, 0, init_data)

def craft_sctp_data(tsn, stream_id, stream_seq, ppid, user_data, flags=0x03):
    data_header = struct.pack('!IHHI', tsn, stream_id, stream_seq, ppid)
    return craft_sctp_chunk(SCTPChunk.CHUNK_DATA, flags, data_header + user_data)

def calculate_sctp_checksum(sctp_packet):
    crc = 0xffffffff
    for byte in sctp_packet:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xedb88320
            else:
                crc >>= 1
    return (~crc) & 0xffffffff

def craft_proper_sctp_packet(src_ip, dst_ip, src_port, dst_port, vtag, chunks):
    sctp_header = craft_sctp_header(src_port, dst_port, vtag, 0)
    
    sctp_packet = sctp_header + b''.join(chunks)
    
    checksum = calculate_sctp_checksum(sctp_packet)
    sctp_packet = sctp_header[:8] + struct.pack('!I', checksum) + sctp_packet[12:]
    
    ip_packet = IP(src=src_ip, dst=dst_ip, proto=132)/Raw(load=sctp_packet)
    
    return ip_packet

def send_sctp_init(src_ip, dst_ip, src_port=38412, dst_port=38412, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Sending SCTP INIT: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    try:
        initiate_tag = 0x12345678
        init_chunk = craft_sctp_init(initiate_tag)
        
        pkt = craft_proper_sctp_packet(src_ip, dst_ip, src_port, dst_port, 0, [init_chunk])
        
        send(pkt, iface=iface, verbose=0)
        logger.info("✓ SCTP INIT sent")
        return True
    except Exception as e:
        logger.error(f"Failed to send SCTP INIT: {e}")
        return False

def send_ngap_over_proper_sctp(src_ip, dst_ip, ngap_payload, vtag=0x12345678, tsn=1, src_port=38412, dst_port=38412, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"Sending NGAP over proper SCTP")
    
    try:
        ppid = 60
        data_chunk = craft_sctp_data(tsn, stream_id=0, stream_seq=0, ppid=ppid, user_data=ngap_payload)
        
        pkt = craft_proper_sctp_packet(src_ip, dst_ip, src_port, dst_port, vtag, [data_chunk])
        
        send(pkt, iface=iface, verbose=0)
        logger.info("✓ NGAP over SCTP sent with proper chunking")
        return True
    except Exception as e:
        logger.error(f"Failed to send NGAP over SCTP: {e}")
        return False

def sctp_association_setup(src_ip, dst_ip, src_port=38412, dst_port=38412, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info("=== SCTP Association Setup ===")
    
    try:
        logger.info("Step 1: Sending INIT")
        send_sctp_init(src_ip, dst_ip, src_port, dst_port, iface)
        
        logger.info("Step 2: Waiting for INIT-ACK (not implemented - one-way test)")
        
        logger.info("Step 3: Would send COOKIE-ECHO (skipped)")
        
        logger.info("✓ SCTP handshake initiated (one-way)")
        return True
    except Exception as e:
        logger.error(f"SCTP association setup failed: {e}")
        return False

if __name__ == "__main__":
    src_ip = TEST_CONFIG["outer_src"]
    dst_ip = TEST_CONFIG["amf_ip"]
    
    logger.info("Test 1: SCTP INIT")
    send_sctp_init(src_ip, dst_ip)
    
    logger.info("\nTest 2: NGAP over proper SCTP")
    ngap_payload = craft_ngap_setup_request()
    send_ngap_over_proper_sctp(src_ip, dst_ip, ngap_payload)
    
    logger.info("\nTest 3: Full SCTP Association (one-way)")
    sctp_association_setup(src_ip, dst_ip)

