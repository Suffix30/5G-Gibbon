#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import socket
import struct
import logging
import time
import random
from typing import Optional, Dict, List, Any, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1, sniff
    from scapy.config import conf
    from scapy.layers.sctp import SCTP, SCTPChunkData
    from scapy.contrib.sctp import (
        SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieEcho, 
        SCTPChunkCookieAck, SCTPChunkHeartbeat, 
        SCTPChunkHeartbeatAck, SCTPChunkAbort, SCTPChunkShutdown
    )

try:
    from scapy.layers.inet import IP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1, sniff
    from scapy.config import conf
    from scapy.layers.sctp import SCTP, SCTPChunkData
    from scapy.contrib.sctp import (
        SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieEcho, 
        SCTPChunkCookieAck, SCTPChunkHeartbeat, 
        SCTPChunkHeartbeatAck, SCTPChunkAbort, SCTPChunkShutdown
    )
    SCAPY_SCTP_AVAILABLE = True
except ImportError:
    SCAPY_SCTP_AVAILABLE = False
    logger.warning("Scapy SCTP not available")

class SCTPChunkType(IntEnum):
    DATA = 0
    INIT = 1
    INIT_ACK = 2
    SACK = 3
    HEARTBEAT = 4
    HEARTBEAT_ACK = 5
    ABORT = 6
    SHUTDOWN = 7
    SHUTDOWN_ACK = 8
    ERROR = 9
    COOKIE_ECHO = 10
    COOKIE_ACK = 11
    SHUTDOWN_COMPLETE = 14
    FORWARD_TSN = 192

class NGAPProcedure(IntEnum):
    AMF_CONFIGURATION_UPDATE = 0
    RAN_CONFIGURATION_UPDATE = 35
    NG_SETUP = 21
    INITIAL_UE_MESSAGE = 15
    INITIAL_CONTEXT_SETUP = 14
    UE_CONTEXT_RELEASE = 42
    HANDOVER_PREPARATION = 12
    PAGING = 34
    PDU_SESSION_RESOURCE_SETUP = 29

@dataclass
class SCTPAssociation:
    local_port: int
    remote_port: int
    local_tag: int
    remote_tag: int
    local_tsn: int
    remote_tsn: int
    state: str = "CLOSED"
    cookie: bytes = b""
    streams_in: int = 2
    streams_out: int = 2

@dataclass
class SCTPChunk:
    chunk_type: int
    flags: int = 0
    length: int = 0
    data: bytes = b""
    
    def to_bytes(self) -> bytes:
        chunk_len = 4 + len(self.data)
        padding = (4 - (chunk_len % 4)) % 4
        
        header = struct.pack(">BBH", self.chunk_type, self.flags, chunk_len)
        return header + self.data + (b"\x00" * padding)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['SCTPChunk']:
        if len(data) < 4:
            return None
        
        chunk_type, flags, length = struct.unpack(">BBH", data[:4])
        chunk_data = data[4:length] if length > 4 else b""
        
        return cls(chunk_type=chunk_type, flags=flags, length=length, data=chunk_data)

@dataclass
class SCTPPacket:
    src_port: int
    dst_port: int
    verification_tag: int
    checksum: int = 0
    chunks: List[SCTPChunk] = field(default_factory=list)
    
    def to_bytes(self) -> bytes:
        chunks_data = b"".join(chunk.to_bytes() for chunk in self.chunks)
        
        header = struct.pack(">HHII",
            self.src_port,
            self.dst_port,
            self.verification_tag,
            0
        )
        
        packet = header + chunks_data
        
        checksum = self._calculate_crc32c(packet)
        packet = packet[:8] + struct.pack("<I", checksum) + packet[12:]
        
        return packet
    
    @staticmethod
    def _calculate_crc32c(data: bytes) -> int:
        try:
            import crc32c
            return crc32c.crc32c(data)
        except ImportError:
            crc = 0xFFFFFFFF
            poly = 0x82F63B78
            
            for byte in data:
                crc ^= byte
                for _ in range(8):
                    if crc & 1:
                        crc = (crc >> 1) ^ poly
                    else:
                        crc >>= 1
            
            return crc ^ 0xFFFFFFFF
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['SCTPPacket']:
        if len(data) < 12:
            return None
        
        src_port, dst_port, vtag, checksum = struct.unpack(">HHII", data[:12])
        
        chunks = []
        offset = 12
        while offset < len(data):
            chunk = SCTPChunk.from_bytes(data[offset:])
            if chunk:
                chunks.append(chunk)
                chunk_len = chunk.length
                padding = (4 - (chunk_len % 4)) % 4
                offset += chunk_len + padding
            else:
                break
        
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            verification_tag=vtag,
            checksum=checksum,
            chunks=chunks
        )

class EnhancedSCTPClient:
    def __init__(
        self,
        local_port: int = 0,
        timeout: float = 5.0
    ):
        self.local_port = local_port or random.randint(49152, 65535)
        self.timeout = timeout
        self.association: Optional[SCTPAssociation] = None
        self._socket: Optional[socket.socket] = None
        self._raw_socket = False
    
    def _create_init_chunk(self, init_tag: int, a_rwnd: int = 65535, streams_out: int = 2, streams_in: int = 2) -> SCTPChunk:
        data = struct.pack(">IIHHI",
            init_tag,
            a_rwnd,
            streams_out,
            streams_in,
            random.randint(0, 0xFFFFFFFF)
        )
        return SCTPChunk(chunk_type=SCTPChunkType.INIT, data=data)
    
    def _create_cookie_echo_chunk(self, cookie: bytes) -> SCTPChunk:
        return SCTPChunk(chunk_type=SCTPChunkType.COOKIE_ECHO, data=cookie)
    
    def _create_data_chunk(
        self,
        tsn: int,
        stream_id: int,
        stream_seq: int,
        ppid: int,
        payload: bytes,
        flags: int = 0x03
    ) -> SCTPChunk:
        data = struct.pack(">IHHIH",
            tsn,
            stream_id,
            stream_seq,
            ppid,
            0
        )[:12] + struct.pack(">I", ppid) + payload
        
        data = struct.pack(">I", tsn) + struct.pack(">H", stream_id) + struct.pack(">H", stream_seq) + struct.pack(">I", ppid) + payload
        
        return SCTPChunk(chunk_type=SCTPChunkType.DATA, flags=flags, data=data)
    
    def _create_heartbeat_chunk(self) -> SCTPChunk:
        heartbeat_info = struct.pack(">HHQ",
            1,
            12,
            int(time.time() * 1000)
        )
        return SCTPChunk(chunk_type=SCTPChunkType.HEARTBEAT, data=heartbeat_info)
    
    def _parse_init_ack(self, chunk: SCTPChunk) -> Tuple[int, int, bytes]:
        if len(chunk.data) < 16:
            return 0, 0, b""
        
        init_tag = struct.unpack(">I", chunk.data[:4])[0]
        a_rwnd = struct.unpack(">I", chunk.data[4:8])[0]
        
        cookie = b""
        offset = 16
        while offset < len(chunk.data):
            if offset + 4 > len(chunk.data):
                break
            
            param_type, param_len = struct.unpack(">HH", chunk.data[offset:offset+4])
            
            if param_type == 7:
                cookie = chunk.data[offset+4:offset+param_len]
                break
            
            offset += param_len
            offset += (4 - (param_len % 4)) % 4
        
        return init_tag, a_rwnd, cookie
    
    def connect_scapy(self, remote_ip: str, remote_port: int) -> bool:
        if not SCAPY_SCTP_AVAILABLE:
            logger.error("Scapy SCTP not available")
            return False
        
        local_tag = random.randint(1, 0xFFFFFFFF)
        local_tsn = random.randint(0, 0xFFFFFFFF)
        
        logger.info(f"SCTP INIT to {remote_ip}:{remote_port}")
        
        try:
            conf.verb = 0
            
            init_pkt = IP(dst=remote_ip) / SCTP(sport=self.local_port, dport=remote_port) / SCTPChunkInit(
                init_tag=local_tag,
                a_rwnd=65535,
                n_out_streams=2,
                n_in_streams=2,
                init_tsn=local_tsn
            )
            
            resp = sr1(init_pkt, timeout=self.timeout, verbose=0)
            
            if not resp or not resp.haslayer(SCTP):
                logger.warning("No INIT-ACK received")
                return False
            
            if resp.haslayer(SCTPChunkInitAck):
                init_ack = resp[SCTPChunkInitAck]
                remote_tag = init_ack.init_tag
                
                cookie = b""
                if hasattr(init_ack, 'params'):
                    for param in init_ack.params:
                        if hasattr(param, 'type') and param.type == 7:
                            cookie = bytes(param.cookie) if hasattr(param, 'cookie') else b""
                            break
                
                if not cookie:
                    cookie = bytes(resp[SCTP].payload)[16:] if len(bytes(resp[SCTP].payload)) > 16 else b""
                
                logger.info(f"INIT-ACK received, sending COOKIE-ECHO")
                
                cookie_pkt = IP(dst=remote_ip) / SCTP(sport=self.local_port, dport=remote_port, tag=remote_tag) / SCTPChunkCookieEcho(cookie=cookie)
                
                resp2 = sr1(cookie_pkt, timeout=self.timeout, verbose=0)
                
                if resp2 and resp2.haslayer(SCTPChunkCookieAck):
                    logger.info("SCTP association established!")
                    
                    self.association = SCTPAssociation(
                        local_port=self.local_port,
                        remote_port=remote_port,
                        local_tag=local_tag,
                        remote_tag=remote_tag,
                        local_tsn=local_tsn,
                        remote_tsn=init_ack.init_tsn if hasattr(init_ack, 'init_tsn') else 0,
                        state="ESTABLISHED",
                        cookie=cookie
                    )
                    return True
                else:
                    logger.warning("No COOKIE-ACK received")
            else:
                logger.warning("Unexpected response (no INIT-ACK)")
            
        except Exception as e:
            logger.error(f"SCTP connect failed: {e}")
        
        return False
    
    def send_data(
        self,
        remote_ip: str,
        payload: bytes,
        ppid: int = 60,
        stream_id: int = 0
    ) -> bool:
        if not self.association or self.association.state != "ESTABLISHED":
            logger.error("No established association")
            return False
        
        if not SCAPY_SCTP_AVAILABLE:
            return False
        
        try:
            data_pkt = IP(dst=remote_ip) / SCTP(
                sport=self.association.local_port,
                dport=self.association.remote_port,
                tag=self.association.remote_tag
            ) / SCTPChunkData(
                tsn=self.association.local_tsn,
                stream_id=stream_id,
                stream_seq=0,
                proto_id=ppid,
                data=payload,
                flags=0x03
            )
            
            send(data_pkt, verbose=0)
            self.association.local_tsn += 1
            
            logger.debug(f"Sent DATA chunk, TSN={self.association.local_tsn - 1}")
            return True
            
        except Exception as e:
            logger.error(f"Send DATA failed: {e}")
            return False
    
    def send_ngap(
        self,
        remote_ip: str,
        ngap_pdu: bytes,
        stream_id: int = 0
    ) -> bool:
        return self.send_data(remote_ip, ngap_pdu, ppid=60, stream_id=stream_id)
    
    def heartbeat(self, remote_ip: str) -> bool:
        if not self.association or not SCAPY_SCTP_AVAILABLE:
            return False
        
        try:
            hb_info = struct.pack(">HH", 1, 8) + struct.pack(">Q", int(time.time() * 1000))
            
            hb_pkt = IP(dst=remote_ip) / SCTP(
                sport=self.association.local_port,
                dport=self.association.remote_port,
                tag=self.association.remote_tag
            ) / SCTPChunkHeartbeat(heartbeat_info=hb_info)
            
            resp = sr1(hb_pkt, timeout=self.timeout, verbose=0)
            
            if resp and resp.haslayer(SCTPChunkHeartbeatAck):
                logger.debug("Heartbeat ACK received")
                return True
            
        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")
        
        return False
    
    def close(self, remote_ip: str):
        if not self.association or not SCAPY_SCTP_AVAILABLE:
            return
        
        try:
            shutdown_pkt = IP(dst=remote_ip) / SCTP(
                sport=self.association.local_port,
                dport=self.association.remote_port,
                tag=self.association.remote_tag
            ) / SCTPChunkShutdown(cum_tsn_ack=self.association.remote_tsn)
            
            send(shutdown_pkt, verbose=0)
            self.association.state = "SHUTDOWN-SENT"
            
            logger.info("SCTP SHUTDOWN sent")
            
        except Exception as e:
            logger.error(f"SCTP shutdown failed: {e}")
        
        self.association = None

class NGAPClient:
    def __init__(self, amf_ip: str, amf_port: int = 38412, timeout: float = 5.0):
        self.amf_ip = amf_ip
        self.amf_port = amf_port
        self.sctp = EnhancedSCTPClient(timeout=timeout)
        self._connected = False
    
    def connect(self) -> bool:
        self._connected = self.sctp.connect_scapy(self.amf_ip, self.amf_port)
        return self._connected
    
    def close(self):
        if self._connected:
            self.sctp.close(self.amf_ip)
            self._connected = False
    
    def _create_ng_setup_request(
        self,
        global_ran_node_id: bytes,
        ran_node_name: str = "gNB-Test",
        supported_ta_list: Optional[List[Dict]] = None
    ) -> bytes:
        if supported_ta_list is None:
            supported_ta_list = [{
                "tac": bytes([0x00, 0x00, 0x01]),
                "plmn": bytes([0x00, 0xF1, 0x10])
            }]
        
        pdu = bytes([
            0x00,
            NGAPProcedure.NG_SETUP,
            0x00,
            0x00,
        ])
        
        return pdu + global_ran_node_id
    
    def ng_setup(
        self,
        gnb_id: int = 1,
        mcc: str = "001",
        mnc: str = "01",
        tac: int = 1
    ) -> Optional[bytes]:
        if not self._connected:
            if not self.connect():
                return None
        
        global_ran_id = struct.pack(">I", gnb_id)[:3]
        
        plmn = bytes([
            (int(mcc[1]) << 4) | int(mcc[0]),
            (int(mnc[0]) << 4) | int(mcc[2]),
            (int(mnc[1]) << 4) | (int(mnc[2]) if len(mnc) > 2 else 0xF)
        ])
        
        ng_setup_pdu = self._create_ng_setup_request(
            global_ran_node_id=plmn + global_ran_id
        )
        
        if self.sctp.send_ngap(self.amf_ip, ng_setup_pdu):
            logger.info("NG Setup Request sent")
            return ng_setup_pdu
        
        return None
    
    def send_initial_ue_message(
        self,
        nas_pdu: bytes,
        ran_ue_ngap_id: int = 1,
        tai: Optional[bytes] = None,
        user_location: Optional[bytes] = None
    ) -> bool:
        if not self._connected:
            return False
        
        pdu = bytes([
            0x00,
            NGAPProcedure.INITIAL_UE_MESSAGE,
            0x00,
            0x00
        ]) + struct.pack(">I", ran_ue_ngap_id) + nas_pdu
        
        return self.sctp.send_ngap(self.amf_ip, pdu)
    
    def heartbeat(self) -> bool:
        return self.sctp.heartbeat(self.amf_ip)

def test_sctp_connection(amf_ip: str, amf_port: int = 38412) -> Dict[str, Any]:
    result = {
        "target": f"{amf_ip}:{amf_port}",
        "connected": False,
        "ng_setup_sent": False,
        "response": None
    }
    
    client = NGAPClient(amf_ip, amf_port)
    
    if client.connect():
        result["connected"] = True
        logger.info("SCTP association established")
        
        ng_setup = client.ng_setup()
        if ng_setup:
            result["ng_setup_sent"] = True
            result["pdu"] = ng_setup.hex()
        
        client.close()
    
    return result

def send_abort(target_ip: str, target_port: int = 38412, source_port: Optional[int] = None) -> bool:
    if not SCAPY_SCTP_AVAILABLE:
        return False
    
    src_port = source_port or random.randint(40000, 60000)
    conf.verb = 0
    
    abort_pkt = IP(dst=target_ip) / SCTP(sport=src_port, dport=target_port) / SCTPChunkAbort()
    send(abort_pkt, verbose=0)
    logger.info(f"Sent SCTP ABORT to {target_ip}:{target_port}")
    return True


def send_raw_sctp_data(target_ip: str, target_port: int, payload: bytes, 
                       tsn: int = 1, stream_id: int = 0) -> bool:
    if not SCAPY_SCTP_AVAILABLE:
        return False
    
    conf.verb = 0
    data_pkt = IP(dst=target_ip) / SCTP(dport=target_port) / SCTPChunkData(
        tsn=tsn, stream_id=stream_id, stream_seq=0
    ) / Raw(load=payload)
    
    send(data_pkt, verbose=0)
    logger.info(f"Sent raw SCTP DATA ({len(payload)} bytes) to {target_ip}:{target_port}")
    return True


def capture_sctp_traffic(interface: str, target_ip: Optional[str] = None, count: int = 10, timeout: int = 30) -> List[Dict]:
    if not SCAPY_SCTP_AVAILABLE:
        return []
    
    filter_expr = "sctp"
    if target_ip:
        filter_expr = f"sctp and host {target_ip}"
    
    packets = sniff(iface=interface, filter=filter_expr, count=count, timeout=timeout)
    
    results = []
    for pkt in packets:
        if SCTP in pkt:
            results.append({
                "src": pkt[IP].src if IP in pkt else "unknown",
                "dst": pkt[IP].dst if IP in pkt else "unknown",
                "sport": pkt[SCTP].sport,
                "dport": pkt[SCTP].dport,
                "raw": bytes(pkt[SCTP].payload).hex() if pkt[SCTP].payload else ""
            })
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced SCTP/NGAP Client")
    parser.add_argument("--amf", "-a", required=True, help="AMF IP address")
    parser.add_argument("--port", "-p", type=int, default=38412)
    parser.add_argument("--test", "-t", action="store_true", help="Test connection")
    parser.add_argument("--setup", "-s", action="store_true", help="Send NG Setup")
    parser.add_argument("--abort", action="store_true", help="Send ABORT")
    parser.add_argument("--capture", action="store_true", help="Capture SCTP traffic")
    parser.add_argument("--interface", "-i", help="Interface for capture")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    if args.test:
        result = test_sctp_connection(args.amf, args.port)
        print(f"\nResult: {result}")
    elif args.setup:
        client = NGAPClient(args.amf, args.port)
        if client.connect():
            client.ng_setup()
            time.sleep(2)
            client.close()
    elif args.abort:
        send_abort(args.amf, args.port)
    elif args.capture and args.interface:
        packets = capture_sctp_traffic(args.interface, args.amf, count=10)
        for pkt in packets:
            print(pkt)
    else:
        sctp = EnhancedSCTPClient()
        if sctp.connect_scapy(args.amf, args.port):
            print("Connected!")
            sctp.heartbeat(args.amf)
            sctp.close(args.amf)

