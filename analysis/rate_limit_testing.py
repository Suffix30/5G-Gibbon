#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from scapy.contrib.gtp import GTPHeader
import time
import logging
from core.config import TEST_CONFIG, validate_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def high_speed_enumeration(upf_ip, start_teid, end_teid, packets_per_second=1000, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"High-speed TEID enumeration at {packets_per_second} pps")
    logger.info(f"Range: {start_teid}-{end_teid}")
    
    packets_sent = 0
    responses_received = 0
    active_teids = []
    start_time = time.time()
    
    delay = 1.0 / packets_per_second
    
    try:
        for teid in range(start_teid, end_teid):
            pkt = IP(dst=upf_ip)/UDP(dport=2152)/GTPHeader(teid=teid, gtp_type=1)
            resp = sr1(pkt, timeout=0.01, iface=iface, verbose=0)
            packets_sent += 1
            
            if resp:
                responses_received += 1
                if resp.haslayer(GTPHeader):
                    gtp_type = resp[GTPHeader].gtp_type
                    if gtp_type == 2:
                        active_teids.append(teid)
            
            time.sleep(delay)
            
            if packets_sent % 100 == 0:
                elapsed = time.time() - start_time
                actual_rate = packets_sent / elapsed
                response_rate = (responses_received / packets_sent * 100)
                logger.debug(f"Sent {packets_sent}, Rate: {actual_rate:.0f} pps, Responses: {response_rate:.1f}%")
        
        elapsed = time.time() - start_time
        actual_rate = packets_sent / elapsed
        response_rate = (responses_received / packets_sent * 100) if packets_sent > 0 else 0
        
        logger.info(f"✓ Completed: {packets_sent} packets in {elapsed:.2f}s")
        logger.info(f"Actual rate: {actual_rate:.0f} pps")
        logger.info(f"Response rate: {response_rate:.1f}% ({responses_received}/{packets_sent})")
        logger.info(f"Active TEIDs found: {len(active_teids)}")
        
        return {
            "packets_sent": packets_sent,
            "responses_received": responses_received,
            "response_rate": response_rate,
            "active_teids": active_teids,
            "elapsed_time": elapsed,
            "actual_rate": actual_rate
        }
    except Exception as e:
        logger.error(f"High-speed enumeration failed: {e}")
        return None

def detect_rate_limiting(upf_ip, test_rates=[10, 50, 100, 500, 1000], test_duration=5, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info("=== Rate Limit Detection ===")
    
    results = {}
    
    for rate in test_rates:
        logger.info(f"\nTesting at {rate} pps for {test_duration}s...")
        
        packets_sent = 0
        responses_received = 0
        errors_detected = 0
        
        start_time = time.time()
        delay = 1.0 / rate
        teid_base = 10000
        
        try:
            while time.time() - start_time < test_duration:
                teid = teid_base + packets_sent
                pkt = IP(dst=upf_ip)/UDP(dport=2152)/GTPHeader(teid=teid, gtp_type=1)
                
                resp = sr1(pkt, timeout=0.01, iface=iface, verbose=0)
                
                packets_sent += 1
                
                if resp:
                    responses_received += 1
                    if resp.haslayer(GTPHeader) and resp[GTPHeader].gtp_type == 26:
                        errors_detected += 1
                
                time.sleep(delay)
            
            elapsed = time.time() - start_time
            response_rate = (responses_received / packets_sent * 100) if packets_sent > 0 else 0
            
            results[rate] = {
                "packets_sent": packets_sent,
                "responses_received": responses_received,
                "response_rate": response_rate,
                "errors_detected": errors_detected,
                "elapsed": elapsed
            }
            
            logger.info(f"  Sent: {packets_sent}, Responses: {responses_received} ({response_rate:.1f}%)")
            
            if response_rate < 50 and rate > 100:
                logger.warning(f"  ⚠ Possible rate limiting detected at {rate} pps")
        
        except Exception as e:
            logger.error(f"Test failed at {rate} pps: {e}")
    
    logger.info("\n=== Rate Limit Analysis ===")
    for rate, data in sorted(results.items()):
        logger.info(f"{rate:4d} pps: {data['response_rate']:5.1f}% responses, {data['errors_detected']} errors")
    
    return results

def burst_attack_test(upf_ip, burst_size=100, burst_count=10, burst_delay=1.0, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"=== Burst Attack Test ===")
    logger.info(f"Bursts: {burst_count} x {burst_size} packets, {burst_delay}s delay")
    
    total_sent = 0
    total_responses = 0
    burst_results = []
    
    try:
        for burst_num in range(burst_count):
            logger.info(f"\nBurst {burst_num + 1}/{burst_count}")
            
            burst_start = time.time()
            burst_sent = 0
            burst_responses = 0
            
            for _ in range(burst_size):
                teid = 20000 + total_sent
                pkt = IP(dst=upf_ip)/UDP(dport=2152)/GTPHeader(teid=teid, gtp_type=1)
                resp = sr1(pkt, timeout=0.005, iface=iface, verbose=0)
                total_sent += 1
                burst_sent += 1
                
                if resp:
                    total_responses += 1
                    burst_responses += 1
            
            burst_elapsed = time.time() - burst_start
            burst_rate = burst_size / burst_elapsed if burst_elapsed > 0 else 0
            burst_response_rate = (burst_responses / burst_sent * 100) if burst_sent > 0 else 0
            
            burst_results.append({
                "burst_num": burst_num + 1,
                "sent": burst_sent,
                "responses": burst_responses,
                "response_rate": burst_response_rate,
                "duration": burst_elapsed,
                "rate": burst_rate
            })
            
            logger.info(f"  Sent {burst_size} in {burst_elapsed:.3f}s ({burst_rate:.0f} pps)")
            logger.info(f"  Responses: {burst_responses}/{burst_sent} ({burst_response_rate:.1f}%)")
            
            if burst_response_rate < 50:
                logger.warning(f"  ⚠ Low response rate - possible rate limiting!")
            
            time.sleep(burst_delay)
        
        overall_response_rate = (total_responses / total_sent * 100) if total_sent > 0 else 0
        logger.info(f"\n✓ Burst test complete: {total_sent} total packets")
        logger.info(f"Overall response rate: {overall_response_rate:.1f}%")
        
        return {
            "total_sent": total_sent,
            "total_responses": total_responses,
            "overall_response_rate": overall_response_rate,
            "bursts": burst_results
        }
    except Exception as e:
        logger.error(f"Burst test failed: {e}")
        return {"total_sent": total_sent, "total_responses": total_responses, "bursts": burst_results}

def sustained_load_test(upf_ip, target_rate=500, duration=30, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"=== Sustained Load Test ===")
    logger.info(f"Target: {target_rate} pps for {duration}s")
    
    packets_sent = 0
    responses_received = 0
    response_times = []
    start_time = time.time()
    delay = 1.0 / target_rate
    last_report_time = start_time
    
    try:
        while time.time() - start_time < duration:
            teid = 30000 + packets_sent
            pkt = IP(dst=upf_ip)/UDP(dport=2152)/GTPHeader(teid=teid, gtp_type=1)
            
            send_time = time.time()
            resp = sr1(pkt, timeout=0.01, iface=iface, verbose=0)
            packets_sent += 1
            
            if resp:
                responses_received += 1
                response_time = (time.time() - send_time) * 1000
                response_times.append(response_time)
            
            time.sleep(delay)
            
            current_time = time.time()
            if current_time - last_report_time >= 5:
                elapsed = current_time - start_time
                actual_rate = packets_sent / elapsed
                response_rate = (responses_received / packets_sent * 100) if packets_sent > 0 else 0
                avg_latency = sum(response_times[-100:]) / len(response_times[-100:]) if response_times else 0
                logger.info(f"Progress: {packets_sent} pkts, {actual_rate:.0f} pps, {response_rate:.1f}% resp, {avg_latency:.1f}ms avg")
                last_report_time = current_time
        
        elapsed = time.time() - start_time
        actual_rate = packets_sent / elapsed
        response_rate = (responses_received / packets_sent * 100) if packets_sent > 0 else 0
        avg_latency = sum(response_times) / len(response_times) if response_times else 0
        min_latency = min(response_times) if response_times else 0
        max_latency = max(response_times) if response_times else 0
        
        logger.info(f"\n✓ Sustained load complete: {packets_sent} packets")
        logger.info(f"Average rate: {actual_rate:.0f} pps")
        logger.info(f"Response rate: {response_rate:.1f}% ({responses_received}/{packets_sent})")
        logger.info(f"Latency: avg={avg_latency:.1f}ms, min={min_latency:.1f}ms, max={max_latency:.1f}ms")
        
        return {
            "packets_sent": packets_sent,
            "responses_received": responses_received,
            "response_rate": response_rate,
            "duration": elapsed,
            "average_rate": actual_rate,
            "latency": {
                "avg": avg_latency,
                "min": min_latency,
                "max": max_latency
            }
        }
    except Exception as e:
        logger.error(f"Sustained load test failed: {e}")
        return None

if __name__ == "__main__":
    upf_ip = TEST_CONFIG["upf_ip"]
    
    logger.info("Test 1: Rate Limit Detection")
    detect_rate_limiting(upf_ip, test_rates=[10, 50, 100], test_duration=3)
    
    logger.info("\n\nTest 2: Burst Attack")
    burst_attack_test(upf_ip, burst_size=50, burst_count=3, burst_delay=1.0)
    
    logger.info("\n\nTest 3: High-Speed Enumeration")
    high_speed_enumeration(upf_ip, 0, 100, packets_per_second=100)

