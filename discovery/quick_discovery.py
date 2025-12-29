#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.layers.inet import IP, UDP, ICMP
from scapy.sendrecv import sr1
from scapy.contrib.gtp import GTPHeader
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def quick_scan_5g_network():
    logger.info("Quick 5G Network Discovery")
    logger.info("=" * 80)
    
    local_ip = socket.gethostbyname(socket.gethostname())
    logger.info(f"Your IP: {local_ip}")
    
    base = '.'.join(local_ip.split('.')[:-1])
    
    priority_ips = [
        (f"{base}.1", "Gateway/Router"),
        (f"{base}.2", "AMF"),
        (f"{base}.3", "SMF"),
        (f"{base}.10", "UPF"),
        (f"{base}.100", "UPF"),
        (f"{base}.200", "UPF"),
        (f"{base}.254", "Gateway")
    ]
    
    logger.info(f"\nScanning priority IPs in {base}.0/24 network...\n")
    
    found_components = []
    
    for ip, expected in priority_ips:
        if ip == local_ip:
            continue
        
        logger.info(f"Probing {ip} ({expected})...")
        
        services = []
        component_type = "Unknown"
        
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=0.5, verbose=0)
        if resp:
            services.append("ICMP")
        
        try:
            pkt = IP(dst=ip)/UDP(dport=2152)/GTPHeader(teid=1, gtp_type=1)
            resp = sr1(pkt, timeout=0.5, verbose=0)
            if resp:
                services.append("GTP-U:2152")
                component_type = "UPF"
        except:
            pass
        
        try:
            pkt = IP(dst=ip)/UDP(dport=8805)
            resp = sr1(pkt, timeout=0.5, verbose=0)
            if resp:
                services.append("PFCP:8805")
                if component_type == "UPF":
                    component_type = "UPF"
                else:
                    component_type = "SMF"
        except:
            pass
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex((ip, 38412)) == 0:
                services.append("NGAP:38412")
                component_type = "AMF"
            sock.close()
        except:
            pass
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex((ip, 80)) == 0:
                services.append("HTTP:80")
            sock.close()
        except:
            pass
        
        if services:
            found_components.append({
                'ip': ip,
                'type': component_type,
                'services': services,
                'expected': expected
            })
            logger.info(f"  ✓ FOUND: {component_type} - Services: {', '.join(services)}\n")
        else:
            logger.info(f"  ✗ No response\n")
    
    logger.info("=" * 80)
    logger.info("DISCOVERY COMPLETE")
    logger.info("=" * 80 + "\n")
    
    if not found_components:
        logger.warning("No 5G components found!")
        logger.info("\nTroubleshooting:")
        logger.info("  1. Verify 5G infrastructure is running")
        logger.info("  2. Check firewall settings")
        logger.info("  3. Confirm you're on the correct network")
        return None
    
    print("\n" + "=" * 80)
    print("DISCOVERED 5G COMPONENTS")
    print("=" * 80 + "\n")
    
    upf = None
    amf = None
    smf = None
    
    for comp in found_components:
        print(f"IP: {comp['ip']:<15} | Type: {comp['type']:<10} | Services: {', '.join(comp['services'])}")
        
        if comp['type'] == 'UPF' and not upf:
            upf = comp['ip']
        elif comp['type'] == 'AMF' and not amf:
            amf = comp['ip']
        elif comp['type'] == 'SMF' and not smf:
            smf = comp['ip']
    
    print("\n" + "=" * 80)
    print("RECOMMENDED CONFIGURATION")
    print("=" * 80 + "\n")
    
    if upf:
        print(f"UPF IP: {upf}")
    else:
        print("UPF IP: NOT FOUND - use default 192.168.1.200")
    
    if amf:
        print(f"AMF IP: {amf}")
    else:
        print(f"AMF IP: NOT FOUND - use default {base}.2")
    
    if smf:
        print(f"SMF IP: {smf}")
    else:
        print(f"SMF IP: NOT FOUND - use default {base}.3")
    
    print("\n" + "=" * 80 + "\n")
    
    return {
        'upf': upf or f"{base}.1",
        'amf': amf or f"{base}.2",
        'smf': smf or f"{base}.3",
        'components': found_components
    }

if __name__ == "__main__":
    result = quick_scan_5g_network()

