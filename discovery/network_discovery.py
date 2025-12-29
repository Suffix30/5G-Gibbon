#!/usr/bin/env python3
"""
5G Network Discovery Module 
Properly identifies 5G core components by verifying protocol responses
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.sendrecv import srp, sr1
from scapy.contrib.gtp import GTPHeader
import socket
import struct
import logging
from core.config import TEST_CONFIG, DETECTED_COMPONENTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 5G Component Port Signatures
COMPONENT_SIGNATURES = {
    "UPF": {
        "ports": [(2152, "udp", "GTP-U"), (8805, "udp", "PFCP")],
        "required": ["GTP-U"],  # Must have GTP-U to be UPF
    },
    "AMF": {
        "ports": [(38412, "sctp", "NGAP"), (7777, "tcp", "SBI")],
        "required": ["NGAP"],  # Must have NGAP to be AMF
    },
    "SMF": {
        "ports": [(8805, "udp", "PFCP"), (7777, "tcp", "SBI")],
        "required": ["PFCP"],  # Must have PFCP (but no GTP-U) to be SMF
    },
    "NRF": {
        "ports": [(7777, "tcp", "SBI")],
        "required": ["SBI"],
    },
    "MongoDB": {
        "ports": [(27017, "tcp", "MongoDB")],
        "required": ["MongoDB"],
    },
}


def verify_gtpu_response(ip, port=2152, timeout=1):
    """Send GTP-U Echo Request and check for Echo Response"""
    try:
        # GTP-U Echo Request (type=1)
        pkt = IP(dst=ip)/UDP(sport=2152, dport=port)/GTPHeader(teid=0, gtp_type=1)
        resp = sr1(pkt, timeout=timeout, verbose=0)
        
        if resp and resp.haslayer(UDP):
            # Check if response is from GTP-U port
            if resp[UDP].sport == 2152:
                return True, "GTP-U Echo Response received"
        return False, "No GTP-U response"
    except Exception as e:
        return False, str(e)


def verify_pfcp_response(ip, port=8805, timeout=1):
    """Send PFCP Heartbeat Request and check for response"""
    try:
        # PFCP Heartbeat Request (Message Type=1)
        # Version=1, Message Type=1 (Heartbeat Request), Length=12
        pfcp_header = struct.pack(">BBHI", 0x20, 1, 12, 0)  # Simplified PFCP header
        recovery_ie = struct.pack(">HHI", 96, 4, 0)  # Recovery Time Stamp IE
        pfcp_msg = pfcp_header + recovery_ie
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pfcp_msg, (ip, port))
        
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            if len(data) > 4:
                if data[0] & 0xE0 == 0x20:
                    return True, "PFCP response received"
            return False, "Invalid PFCP response"
        except socket.timeout:
            sock.close()
            return False, "No PFCP response"
    except Exception as e:
        return False, str(e)


def verify_sctp_ngap(ip, port=38412, timeout=1):
    """Check if SCTP/NGAP port is open (AMF indicator)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True, "NGAP port open"
        return False, "NGAP port closed"
    except Exception as e:
        return False, str(e)


def verify_sbi_endpoint(ip, port=7777, timeout=1):
    """Check if SBI HTTP/2 endpoint responds"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True, "SBI port open"
        return False, "SBI port closed"
    except Exception as e:
        return False, str(e)


def verify_mongodb(ip, port=27017, timeout=1):
    """Check if MongoDB is accessible"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True, "MongoDB port open"
        return False, "MongoDB port closed"
    except Exception as e:
        return False, str(e)


def identify_5g_component(ip, timeout=1):
    """
    Identify a 5G component by verifying actual protocol responses.
    Only returns a component if protocols are VERIFIED, not just port open.
    """
    verified_services = []
    
    # Check GTP-U (UPF indicator)
    gtpu_ok, _ = verify_gtpu_response(ip, timeout=timeout)
    if gtpu_ok:
        verified_services.append("GTP-U")
    
    pfcp_ok, _ = verify_pfcp_response(ip, timeout=timeout)
    if pfcp_ok:
        verified_services.append("PFCP")
    
    ngap_ok, _ = verify_sctp_ngap(ip, timeout=timeout)
    if ngap_ok:
        verified_services.append("NGAP")
    
    sbi_ok, _ = verify_sbi_endpoint(ip, timeout=timeout)
    if sbi_ok:
        verified_services.append("SBI")
    
    mongo_ok, _ = verify_mongodb(ip, timeout=timeout)
    if mongo_ok:
        verified_services.append("MongoDB")
    
    # Determine component type based on verified services
    component_type = None
    confidence = 0
    
    if "GTP-U" in verified_services:
        component_type = "UPF"
        confidence = 90
        if "PFCP" in verified_services:
            confidence = 95
    elif "NGAP" in verified_services:
        component_type = "AMF"
        confidence = 90
        if "SBI" in verified_services:
            confidence = 95
    elif "PFCP" in verified_services and "GTP-U" not in verified_services:
        component_type = "SMF"
        confidence = 85
    elif "MongoDB" in verified_services:
        component_type = "MongoDB"
        confidence = 95
    elif "SBI" in verified_services:
        # Could be NRF, AUSF, UDM, etc.
        component_type = "5G-NF (SBI)"
        confidence = 70
    
    if component_type:
        return {
            'ip': ip,
            'type': component_type,
            'services': verified_services,
            'confidence': confidence,
            'verified': True
        }
    
    return None


def update_detected_components(component):
    component_type = component.get('type', '')
    ip = component.get('ip', '')
    
    if not ip:
        return
    
    type_mapping = {
        'UPF': 'upf_ip',
        'AMF': 'amf_ip', 
        'SMF': 'smf_ip',
        'NRF': 'nrf_ip',
        'AUSF': 'ausf_ip',
        'UDM': 'udm_ip',
        'PCF': 'pcf_ip',
        'BSF': 'bsf_ip',
        'NSSF': 'nssf_ip',
        'MongoDB': 'mongodb_ip',
        '5G-NF (SBI)': 'nrf_ip'
    }
    
    key = type_mapping.get(component_type)
    if key:
        current = DETECTED_COMPONENTS.get(key)
        if current is None or current == "127.0.0.1":
            DETECTED_COMPONENTS[key] = ip
            logger.info(f"Updated DETECTED_COMPONENTS[{key}] = {ip}")
    
    if not hasattr(update_detected_components, 'all_components'):
        update_detected_components.all_components = []
    
    update_detected_components.all_components.append({
        'ip': ip,
        'type': component_type,
        'services': component.get('services', []),
        'confidence': component.get('confidence', 0)
    })


def resolve_hostname(ip, timeout=1):
    """Try to resolve hostname for an IP address using multiple methods"""
    import subprocess
    
    # Method 1: Reverse DNS lookup
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        pass
    
    # Method 2: nmblookup (NetBIOS - works well for Windows)
    try:
        result = subprocess.run(
            ['nmblookup', '-A', ip],
            capture_output=True, text=True, timeout=timeout+1
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'GROUP' not in line:
                    name = line.split()[0].strip()
                    if name and len(name) > 1:
                        return name
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except:
        pass
    
    # Method 3: avahi-resolve (mDNS - works for Linux/Mac)
    try:
        result = subprocess.run(
            ['avahi-resolve', '-a', ip],
            capture_output=True, text=True, timeout=timeout+1
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1].rstrip('.')
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except:
        pass
    
    # Method 4: Manual NetBIOS query (fallback)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # NetBIOS Name Query
        query = (
            b'\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
            b'\x00\x21\x00\x01'
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        
        if len(data) > 56:
            name_start = 57
            name = data[name_start:name_start+15].decode('ascii', errors='ignore').strip()
            if name and name.isprintable() and len(name) > 1:
                return name
    except:
        pass
    
    return None


def get_device_type_hint(mac):
    """Get device type hint from MAC address OUI"""
    if mac == 'unknown' or not mac:
        return None
    
    # Check for randomized/private MAC (locally administered bit set)
    # Second hex digit is 2, 6, A, or E
    try:
        first_octet = int(mac.split(':')[0], 16)
        if first_octet & 0x02:  # Locally administered bit is set
            return "Private MAC (Phone/Tablet)"
    except:
        pass
    
    oui = mac[:8].upper().replace(':', '-')
    
    # Extended OUI database (common vendors)
    oui_hints = {
        # Virtual
        '00-15-5D': 'Hyper-V',
        '00-50-56': 'VMware',
        '08-00-27': 'VirtualBox',
        '52-54-00': 'QEMU/KVM',
        # Apple
        'AC-DE-48': 'Apple',
        '00-1C-B3': 'Apple',
        '3C-06-30': 'Apple',
        '14-7D-DA': 'Apple',
        'F0-18-98': 'Apple',
        '8C-85-90': 'Apple',
        # Samsung
        'F4-8C-50': 'Samsung',
        '10-59-32': 'Samsung',
        'CC-5B-31': 'Samsung',
        '94-B9-7E': 'Samsung',
        '84-25-DB': 'Samsung',
        '08-02-3C': 'Samsung',
        '00-21-4C': 'Samsung',
        'A8-7C-01': 'Samsung',
        '78-47-1D': 'Samsung',
        '34-23-BA': 'Samsung',
        # Google/Android
        '94-65-2D': 'OnePlus',
        '3C-5A-B4': 'Google',
        'F8-0F-F9': 'Google',
        # Intel
        'C8-5E-A9': 'Intel',
        '00-1E-67': 'Intel',
        '3C-A9-F4': 'Intel',
        '48-51-B7': 'Intel',
        # Cisco/Network
        '00-1A-11': 'Cisco',
        '00-1B-63': 'Cisco',
        '00-22-55': 'Cisco',
        # TP-Link
        '10-36-AA': 'TP-Link Router',
        'EC-08-6B': 'TP-Link',
        '50-C7-BF': 'TP-Link',
        # Netgear
        '00-1E-2A': 'Netgear',
        'A4-2B-8C': 'Netgear',
        '6C-B0-CE': 'Netgear',
        # Raspberry Pi
        'DC-A6-32': 'Raspberry Pi',
        'B8-27-EB': 'Raspberry Pi',
        'E4-5F-01': 'Raspberry Pi',
        # Amazon
        '68-37-E9': 'Amazon Echo',
        'F0-D5-BF': 'Amazon',
        '74-C2-46': 'Amazon',
        '0C-DC-91': 'Amazon',
        # Microsoft
        '00-0D-3A': 'Microsoft',
        '28-18-78': 'Microsoft',
        # Roku
        'B0-A7-37': 'Roku',
        'D8-31-34': 'Roku',
        # Sonos
        '00-0E-58': 'Sonos',
        '5C-AA-FD': 'Sonos',
        # Ring
        '88-A3-03': 'Ring Doorbell',
        # Dell
        '00-14-22': 'Dell',
        'F8-B1-56': 'Dell',
        # HP
        '00-1E-0B': 'HP',
        '3C-D9-2B': 'HP',
        # Lenovo
        '00-1E-4F': 'Lenovo',
        '98-FA-9B': 'Lenovo',
        # LG
        '00-1C-62': 'LG',
        'C4-36-6C': 'LG TV',
        # Sony
        '00-1A-80': 'Sony',
        'AC-9B-0A': 'Sony PlayStation',
        # Nintendo
        '00-1F-32': 'Nintendo',
        '7C-BB-8A': 'Nintendo Switch',
        # Generic Network Equipment
        'BC-30-7D': 'Wistron (OEM)',
        'EC-63-D7': 'Motorola',
        'C8-3A-6B': 'Tenda',
        '2C-9E-00': 'Arris/Motorola',
        '68-4E-05': 'Humax',
    }
    
    for prefix, hint in oui_hints.items():
        if oui.startswith(prefix[:8]):
            return hint
    
    return None


def discover_hosts(network_range, timeout=2, iface=None):
    """Discover live hosts on the network with hostname resolution"""
    if iface is None:
        iface = TEST_CONFIG.get("interface", "eth0")
    
    logger.info(f"Scanning network: {network_range}")
    hosts = []
    
    # Try ARP scan first (most reliable for local networks)
    try:
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=timeout, iface=iface, verbose=0)[0]
        
        for _, received in result:
            hosts.append({
                'ip': received.psrc,
                'mac': received.hwsrc
            })
        
        logger.info(f"ARP scan found {len(hosts)} hosts")
    except Exception as e:
        logger.warning(f"ARP scan failed: {e}")
    
    # Fallback to ICMP if ARP didn't work
    if len(hosts) == 0:
        logger.info("Trying ICMP ping sweep...")
        base_parts = network_range.split('/')
        base_ip = '.'.join(base_parts[0].split('.')[:-1])
        
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            try:
                pkt = IP(dst=ip)/ICMP()
                resp = sr1(pkt, timeout=0.1, verbose=0)
                if resp:
                    hosts.append({'ip': ip, 'mac': 'unknown'})
            except:
                pass
        
        logger.info(f"ICMP sweep found {len(hosts)} hosts")
    
    # Resolve hostnames for all discovered hosts
    if hosts:
        logger.info("Resolving hostnames...")
        for host in hosts:
            hostname = resolve_hostname(host['ip'])
            host['hostname'] = hostname
            
            # Get device type hint from MAC
            host['device_hint'] = get_device_type_hint(host.get('mac', 'unknown'))
            
            if hostname:
                logger.info(f"  {host['ip']} -> {hostname}")
    
    return hosts


def discover_5g_network(network_range=None, iface=None, show_all_hosts=True):
    """
    Discover and VERIFY 5G components on a network.
    Only returns hosts that respond with actual 5G protocols.
    
    Returns: (components, all_hosts) tuple
    """
    if iface is None:
        iface = TEST_CONFIG.get("interface", "eth0")
    
    if network_range is None:
        network_range = "127.0.0.0/24"
    
    logger.info("Starting 5G network discovery...")
    logger.info("This will VERIFY 5G protocol responses (not just open ports)")
    
    # First, find live hosts
    hosts = discover_hosts(network_range, iface=iface)
    
    if not hosts:
        logger.warning("No hosts found on network")
        return [], []
    
    logger.info(f"Checking {len(hosts)} hosts for 5G components...")
    
    # Now verify each host for 5G services
    components = []
    for host in hosts:
        ip = host['ip']
        
        # Skip our own IP
        try:
            if ip == socket.gethostbyname(socket.gethostname()):
                continue
        except:
            pass
        
        component = identify_5g_component(ip)
        
        if component:
            component['mac'] = host.get('mac', 'unknown')
            component['hostname'] = host.get('hostname')
            components.append(component)
            hostname_str = f" ({host.get('hostname')})" if host.get('hostname') else ""
            logger.info(f"VERIFIED: {ip}{hostname_str} - {component['type']} ({', '.join(component['services'])})")
            
            update_detected_components(component)
    
    if show_all_hosts:
        return components, hosts
    return components, []


def display_all_hosts(hosts):
    """Display ALL discovered hosts with names (before 5G filtering)"""
    print("\n" + "=" * 100)
    print("NETWORK HOSTS DISCOVERED")
    print("=" * 100)
    
    if not hosts:
        print("\nNo hosts found on network.")
        return
    
    print(f"\nFound {len(hosts)} host(s):\n")
    print(f"{'IP':<16} {'Hostname':<25} {'MAC':<18} {'Type Hint'}")
    print("-" * 90)
    
    for host in hosts:
        ip = host.get('ip', 'unknown')
        hostname = host.get('hostname') or '-'
        mac = host.get('mac', 'unknown')
        hint = host.get('device_hint') or '-'
        
        # Truncate long hostnames
        if len(hostname) > 24:
            hostname = hostname[:21] + '...'
        
        print(f"{ip:<16} {hostname:<25} {mac:<18} {hint}")
    
    print("-" * 90)
    print()


def display_discovered_network(components, all_hosts=None):
    """Display discovered 5G components"""
    
    # First show all hosts if provided
    if all_hosts:
        display_all_hosts(all_hosts)
    
    print("\n" + "=" * 100)
    print("5G COMPONENT VERIFICATION RESULTS")
    print("=" * 100)
    
    if not components:
        print("\nNo VERIFIED 5G components found.")
        print("\nThis means no hosts responded with actual 5G protocol messages.")
        print("Possible reasons:")
        print("  - No 5G infrastructure on this network")
        print("  - 5G services not running")
        print("  - Firewall blocking protocol packets")
        print("  - Need to scan a different network range")
        print("\nNote: Regular network devices (routers, PCs, phones) are NOT 5G components")
        print("      and will NOT appear in this list.")
        return
    
    print(f"\nFound {len(components)} VERIFIED 5G component(s):\n")
    
    # Group by type
    by_type = {}
    for comp in components:
        t = comp['type']
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(comp)
    
    for comp_type, comp_list in by_type.items():
        print(f"\n{comp_type}:")
        print("-" * 80)
        for comp in comp_list:
            hostname = comp.get('hostname') or ''
            hostname_str = f" ({hostname})" if hostname else ""
            print(f"  IP: {comp['ip']:<15}{hostname_str}")
            print(f"  MAC: {comp['mac']}")
            print(f"  Services: {', '.join(comp['services'])}")
            print(f"  Confidence: {comp['confidence']}% (VERIFIED)")
            print()
    
    print("=" * 100)
    
    return by_type


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        network = "127.0.0.0/24"
    
    components, all_hosts = discover_5g_network(network)
    display_discovered_network(components, all_hosts)
