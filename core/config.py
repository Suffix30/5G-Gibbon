#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import platform
import socket
from typing import Dict, Optional
 
try:
    from scapy.all import get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    get_if_list = None
    SCAPY_AVAILABLE = False

def get_default_interface():
    if get_if_list is None:
        return "eth0"
    
    system = platform.system()
    interfaces = get_if_list()
    
    if system == "Windows":
        for iface in interfaces:
            if "Ethernet" in iface or "Wi-Fi" in iface or "Local Area Connection" in iface:
                return iface
        return interfaces[0] if interfaces else None
    elif system == "Linux":
        priority = ["eth0", "ens33", "enp0s3", "wlan0", "lo"]
        for p in priority:
            if p in interfaces:
                return p
        return interfaces[0] if interfaces else "eth0"
    else:
        return interfaces[0] if interfaces else "eth0"

def check_root():
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else True

def auto_detect_5g_components():
    components: Dict[str, Optional[str]] = {"upf_ip": None, "amf_ip": None, "smf_ip": None}
    
    open5gs_ips = [
        ("127.0.0.7", 2152, "upf_ip"),
        ("127.0.0.7", 8805, "upf_ip"),
        ("127.0.0.5", 7777, "amf_ip"),
        ("127.0.0.4", 8805, "smf_ip"),
        ("127.0.0.4", 7777, "smf_ip"),
        ("10.0.0.1", 2152, "upf_ip"),
        ("10.0.0.2", 38412, "amf_ip"),
        ("10.0.0.3", 8805, "smf_ip"),
        ("127.0.0.1", 2152, "upf_ip"),
        ("127.0.0.1", 8805, "smf_ip"),
        ("127.0.0.1", 38412, "amf_ip"),
    ]
    
    for ip, port, comp_type in open5gs_ips:
        if components[comp_type] is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    components[comp_type] = ip
            except:
                pass
    
    for comp_type in components:
        if components[comp_type] is None:
            if comp_type == "upf_ip":
                components[comp_type] = "127.0.0.7"
            elif comp_type == "amf_ip":
                components[comp_type] = "127.0.0.5"
            elif comp_type == "smf_ip":
                components[comp_type] = "127.0.0.4"
    
    return components

DEFAULT_IFACE = get_default_interface()
IS_ROOT = check_root()
DETECTED_COMPONENTS = auto_detect_5g_components()

TEST_CONFIG = {
    "upf_ip": DETECTED_COMPONENTS["upf_ip"],
    "amf_ip": DETECTED_COMPONENTS["amf_ip"],
    "smf_ip": DETECTED_COMPONENTS["smf_ip"],
    "mme_ip": "10.0.0.1",
    "hss_ip": "10.0.0.2",
    "outer_src": "10.0.0.8",
    "outer_teid": 12345,
    "inner_src": "10.0.0.8",
    "inner_teid": 54321,
    "victim_ip": DETECTED_COMPONENTS["upf_ip"],
    "victim_teid": 12345,
    "attacker_ue_ip": "10.0.0.100",
    "interface": DEFAULT_IFACE,
    "teid_range": (0, 100),
    "seid_range": (0, 100),
    "enum_timeout": 0.5,
    "enum_delay": 0.01
}

def validate_config():
    if not DEFAULT_IFACE:
        raise RuntimeError("No network interface detected")
    return True

def print_status():
    print("\n" + "=" * 50)
    print("5G-Gibbon Field Status")
    print("=" * 50)
    print(f"Running as root: {'Yes' if IS_ROOT else 'No (run with sudo for full features)'}")
    print(f"Scapy available: {'Yes' if SCAPY_AVAILABLE else 'No'}")
    print(f"Interface: {DEFAULT_IFACE}")
    print(f"UPF detected: {DETECTED_COMPONENTS['upf_ip'] or 'Not found'}")
    print(f"AMF detected: {DETECTED_COMPONENTS['amf_ip'] or 'Not found'}")
    print(f"SMF detected: {DETECTED_COMPONENTS['smf_ip'] or 'Not found'}")
    print("=" * 50)
    if not IS_ROOT:
        print("\n⚠️  For attack modules, run: sudo python3 cli.py <command>")
    print()

