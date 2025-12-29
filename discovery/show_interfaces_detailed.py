#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, conf
import platform

print('\n' + '=' * 100)
print('DETAILED NETWORK INTERFACES')
print('=' * 100 + '\n')

interfaces = get_if_list()

for i, iface in enumerate(interfaces, 1):
    print(f'{i}. Interface: {iface}')
    
    try:
        addr = get_if_addr(iface)
        if addr and addr != '0.0.0.0':
            print(f'   IP Address: {addr}')
        else:
            print(f'   IP Address: Not assigned')
    except Exception as e:
        print(f'   IP Address: Unable to retrieve')
    
    try:
        mac = get_if_hwaddr(iface)
        if mac:
            print(f'   MAC Address (BSSID): {mac}')
    except Exception as e:
        print(f'   MAC Address: Unable to retrieve')
    
    print()

print('=' * 100)
print(f'Total interfaces found: {len(interfaces)}')
print(f'Platform: {platform.system()}')
print(f'Default interface: {conf.iface if hasattr(conf, "iface") else "N/A"}')
print('=' * 100 + '\n')

