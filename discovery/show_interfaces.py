#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.all import get_if_list, get_if_addr, conf
import platform

print('\n' + '=' * 80)
print('AVAILABLE NETWORK INTERFACES')
print('=' * 80 + '\n')

interfaces = get_if_list()

for i, iface in enumerate(interfaces, 1):
    print(f'{i}. {iface}')
    try:
        addr = get_if_addr(iface)
        if addr and addr != '0.0.0.0':
            print(f'   IP Address: {addr}')
    except:
        pass
    print()

print('=' * 80)
print(f'Total interfaces found: {len(interfaces)}')
print(f'Platform: {platform.system()}')
print(f'Default interface (auto-detected): {conf.iface if hasattr(conf, "iface") else "N/A"}')
print('=' * 80 + '\n')

