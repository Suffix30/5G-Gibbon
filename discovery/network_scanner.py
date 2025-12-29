#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import socket
import ipaddress
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from scapy.layers.inet import IP, UDP, ICMP
    from scapy.sendrecv import sr1
    from scapy.config import conf
    from scapy.arch import get_if_list, get_if_addr
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - limited functionality")

FIVE_G_PORTS = {
    2152: ("GTP-U", "UPF - User Plane"),
    2123: ("GTPv2-C", "SMF/SGW - Control"),
    8805: ("PFCP", "SMF/UPF - Session Control"),
    38412: ("NGAP/SCTP", "AMF - Control Plane"),
    38472: ("Xn-AP", "gNodeB Interface"),
    36412: ("S1-AP", "MME - LTE Control"),
    36422: ("X2-AP", "eNodeB Interface"),
    7777: ("SBI/HTTP2", "NRF/SCP - Service Discovery"),
    80: ("HTTP", "Web Interface/API"),
    443: ("HTTPS", "Secure API"),
    27017: ("MongoDB", "Subscriber Database"),
    9090: ("Prometheus", "Metrics"),
    3000: ("Grafana/WebUI", "Monitoring"),
    29500: ("SBI-NRF", "NRF Service"),
    29501: ("SBI-UDM", "UDM Service"),
    29502: ("SBI-AMF", "AMF Service"),
    29503: ("SBI-SMF", "SMF Service"),
    29504: ("SBI-PCF", "PCF Service"),
    29505: ("SBI-BSF", "BSF Service"),
    29518: ("SBI-AUSF", "AUSF Service"),
    29519: ("SBI-UDR", "UDR Service"),
}

COMPONENT_SIGNATURES = {
    "UPF": [2152, 8805],
    "SMF": [8805, 2123, 29503],
    "AMF": [38412, 29502],
    "NRF": [7777, 29500],
    "AUSF": [29518],
    "UDM": [29501],
    "UDR": [29519],
    "PCF": [29504],
    "BSF": [29505],
    "MME": [36412, 2123],
    "gNodeB": [38412, 38472],
    "eNodeB": [36412, 36422],
    "MongoDB": [27017],
}


class NetworkScanner:
    def __init__(self, timeout: float = 1.0, workers: int = 50):
        self.timeout = timeout
        self.workers = workers
        self.discovered = []
        
    def get_local_networks(self) -> List[str]:
        networks = []
        if SCAPY_AVAILABLE:
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                        networks.append(str(network))
                except:
                    pass
        else:
            hostname = socket.gethostname()
            try:
                ip = socket.gethostbyname(hostname)
                if ip and not ip.startswith("127."):
                    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    networks.append(str(network))
            except:
                pass
        
        if not networks:
            networks = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
        
        return networks
    
    def get_common_5g_ranges(self) -> List[str]:
        return [
            "10.0.0.0/24",
            "10.45.0.0/16",
            "172.16.0.0/24",
            "172.17.0.0/24",
            "172.18.0.0/24",
            "192.168.100.0/24",
            "192.168.200.0/24",
        ]
    
    def scan_port(self, ip: str, port: int) -> Optional[Tuple[int, str, str]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                service = FIVE_G_PORTS.get(port, ("Unknown", "Unknown Service"))
                return (port, service[0], service[1])
        except:
            pass
        return None
    
    def scan_udp_port(self, ip: str, port: int) -> Optional[Tuple[int, str, str]]:
        if not SCAPY_AVAILABLE:
            return None
        try:
            conf.verb = 0
            if port == 2152:
                pkt = IP(dst=ip)/UDP(dport=port)/GTPHeader(teid=0, gtp_type=1)
            else:
                pkt = IP(dst=ip)/UDP(dport=port)/b"\x00" * 8
            
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp:
                service = FIVE_G_PORTS.get(port, ("Unknown", "Unknown Service"))
                return (port, service[0], service[1])
        except:
            pass
        return None
    
    def identify_component(self, open_ports: List[int]) -> str:
        best_match = "Unknown"
        best_score = 0
        
        for component, signature_ports in COMPONENT_SIGNATURES.items():
            matches = len(set(open_ports) & set(signature_ports))
            if matches > best_score:
                best_score = matches
                best_match = component
        
        return best_match if best_score > 0 else "Unknown Host"
    
    def scan_host(self, ip: str, ports: Optional[List[int]] = None) -> Optional[Dict]:
        if ports is None:
            ports = list(FIVE_G_PORTS.keys())
        
        open_ports = []
        services = []
        
        tcp_ports = [p for p in ports if p not in [2152, 8805, 2123]]
        udp_ports = [p for p in ports if p in [2152, 8805, 2123]]
        
        for port in tcp_ports:
            result = self.scan_port(ip, port)
            if result:
                open_ports.append(result[0])
                services.append({"port": result[0], "protocol": result[1], "service": result[2]})
        
        for port in udp_ports:
            result = self.scan_udp_port(ip, port)
            if result:
                open_ports.append(result[0])
                services.append({"port": result[0], "protocol": result[1], "service": result[2], "type": "UDP"})
        
        if open_ports:
            component = self.identify_component(open_ports)
            return {
                "ip": ip,
                "component": component,
                "open_ports": open_ports,
                "services": services,
                "confidence": min(len(open_ports) * 20, 100)
            }
        return None
    
    def ping_sweep(self, network: str) -> List[str]:
        live_hosts = []
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())[:254]
            
            if SCAPY_AVAILABLE:
                conf.verb = 0
                for host in hosts:
                    try:
                        resp = sr1(IP(dst=str(host))/ICMP(), timeout=0.5, verbose=0)
                        if resp:
                            live_hosts.append(str(host))
                    except:
                        pass
            else:
                for host in hosts:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.3)
                        result = sock.connect_ex((str(host), 80))
                        sock.close()
                        if result == 0:
                            live_hosts.append(str(host))
                    except:
                        pass
        except Exception as e:
            logger.error(f"Ping sweep error: {e}")
        
        return live_hosts
    
    def scan_network(self, network: str, quick: bool = False) -> List[Dict]:
        logger.info(f"Scanning network: {network}")
        results = []
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = [str(h) for h in list(net.hosts())[:254]]
        except Exception as e:
            logger.error(f"Invalid network: {e}")
            return results
        
        if quick:
            ports = [2152, 8805, 38412, 7777, 27017]
        else:
            ports = list(FIVE_G_PORTS.keys())
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self.scan_host, host, ports): host for host in hosts}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    logger.info(f"  ✓ Found {result['component']} at {result['ip']} - Ports: {result['open_ports']}")
        
        self.discovered.extend(results)
        return results
    
    def full_scan(self, include_common: bool = True) -> List[Dict]:
        logger.info("=" * 60)
        logger.info("5G NETWORK INFRASTRUCTURE SCANNER")
        logger.info("=" * 60)
        
        all_results = []
        
        local_networks = self.get_local_networks()
        logger.info(f"\nDetected local networks: {local_networks}")
        
        for network in local_networks:
            logger.info(f"\n[LOCAL] Scanning {network}...")
            results = self.scan_network(network, quick=False)
            all_results.extend(results)
        
        if include_common:
            common_ranges = self.get_common_5g_ranges()
            for network in common_ranges:
                if network not in local_networks:
                    logger.info(f"\n[COMMON 5G RANGE] Scanning {network}...")
                    results = self.scan_network(network, quick=True)
                    all_results.extend(results)
        
        self.print_summary(all_results)
        return all_results
    
    def targeted_scan(self, targets: List[str]) -> List[Dict]:
        logger.info("=" * 60)
        logger.info("TARGETED 5G COMPONENT SCAN")
        logger.info("=" * 60)
        
        all_results = []
        
        for target in targets:
            if "/" in target:
                network_results = self.scan_network(target)
                all_results.extend(network_results)
            else:
                result = self.scan_host(target)
                if result:
                    all_results.append(result)
                    logger.info(f"  ✓ Found {result['component']} at {result['ip']}")
        
        self.print_summary(all_results)
        return all_results
    
    def print_summary(self, results: List[Dict]):
        logger.info("\n" + "=" * 60)
        logger.info("SCAN RESULTS SUMMARY")
        logger.info("=" * 60)
        
        if not results:
            logger.info("No 5G components found.")
            return
        
        components = {}
        for r in results:
            comp = r['component']
            if comp not in components:
                components[comp] = []
            components[comp].append(r)
        
        for comp, hosts in sorted(components.items()):
            logger.info(f"\n{comp}:")
            for h in hosts:
                ports = ", ".join(map(str, h['open_ports']))
                logger.info(f"  • {h['ip']} (ports: {ports}) [{h['confidence']}% confidence]")
        
        logger.info("\n" + "-" * 60)
        logger.info(f"Total components found: {len(results)}")
        
        upf = [r for r in results if r['component'] == 'UPF']
        amf = [r for r in results if r['component'] == 'AMF']
        smf = [r for r in results if r['component'] == 'SMF']
        
        if upf:
            logger.info(f"\n✓ UPF found at: {upf[0]['ip']} → Use for GTP-U testing")
        if amf:
            logger.info(f"✓ AMF found at: {amf[0]['ip']} → Use for NGAP testing")
        if smf:
            logger.info(f"✓ SMF found at: {smf[0]['ip']} → Use for PFCP testing")
        
        logger.info("\nTo test discovered components:")
        if upf:
            logger.info(f"  python3 cli.py enum --type teid --upf-ip {upf[0]['ip']} --start 0 --end 1000")
        if amf:
            logger.info(f"  python3 cli.py ngap --amf-ip {amf[0]['ip']}")


def main():
    parser = argparse.ArgumentParser(description="5G Network Infrastructure Scanner")
    parser.add_argument("--network", "-n", type=str, help="Specific network to scan (CIDR notation)")
    parser.add_argument("--target", "-t", type=str, action="append", help="Specific IP or network to scan")
    parser.add_argument("--full", "-f", action="store_true", help="Full scan of local + common 5G ranges")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick scan (fewer ports)")
    parser.add_argument("--local", "-l", action="store_true", help="Scan only local networks")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout")
    parser.add_argument("--workers", "-w", type=int, default=50, help="Parallel workers")
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(timeout=args.timeout, workers=args.workers)
    
    if args.target:
        scanner.targeted_scan(args.target)
    elif args.network:
        scanner.scan_network(args.network, quick=args.quick)
        scanner.print_summary(scanner.discovered)
    elif args.full:
        scanner.full_scan(include_common=True)
    elif args.local:
        scanner.full_scan(include_common=False)
    else:
        scanner.full_scan(include_common=True)


if __name__ == "__main__":
    main()

