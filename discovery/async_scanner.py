#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import asyncio
import socket
import ipaddress
import logging
import time
from typing import List, Dict, Optional, Any, Set, TYPE_CHECKING
from dataclasses import dataclass, field
from core.async_utils import (
    async_tcp_connect, async_udp_probe, run_in_executor,
    AsyncRateLimiter, run_async
)
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console
from rich.table import Table

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP, ICMP
    from scapy.sendrecv import sr1
    from scapy.config import conf
    from scapy.arch import get_if_list, get_if_addr
    from scapy.contrib.gtp import GTPHeader

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

@dataclass
class ScanResult:
    ip: str
    component: str
    open_ports: List[int] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    confidence: int = 0
    scan_time: float = 0.0

@dataclass
class ScanStats:
    hosts_scanned: int = 0
    hosts_found: int = 0
    ports_scanned: int = 0
    ports_open: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate(self) -> float:
        if self.elapsed > 0:
            return self.hosts_scanned / self.elapsed
        return 0.0

class AsyncNetworkScanner:
    def __init__(
        self,
        timeout: float = 1.0,
        concurrency: int = 200,
        rate_limit: float = 1000.0
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=100)
        self._semaphore = asyncio.Semaphore(concurrency)
        self.stats = ScanStats()
        self.discovered: List[ScanResult] = []
        self._cancel_event = asyncio.Event()
    
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
            networks = ["192.168.1.0/24", "10.0.0.0/24"]
        
        return list(set(networks))
    
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
    
    async def scan_tcp_port(self, ip: str, port: int) -> Optional[Dict]:
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                is_open = await async_tcp_connect(ip, port, self.timeout)
                if is_open:
                    service = FIVE_G_PORTS.get(port, ("Unknown", "Unknown Service"))
                    return {
                        "port": port,
                        "protocol": service[0],
                        "service": service[1],
                        "type": "TCP"
                    }
            except Exception as e:
                logger.debug(f"TCP scan error {ip}:{port}: {e}")
        return None
    
    async def scan_udp_port(self, ip: str, port: int) -> Optional[Dict]:
        if not SCAPY_AVAILABLE:
            return None
        
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                def probe_udp():
                    conf.verb = 0
                    if port == 2152:
                        pkt = IP(dst=ip)/UDP(dport=port)/GTPHeader(teid=0, gtp_type=1)
                    else:
                        pkt = IP(dst=ip)/UDP(dport=port)/b"\x00" * 8
                    
                    resp = sr1(pkt, timeout=self.timeout, verbose=0)
                    return resp is not None
                
                is_open = await asyncio.wait_for(
                    run_in_executor(probe_udp),
                    timeout=self.timeout + 1
                )
                
                if is_open:
                    service = FIVE_G_PORTS.get(port, ("Unknown", "Unknown Service"))
                    return {
                        "port": port,
                        "protocol": service[0],
                        "service": service[1],
                        "type": "UDP"
                    }
            except Exception as e:
                logger.debug(f"UDP scan error {ip}:{port}: {e}")
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
    
    async def scan_host(
        self,
        ip: str,
        ports: Optional[List[int]] = None
    ) -> Optional[ScanResult]:
        if self._cancel_event.is_set():
            return None
        
        if ports is None:
            ports = list(FIVE_G_PORTS.keys())
        
        start_time = time.time()
        open_services: List[Dict] = []
        
        tcp_ports = [p for p in ports if p not in [2152, 8805, 2123]]
        udp_ports = [p for p in ports if p in [2152, 8805, 2123]]
        
        tcp_tasks = [self.scan_tcp_port(ip, port) for port in tcp_ports]
        tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
        
        for result in tcp_results:
            if isinstance(result, dict):
                open_services.append(result)
                self.stats.ports_open += 1
        
        udp_tasks = [self.scan_udp_port(ip, port) for port in udp_ports]
        udp_results = await asyncio.gather(*udp_tasks, return_exceptions=True)
        
        for result in udp_results:
            if isinstance(result, dict):
                open_services.append(result)
                self.stats.ports_open += 1
        
        self.stats.hosts_scanned += 1
        self.stats.ports_scanned += len(ports)
        
        if open_services:
            open_ports = [s["port"] for s in open_services]
            component = self.identify_component(open_ports)
            
            scan_result = ScanResult(
                ip=ip,
                component=component,
                open_ports=open_ports,
                services=open_services,
                confidence=min(len(open_ports) * 20, 100),
                scan_time=time.time() - start_time
            )
            
            self.stats.hosts_found += 1
            self.discovered.append(scan_result)
            return scan_result
        
        return None
    
    async def scan_network(
        self,
        network: str,
        ports: Optional[List[int]] = None,
        quick: bool = False,
        show_progress: bool = True
    ) -> List[ScanResult]:
        logger.info(f"Async scanning network: {network}")
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = [str(h) for h in list(net.hosts())[:254]]
        except Exception as e:
            logger.error(f"Invalid network: {e}")
            return []
        
        if quick:
            ports = [2152, 8805, 38412, 7777, 27017]
        elif ports is None:
            ports = list(FIVE_G_PORTS.keys())
        
        results: List[ScanResult] = []
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Found: {task.fields[found]} | Rate: {task.fields[rate]}/s"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]Scanning {network}",
                        total=len(hosts),
                        found=0,
                        rate="0"
                    )
                    
                    batch_size = min(50, len(hosts))
                    completed = 0
                    
                    for i in range(0, len(hosts), batch_size):
                        if self._cancel_event.is_set():
                            break
                        
                        batch = hosts[i:i + batch_size]
                        tasks = [self.scan_host(host, ports) for host in batch]
                        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                        
                        for result in batch_results:
                            if isinstance(result, ScanResult):
                                results.append(result)
                                logger.info(f"  + Found {result.component} at {result.ip}")
                        
                        completed += len(batch)
                        progress.update(
                            task,
                            completed=completed,
                            found=len(results),
                            rate=f"{self.stats.rate:.1f}"
                        )
            else:
                tasks = [self.scan_host(host, ports) for host in hosts]
                all_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in all_results:
                    if isinstance(result, ScanResult):
                        results.append(result)
                        logger.info(f"  + Found {result.component} at {result.ip}")
            
            return results
            
        except KeyboardInterrupt:
            self._cancel_event.set()
            logger.warning("Scan interrupted")
            return results
    
    async def full_scan(
        self,
        include_common: bool = True,
        show_progress: bool = True
    ) -> List[ScanResult]:
        logger.info("=" * 60)
        logger.info("5G NETWORK INFRASTRUCTURE SCANNER (ASYNC)")
        logger.info("=" * 60)
        
        self.stats = ScanStats()
        all_results: List[ScanResult] = []
        
        local_networks = self.get_local_networks()
        logger.info(f"\nDetected local networks: {local_networks}")
        
        for network in local_networks:
            logger.info(f"\n[LOCAL] Scanning {network}...")
            results = await self.scan_network(network, quick=False, show_progress=show_progress)
            all_results.extend(results)
        
        if include_common:
            common_ranges = self.get_common_5g_ranges()
            for network in common_ranges:
                if network not in local_networks:
                    logger.info(f"\n[COMMON 5G RANGE] Scanning {network}...")
                    results = await self.scan_network(network, quick=True, show_progress=show_progress)
                    all_results.extend(results)
        
        self.print_summary(all_results)
        return all_results
    
    async def targeted_scan(
        self,
        targets: List[str],
        show_progress: bool = True
    ) -> List[ScanResult]:
        logger.info("=" * 60)
        logger.info("TARGETED 5G COMPONENT SCAN (ASYNC)")
        logger.info("=" * 60)
        
        self.stats = ScanStats()
        all_results: List[ScanResult] = []
        
        for target in targets:
            if "/" in target:
                results = await self.scan_network(target, show_progress=show_progress)
                all_results.extend(results)
            else:
                result = await self.scan_host(target)
                if result:
                    all_results.append(result)
                    logger.info(f"  + Found {result.component} at {result.ip}")
        
        self.print_summary(all_results)
        return all_results
    
    def print_summary(self, results: List[ScanResult]):
        console = Console()
        
        console.print("\n" + "=" * 60)
        console.print("[bold cyan]SCAN RESULTS SUMMARY[/bold cyan]")
        console.print("=" * 60)
        
        if not results:
            console.print("[yellow]No 5G components found.[/yellow]")
            return
        
        table = Table(title="Discovered Components")
        table.add_column("Component", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Ports", style="yellow")
        table.add_column("Confidence", style="magenta")
        
        for r in sorted(results, key=lambda x: x.component):
            ports = ", ".join(map(str, r.open_ports))
            table.add_row(r.component, r.ip, ports, f"{r.confidence}%")
        
        console.print(table)
        
        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  Hosts scanned: {self.stats.hosts_scanned}")
        console.print(f"  Hosts found: {self.stats.hosts_found}")
        console.print(f"  Scan rate: {self.stats.rate:.1f} hosts/sec")
        console.print(f"  Elapsed: {self.stats.elapsed:.1f}s")
        
        upf = [r for r in results if r.component == 'UPF']
        amf = [r for r in results if r.component == 'AMF']
        smf = [r for r in results if r.component == 'SMF']
        
        if upf or amf or smf:
            console.print("\n[bold]Next steps:[/bold]")
            if upf:
                console.print(f"  [green]+ UPF at {upf[0].ip}[/green] - Use for GTP-U testing")
            if amf:
                console.print(f"  [green]+ AMF at {amf[0].ip}[/green] - Use for NGAP testing")
            if smf:
                console.print(f"  [green]+ SMF at {smf[0].ip}[/green] - Use for PFCP testing")
    
    def cancel(self):
        self._cancel_event.set()

async def quick_scan_async(network: Optional[str] = None) -> List[ScanResult]:
    scanner = AsyncNetworkScanner()
    
    if network:
        return await scanner.scan_network(network, quick=True)
    else:
        local = scanner.get_local_networks()
        if local:
            return await scanner.scan_network(local[0], quick=True)
    return []

def quick_scan_sync(network: Optional[str] = None) -> List[ScanResult]:
    return run_async(quick_scan_async(network))


async def probe_5g_port(host: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    if port == 2152:
        payload = bytes([0x30, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01])
    elif port == 8805:
        payload = bytes([0x21, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00])
    else:
        payload = b"\x00" * 16
    
    response = await async_udp_probe(host, port, payload, timeout)
    if response:
        return {"host": host, "port": port, "response": response, "responsive": True}
    return None


def get_scanned_hosts_set(results: List[ScanResult]) -> Set[str]:
    return {r.ip for r in results}


def send_icmp_probe(target: str) -> bool:
    if not SCAPY_AVAILABLE:
        return False
    try:
        conf.verb = 0
        pkt = IP(dst=target) / ICMP()
        resp = sr1(pkt, timeout=1.0, verbose=0)
        return resp is not None
    except Exception:
        return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Async 5G Network Scanner")
    parser.add_argument("--network", "-n", type=str, help="Network to scan (CIDR)")
    parser.add_argument("--target", "-t", type=str, action="append", help="Specific target(s)")
    parser.add_argument("--full", "-f", action="store_true", help="Full scan")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick scan")
    parser.add_argument("--concurrency", "-c", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=1.0)
    
    args = parser.parse_args()
    
    async def main():
        scanner = AsyncNetworkScanner(
            timeout=args.timeout,
            concurrency=args.concurrency
        )
        
        if args.target:
            await scanner.targeted_scan(args.target)
        elif args.network:
            await scanner.scan_network(args.network, quick=args.quick)
            scanner.print_summary(scanner.discovered)
        elif args.full:
            await scanner.full_scan(include_common=True)
        else:
            await scanner.full_scan(include_common=False)
    
    asyncio.run(main())

