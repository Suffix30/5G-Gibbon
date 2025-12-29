#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import logging
import time
import statistics
from typing import List, Dict, Optional, Any, Tuple, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from core.config import TEST_CONFIG
from rich.console import Console
from rich.table import Table
 
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.packet import Raw
    from scapy.sendrecv import sr1, sniff
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader

try:
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.packet import Raw
    from scapy.sendrecv import sr1, sniff
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class SideChannelType(Enum):
    PACKET_SIZE = "packet_size"
    RESPONSE_PATTERN = "response_pattern"
    ERROR_ORACLE = "error_oracle"
    TRAFFIC_ANALYSIS = "traffic_analysis"
    RESOURCE_EXHAUSTION = "resource_exhaustion"

@dataclass
class SideChannelObservation:
    probe_id: int
    input_value: Any
    observed_size: int = 0
    observed_pattern: bytes = b""
    timing: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SideChannelAnalysis:
    channel_type: SideChannelType
    observations: List[SideChannelObservation] = field(default_factory=list)
    patterns_found: Dict[str, Any] = field(default_factory=dict)
    leakage_detected: bool = False
    leakage_details: str = ""

class SideChannelAnalyzer:
    def __init__(
        self,
        target_ip: str,
        target_port: int = 2152,
        iface: Optional[str] = None,
        timeout: float = 2.0
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface or TEST_CONFIG.get("interface")
        self.timeout = timeout
        self.console = Console()
    
    def packet_size_oracle(
        self,
        test_values: List[Any],
        packet_crafter: Callable[[Any], Any]
    ) -> SideChannelAnalysis:
        analysis = SideChannelAnalysis(channel_type=SideChannelType.PACKET_SIZE)
        size_groups: Dict[int, List[Any]] = defaultdict(list)
        
        logger.info(f"Packet Size Oracle: Testing {len(test_values)} values")
        
        for idx, value in enumerate(test_values):
            try:
                pkt = packet_crafter(value)
                start = time.perf_counter()
                resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
                elapsed = time.perf_counter() - start
                
                if resp:
                    resp_size = len(bytes(resp))
                    size_groups[resp_size].append(value)
                    
                    obs = SideChannelObservation(
                        probe_id=idx,
                        input_value=value,
                        observed_size=resp_size,
                        timing=elapsed,
                        metadata={"has_response": True}
                    )
                else:
                    obs = SideChannelObservation(
                        probe_id=idx,
                        input_value=value,
                        observed_size=0,
                        timing=elapsed,
                        metadata={"has_response": False}
                    )
                
                analysis.observations.append(obs)
                
            except Exception as e:
                logger.debug(f"Probe {idx} error: {e}")
        
        if len(size_groups) > 1:
            analysis.leakage_detected = True
            analysis.leakage_details = f"Found {len(size_groups)} distinct response sizes"
            analysis.patterns_found = {str(k): v for k, v in size_groups.items()}
        
        self._print_size_analysis(analysis, size_groups)
        return analysis
    
    def error_oracle(
        self,
        test_inputs: List[bytes],
        protocol: str = "gtp"
    ) -> SideChannelAnalysis:
        analysis = SideChannelAnalysis(channel_type=SideChannelType.ERROR_ORACLE)
        error_patterns: Dict[str, List[int]] = defaultdict(list)
        
        logger.info(f"Error Oracle: Testing {len(test_inputs)} malformed inputs")
        
        for idx, input_data in enumerate(test_inputs):
            try:
                if protocol == "gtp":
                    pkt = IP(dst=self.target_ip) / UDP(dport=2152) / Raw(load=input_data)
                elif protocol == "pfcp":
                    pkt = IP(dst=self.target_ip) / UDP(dport=8805) / Raw(load=input_data)
                else:
                    pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=input_data)
                
                start = time.perf_counter()
                resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
                elapsed = time.perf_counter() - start
                
                if resp:
                    resp_bytes = bytes(resp)
                    
                    if resp.haslayer(Raw):
                        pattern = bytes(resp[Raw])[:8].hex()
                    else:
                        pattern = resp_bytes[:16].hex()
                    
                    error_patterns[pattern].append(idx)
                    
                    obs = SideChannelObservation(
                        probe_id=idx,
                        input_value=input_data[:16].hex(),
                        observed_pattern=resp_bytes[:32],
                        timing=elapsed,
                        metadata={"pattern": pattern}
                    )
                else:
                    error_patterns["no_response"].append(idx)
                    obs = SideChannelObservation(
                        probe_id=idx,
                        input_value=input_data[:16].hex(),
                        timing=elapsed,
                        metadata={"pattern": "no_response"}
                    )
                
                analysis.observations.append(obs)
                
            except Exception as e:
                logger.debug(f"Error oracle probe {idx}: {e}")
        
        if len(error_patterns) > 2:
            analysis.leakage_detected = True
            analysis.leakage_details = f"Found {len(error_patterns)} distinct error patterns"
        
        analysis.patterns_found = {k: v for k, v in error_patterns.items()}
        
        self._print_error_analysis(analysis, error_patterns)
        return analysis
    
    def traffic_analysis(
        self,
        duration: float = 30.0,
        filter_expr: Optional[str] = None
    ) -> SideChannelAnalysis:
        analysis = SideChannelAnalysis(channel_type=SideChannelType.TRAFFIC_ANALYSIS)
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy required for traffic analysis")
            return analysis
        
        logger.info(f"Traffic Analysis: Capturing for {duration}s")
        
        if filter_expr is None:
            filter_expr = f"host {self.target_ip}"
        
        try:
            packets = sniff(
                iface=self.iface,
                filter=filter_expr,
                timeout=duration,
                store=True
            )
            
            size_dist: Dict[int, int] = defaultdict(int)
            timing_gaps: List[float] = []
            protocol_dist: Dict[str, int] = defaultdict(int)
            last_time = None
            
            for idx, pkt in enumerate(packets):
                size = len(bytes(pkt))
                size_bucket = (size // 100) * 100
                size_dist[size_bucket] += 1
                
                if pkt.haslayer(UDP):
                    dport = pkt[UDP].dport
                    if dport == 2152:
                        protocol_dist["GTP-U"] += 1
                    elif dport == 8805:
                        protocol_dist["PFCP"] += 1
                    elif dport == 38412:
                        protocol_dist["NGAP"] += 1
                    else:
                        protocol_dist[f"UDP:{dport}"] += 1
                elif pkt.haslayer(TCP):
                    protocol_dist["TCP"] += 1
                
                if hasattr(pkt, 'time'):
                    if last_time is not None:
                        gap = float(pkt.time) - last_time
                        timing_gaps.append(gap)
                    last_time = float(pkt.time)
                
                obs = SideChannelObservation(
                    probe_id=idx,
                    input_value="captured",
                    observed_size=size,
                    metadata={"protocol": list(protocol_dist.keys())[-1] if protocol_dist else "unknown"}
                )
                analysis.observations.append(obs)
            
            analysis.patterns_found = {
                "size_distribution": dict(size_dist),
                "protocol_distribution": dict(protocol_dist),
                "packet_count": len(packets)
            }
            
            if timing_gaps:
                avg_gap = statistics.mean(timing_gaps)
                std_gap = statistics.stdev(timing_gaps) if len(timing_gaps) > 1 else 0
                
                if std_gap < avg_gap * 0.1 and len(timing_gaps) > 10:
                    analysis.leakage_detected = True
                    analysis.leakage_details = f"Regular timing pattern detected: {avg_gap*1000:.2f}ms +/- {std_gap*1000:.2f}ms"
            
            self._print_traffic_analysis(analysis, packets)
            
        except Exception as e:
            logger.error(f"Traffic analysis error: {e}")
        
        return analysis
    
    def resource_exhaustion_probe(
        self,
        resource_type: str = "sessions",
        max_count: int = 1000
    ) -> SideChannelAnalysis:
        analysis = SideChannelAnalysis(channel_type=SideChannelType.RESOURCE_EXHAUSTION)
        
        logger.info(f"Resource Exhaustion Probe: Testing {resource_type} limit")
        
        response_times: List[float] = []
        last_success = 0
        
        try:
            for i in range(max_count):
                if resource_type == "sessions":
                    pkt = IP(dst=self.target_ip) / UDP(dport=8805) / Raw(
                        load=b"\x21\x01" + i.to_bytes(8, 'big') + b"\x00" * 8
                    )
                elif resource_type == "teids":
                    pkt = IP(dst=self.target_ip) / UDP(dport=2152) / GTPHeader(teid=i, gtp_type=1)
                else:
                    pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=f"probe_{i}".encode())
                
                start = time.perf_counter()
                resp = sr1(pkt, iface=self.iface, timeout=1.0, verbose=0)
                elapsed = time.perf_counter() - start
                
                response_times.append(elapsed)
                
                if resp:
                    last_success = i
                
                obs = SideChannelObservation(
                    probe_id=i,
                    input_value=i,
                    timing=elapsed,
                    metadata={"success": resp is not None}
                )
                analysis.observations.append(obs)
                
                if i > 0 and i % 100 == 0:
                    recent_times = response_times[-100:]
                    avg_recent = statistics.mean(recent_times)
                    
                    if len(response_times) > 100:
                        baseline = statistics.mean(response_times[:100])
                        if avg_recent > baseline * 3:
                            analysis.leakage_detected = True
                            analysis.leakage_details = f"Resource exhaustion detected at ~{i} {resource_type}"
                            logger.warning(f"Possible exhaustion at {i}: {avg_recent*1000:.1f}ms vs baseline {baseline*1000:.1f}ms")
                            break
            
            analysis.patterns_found = {
                "last_success": last_success,
                "total_probes": len(analysis.observations),
                "avg_response_time": statistics.mean(response_times) if response_times else 0
            }
            
            self._print_exhaustion_analysis(analysis)
            
        except KeyboardInterrupt:
            logger.warning("Exhaustion probe interrupted")
        
        return analysis
    
    def _print_size_analysis(self, analysis: SideChannelAnalysis, size_groups: Dict):
        self.console.print(f"\n[bold cyan]Packet Size Oracle Analysis[/bold cyan]")
        self.console.print(f"Total probes: {len(analysis.observations)}")
        
        if size_groups:
            table = Table(title="Response Size Distribution")
            table.add_column("Size (bytes)", style="cyan")
            table.add_column("Count", style="green")
            table.add_column("Sample Values", style="yellow")
            
            for size, values in sorted(size_groups.items()):
                sample = str(values[:3])[:50]
                table.add_row(str(size), str(len(values)), sample)
            
            self.console.print(table)
        
        if analysis.leakage_detected:
            self.console.print(f"\n[red]LEAKAGE DETECTED: {analysis.leakage_details}[/red]")
    
    def _print_error_analysis(self, analysis: SideChannelAnalysis, patterns: Dict):
        self.console.print(f"\n[bold cyan]Error Oracle Analysis[/bold cyan]")
        self.console.print(f"Total probes: {len(analysis.observations)}")
        self.console.print(f"Distinct patterns: {len(patterns)}")
        
        if patterns:
            table = Table(title="Error Pattern Distribution")
            table.add_column("Pattern", style="cyan")
            table.add_column("Count", style="green")
            
            for pattern, indices in sorted(patterns.items(), key=lambda x: -len(x[1]))[:10]:
                table.add_row(pattern[:32], str(len(indices)))
            
            self.console.print(table)
        
        if analysis.leakage_detected:
            self.console.print(f"\n[red]LEAKAGE DETECTED: {analysis.leakage_details}[/red]")
    
    def _print_traffic_analysis(self, analysis: SideChannelAnalysis, packets):
        self.console.print(f"\n[bold cyan]Traffic Analysis[/bold cyan]")
        self.console.print(f"Packets captured: {len(packets)}")
        
        if analysis.patterns_found:
            if "protocol_distribution" in analysis.patterns_found:
                table = Table(title="Protocol Distribution")
                table.add_column("Protocol", style="cyan")
                table.add_column("Count", style="green")
                
                for proto, count in analysis.patterns_found["protocol_distribution"].items():
                    table.add_row(proto, str(count))
                
                self.console.print(table)
        
        if analysis.leakage_detected:
            self.console.print(f"\n[yellow]PATTERN DETECTED: {analysis.leakage_details}[/yellow]")
    
    def _print_exhaustion_analysis(self, analysis: SideChannelAnalysis):
        self.console.print(f"\n[bold cyan]Resource Exhaustion Analysis[/bold cyan]")
        self.console.print(f"Total probes: {len(analysis.observations)}")
        
        if analysis.patterns_found:
            self.console.print(f"Last successful probe: {analysis.patterns_found.get('last_success', 'N/A')}")
            avg_time = analysis.patterns_found.get('avg_response_time', 0)
            self.console.print(f"Average response time: {avg_time*1000:.2f}ms")
        
        if analysis.leakage_detected:
            self.console.print(f"\n[red]EXHAUSTION DETECTED: {analysis.leakage_details}[/red]")

def generate_malformed_gtp_inputs(count: int = 100) -> List[bytes]:
    inputs = []
    
    inputs.append(b"")
    inputs.append(b"\x00")
    inputs.append(b"\xff" * 8)
    inputs.append(b"\x30\x00\x00\x00")
    inputs.append(b"\x30\xff\x00\x08" + b"\x00" * 8)
    
    for version in range(8):
        inputs.append(bytes([version << 5]) + b"\x01\x00\x08" + b"\x00" * 8)
    
    for msg_type in [0, 1, 2, 16, 17, 26, 27, 255]:
        inputs.append(b"\x30" + bytes([msg_type]) + b"\x00\x08" + b"\x00" * 8)
    
    import random
    while len(inputs) < count:
        length = random.randint(4, 100)
        inputs.append(bytes([random.randint(0, 255) for _ in range(length)]))
    
    return inputs[:count]

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="5G Side-Channel Analysis")
    parser.add_argument("analysis", choices=["size-oracle", "error-oracle", "traffic", "exhaustion"])
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--duration", "-d", type=float, default=30.0)
    parser.add_argument("--count", "-c", type=int, default=100)
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    analyzer = SideChannelAnalyzer(args.target)
    
    if args.analysis == "error-oracle":
        inputs = generate_malformed_gtp_inputs(args.count)
        analyzer.error_oracle(inputs)
    elif args.analysis == "traffic":
        analyzer.traffic_analysis(duration=args.duration)
    elif args.analysis == "exhaustion":
        analyzer.resource_exhaustion_probe(max_count=args.count)
    elif args.analysis == "size-oracle":
        def gtp_crafter(teid):
            return IP(dst=args.target) / UDP(dport=2152) / GTPHeader(teid=teid, gtp_type=1)
        analyzer.packet_size_oracle(list(range(args.count)), gtp_crafter)


async def async_side_channel_scan(target_ip: str, analysis_type: str, 
                                   count: int = 100, concurrency: int = 10) -> Tuple[List, List]:
    conf.verb = 0
    analyzer = SideChannelAnalyzer(target_ip, timeout=1.0)
    results: List = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def run_single_probe(probe_id: int):
        async with semaphore:
            loop = asyncio.get_event_loop()
            if analysis_type == "error-oracle":
                input_data = b"\x00" * 20 + bytes([probe_id % 256]) * 4
                result = await loop.run_in_executor(None, lambda: analyzer.error_oracle([input_data]))
                return result
            elif analysis_type == "exhaustion":
                result = await loop.run_in_executor(None, lambda: analyzer.resource_exhaustion_probe("sessions", count))
                return result
            return None
    
    tasks = [run_single_probe(i) for i in range(count)]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results = [r for r in gathered if r is not None and not isinstance(r, Exception)]
    
    return results, []


def run_async_side_channel(target_ip: str, analysis_type: str, count: int = 100) -> Tuple:
    return asyncio.run(async_side_channel_scan(target_ip, analysis_type, count))

