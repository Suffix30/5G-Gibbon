#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import asyncio
import logging
import time
from typing import List, Dict, Optional, Any, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from core.async_utils import (
    AsyncScanner, AsyncRateLimiter, run_in_executor, 
    gather_with_concurrency, run_async
)
from core.config import TEST_CONFIG, validate_config
from core.response_verifier import ResponseVerifier
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console
from rich.live import Live
from rich.table import Table

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP
    from scapy.sendrecv import sr1
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader

try:
    from scapy.layers.inet import IP, UDP
    from scapy.sendrecv import sr1
    from scapy.config import conf
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available")

try:
    from protocol.protocol_layers import PFCPHeader
    PFCP_AVAILABLE = True
except ImportError:
    PFCP_AVAILABLE = False

@dataclass
class EnumerationResult:
    id: int
    status: str
    response_time: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EnumerationStats:
    total: int = 0
    active: int = 0
    live_sessions: int = 0
    errors: int = 0
    timeouts: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate(self) -> float:
        if self.elapsed > 0:
            return self.total / self.elapsed
        return 0.0
    
    @property
    def success_rate(self) -> float:
        if self.total > 0:
            return (self.active + self.live_sessions) / self.total * 100
        return 0.0

class AsyncTEIDEnumerator:
    def __init__(
        self,
        upf_ip: str,
        iface: Optional[str] = None,
        timeout: float = 2.0,
        concurrency: int = 100,
        rate_limit: float = 500.0
    ):
        self.upf_ip = upf_ip
        self.iface = iface or TEST_CONFIG.get("interface")
        self.timeout = timeout
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=50)
        self.verifier = ResponseVerifier(timeout=timeout)
        self.stats = EnumerationStats()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._results: List[EnumerationResult] = []
        self._active_teids: List[int] = []
        self._live_sessions: List[int] = []
        self._cancel_event = asyncio.Event()
    
    def _probe_teid_sync(self, teid: int) -> Optional[Tuple[int, str, Dict]]:
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            start = time.time()
            pkt = IP(dst=self.upf_ip) / UDP(dport=2152) / GTPHeader(teid=teid, gtp_type=1)
            resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
            response_time = time.time() - start
            
            if resp:
                if resp.haslayer(GTPHeader):
                    gtp_type = resp[GTPHeader].gtp_type
                    if gtp_type == 2:
                        return (teid, "active", {"gtp_type": 2, "response_time": response_time})
                    elif gtp_type == 26:
                        return (teid, "live_session", {"gtp_type": 26, "response_time": response_time})
                return (teid, "response", {"response_time": response_time})
        except Exception as e:
            logger.debug(f"Error probing TEID {teid}: {e}")
        return None
    
    async def probe_teid(self, teid: int) -> Optional[EnumerationResult]:
        if self._cancel_event.is_set():
            return None
        
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                result = await asyncio.wait_for(
                    run_in_executor(self._probe_teid_sync, teid),
                    timeout=self.timeout + 1
                )
                
                if result:
                    teid_val, status, details = result
                    enum_result = EnumerationResult(
                        id=teid_val,
                        status=status,
                        response_time=details.get("response_time", 0),
                        details=details
                    )
                    
                    if status == "active":
                        self._active_teids.append(teid_val)
                        self.stats.active += 1
                    elif status == "live_session":
                        self._live_sessions.append(teid_val)
                        self.stats.live_sessions += 1
                    
                    self._results.append(enum_result)
                    return enum_result
                
                self.stats.total += 1
                return None
                
            except asyncio.TimeoutError:
                self.stats.timeouts += 1
                self.stats.total += 1
                return None
            except Exception as e:
                self.stats.errors += 1
                self.stats.total += 1
                logger.debug(f"Async probe error for TEID {teid}: {e}")
                return None
    
    async def enumerate(
        self,
        start_teid: int,
        end_teid: int,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        validate_config()
        self.stats = EnumerationStats()
        self._results = []
        self._active_teids = []
        self._live_sessions = []
        self._cancel_event.clear()
        
        total_range = end_teid - start_teid
        teids = list(range(start_teid, end_teid))
        
        logger.info(f"Async TEID enumeration: {start_teid} to {end_teid} ({total_range} TEIDs)")
        logger.info(f"Concurrency: {self.concurrency}, Rate limit: {self.rate_limiter.rate}/s")
        
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Active: {task.fields[active]} | Live: {task.fields[live]} | Rate: {task.fields[rate]}/s"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[cyan]TEID Enumeration (Async)",
                        total=total_range,
                        active=0,
                        live=0,
                        rate="0"
                    )
                    
                    batch_size = min(1000, total_range)
                    completed = 0
                    
                    for i in range(0, total_range, batch_size):
                        if self._cancel_event.is_set():
                            break
                        
                        batch = teids[i:i + batch_size]
                        tasks = [self.probe_teid(teid) for teid in batch]
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
                        completed += len(batch)
                        progress.update(
                            task,
                            completed=completed,
                            active=len(self._active_teids),
                            live=len(self._live_sessions),
                            rate=f"{self.stats.rate:.1f}"
                        )
            else:
                tasks = [self.probe_teid(teid) for teid in teids]
                await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"Enumeration complete: {len(self._active_teids)} active, {len(self._live_sessions)} live")
            logger.info(f"Rate: {self.stats.rate:.1f} probes/sec, Elapsed: {self.stats.elapsed:.1f}s")
            
            return {
                "active": self._active_teids,
                "live_sessions": self._live_sessions,
                "total_probed": total_range,
                "success_rate": self.stats.success_rate,
                "rate": self.stats.rate,
                "elapsed": self.stats.elapsed,
                "errors": self.stats.errors,
                "timeouts": self.stats.timeouts,
                "results": self._results
            }
            
        except KeyboardInterrupt:
            self._cancel_event.set()
            logger.warning("Enumeration interrupted by user")
            return {
                "active": self._active_teids,
                "live_sessions": self._live_sessions,
                "interrupted": True
            }
        except Exception as e:
            logger.error(f"Enumeration failed: {e}", exc_info=True)
            return {
                "active": self._active_teids,
                "live_sessions": self._live_sessions,
                "error": str(e)
            }
    
    def cancel(self):
        self._cancel_event.set()

class AsyncSEIDEnumerator:
    def __init__(
        self,
        smf_ip: str,
        iface: Optional[str] = None,
        timeout: float = 2.0,
        concurrency: int = 100,
        rate_limit: float = 500.0
    ):
        self.smf_ip = smf_ip
        self.iface = iface or TEST_CONFIG.get("interface")
        self.timeout = timeout
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=50)
        self.verifier = ResponseVerifier(timeout=timeout)
        self.stats = EnumerationStats()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._results: List[EnumerationResult] = []
        self._active_seids: List[int] = []
        self._cancel_event = asyncio.Event()
    
    def _probe_seid_sync(self, seid: int) -> Optional[Tuple[int, str, Dict]]:
        if not SCAPY_AVAILABLE or not PFCP_AVAILABLE:
            return None
        
        try:
            start = time.time()
            pkt = IP(dst=self.smf_ip) / UDP(dport=8805) / PFCPHeader(version=1, seid=seid, message_type=1)
            resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
            response_time = time.time() - start
            
            if resp:
                if resp.haslayer(PFCPHeader):
                    if resp[PFCPHeader].message_type == 2:
                        return (seid, "active", {"message_type": 2, "response_time": response_time})
                return (seid, "response", {"response_time": response_time})
        except Exception as e:
            logger.debug(f"Error probing SEID {seid}: {e}")
        return None
    
    async def probe_seid(self, seid: int) -> Optional[EnumerationResult]:
        if self._cancel_event.is_set():
            return None
        
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                result = await asyncio.wait_for(
                    run_in_executor(self._probe_seid_sync, seid),
                    timeout=self.timeout + 1
                )
                
                if result:
                    seid_val, status, details = result
                    enum_result = EnumerationResult(
                        id=seid_val,
                        status=status,
                        response_time=details.get("response_time", 0),
                        details=details
                    )
                    
                    if status == "active":
                        self._active_seids.append(seid_val)
                        self.stats.active += 1
                    
                    self._results.append(enum_result)
                    return enum_result
                
                self.stats.total += 1
                return None
                
            except asyncio.TimeoutError:
                self.stats.timeouts += 1
                self.stats.total += 1
                return None
            except Exception as e:
                self.stats.errors += 1
                self.stats.total += 1
                logger.debug(f"Async probe error for SEID {seid}: {e}")
                return None
    
    async def enumerate(
        self,
        start_seid: int,
        end_seid: int,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        validate_config()
        self.stats = EnumerationStats()
        self._results = []
        self._active_seids = []
        self._cancel_event.clear()
        
        total_range = end_seid - start_seid
        seids = list(range(start_seid, end_seid))
        
        logger.info(f"Async SEID enumeration: {start_seid} to {end_seid} ({total_range} SEIDs)")
        logger.info(f"Concurrency: {self.concurrency}, Rate limit: {self.rate_limiter.rate}/s")
        
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Active: {task.fields[active]} | Rate: {task.fields[rate]}/s"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[cyan]SEID Enumeration (Async)",
                        total=total_range,
                        active=0,
                        rate="0"
                    )
                    
                    batch_size = min(1000, total_range)
                    completed = 0
                    
                    for i in range(0, total_range, batch_size):
                        if self._cancel_event.is_set():
                            break
                        
                        batch = seids[i:i + batch_size]
                        tasks = [self.probe_seid(seid) for seid in batch]
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
                        completed += len(batch)
                        progress.update(
                            task,
                            completed=completed,
                            active=len(self._active_seids),
                            rate=f"{self.stats.rate:.1f}"
                        )
            else:
                tasks = [self.probe_seid(seid) for seid in seids]
                await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"Enumeration complete: {len(self._active_seids)} active SEIDs")
            logger.info(f"Rate: {self.stats.rate:.1f} probes/sec, Elapsed: {self.stats.elapsed:.1f}s")
            
            return {
                "active": self._active_seids,
                "total_probed": total_range,
                "success_rate": self.stats.success_rate,
                "rate": self.stats.rate,
                "elapsed": self.stats.elapsed,
                "errors": self.stats.errors,
                "timeouts": self.stats.timeouts,
                "results": self._results
            }
            
        except KeyboardInterrupt:
            self._cancel_event.set()
            logger.warning("Enumeration interrupted by user")
            return {"active": self._active_seids, "interrupted": True}
        except Exception as e:
            logger.error(f"Enumeration failed: {e}", exc_info=True)
            return {"active": self._active_seids, "error": str(e)}
    
    def cancel(self):
        self._cancel_event.set()

async def enumerate_teid_async(
    upf_ip: str,
    start_teid: Optional[int] = None,
    end_teid: Optional[int] = None,
    iface: Optional[str] = None,
    concurrency: int = 100,
    rate_limit: float = 500.0,
    show_progress: bool = True
) -> Dict[str, Any]:
    teid_range = TEST_CONFIG.get("teid_range", [0, 1000])
    actual_start: int = start_teid if start_teid is not None else int(teid_range[0])
    actual_end: int = end_teid if end_teid is not None else int(teid_range[1])
    
    enumerator = AsyncTEIDEnumerator(
        upf_ip=upf_ip,
        iface=iface,
        concurrency=concurrency,
        rate_limit=rate_limit
    )
    
    return await enumerator.enumerate(actual_start, actual_end, show_progress)

async def enumerate_seid_async(
    smf_ip: str,
    start_seid: Optional[int] = None,
    end_seid: Optional[int] = None,
    iface: Optional[str] = None,
    concurrency: int = 100,
    rate_limit: float = 500.0,
    show_progress: bool = True
) -> Dict[str, Any]:
    seid_range = TEST_CONFIG.get("seid_range", [0, 1000])
    actual_start: int = start_seid if start_seid is not None else int(seid_range[0])
    actual_end: int = end_seid if end_seid is not None else int(seid_range[1])
    
    enumerator = AsyncSEIDEnumerator(
        smf_ip=smf_ip,
        iface=iface,
        concurrency=concurrency,
        rate_limit=rate_limit
    )
    
    return await enumerator.enumerate(actual_start, actual_end, show_progress)

def enumerate_teid_sync_wrapper(
    upf_ip: str,
    start_teid: Optional[int] = None,
    end_teid: Optional[int] = None,
    **kwargs
) -> Dict[str, Any]:
    return run_async(enumerate_teid_async(upf_ip, start_teid, end_teid, **kwargs))

def enumerate_seid_sync_wrapper(
    smf_ip: str,
    start_seid: Optional[int] = None,
    end_seid: Optional[int] = None,
    **kwargs
) -> Dict[str, Any]:
    return run_async(enumerate_seid_async(smf_ip, start_seid, end_seid, **kwargs))


async def enumerate_parallel_targets(targets: List[Tuple[str, int, int]], 
                                     concurrency: int = 5) -> Dict[str, Any]:
    async def enumerate_one(target: Tuple[str, int, int]) -> Dict:
        ip, start, end = target
        return await enumerate_teid_async(ip, start, end)
    
    tasks = [enumerate_one(t) for t in targets]
    results = await gather_with_concurrency(concurrency, *tasks)
    return {"results": results, "total_targets": len(targets)}


def display_live_results(results: List[Dict]) -> None:
    table = Table(title="Enumeration Results")
    table.add_column("Target", style="cyan")
    table.add_column("Valid TEIDs", style="green")
    table.add_column("Status", style="magenta")
    
    for r in results:
        table.add_row(
            r.get("target", "N/A"),
            str(len(r.get("valid_teids", []))),
            "Complete" if r.get("complete") else "Partial"
        )
    
    console = Console()
    with Live(table, console=console, refresh_per_second=4) as live:
        live.update(table)


def run_with_scanner(upf_ip: str, start: int, end: int) -> Dict:
    if SCAPY_AVAILABLE:
        conf.verb = 0
    scanner = AsyncScanner(concurrency=100)
    logger.info(f"Scanner initialized with concurrency: {scanner.concurrency}")
    return run_async(enumerate_teid_async(upf_ip, start, end))


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Async TEID/SEID Enumeration")
    parser.add_argument("--type", choices=["teid", "seid"], default="teid")
    parser.add_argument("--ip", required=True, help="Target IP (UPF for TEID, SMF for SEID)")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=1000)
    parser.add_argument("--concurrency", "-c", type=int, default=100)
    parser.add_argument("--rate", "-r", type=float, default=500.0)
    
    args = parser.parse_args()
    
    async def main():
        if args.type == "teid":
            result = await enumerate_teid_async(
                args.ip, args.start, args.end,
                concurrency=args.concurrency, rate_limit=args.rate
            )
        else:
            result = await enumerate_seid_async(
                args.ip, args.start, args.end,
                concurrency=args.concurrency, rate_limit=args.rate
            )
        
        print(f"\nResults: {result}")
    
    asyncio.run(main())

