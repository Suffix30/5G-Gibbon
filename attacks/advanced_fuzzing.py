#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import asyncio
import logging
import random
import struct
import time
from typing import List, Dict, Optional, Any, Generator, Tuple, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from core.config import TEST_CONFIG
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
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

class FuzzStrategy(Enum):
    MUTATION = "mutation"
    GENERATION = "generation"
    COVERAGE_GUIDED = "coverage_guided"
    GRAMMAR_BASED = "grammar_based"
    DIFFERENTIAL = "differential"
    STATE_AWARE = "state_aware"

@dataclass
class FuzzCase:
    case_id: int
    strategy: FuzzStrategy
    input_data: bytes
    field_mutations: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

@dataclass
class FuzzResult:
    case: FuzzCase
    crash: bool = False
    timeout: bool = False
    response: Optional[bytes] = None
    response_time: float = 0.0
    interesting: bool = False
    notes: str = ""

@dataclass
class FuzzCampaign:
    strategy: FuzzStrategy
    protocol: str
    total_cases: int = 0
    crashes: List[FuzzResult] = field(default_factory=list)
    timeouts: List[FuzzResult] = field(default_factory=list)
    interesting: List[FuzzResult] = field(default_factory=list)
    coverage_map: Dict[str, int] = field(default_factory=dict)

class BaseFuzzer(ABC):
    strategy: FuzzStrategy = FuzzStrategy.MUTATION
    protocol: str = "UNKNOWN"
    
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        timeout: float = 2.0,
        iface: Optional[str] = None
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.iface = iface or TEST_CONFIG.get("interface")
        self.console = Console()
    
    @abstractmethod
    def generate_cases(self, count: int) -> Generator[FuzzCase, None, None]:
        pass
    
    def send_and_receive(self, data: bytes) -> Tuple[Optional[bytes], float, bool]:
        if not SCAPY_AVAILABLE:
            return None, 0.0, False
        
        pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=data)
        
        try:
            start = time.perf_counter()
            resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
            elapsed = time.perf_counter() - start
            
            if resp:
                return bytes(resp), elapsed, False
            elif elapsed >= self.timeout * 0.95:
                return None, elapsed, True
            else:
                return None, elapsed, False
        except Exception as e:
            logger.debug(f"Fuzz send error: {e}")
            return None, 0.0, False
    
    def fuzz_case(self, case: FuzzCase) -> FuzzResult:
        resp_data, elapsed, is_timeout = self.send_and_receive(case.input_data)
        result = FuzzResult(
            case=case,
            response=resp_data,
            response_time=elapsed,
            timeout=is_timeout
        )
        if is_timeout:
            result.notes = "Timeout - possible hang"
        return result
    
    def run_campaign(
        self,
        max_cases: int = 1000,
        stop_on_crash: bool = False
    ) -> FuzzCampaign:
        campaign = FuzzCampaign(
            strategy=self.strategy,
            protocol=self.protocol
        )
        
        logger.info(f"Starting {self.strategy.value} fuzzing campaign: {max_cases} cases")
        
        seen_responses: Dict[str, int] = {}
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
            ) as progress:
                task = progress.add_task(f"[cyan]{self.strategy.value}", total=max_cases)
                
                for case in self.generate_cases(max_cases):
                    campaign.total_cases += 1
                    
                    resp_data, elapsed, is_timeout = self.send_and_receive(case.input_data)
                    
                    result = FuzzResult(
                        case=case,
                        response=resp_data,
                        response_time=elapsed,
                        timeout=is_timeout
                    )
                    
                    if is_timeout:
                        result.notes = "Timeout - possible hang"
                        campaign.timeouts.append(result)
                    
                    if resp_data:
                        resp_sig = resp_data[:32].hex()
                        if resp_sig not in seen_responses:
                            seen_responses[resp_sig] = campaign.total_cases
                            result.interesting = True
                            result.notes = f"New response pattern: {resp_sig[:16]}..."
                            campaign.interesting.append(result)
                            campaign.coverage_map[resp_sig] = 1
                        else:
                            campaign.coverage_map[resp_sig] += 1
                    
                    if self._is_crash_indicator(resp_data, elapsed, is_timeout):
                        result.crash = True
                        result.notes = "Potential crash detected"
                        campaign.crashes.append(result)
                        
                        if stop_on_crash:
                            logger.warning(f"Crash at case {case.case_id}")
                            break
                    
                    progress.update(task, advance=1)
                    
                    if campaign.total_cases % 100 == 0:
                        progress.update(
                            task,
                            description=f"[cyan]{self.strategy.value} | Crashes: {len(campaign.crashes)} | Interesting: {len(campaign.interesting)}"
                        )
        
        except KeyboardInterrupt:
            logger.warning("Fuzzing interrupted")
        
        self._print_campaign_results(campaign)
        return campaign
    
    def _is_crash_indicator(
        self,
        response: Optional[bytes],
        elapsed: float,
        is_timeout: bool
    ) -> bool:
        if is_timeout and elapsed > self.timeout * 5:
            return True
        
        if response:
            if len(response) > 10000:
                return True
            
            crash_patterns = [b"error", b"fault", b"abort", b"core dump"]
            for pattern in crash_patterns:
                if pattern in response.lower() if hasattr(response, 'lower') else pattern in response:
                    return True
        
        return False
    
    def _print_campaign_results(self, campaign: FuzzCampaign):
        self.console.print(f"\n[bold cyan]Fuzzing Campaign Results[/bold cyan]")
        self.console.print(f"Strategy: {campaign.strategy.value}")
        self.console.print(f"Protocol: {campaign.protocol}")
        self.console.print(f"Total cases: {campaign.total_cases}")
        self.console.print(f"Unique responses: {len(campaign.coverage_map)}")
        
        if campaign.crashes:
            self.console.print(f"\n[red]CRASHES: {len(campaign.crashes)}[/red]")
            table = Table(title="Crash Cases")
            table.add_column("Case ID", style="cyan")
            table.add_column("Input (hex)", style="yellow")
            table.add_column("Notes", style="red")
            
            for r in campaign.crashes[:10]:
                table.add_row(
                    str(r.case.case_id),
                    r.case.input_data[:16].hex(),
                    r.notes
                )
            self.console.print(table)
        
        if campaign.interesting:
            self.console.print(f"\n[yellow]Interesting cases: {len(campaign.interesting)}[/yellow]")
        
        if campaign.timeouts:
            self.console.print(f"\n[yellow]Timeouts: {len(campaign.timeouts)}[/yellow]")

class GTPFuzzer(BaseFuzzer):
    strategy = FuzzStrategy.MUTATION
    protocol = "GTP-U"
    
    def __init__(self, target_ip: str, target_port: int = 2152, **kwargs):
        super().__init__(target_ip, target_port, **kwargs)
    
    def generate_cases(self, count: int) -> Generator[FuzzCase, None, None]:
        case_id = 0
        
        valid_header = b"\x30\xff\x00\x08" + b"\x00\x00\x00\x01" + b"\x00" * 4
        
        for i in range(min(count // 4, 256)):
            mutated = bytearray(valid_header)
            pos = random.randint(0, len(mutated) - 1)
            mutated[pos] = i
            
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.MUTATION,
                input_data=bytes(mutated),
                field_mutations={"byte_flip": pos, "value": i},
                description=f"Byte flip at position {pos}"
            )
            case_id += 1
        
        for version in range(8):
            header = bytes([version << 5 | 0x10]) + b"\xff\x00\x08" + b"\x00" * 8
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GENERATION,
                input_data=header,
                field_mutations={"version": version},
                description=f"GTP version {version}"
            )
            case_id += 1
        
        for msg_type in [0, 1, 2, 16, 17, 26, 27, 31, 254, 255]:
            header = b"\x30" + bytes([msg_type]) + b"\x00\x08" + b"\x00" * 8
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GENERATION,
                input_data=header,
                field_mutations={"message_type": msg_type},
                description=f"Message type {msg_type}"
            )
            case_id += 1
        
        for length in [0, 1, 4, 8, 16, 100, 1000, 65535]:
            header = b"\x30\xff" + struct.pack("!H", length) + b"\x00" * 8
            if length > 8:
                header += b"\x00" * (length - 8)
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GENERATION,
                input_data=header[:min(len(header), 1500)],
                field_mutations={"length": length},
                description=f"Length field {length}"
            )
            case_id += 1
        
        for teid in [0, 1, 0xFFFFFFFF, 0xDEADBEEF, 0x12345678]:
            header = b"\x30\xff\x00\x08" + struct.pack("!I", teid) + b"\x00" * 4
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GENERATION,
                input_data=header,
                field_mutations={"teid": teid},
                description=f"TEID {hex(teid)}"
            )
            case_id += 1
        
        while case_id < count:
            length = random.randint(1, 200)
            data = bytes([random.randint(0, 255) for _ in range(length)])
            
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.MUTATION,
                input_data=data,
                description=f"Random data {length} bytes"
            )
            case_id += 1

class PFCPFuzzer(BaseFuzzer):
    strategy = FuzzStrategy.GRAMMAR_BASED
    protocol = "PFCP"
    
    def __init__(self, target_ip: str, target_port: int = 8805, **kwargs):
        super().__init__(target_ip, target_port, **kwargs)
    
    def generate_cases(self, count: int) -> Generator[FuzzCase, None, None]:
        case_id = 0
        
        msg_types = [1, 2, 3, 4, 5, 50, 51, 52, 53, 54, 55, 56, 57]
        
        for msg_type in msg_types:
            header = bytes([0x21, msg_type]) + b"\x00\x10" + b"\x00" * 12
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GRAMMAR_BASED,
                input_data=header,
                field_mutations={"message_type": msg_type},
                description=f"PFCP message type {msg_type}"
            )
            case_id += 1
        
        ie_types = [1, 2, 3, 19, 20, 21, 22, 60, 61, 69, 96, 97]
        for ie_type in ie_types:
            ie = struct.pack("!HH", ie_type, 4) + b"\x00\x00\x00\x01"
            header = b"\x21\x32\x00" + bytes([16 + len(ie)]) + b"\x00" * 12 + ie
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GRAMMAR_BASED,
                input_data=header,
                field_mutations={"ie_type": ie_type},
                description=f"PFCP IE type {ie_type}"
            )
            case_id += 1
        
        for seid in [0, 1, 0xFFFFFFFFFFFFFFFF, 0xDEADBEEFDEADBEEF]:
            header = b"\x21\x32\x00\x10" + struct.pack("!Q", seid) + b"\x00" * 4
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GRAMMAR_BASED,
                input_data=header,
                field_mutations={"seid": seid},
                description=f"SEID {hex(seid)}"
            )
            case_id += 1
        
        for length in [0, 4, 65535]:
            ie = struct.pack("!HH", 1, length)
            if length > 0 and length < 1000:
                ie += b"\x00" * length
            header = b"\x21\x32\x00" + bytes([16 + len(ie)]) + b"\x00" * 12 + ie
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GRAMMAR_BASED,
                input_data=header[:1500],
                field_mutations={"ie_length": length},
                description=f"IE with length {length}"
            )
            case_id += 1
        
        while case_id < count:
            msg_type = random.choice(msg_types)
            num_ies = random.randint(0, 10)
            
            ies = b""
            for _ in range(num_ies):
                ie_type = random.choice(ie_types)
                ie_len = random.randint(0, 50)
                ie_data = bytes([random.randint(0, 255) for _ in range(ie_len)])
                ies += struct.pack("!HH", ie_type, ie_len) + ie_data
            
            total_len = 12 + len(ies)
            header = bytes([0x21, msg_type]) + struct.pack("!H", total_len) + b"\x00" * 12 + ies
            
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.GRAMMAR_BASED,
                input_data=header[:1500],
                description=f"Generated PFCP with {num_ies} IEs"
            )
            case_id += 1

class NGAPFuzzer(BaseFuzzer):
    strategy = FuzzStrategy.STATE_AWARE
    protocol = "NGAP"
    
    def __init__(self, target_ip: str, target_port: int = 38412, **kwargs):
        super().__init__(target_ip, target_port, **kwargs)
        self.state = "initial"
        self.ran_ue_id = random.randint(1, 0xFFFFFFFF)
        self.amf_ue_id = random.randint(1, 0xFFFFFFFF)
    
    def generate_cases(self, count: int) -> Generator[FuzzCase, None, None]:
        case_id = 0
        
        procedures = [
            (14, "NGSetupRequest"),
            (15, "InitialUEMessage"),
            (12, "DownlinkNASTransport"),
            (46, "UplinkNASTransport"),
            (29, "InitialContextSetupRequest"),
            (41, "UEContextReleaseCommand"),
            (10, "HandoverRequired"),
        ]
        
        for proc_code, name in procedures:
            pdu = self._create_ngap_pdu(proc_code, initiating=True)
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.STATE_AWARE,
                input_data=pdu,
                field_mutations={"procedure": proc_code, "name": name},
                description=f"NGAP {name}"
            )
            case_id += 1
            
            pdu = self._create_ngap_pdu(proc_code, initiating=False)
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.STATE_AWARE,
                input_data=pdu,
                field_mutations={"procedure": proc_code, "name": name, "response": True},
                description=f"NGAP {name} (response)"
            )
            case_id += 1
        
        for criticality in [0, 1, 2]:
            pdu = self._create_ngap_pdu(14, initiating=True, criticality=criticality)
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.STATE_AWARE,
                input_data=pdu,
                field_mutations={"criticality": criticality},
                description=f"Criticality {criticality}"
            )
            case_id += 1
        
        for ie_id in [0, 10, 27, 38, 85, 86, 100, 121]:
            pdu = self._create_ngap_pdu_with_ie(14, ie_id)
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.STATE_AWARE,
                input_data=pdu,
                field_mutations={"ie_id": ie_id},
                description=f"IE {ie_id}"
            )
            case_id += 1
        
        while case_id < count:
            proc_code = random.choice([p[0] for p in procedures])
            pdu = self._create_ngap_pdu(proc_code, initiating=random.choice([True, False]))
            
            mutated = bytearray(pdu)
            num_mutations = random.randint(1, 5)
            for _ in range(num_mutations):
                if len(mutated) > 0:
                    pos = random.randint(0, len(mutated) - 1)
                    mutated[pos] = random.randint(0, 255)
            
            yield FuzzCase(
                case_id=case_id,
                strategy=FuzzStrategy.STATE_AWARE,
                input_data=bytes(mutated),
                description=f"Mutated NGAP proc {proc_code}"
            )
            case_id += 1
    
    def _create_ngap_pdu(
        self,
        procedure_code: int,
        initiating: bool = True,
        criticality: int = 0
    ) -> bytes:
        pdu_type = 0x00 if initiating else 0x20
        
        pdu = bytes([
            pdu_type,
            procedure_code,
            criticality << 6,
            0x00, 0x00
        ])
        
        return pdu
    
    def _create_ngap_pdu_with_ie(self, procedure_code: int, ie_id: int) -> bytes:
        base = self._create_ngap_pdu(procedure_code)
        
        ie_value = b"\x00\x01\x02\x03"
        ie = struct.pack("!H", ie_id) + bytes([0x00]) + bytes([len(ie_value)]) + ie_value
        
        return base + ie

class DifferentialFuzzer:
    def __init__(
        self,
        targets: List[Tuple[str, int]],
        fuzzer_class: type,
        iface: Optional[str] = None
    ):
        self.targets = targets
        self.fuzzer_class = fuzzer_class
        self.iface = iface
        self.console = Console()
    
    def run(self, max_cases: int = 100) -> Dict[str, Any]:
        results: Dict[int, List[Tuple[str, Optional[bytes]]]] = {}
        
        logger.info(f"Differential fuzzing across {len(self.targets)} targets")
        
        reference_fuzzer = self.fuzzer_class(
            self.targets[0][0],
            self.targets[0][1],
            iface=self.iface
        )
        
        for case in reference_fuzzer.generate_cases(max_cases):
            results[case.case_id] = []
            
            for target_ip, target_port in self.targets:
                fuzzer = self.fuzzer_class(target_ip, target_port, iface=self.iface)
                resp, _, _ = fuzzer.send_and_receive(case.input_data)
                results[case.case_id].append((f"{target_ip}:{target_port}", resp))
        
        discrepancies = []
        for case_id, responses in results.items():
            unique_responses = set()
            for _, resp in responses:
                if resp:
                    unique_responses.add(resp[:32])
                else:
                    unique_responses.add(b"<no_response>")
            
            if len(unique_responses) > 1:
                discrepancies.append({
                    "case_id": case_id,
                    "responses": responses
                })
        
        self._print_differential_results(discrepancies)
        
        return {
            "total_cases": max_cases,
            "discrepancies": len(discrepancies),
            "details": discrepancies
        }
    
    def _print_differential_results(self, discrepancies: List[Dict]):
        self.console.print(f"\n[bold cyan]Differential Fuzzing Results[/bold cyan]")
        self.console.print(f"Discrepancies found: {len(discrepancies)}")
        
        if discrepancies:
            table = Table(title="Response Discrepancies")
            table.add_column("Case ID", style="cyan")
            table.add_column("Target", style="green")
            table.add_column("Response", style="yellow")
            
            for d in discrepancies[:10]:
                for target, resp in d["responses"]:
                    resp_str = resp[:16].hex() if resp else "No response"
                    table.add_row(str(d["case_id"]), target, resp_str)
                table.add_row("---", "---", "---")
            
            self.console.print(table)

def run_gtp_fuzzing(target_ip: str, max_cases: int = 1000) -> FuzzCampaign:
    fuzzer = GTPFuzzer(target_ip)
    return fuzzer.run_campaign(max_cases=max_cases)

def run_pfcp_fuzzing(target_ip: str, max_cases: int = 1000) -> FuzzCampaign:
    fuzzer = PFCPFuzzer(target_ip)
    return fuzzer.run_campaign(max_cases=max_cases)

def run_ngap_fuzzing(target_ip: str, max_cases: int = 1000) -> FuzzCampaign:
    fuzzer = NGAPFuzzer(target_ip)
    return fuzzer.run_campaign(max_cases=max_cases)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Protocol Fuzzing")
    parser.add_argument("protocol", choices=["gtp", "pfcp", "ngap", "differential"])
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--port", "-p", type=int)
    parser.add_argument("--cases", "-c", type=int, default=1000)
    parser.add_argument("--targets", nargs="+", help="Multiple targets for differential fuzzing")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    if args.protocol == "gtp":
        run_gtp_fuzzing(args.target, args.cases)
    elif args.protocol == "pfcp":
        run_pfcp_fuzzing(args.target, args.cases)
    elif args.protocol == "ngap":
        run_ngap_fuzzing(args.target, args.cases)
    elif args.protocol == "differential":
        if args.targets:
            targets = [(t.split(":")[0], int(t.split(":")[1])) for t in args.targets]
            diff = DifferentialFuzzer(targets, GTPFuzzer)
            diff.run(args.cases)


async def async_fuzz_batch(fuzzer: 'BaseFuzzer', cases: List[FuzzCase], 
                           concurrency: int = 10, callback: Optional[Callable] = None) -> List[FuzzResult]:
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    
    async def fuzz_one(case: FuzzCase) -> FuzzResult:
        async with semaphore:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, fuzzer.fuzz_case, case)
            if callback:
                callback(result)
            return result
    
    tasks = [fuzz_one(case) for case in cases]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, FuzzResult)]


def run_async_fuzzing(fuzzer: 'BaseFuzzer', num_cases: int = 100, concurrency: int = 10) -> List[FuzzResult]:
    cases = list(fuzzer.generate_cases(num_cases))
    return asyncio.run(async_fuzz_batch(fuzzer, cases, concurrency))


def send_gtp_fuzz_packet(target_ip: str, teid: int, payload: bytes, iface: Optional[str] = None) -> bool:
    if not SCAPY_AVAILABLE:
        return False
    conf.verb = 0
    pkt = IP(dst=target_ip) / UDP(dport=2152) / GTPHeader(teid=teid, gtp_type=255) / Raw(load=payload)
    send(pkt, iface=iface, verbose=0)
    return True


def send_tcp_fuzz_packet(target_ip: str, target_port: int, payload: bytes, iface: Optional[str] = None) -> bool:
    if not SCAPY_AVAILABLE:
        return False
    conf.verb = 0
    pkt = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=payload)
    send(pkt, iface=iface, verbose=0)
    return True

