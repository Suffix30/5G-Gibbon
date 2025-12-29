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
from typing import List, Dict, Optional, Any, Callable, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from core.async_utils import run_in_executor, AsyncRateLimiter
from core.adaptive_rate import AdaptiveRateLimiter
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.console import Console

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1
    from scapy.config import conf
    from scapy.layers.sctp import SCTP
    from scapy.contrib.gtp import GTPHeader

try:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import send, sr1
    from scapy.config import conf
    from scapy.layers.sctp import SCTP
    from scapy.contrib.gtp import GTPHeader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class FuzzStrategy(Enum):
    RANDOM = "random"
    MUTATION = "mutation"
    GENERATION = "generation"
    BOUNDARY = "boundary"
    FORMAT_STRING = "format_string"
    OVERFLOW = "overflow"

@dataclass
class FuzzCase:
    id: int
    strategy: FuzzStrategy
    field: str
    original_value: Any
    fuzzed_value: Any
    payload: bytes

@dataclass
class FuzzResult:
    case: FuzzCase
    success: bool
    response: Optional[bytes] = None
    response_time: float = 0.0
    error: Optional[str] = None
    interesting: bool = False
    reason: str = ""

@dataclass
class FuzzStats:
    total_cases: int = 0
    sent: int = 0
    responses: int = 0
    crashes: int = 0
    interesting: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate(self) -> float:
        if self.elapsed > 0:
            return self.sent / self.elapsed
        return 0.0

class FieldMutator:
    @staticmethod
    def mutate_int(value: int, bits: int = 32) -> List[int]:
        max_val = (1 << bits) - 1
        mutations = [
            0,
            1,
            max_val,
            max_val - 1,
            value + 1,
            value - 1 if value > 0 else 0,
            value ^ 0xFF,
            value ^ 0xFFFF,
            value << 1 & max_val,
            value >> 1,
            random.randint(0, max_val),
            0x7FFFFFFF if bits >= 32 else max_val // 2,
            0x80000000 if bits >= 32 else (max_val // 2) + 1,
        ]
        return list(set(mutations))
    
    @staticmethod
    def mutate_bytes(data: bytes, max_mutations: int = 20) -> List[bytes]:
        if not data:
            return [b"\x00", b"\xff", b"\x00" * 100]
        
        mutations = []
        
        mutations.append(b"")
        mutations.append(b"\x00")
        mutations.append(b"\xff")
        mutations.append(data + b"\x00" * 100)
        mutations.append(data * 10)
        
        if len(data) > 0:
            mutated = bytearray(data)
            mutated[0] = 0x00
            mutations.append(bytes(mutated))
            
            mutated = bytearray(data)
            mutated[0] = 0xFF
            mutations.append(bytes(mutated))
            
            mutated = bytearray(data)
            mutated[-1] = 0x00
            mutations.append(bytes(mutated))
        
        for _ in range(min(5, max_mutations)):
            mutated = bytearray(data)
            if len(mutated) > 0:
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.randint(0, 255)
                mutations.append(bytes(mutated))
        
        for _ in range(3):
            length = random.randint(1, 1000)
            mutations.append(bytes([random.randint(0, 255) for _ in range(length)]))
        
        return mutations[:max_mutations]
    
    @staticmethod
    def boundary_values(bits: int = 32) -> List[int]:
        values = [0, 1]
        
        for b in [8, 16, 24, 32]:
            if b <= bits:
                max_val = (1 << b) - 1
                values.extend([max_val, max_val - 1, max_val + 1 if b < bits else max_val])
                values.extend([1 << (b - 1), (1 << (b - 1)) - 1])
        
        return list(set(values))
    
    @staticmethod
    def format_strings() -> List[bytes]:
        return [
            b"%s" * 10,
            b"%n" * 10,
            b"%x" * 20,
            b"%.1000d",
            b"%p" * 10,
            b"AAAA%08x.%08x.%08x.%08x",
            b"%s%s%s%s%s%s%s%s%s%s",
        ]
    
    @staticmethod
    def overflow_payloads(base_size: int = 100) -> List[bytes]:
        return [
            b"A" * base_size,
            b"A" * (base_size * 10),
            b"A" * (base_size * 100),
            b"\x00" * base_size,
            b"\xff" * base_size,
            b"A" * 65535,
            b"A" * 65536,
        ]

class GTPFuzzer:
    def __init__(
        self,
        target_ip: str,
        target_port: int = 2152,
        iface: Optional[str] = None,
        timeout: float = 2.0
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface
        self.timeout = timeout
        self.stats = FuzzStats()
        self.interesting_results: List[FuzzResult] = []
        self._cancel = False
    
    def _craft_base_packet(self, teid: int = 1, gtp_type: int = 255, payload: bytes = b"") -> bytes:
        if SCAPY_AVAILABLE:
            pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / GTPHeader(teid=teid, gtp_type=gtp_type) / Raw(load=payload)
            return bytes(pkt)
        
        gtp_header = struct.pack(">BBHI",
            0x30,
            gtp_type,
            len(payload),
            teid
        )
        return gtp_header + payload
    
    def _generate_payload(self, options: Dict) -> bytes:
        strategy = options.get("strategy", "random")
        if strategy == "random":
            teid = random.randint(0, 0xFFFFFFFF)
            gtp_type = random.choice([1, 26, 255])
            payload_len = random.randint(0, 100)
            payload = bytes([random.randint(0, 255) for _ in range(payload_len)])
            return self._craft_base_packet(teid=teid, gtp_type=gtp_type, payload=payload)
        elif strategy == "mutation":
            cases = self.generate_fuzz_cases(FuzzStrategy.MUTATION)
            if cases:
                return random.choice(cases).payload
        return self._craft_base_packet()
    
    def _send_packet(self, payload: bytes) -> Optional[bytes]:
        if not SCAPY_AVAILABLE:
            return None
        try:
            pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=payload)
            conf.verb = 0
            resp = sr1(pkt, timeout=self.timeout, iface=self.iface, verbose=0)
            if resp and resp.haslayer(Raw):
                return bytes(resp[Raw])
            return None
        except Exception:
            return None
    
    def generate_fuzz_cases(self, strategy: FuzzStrategy = FuzzStrategy.MUTATION) -> List[FuzzCase]:
        cases = []
        case_id = 0
        
        for teid in FieldMutator.mutate_int(1, 32):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="teid",
                original_value=1,
                fuzzed_value=teid,
                payload=self._craft_base_packet(teid=teid)
            ))
            case_id += 1
        
        for gtp_type in FieldMutator.mutate_int(255, 8):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="gtp_type",
                original_value=255,
                fuzzed_value=gtp_type,
                payload=self._craft_base_packet(gtp_type=gtp_type)
            ))
            case_id += 1
        
        base_payload = b"\x00" * 20
        for mutated in FieldMutator.mutate_bytes(base_payload):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="payload",
                original_value=base_payload,
                fuzzed_value=mutated,
                payload=self._craft_base_packet(payload=mutated)
            ))
            case_id += 1
        
        if strategy == FuzzStrategy.BOUNDARY:
            for val in FieldMutator.boundary_values(32):
                cases.append(FuzzCase(
                    id=case_id,
                    strategy=strategy,
                    field="teid_boundary",
                    original_value=1,
                    fuzzed_value=val,
                    payload=self._craft_base_packet(teid=val)
                ))
                case_id += 1
        
        if strategy == FuzzStrategy.FORMAT_STRING:
            for fmt in FieldMutator.format_strings():
                cases.append(FuzzCase(
                    id=case_id,
                    strategy=strategy,
                    field="payload_format",
                    original_value=b"",
                    fuzzed_value=fmt,
                    payload=self._craft_base_packet(payload=fmt)
                ))
                case_id += 1
        
        if strategy == FuzzStrategy.OVERFLOW:
            for overflow in FieldMutator.overflow_payloads():
                cases.append(FuzzCase(
                    id=case_id,
                    strategy=strategy,
                    field="payload_overflow",
                    original_value=b"",
                    fuzzed_value=overflow,
                    payload=self._craft_base_packet(payload=overflow)
                ))
                case_id += 1
        
        return cases
    
    def _send_and_analyze(self, case: FuzzCase) -> FuzzResult:
        if not SCAPY_AVAILABLE:
            return FuzzResult(case=case, success=False, error="Scapy not available")
        
        start = time.time()
        result = FuzzResult(case=case, success=False)
        
        try:
            if len(case.payload) > 20:
                pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=case.payload[28:] if len(case.payload) > 28 else case.payload)
            else:
                pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / GTPHeader(teid=1, gtp_type=255)
            
            resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
            result.response_time = time.time() - start
            result.success = True
            
            if resp:
                result.response = bytes(resp)
                self.stats.responses += 1
                
                if self._is_interesting_response(resp, case):
                    result.interesting = True
                    result.reason = self._get_interesting_reason(resp, case)
                    self.stats.interesting += 1
                    self.interesting_results.append(result)
            
        except Exception as e:
            result.error = str(e)
            self.stats.errors += 1
            
            if "timeout" not in str(e).lower():
                result.interesting = True
                result.reason = f"Exception: {e}"
                self.stats.crashes += 1
                self.interesting_results.append(result)
        
        self.stats.sent += 1
        return result
    
    def _is_interesting_response(self, response: Any, case: FuzzCase) -> bool:
        if response.haslayer(Raw):
            raw_data = bytes(response[Raw])
            
            if b"error" in raw_data.lower():
                return True
            if b"invalid" in raw_data.lower():
                return True
            if b"denied" in raw_data.lower():
                return True
        
        if response.haslayer(GTPHeader):
            gtp = response[GTPHeader]
            if gtp.gtp_type in [26, 27, 28]:
                return True
        
        return False
    
    def _get_interesting_reason(self, response: Any, case: FuzzCase) -> str:
        reasons = []
        
        if response.haslayer(GTPHeader):
            gtp = response[GTPHeader]
            reasons.append(f"GTP type={gtp.gtp_type}")
        
        if response.haslayer(Raw):
            reasons.append(f"Has payload ({len(bytes(response[Raw]))} bytes)")
        
        return ", ".join(reasons) if reasons else "Unexpected response"
    
    def fuzz(
        self,
        strategy: FuzzStrategy = FuzzStrategy.MUTATION,
        max_cases: Optional[int] = None,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        self.stats = FuzzStats()
        self.interesting_results = []
        self._cancel = False
        
        cases = self.generate_fuzz_cases(strategy)
        if max_cases:
            cases = cases[:max_cases]
        
        self.stats.total_cases = len(cases)
        
        logger.info(f"GTP Fuzzing: {len(cases)} cases, strategy={strategy.value}")
        logger.info(f"Target: {self.target_ip}:{self.target_port}")
        
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Interesting: {task.fields[interesting]}"),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[yellow]Fuzzing GTP",
                        total=len(cases),
                        interesting=0
                    )
                    
                    for case in cases:
                        if self._cancel:
                            break
                        
                        self._send_and_analyze(case)
                        
                        progress.update(
                            task,
                            advance=1,
                            interesting=self.stats.interesting
                        )
            else:
                for case in cases:
                    if self._cancel:
                        break
                    self._send_and_analyze(case)
            
            logger.info(f"Fuzzing complete: {self.stats.sent} sent, {self.stats.interesting} interesting")
            
            return {
                "total_cases": self.stats.total_cases,
                "sent": self.stats.sent,
                "responses": self.stats.responses,
                "interesting": self.stats.interesting,
                "crashes": self.stats.crashes,
                "errors": self.stats.errors,
                "rate": self.stats.rate,
                "elapsed": self.stats.elapsed,
                "interesting_results": [
                    {
                        "case_id": r.case.id,
                        "field": r.case.field,
                        "reason": r.reason,
                        "fuzzed_value": str(r.case.fuzzed_value)[:100]
                    }
                    for r in self.interesting_results
                ]
            }
            
        except KeyboardInterrupt:
            self._cancel = True
            logger.warning("Fuzzing interrupted")
            return {"sent": self.stats.sent, "interesting": self.stats.interesting, "interrupted": True}
    
    def cancel(self):
        self._cancel = True

class PFCPFuzzer:
    def __init__(
        self,
        target_ip: str,
        target_port: int = 8805,
        iface: Optional[str] = None,
        timeout: float = 2.0
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface
        self.timeout = timeout
        self.stats = FuzzStats()
        self.interesting_results: List[FuzzResult] = []
        self._cancel = False
    
    def _craft_pfcp_packet(
        self,
        version: int = 1,
        message_type: int = 1,
        seid: int = 0,
        seq: int = 1,
        payload: bytes = b""
    ) -> bytes:
        flags = (version << 5) | 0x01
        length = 12 + len(payload)
        
        header = struct.pack(">BBHQBBB",
            flags,
            message_type,
            length,
            seid,
            seq >> 16,
            (seq >> 8) & 0xFF,
            seq & 0xFF
        )
        
        return header + payload
    
    def _generate_payload(self, options: Dict) -> bytes:
        strategy = options.get("strategy", "random")
        if strategy == "random":
            version = random.choice([1, 2])
            msg_type = random.choice([1, 2, 3, 4, 5, 6, 50, 51, 52])
            seid = random.randint(0, 0xFFFFFFFFFFFFFFFF)
            seq = random.randint(0, 0xFFFFFF)
            payload = bytes([random.randint(0, 255) for _ in range(random.randint(0, 50))])
            return self._craft_pfcp_packet(version, msg_type, seid, seq, payload)
        elif strategy == "mutation":
            cases = self.generate_fuzz_cases(FuzzStrategy.MUTATION)
            if cases:
                return random.choice(cases).payload
        return self._craft_pfcp_packet()
    
    def _send_packet(self, payload: bytes) -> Optional[bytes]:
        if not SCAPY_AVAILABLE:
            return None
        try:
            pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=payload)
            conf.verb = 0
            resp = sr1(pkt, timeout=self.timeout, iface=self.iface, verbose=0)
            if resp and resp.haslayer(Raw):
                return bytes(resp[Raw])
            return None
        except Exception:
            return None
    
    def generate_fuzz_cases(self, strategy: FuzzStrategy = FuzzStrategy.MUTATION) -> List[FuzzCase]:
        cases = []
        case_id = 0
        
        for version in FieldMutator.mutate_int(1, 3):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="version",
                original_value=1,
                fuzzed_value=version,
                payload=self._craft_pfcp_packet(version=version)
            ))
            case_id += 1
        
        for msg_type in FieldMutator.mutate_int(1, 8):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="message_type",
                original_value=1,
                fuzzed_value=msg_type,
                payload=self._craft_pfcp_packet(message_type=msg_type)
            ))
            case_id += 1
        
        for seid in FieldMutator.mutate_int(0, 64):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="seid",
                original_value=0,
                fuzzed_value=seid,
                payload=self._craft_pfcp_packet(seid=seid)
            ))
            case_id += 1
        
        base_ie = b"\x00\x3c\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01"
        for mutated in FieldMutator.mutate_bytes(base_ie):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="ie_payload",
                original_value=base_ie,
                fuzzed_value=mutated,
                payload=self._craft_pfcp_packet(payload=mutated)
            ))
            case_id += 1
        
        return cases
    
    def _send_and_analyze(self, case: FuzzCase) -> FuzzResult:
        if not SCAPY_AVAILABLE:
            return FuzzResult(case=case, success=False, error="Scapy not available")
        
        start = time.time()
        result = FuzzResult(case=case, success=False)
        
        try:
            pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=case.payload)
            
            resp = sr1(pkt, iface=self.iface, timeout=self.timeout, verbose=0)
            result.response_time = time.time() - start
            result.success = True
            
            if resp:
                result.response = bytes(resp)
                self.stats.responses += 1
                
                if resp.haslayer(Raw):
                    raw = bytes(resp[Raw])
                    if len(raw) > 0:
                        pfcp_type = raw[1] if len(raw) > 1 else 0
                        if pfcp_type in [2, 4, 6, 8, 10]:
                            result.interesting = True
                            result.reason = f"PFCP response type={pfcp_type}"
                            self.stats.interesting += 1
                            self.interesting_results.append(result)
            
        except Exception as e:
            result.error = str(e)
            self.stats.errors += 1
            
            if "timeout" not in str(e).lower():
                result.interesting = True
                result.reason = f"Exception: {e}"
                self.stats.crashes += 1
                self.interesting_results.append(result)
        
        self.stats.sent += 1
        return result
    
    def fuzz(
        self,
        strategy: FuzzStrategy = FuzzStrategy.MUTATION,
        max_cases: Optional[int] = None,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        self.stats = FuzzStats()
        self.interesting_results = []
        self._cancel = False
        
        cases = self.generate_fuzz_cases(strategy)
        if max_cases:
            cases = cases[:max_cases]
        
        self.stats.total_cases = len(cases)
        
        logger.info(f"PFCP Fuzzing: {len(cases)} cases, strategy={strategy.value}")
        
        console = Console() if show_progress else None
        
        try:
            if show_progress and console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Interesting: {task.fields[interesting]}"),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[yellow]Fuzzing PFCP",
                        total=len(cases),
                        interesting=0
                    )
                    
                    for case in cases:
                        if self._cancel:
                            break
                        
                        self._send_and_analyze(case)
                        progress.update(task, advance=1, interesting=self.stats.interesting)
            else:
                for case in cases:
                    if self._cancel:
                        break
                    self._send_and_analyze(case)
            
            return {
                "total_cases": self.stats.total_cases,
                "sent": self.stats.sent,
                "responses": self.stats.responses,
                "interesting": self.stats.interesting,
                "crashes": self.stats.crashes,
                "errors": self.stats.errors,
                "elapsed": self.stats.elapsed
            }
            
        except KeyboardInterrupt:
            self._cancel = True
            return {"sent": self.stats.sent, "interrupted": True}
    
    def cancel(self):
        self._cancel = True

class NGAPFuzzer:
    def __init__(
        self,
        target_ip: str,
        target_port: int = 38412,
        iface: Optional[str] = None,
        timeout: float = 3.0
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface
        self.timeout = timeout
        self.stats = FuzzStats()
        self.interesting_results: List[FuzzResult] = []
        self._cancel = False
    
    def _craft_ngap_pdu(
        self,
        procedure_code: int = 21,
        criticality: int = 0,
        pdu_type: int = 0,
        payload: bytes = b""
    ) -> bytes:
        pdu = struct.pack(">BBB",
            pdu_type,
            procedure_code,
            criticality
        ) + payload
        
        return pdu
    
    def _generate_payload(self, options: Dict) -> bytes:
        strategy = options.get("strategy", "random")
        if strategy == "random":
            proc_code = random.choice([14, 15, 21, 22, 23, 40, 41, 42])
            criticality = random.choice([0, 1, 2])
            pdu_type = random.choice([0, 1, 2])
            payload = bytes([random.randint(0, 255) for _ in range(random.randint(0, 100))])
            return self._craft_ngap_pdu(proc_code, criticality, pdu_type, payload)
        elif strategy == "mutation":
            cases = self.generate_fuzz_cases(FuzzStrategy.MUTATION)
            if cases:
                return random.choice(cases).payload
        return self._craft_ngap_pdu()
    
    def _send_packet(self, payload: bytes) -> Optional[bytes]:
        if not SCAPY_AVAILABLE:
            return None
        try:
            pkt = IP(dst=self.target_ip) / SCTP(dport=self.target_port) / Raw(load=payload)
            conf.verb = 0
            resp = send(pkt, iface=self.iface, verbose=0)
            return bytes(payload) if resp else None
        except Exception:
            return None
    
    def generate_fuzz_cases(self, strategy: FuzzStrategy = FuzzStrategy.MUTATION) -> List[FuzzCase]:
        cases = []
        case_id = 0
        
        for proc in FieldMutator.mutate_int(21, 8):
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="procedure_code",
                original_value=21,
                fuzzed_value=proc,
                payload=self._craft_ngap_pdu(procedure_code=proc)
            ))
            case_id += 1
        
        for crit in [0, 1, 2, 3, 255]:
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="criticality",
                original_value=0,
                fuzzed_value=crit,
                payload=self._craft_ngap_pdu(criticality=crit)
            ))
            case_id += 1
        
        for pdu_type in [0, 1, 2, 3, 255]:
            cases.append(FuzzCase(
                id=case_id,
                strategy=strategy,
                field="pdu_type",
                original_value=0,
                fuzzed_value=pdu_type,
                payload=self._craft_ngap_pdu(pdu_type=pdu_type)
            ))
            case_id += 1
        
        return cases
    
    def fuzz(
        self,
        strategy: FuzzStrategy = FuzzStrategy.MUTATION,
        max_cases: Optional[int] = None,
        show_progress: bool = True
    ) -> Dict[str, Any]:
        logger.warning("NGAP fuzzing requires SCTP transport - use with sctp_enhanced.py")
        
        cases = self.generate_fuzz_cases(strategy)
        
        return {
            "warning": "NGAP requires SCTP transport",
            "cases_generated": len(cases),
            "hint": "Use NGAPClient from protocol/sctp_enhanced.py"
        }

def fuzz_gtp(
    target_ip: str,
    strategy: FuzzStrategy = FuzzStrategy.MUTATION,
    max_cases: int = 100
) -> Dict[str, Any]:
    fuzzer = GTPFuzzer(target_ip)
    return fuzzer.fuzz(strategy, max_cases)

def fuzz_pfcp(
    target_ip: str,
    strategy: FuzzStrategy = FuzzStrategy.MUTATION,
    max_cases: int = 100
) -> Dict[str, Any]:
    fuzzer = PFCPFuzzer(target_ip)
    return fuzzer.fuzz(strategy, max_cases)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="5G Protocol Fuzzer")
    parser.add_argument("protocol", choices=["gtp", "pfcp", "ngap"])
    parser.add_argument("--target", "-t", required=True, help="Target IP")
    parser.add_argument("--port", "-p", type=int)
    parser.add_argument("--strategy", "-s", choices=["mutation", "boundary", "overflow", "format_string"], default="mutation")
    parser.add_argument("--max-cases", "-m", type=int, default=100)
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    strategy_map = {
        "mutation": FuzzStrategy.MUTATION,
        "boundary": FuzzStrategy.BOUNDARY,
        "overflow": FuzzStrategy.OVERFLOW,
        "format_string": FuzzStrategy.FORMAT_STRING
    }
    strategy = strategy_map[args.strategy]
    
    if args.protocol == "gtp":
        port = args.port or 2152
        fuzzer = GTPFuzzer(args.target, port)
        result = fuzzer.fuzz(strategy, args.max_cases)
    elif args.protocol == "pfcp":
        port = args.port or 8805
        fuzzer = PFCPFuzzer(args.target, port)
        result = fuzzer.fuzz(strategy, args.max_cases)
    else:
        fuzzer = NGAPFuzzer(args.target, args.port or 38412)
        result = fuzzer.fuzz(strategy, args.max_cases)
    
    print(f"\nResults: {result}")


async def async_fuzz_protocol(target_ip: str, protocol: str, max_cases: int = 100, 
                              concurrency: int = 10, callback: Optional[Callable] = None) -> Tuple[int, int]:
    rate_limiter = AsyncRateLimiter(rate_limit=100)
    adaptive = AdaptiveRateLimiter()
    
    port = {"gtp": 2152, "pfcp": 8805, "ngap": 38412}.get(protocol, 2152)
    
    if protocol == "gtp":
        fuzzer = GTPFuzzer(target_ip, port)
    elif protocol == "pfcp":
        fuzzer = PFCPFuzzer(target_ip, port)
    else:
        fuzzer = NGAPFuzzer(target_ip, port)
    
    conf.verb = 0
    successes = 0
    failures = 0
    
    async def fuzz_one(case_idx: int) -> bool:
        nonlocal successes, failures
        async with rate_limiter:
            payload = fuzzer._generate_payload({"strategy": "random"})
            result = await run_in_executor(fuzzer._send_packet, payload)
            
            adaptive.record_response(len(payload), 0.1, success=result is not None)
            
            if result is not None:
                successes += 1
                if callback:
                    callback(case_idx, True, result)
                return True
            else:
                failures += 1
                if callback:
                    callback(case_idx, False, None)
                return False
    
    tasks = [fuzz_one(i) for i in range(max_cases)]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return successes, failures


def run_async_fuzzing(target_ip: str, protocol: str, max_cases: int = 100) -> Tuple[int, int]:
    return asyncio.run(async_fuzz_protocol(target_ip, protocol, max_cases))

