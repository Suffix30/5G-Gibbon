#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import time
import logging
import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from collections import deque
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    RATE_SPIKE = "rate_spike"
    RATE_DROP = "rate_drop"
    SIZE_ANOMALY = "size_anomaly"
    PROTOCOL_VIOLATION = "protocol_violation"
    PATTERN_DEVIATION = "pattern_deviation"
    SOURCE_ANOMALY = "source_anomaly"
    TEID_ANOMALY = "teid_anomaly"
    SEID_ANOMALY = "seid_anomaly"
    TIME_ANOMALY = "time_anomaly"


class SeverityLevel(Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class TrafficSample:
    timestamp: float
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    size: int
    teid: Optional[int] = None
    seid: Optional[int] = None
    msg_type: Optional[int] = None


@dataclass
class Anomaly:
    timestamp: str
    anomaly_type: AnomalyType
    severity: SeverityLevel
    description: str
    source_ip: Optional[str] = None
    details: Dict = field(default_factory=dict)
    recommended_action: str = ""


@dataclass
class BaselineMetrics:
    avg_rate: float = 0.0
    std_rate: float = 0.0
    avg_size: float = 0.0
    std_size: float = 0.0
    common_sources: Dict[str, int] = field(default_factory=dict)
    common_teids: Dict[int, int] = field(default_factory=dict)
    common_seids: Dict[int, int] = field(default_factory=dict)
    hour_distribution: Dict[int, float] = field(default_factory=dict)


class RollingWindow:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.samples: deque = deque()
        
    def add(self, value: float, timestamp: Optional[float] = None):
        ts = timestamp or time.time()
        self.samples.append((ts, value))
        self._cleanup(ts)
    
    def _cleanup(self, current_time: float):
        cutoff = current_time - self.window_seconds
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()
    
    def get_values(self) -> List[float]:
        self._cleanup(time.time())
        return [v for _, v in self.samples]
    
    def get_rate(self) -> float:
        self._cleanup(time.time())
        return len(self.samples) / self.window_seconds if self.samples else 0
    
    def get_stats(self) -> Tuple[float, float]:
        values = self.get_values()
        if not values:
            return 0.0, 0.0
        avg = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        return avg, std


class SourceTracker:
    def __init__(self, max_sources: int = 1000):
        self.sources: Dict[str, RollingWindow] = {}
        self.max_sources = max_sources
        
    def record(self, source_ip: str):
        if source_ip not in self.sources:
            if len(self.sources) >= self.max_sources:
                oldest = min(self.sources.items(), key=lambda x: x[1].samples[0][0] if x[1].samples else float('inf'))
                del self.sources[oldest[0]]
            self.sources[source_ip] = RollingWindow(60)
        self.sources[source_ip].add(1)
    
    def get_top_sources(self, n: int = 10) -> List[Tuple[str, float]]:
        rates = [(ip, window.get_rate()) for ip, window in self.sources.items()]
        return sorted(rates, key=lambda x: x[1], reverse=True)[:n]
    
    def get_source_rate(self, source_ip: str) -> float:
        if source_ip in self.sources:
            return self.sources[source_ip].get_rate()
        return 0.0


class Anomaly5GDetector:
    def __init__(self, sensitivity: float = 2.0, learning_period: int = 300):
        self.sensitivity = sensitivity
        self.learning_period = learning_period
        self.start_time = time.time()
        self.is_learning = True
        
        self.gtp_window = RollingWindow(60)
        self.pfcp_window = RollingWindow(60)
        self.ngap_window = RollingWindow(60)
        self.sbi_window = RollingWindow(60)
        
        self.size_window = RollingWindow(300)
        
        self.gtp_sources = SourceTracker()
        self.pfcp_sources = SourceTracker()
        self.ngap_sources = SourceTracker()
        
        self.baselines: Dict[str, BaselineMetrics] = {
            "gtp": BaselineMetrics(),
            "pfcp": BaselineMetrics(),
            "ngap": BaselineMetrics(),
            "sbi": BaselineMetrics()
        }
        
        self.anomalies: List[Anomaly] = []
        self.sample_count = 0
        
        self.learning_rates: Dict[str, List[float]] = {"gtp": [], "pfcp": [], "ngap": [], "sbi": []}
        self.learning_sizes: List[int] = []
        
    def process_sample(self, sample: TrafficSample) -> Optional[Anomaly]:
        self.sample_count += 1
        
        if time.time() - self.start_time < self.learning_period:
            self._learn(sample)
            if time.time() - self.start_time >= self.learning_period:
                self._finalize_learning()
            return None
        
        return self._detect(sample)
    
    def _learn(self, sample: TrafficSample):
        protocol = sample.protocol.lower()
        
        if protocol in self.learning_rates:
            self.learning_rates[protocol].append(1)
        
        self.learning_sizes.append(sample.size)
        
        if protocol == "gtp":
            if sample.teid:
                self.baselines["gtp"].common_teids[sample.teid] = \
                    self.baselines["gtp"].common_teids.get(sample.teid, 0) + 1
        elif protocol == "pfcp":
            if sample.seid:
                self.baselines["pfcp"].common_seids[sample.seid] = \
                    self.baselines["pfcp"].common_seids.get(sample.seid, 0) + 1
        
        for proto in self.baselines:
            self.baselines[proto].common_sources[sample.source_ip] = \
                self.baselines[proto].common_sources.get(sample.source_ip, 0) + 1
    
    def _finalize_learning(self):
        self.is_learning = False
        logger.info("Learning period complete, establishing baselines...")
        
        for proto, rates in self.learning_rates.items():
            if rates:
                baseline = self.baselines[proto]
                rate_per_second = len(rates) / self.learning_period
                baseline.avg_rate = rate_per_second
                baseline.std_rate = rate_per_second * 0.3
        
        if self.learning_sizes:
            for proto in self.baselines:
                self.baselines[proto].avg_size = statistics.mean(self.learning_sizes)
                self.baselines[proto].std_size = statistics.stdev(self.learning_sizes) if len(self.learning_sizes) > 1 else 0
        
        logger.info(f"Baselines established:")
        for proto, baseline in self.baselines.items():
            logger.info(f"  {proto.upper()}: rate={baseline.avg_rate:.2f}/s, size={baseline.avg_size:.0f}b")
    
    def _detect(self, sample: TrafficSample) -> Optional[Anomaly]:
        protocol = sample.protocol.lower()
        
        if protocol == "gtp":
            self.gtp_window.add(1)
            self.gtp_sources.record(sample.source_ip)
            window = self.gtp_window
        elif protocol == "pfcp":
            self.pfcp_window.add(1)
            self.pfcp_sources.record(sample.source_ip)
            window = self.pfcp_window
        elif protocol == "ngap":
            self.ngap_window.add(1)
            self.ngap_sources.record(sample.source_ip)
            window = self.ngap_window
        elif protocol == "sbi":
            self.sbi_window.add(1)
            window = self.sbi_window
        else:
            return None
        
        self.size_window.add(sample.size)
        
        anomaly = self._check_rate_anomaly(protocol, window)
        if anomaly:
            return anomaly
        
        anomaly = self._check_size_anomaly(protocol, sample)
        if anomaly:
            return anomaly
        
        anomaly = self._check_source_anomaly(protocol, sample)
        if anomaly:
            return anomaly
        
        if protocol == "gtp" and sample.teid:
            anomaly = self._check_teid_anomaly(sample)
            if anomaly:
                return anomaly
        
        if protocol == "pfcp" and sample.seid:
            anomaly = self._check_seid_anomaly(sample)
            if anomaly:
                return anomaly
        
        return None
    
    def _check_rate_anomaly(self, protocol: str, window: RollingWindow) -> Optional[Anomaly]:
        baseline = self.baselines.get(protocol)
        if not baseline or baseline.avg_rate == 0:
            return None
        
        current_rate = window.get_rate()
        threshold_high = baseline.avg_rate + (self.sensitivity * baseline.std_rate)
        threshold_low = max(0, baseline.avg_rate - (self.sensitivity * baseline.std_rate))
        
        if current_rate > threshold_high * 2:
            severity = SeverityLevel.CRITICAL
            anomaly_type = AnomalyType.RATE_SPIKE
            desc = f"{protocol.upper()} traffic spike: {current_rate:.1f}/s (baseline: {baseline.avg_rate:.1f}/s)"
            action = f"Investigate potential DoS attack on {protocol.upper()} interface"
        elif current_rate > threshold_high:
            severity = SeverityLevel.HIGH
            anomaly_type = AnomalyType.RATE_SPIKE
            desc = f"{protocol.upper()} elevated traffic: {current_rate:.1f}/s (baseline: {baseline.avg_rate:.1f}/s)"
            action = "Monitor for sustained increase"
        elif current_rate < threshold_low and baseline.avg_rate > 1:
            severity = SeverityLevel.MEDIUM
            anomaly_type = AnomalyType.RATE_DROP
            desc = f"{protocol.upper()} traffic drop: {current_rate:.1f}/s (baseline: {baseline.avg_rate:.1f}/s)"
            action = "Check network connectivity and component health"
        else:
            return None
        
        anomaly = Anomaly(
            timestamp=datetime.now().isoformat(),
            anomaly_type=anomaly_type,
            severity=severity,
            description=desc,
            details={
                "protocol": protocol,
                "current_rate": current_rate,
                "baseline_rate": baseline.avg_rate,
                "threshold_high": threshold_high
            },
            recommended_action=action
        )
        self.anomalies.append(anomaly)
        return anomaly
    
    def _check_size_anomaly(self, protocol: str, sample: TrafficSample) -> Optional[Anomaly]:
        baseline = self.baselines.get(protocol)
        if not baseline or baseline.avg_size == 0:
            return None
        
        z_score = abs(sample.size - baseline.avg_size) / max(baseline.std_size, 1)
        
        if z_score > self.sensitivity * 3:
            anomaly = Anomaly(
                timestamp=datetime.now().isoformat(),
                anomaly_type=AnomalyType.SIZE_ANOMALY,
                severity=SeverityLevel.HIGH if sample.size > baseline.avg_size else SeverityLevel.MEDIUM,
                description=f"Unusual packet size: {sample.size}b (avg: {baseline.avg_size:.0f}b)",
                source_ip=sample.source_ip,
                details={
                    "size": sample.size,
                    "avg_size": baseline.avg_size,
                    "z_score": z_score
                },
                recommended_action="Investigate for potential buffer overflow or fragmentation attack"
            )
            self.anomalies.append(anomaly)
            return anomaly
        
        return None
    
    def _check_source_anomaly(self, protocol: str, sample: TrafficSample) -> Optional[Anomaly]:
        baseline = self.baselines.get(protocol)
        if not baseline:
            return None
        
        if sample.source_ip not in baseline.common_sources:
            if protocol == "gtp":
                tracker = self.gtp_sources
            elif protocol == "pfcp":
                tracker = self.pfcp_sources
            elif protocol == "ngap":
                tracker = self.ngap_sources
            else:
                return None
            
            source_rate = tracker.get_source_rate(sample.source_ip)
            if source_rate > 10:
                anomaly = Anomaly(
                    timestamp=datetime.now().isoformat(),
                    anomaly_type=AnomalyType.SOURCE_ANOMALY,
                    severity=SeverityLevel.HIGH,
                    description=f"New high-rate source detected: {sample.source_ip} ({source_rate:.1f}/s)",
                    source_ip=sample.source_ip,
                    details={
                        "protocol": protocol,
                        "rate": source_rate,
                        "is_new_source": True
                    },
                    recommended_action="Verify source legitimacy, potential rogue network element"
                )
                self.anomalies.append(anomaly)
                return anomaly
        
        return None
    
    def _check_teid_anomaly(self, sample: TrafficSample) -> Optional[Anomaly]:
        baseline = self.baselines.get("gtp")
        if not baseline or not sample.teid:
            return None
        
        if sample.teid not in baseline.common_teids:
            anomaly = Anomaly(
                timestamp=datetime.now().isoformat(),
                anomaly_type=AnomalyType.TEID_ANOMALY,
                severity=SeverityLevel.MEDIUM,
                description=f"Unknown TEID observed: {sample.teid}",
                source_ip=sample.source_ip,
                details={
                    "teid": sample.teid,
                    "known_teids_count": len(baseline.common_teids)
                },
                recommended_action="Verify TEID ownership, potential tunnel enumeration"
            )
            self.anomalies.append(anomaly)
            return anomaly
        
        return None
    
    def _check_seid_anomaly(self, sample: TrafficSample) -> Optional[Anomaly]:
        baseline = self.baselines.get("pfcp")
        if not baseline or not sample.seid:
            return None
        
        if sample.seid not in baseline.common_seids:
            anomaly = Anomaly(
                timestamp=datetime.now().isoformat(),
                anomaly_type=AnomalyType.SEID_ANOMALY,
                severity=SeverityLevel.MEDIUM,
                description=f"Unknown SEID observed: {sample.seid}",
                source_ip=sample.source_ip,
                details={
                    "seid": sample.seid,
                    "known_seids_count": len(baseline.common_seids)
                },
                recommended_action="Verify SEID ownership, potential session enumeration"
            )
            self.anomalies.append(anomaly)
            return anomaly
        
        return None
    
    def get_statistics(self) -> Dict:
        by_type = {}
        by_severity = {}
        by_source = {}
        
        for a in self.anomalies:
            by_type[a.anomaly_type.value] = by_type.get(a.anomaly_type.value, 0) + 1
            by_severity[a.severity.name] = by_severity.get(a.severity.name, 0) + 1
            if a.source_ip:
                by_source[a.source_ip] = by_source.get(a.source_ip, 0) + 1
        
        return {
            "total_samples": self.sample_count,
            "total_anomalies": len(self.anomalies),
            "anomaly_rate": len(self.anomalies) / max(self.sample_count, 1),
            "by_type": by_type,
            "by_severity": by_severity,
            "top_sources": dict(sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:10]),
            "is_learning": self.is_learning,
            "current_rates": {
                "gtp": self.gtp_window.get_rate(),
                "pfcp": self.pfcp_window.get_rate(),
                "ngap": self.ngap_window.get_rate(),
                "sbi": self.sbi_window.get_rate()
            }
        }
    
    def export_anomalies(self, filename: str = "anomalies.json"):
        data = []
        for a in self.anomalies:
            d = {
                "timestamp": a.timestamp,
                "type": a.anomaly_type.value,
                "severity": a.severity.name,
                "description": a.description,
                "source_ip": a.source_ip,
                "details": a.details,
                "recommended_action": a.recommended_action
            }
            data.append(d)
        
        with open(filename, 'w') as f:
            json.dump({
                "statistics": self.get_statistics(),
                "anomalies": data
            }, f, indent=2)
        
        return filename
    
    def get_recent_anomalies(self, minutes: int = 5) -> List[Anomaly]:
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [a for a in self.anomalies if datetime.fromisoformat(a.timestamp) > cutoff]


class RealtimeAnomalyMonitor:
    def __init__(self, detector: Anomaly5GDetector):
        self.detector = detector
        self.alert_handlers: List[Callable] = []
        
    def add_alert_handler(self, handler: Callable):
        self.alert_handlers.append(handler)
    
    def process_packet(self, packet_data: Dict) -> Optional[Anomaly]:
        sample = TrafficSample(
            timestamp=packet_data.get("timestamp", time.time()),
            source_ip=packet_data.get("source_ip", "0.0.0.0"),
            dest_ip=packet_data.get("dest_ip", "0.0.0.0"),
            protocol=packet_data.get("protocol", "unknown"),
            port=packet_data.get("port", 0),
            size=packet_data.get("size", 0),
            teid=packet_data.get("teid"),
            seid=packet_data.get("seid"),
            msg_type=packet_data.get("msg_type")
        )
        
        anomaly = self.detector.process_sample(sample)
        
        if anomaly and anomaly.severity.value >= SeverityLevel.HIGH.value:
            for handler in self.alert_handlers:
                try:
                    handler(anomaly)
                except Exception as e:
                    logger.error(f"Alert handler error: {e}")
        
        return anomaly


def demo_anomaly_detection():
    import random
    
    logger.info("Starting anomaly detection demo (5-second learning, then detection)...")
    
    detector = Anomaly5GDetector(sensitivity=2.0, learning_period=5)
    
    normal_sources = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    
    logger.info("Learning phase...")
    for _ in range(50):
        sample = TrafficSample(
            timestamp=time.time(),
            source_ip=random.choice(normal_sources),
            dest_ip="192.168.1.1",
            protocol="gtp",
            port=2152,
            size=random.randint(100, 500),
            teid=random.randint(1, 100)
        )
        detector.process_sample(sample)
        time.sleep(0.1)
    
    time.sleep(1)
    
    logger.info("\nDetection phase - injecting anomalies...")
    
    attack_source = "192.168.100.100"
    for _ in range(20):
        sample = TrafficSample(
            timestamp=time.time(),
            source_ip=attack_source,
            dest_ip="192.168.1.1",
            protocol="gtp",
            port=2152,
            size=5000,
            teid=99999
        )
        anomaly = detector.process_sample(sample)
        if anomaly:
            logger.warning(f"ANOMALY: {anomaly.description}")
        time.sleep(0.05)
    
    stats = detector.get_statistics()
    logger.info(f"\nDetection Statistics:\n{json.dumps(stats, indent=2)}")
    
    detector.export_anomalies()
    logger.info("\nAnomalies exported to anomalies.json")
    
    return detector


if __name__ == "__main__":
    demo_anomaly_detection()

