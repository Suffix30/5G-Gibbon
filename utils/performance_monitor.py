#!/usr/bin/env python3
import time
import logging
from collections import deque
from threading import Lock

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.metrics = {
            "packets_per_second": deque(maxlen=window_size),
            "bytes_per_second": deque(maxlen=window_size),
            "response_rate": deque(maxlen=window_size),
            "cpu_usage": deque(maxlen=window_size),
            "memory_usage": deque(maxlen=window_size),
        }
        self.lock = Lock()
        self.start_time = None
        self.total_packets = 0
        self.total_bytes = 0
        self.total_responses = 0
    
    def start(self):
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.total_responses = 0
    
    def record_packet(self, packet_size=0, is_response=False):
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet_size
            if is_response:
                self.total_responses += 1
    
    def update_metrics(self):
        if not self.start_time:
            return
        
        elapsed = time.time() - self.start_time
        if elapsed < 0.1:
            return
        
        with self.lock:
            pps = self.total_packets / elapsed
            bps = self.total_bytes / elapsed
            resp_rate = (self.total_responses / self.total_packets * 100) if self.total_packets > 0 else 0
            
            self.metrics["packets_per_second"].append(pps)
            self.metrics["bytes_per_second"].append(bps)
            self.metrics["response_rate"].append(resp_rate)
            
            if PSUTIL_AVAILABLE and psutil:
                try:
                    self.metrics["cpu_usage"].append(psutil.cpu_percent(interval=0.1))
                    self.metrics["memory_usage"].append(psutil.virtual_memory().percent)
                except Exception:
                    pass
    
    def get_current_stats(self):
        with self.lock:
            if not self.metrics["packets_per_second"]:
                return {
                    "pps": 0,
                    "bps": 0,
                    "response_rate": 0,
                    "cpu": 0,
                    "memory": 0
                }
            
            return {
                "pps": sum(self.metrics["packets_per_second"]) / len(self.metrics["packets_per_second"]),
                "bps": sum(self.metrics["bytes_per_second"]) / len(self.metrics["bytes_per_second"]),
                "response_rate": sum(self.metrics["response_rate"]) / len(self.metrics["response_rate"]),
                "cpu": sum(self.metrics["cpu_usage"]) / len(self.metrics["cpu_usage"]) if self.metrics["cpu_usage"] else 0,
                "memory": sum(self.metrics["memory_usage"]) / len(self.metrics["memory_usage"]) if self.metrics["memory_usage"] else 0
            }
    
    def get_summary(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        stats = self.get_current_stats()
        
        return {
            "duration": elapsed,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_responses": self.total_responses,
            "average_pps": stats["pps"],
            "average_bps": stats["bps"],
            "response_rate": stats["response_rate"],
            "cpu_usage": stats["cpu"],
            "memory_usage": stats["memory"]
        }

