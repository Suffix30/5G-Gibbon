#!/usr/bin/env python3
import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Deque, List, Callable, Any, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

class RateLimitState(Enum):
    NORMAL = "normal"
    THROTTLED = "throttled"
    BACKING_OFF = "backing_off"
    PROBING = "probing"
    RATE_LIMITED = "rate_limited"

@dataclass
class RateLimitMetrics:
    requests_sent: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    rate_limit_hits: int = 0
    timeouts: int = 0
    current_rate: float = 0.0
    target_rate: float = 0.0
    window_start: float = field(default_factory=time.time)
    
    @property
    def success_rate(self) -> float:
        if self.requests_sent > 0:
            return self.requests_successful / self.requests_sent * 100
        return 100.0
    
    @property
    def failure_rate(self) -> float:
        if self.requests_sent > 0:
            return self.requests_failed / self.requests_sent * 100
        return 0.0
    
    def reset_window(self):
        self.requests_sent = 0
        self.requests_successful = 0
        self.requests_failed = 0
        self.rate_limit_hits = 0
        self.timeouts = 0
        self.window_start = time.time()

class AdaptiveRateLimiter:
    def __init__(
        self,
        initial_rate: float = 100.0,
        min_rate: float = 1.0,
        max_rate: float = 10000.0,
        burst: int = 20,
        increase_factor: float = 1.2,
        decrease_factor: float = 0.5,
        success_threshold: float = 95.0,
        failure_threshold: float = 10.0,
        window_size: float = 5.0,
        probe_interval: float = 30.0
    ):
        self.initial_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.burst = burst
        self.increase_factor = increase_factor
        self.decrease_factor = decrease_factor
        self.success_threshold = success_threshold
        self.failure_threshold = failure_threshold
        self.window_size = window_size
        self.probe_interval = probe_interval
        
        self.current_rate = initial_rate
        self.tokens = float(burst)
        self.last_update = time.monotonic()
        self.state = RateLimitState.NORMAL
        self.metrics = RateLimitMetrics(target_rate=initial_rate)
        self.last_probe = time.time()
        self.backoff_until = 0.0
        
        self._response_times: Deque[float] = deque(maxlen=100)
        self._lock = asyncio.Lock()
        self._callbacks: List[Callable[[RateLimitState, float], Any]] = []
    
    def add_state_callback(self, callback: Callable[[RateLimitState, float], Any]):
        self._callbacks.append(callback)
    
    def _notify_state_change(self, new_state: RateLimitState, new_rate: float):
        for callback in self._callbacks:
            try:
                callback(new_state, new_rate)
            except Exception as e:
                logger.debug(f"State callback error: {e}")
    
    async def acquire(self, tokens: int = 1) -> bool:
        async with self._lock:
            now = time.monotonic()
            
            if self.state == RateLimitState.BACKING_OFF:
                if time.time() < self.backoff_until:
                    wait_time = self.backoff_until - time.time()
                    await asyncio.sleep(wait_time)
                else:
                    self.state = RateLimitState.PROBING
                    self._notify_state_change(self.state, self.current_rate)
            
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.current_rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                self.metrics.requests_sent += 1
                return True
            
            wait_time = (tokens - self.tokens) / self.current_rate
            await asyncio.sleep(wait_time)
            self.tokens = 0
            self.metrics.requests_sent += 1
            return True
    
    def record_success(self, response_time: Optional[float] = None):
        self.metrics.requests_successful += 1
        
        if response_time is not None:
            self._response_times.append(response_time)
        
        self._maybe_adjust_rate()
    
    def record_failure(self, is_rate_limit: bool = False, is_timeout: bool = False):
        self.metrics.requests_failed += 1
        
        if is_rate_limit:
            self.metrics.rate_limit_hits += 1
            self._handle_rate_limit()
        elif is_timeout:
            self.metrics.timeouts += 1
        
        self._maybe_adjust_rate()
    
    def record_response(self, payload_size: int, response_time: float, success: bool = True):
        if success:
            self.record_success(response_time)
        else:
            self.record_failure(is_timeout=(response_time > self.window_size))
    
    def _handle_rate_limit(self):
        old_rate = self.current_rate
        self.current_rate = max(self.min_rate, self.current_rate * self.decrease_factor)
        self.state = RateLimitState.RATE_LIMITED
        
        logger.warning(f"Rate limit detected. Reducing rate: {old_rate:.1f} -> {self.current_rate:.1f}")
        self._notify_state_change(self.state, self.current_rate)
        
        if self.metrics.rate_limit_hits >= 3:
            self.backoff_until = time.time() + min(60, 5 * self.metrics.rate_limit_hits)
            self.state = RateLimitState.BACKING_OFF
            logger.warning(f"Multiple rate limits. Backing off until {self.backoff_until}")
            self._notify_state_change(self.state, self.current_rate)
    
    def _maybe_adjust_rate(self):
        now = time.time()
        
        if now - self.metrics.window_start < self.window_size:
            return
        
        if self.metrics.requests_sent < 10:
            self.metrics.reset_window()
            return
        
        old_rate = self.current_rate
        old_state = self.state
        
        if self.metrics.success_rate >= self.success_threshold:
            if self.state == RateLimitState.PROBING:
                self.current_rate = min(self.max_rate, self.current_rate * self.increase_factor)
                self.state = RateLimitState.NORMAL
            elif self.state == RateLimitState.NORMAL:
                if now - self.last_probe > self.probe_interval:
                    self.current_rate = min(self.max_rate, self.current_rate * self.increase_factor)
                    self.last_probe = now
            elif self.state in (RateLimitState.THROTTLED, RateLimitState.RATE_LIMITED):
                self.state = RateLimitState.PROBING
        
        elif self.metrics.failure_rate > self.failure_threshold:
            self.current_rate = max(self.min_rate, self.current_rate * self.decrease_factor)
            self.state = RateLimitState.THROTTLED
        
        if old_rate != self.current_rate or old_state != self.state:
            self.metrics.current_rate = self.current_rate
            logger.info(f"Rate adjusted: {old_rate:.1f} -> {self.current_rate:.1f} (state: {self.state.value})")
            self._notify_state_change(self.state, self.current_rate)
        
        self.metrics.reset_window()
    
    @property
    def average_response_time(self) -> float:
        if self._response_times:
            return sum(self._response_times) / len(self._response_times)
        return 0.0
    
    def reset(self):
        self.current_rate = self.initial_rate
        self.tokens = float(self.burst)
        self.state = RateLimitState.NORMAL
        self.metrics = RateLimitMetrics(target_rate=self.initial_rate)
        self.backoff_until = 0.0
        self._response_times.clear()

class MultiTargetRateLimiter:
    def __init__(
        self,
        default_rate: float = 100.0,
        min_rate: float = 1.0,
        max_rate: float = 10000.0
    ):
        self.default_rate = default_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self._limiters: dict[str, AdaptiveRateLimiter] = {}
        self._lock = asyncio.Lock()
    
    async def get_limiter(self, target: str) -> AdaptiveRateLimiter:
        async with self._lock:
            if target not in self._limiters:
                self._limiters[target] = AdaptiveRateLimiter(
                    initial_rate=self.default_rate,
                    min_rate=self.min_rate,
                    max_rate=self.max_rate
                )
            return self._limiters[target]
    
    async def acquire(self, target: str, tokens: int = 1) -> bool:
        limiter = await self.get_limiter(target)
        return await limiter.acquire(tokens)
    
    def record_success(self, target: str, response_time: Optional[float] = None):
        if target in self._limiters:
            self._limiters[target].record_success(response_time)
    
    def record_failure(self, target: str, is_rate_limit: bool = False, is_timeout: bool = False):
        if target in self._limiters:
            self._limiters[target].record_failure(is_rate_limit, is_timeout)
    
    def get_stats(self) -> dict:
        return {
            target: {
                "rate": limiter.current_rate,
                "state": limiter.state.value,
                "success_rate": limiter.metrics.success_rate
            }
            for target, limiter in self._limiters.items()
        }

class RateLimitDetector:
    def __init__(
        self,
        response_threshold: float = 3.0,
        error_codes: Optional[List[int]] = None,
        patterns: Optional[List[str]] = None
    ):
        self.response_threshold = response_threshold
        self.error_codes = error_codes or [429, 503, 509]
        self.patterns = patterns or [
            "rate limit",
            "too many requests",
            "throttl",
            "slow down",
            "try again later"
        ]
        
        self._baseline_response_time: Optional[float] = None
        self._response_times: Deque[float] = deque(maxlen=50)
    
    def update_baseline(self, response_time: float):
        self._response_times.append(response_time)
        if len(self._response_times) >= 10:
            sorted_times = sorted(self._response_times)
            self._baseline_response_time = sorted_times[len(sorted_times) // 2]
    
    def is_rate_limited(
        self,
        response_time: Optional[float] = None,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None
    ) -> bool:
        if status_code is not None and status_code in self.error_codes:
            return True
        
        if response_body is not None:
            body_lower = response_body.lower()
            for pattern in self.patterns:
                if pattern in body_lower:
                    return True
        
        if response_time is not None and self._baseline_response_time is not None:
            if response_time > self._baseline_response_time * self.response_threshold:
                return True
        
        return False
    
    def analyze_response(
        self,
        response_time: float,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        is_limited = self.is_rate_limited(response_time, status_code, response_body)
        
        if is_limited:
            if status_code and status_code in self.error_codes:
                reason = f"HTTP {status_code}"
            elif response_body and any(p in response_body.lower() for p in self.patterns):
                reason = "Response pattern match"
            else:
                reason = "Response time spike"
            return True, reason
        
        self.update_baseline(response_time)
        return False, ""

async def adaptive_scan(
    items: List[Any],
    scanner_func: Callable[[Any], Any],
    initial_rate: float = 100.0,
    on_rate_change: Optional[Callable[[float], None]] = None
) -> List[Any]:
    rate_limiter = AdaptiveRateLimiter(initial_rate=initial_rate)
    
    if on_rate_change:
        rate_limiter.add_state_callback(lambda state, rate: on_rate_change(rate))
    
    results = []
    
    for item in items:
        await rate_limiter.acquire()
        
        start = time.time()
        try:
            if asyncio.iscoroutinefunction(scanner_func):
                result = await scanner_func(item)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, scanner_func, item)
            
            response_time = time.time() - start
            rate_limiter.record_success(response_time)
            
            if result is not None:
                results.append(result)
                
        except asyncio.TimeoutError:
            rate_limiter.record_failure(is_timeout=True)
        except Exception as e:
            error_str = str(e).lower()
            is_rate_limit = any(p in error_str for p in ["rate", "limit", "throttle", "429"])
            rate_limiter.record_failure(is_rate_limit=is_rate_limit)
    
    return results

