#!/usr/bin/env python3
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar, Callable, Any, List, Optional, Dict, Coroutine, Tuple
from functools import wraps
import time
 
logger = logging.getLogger(__name__)

T = TypeVar('T')

_executor: Optional[ThreadPoolExecutor] = None
_executor_workers = 50

def get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=_executor_workers)
    return _executor

def set_executor_workers(workers: int):
    global _executor_workers, _executor
    _executor_workers = workers
    if _executor is not None:
        _executor.shutdown(wait=False)
        _executor = None

async def run_in_executor(func: Callable[..., T], *args, **kwargs) -> T:
    loop = asyncio.get_event_loop()
    executor = get_executor()
    if kwargs:
        return await loop.run_in_executor(executor, lambda: func(*args, **kwargs))
    return await loop.run_in_executor(executor, func, *args)

async def gather_with_concurrency(n: int, *tasks: Coroutine) -> List[Any]:
    semaphore = asyncio.Semaphore(n)
    
    async def sem_task(task: Coroutine) -> Any:
        async with semaphore:
            return await task
    
    return await asyncio.gather(*(sem_task(t) for t in tasks), return_exceptions=True)

async def batch_process(
    items: List[Any],
    processor: Callable[[Any], Coroutine],
    batch_size: int = 100,
    concurrency: int = 50,
    on_batch_complete: Optional[Callable[[int, int], None]] = None
) -> List[Any]:
    results = []
    total = len(items)
    
    for i in range(0, total, batch_size):
        batch = items[i:i + batch_size]
        batch_results = await gather_with_concurrency(
            concurrency,
            *[processor(item) for item in batch]
        )
        results.extend(batch_results)
        
        if on_batch_complete:
            on_batch_complete(i + len(batch), total)
    
    return results

class AsyncRateLimiter:
    def __init__(self, rate: float = 100.0, burst: int = 10, rate_limit: Optional[float] = None):
        self.rate = rate_limit if rate_limit is not None else rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return
            
            wait_time = (tokens - self.tokens) / self.rate
            await asyncio.sleep(wait_time)
            self.tokens = 0
    
    async def __aenter__(self):
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

class AsyncRetry:
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 0.1,
        max_delay: float = 10.0,
        exponential: bool = True,
        exceptions: Tuple[type, ...] = (Exception,)
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential = exponential
        self.exceptions = exceptions
    
    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception: Optional[Exception] = None
            for attempt in range(self.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if isinstance(e, self.exceptions):
                        last_exception = e
                        if attempt < self.max_retries:
                            if self.exponential:
                                delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                            else:
                                delay = self.base_delay
                            await asyncio.sleep(delay)
                    else:
                        raise
            if last_exception:
                raise last_exception
        return wrapper

class AsyncScanner:
    def __init__(
        self,
        concurrency: int = 50,
        rate_limit: float = 1000.0,
        timeout: float = 2.0
    ):
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit)
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self._results: List[Any] = []
        self._errors: List[Dict] = []
        self._processed = 0
        self._lock = asyncio.Lock()
    
    async def scan_item(self, item: Any, scanner_func: Callable) -> Optional[Any]:
        await self.rate_limiter.acquire()
        async with self._semaphore:
            try:
                result = await asyncio.wait_for(
                    run_in_executor(scanner_func, item),
                    timeout=self.timeout
                )
                async with self._lock:
                    self._processed += 1
                    if result:
                        self._results.append(result)
                return result
            except asyncio.TimeoutError:
                async with self._lock:
                    self._processed += 1
                    self._errors.append({"item": item, "error": "timeout"})
                return None
            except Exception as e:
                async with self._lock:
                    self._processed += 1
                    self._errors.append({"item": item, "error": str(e)})
                return None
    
    async def scan_all(
        self,
        items: List[Any],
        scanner_func: Callable,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        self._results = []
        self._errors = []
        self._processed = 0
        total = len(items)
        
        tasks = []
        for item in items:
            tasks.append(self.scan_item(item, scanner_func))
        
        if progress_callback:
            async def progress_monitor():
                while self._processed < total:
                    progress_callback(self._processed, total)
                    await asyncio.sleep(0.1)
                progress_callback(total, total)
            
            monitor_task = asyncio.create_task(progress_monitor())
            await asyncio.gather(*tasks)
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        else:
            await asyncio.gather(*tasks)
        
        return {
            "results": self._results,
            "errors": self._errors,
            "total": total,
            "success": len(self._results),
            "failed": len(self._errors)
        }

async def async_tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False

async def async_udp_probe(host: str, port: int, payload: bytes, timeout: float = 1.0) -> Optional[bytes]:
    loop = asyncio.get_event_loop()
    
    class UDPProtocol(asyncio.DatagramProtocol):
        def __init__(self, future: asyncio.Future):
            self.future = future
            self.transport = None
        
        def connection_made(self, transport):
            self.transport = transport
            transport.sendto(payload)
        
        def datagram_received(self, data, addr):
            if not self.future.done():
                self.future.set_result(data)
        
        def error_received(self, exc):
            if not self.future.done():
                self.future.set_exception(exc)
    
    try:
        response_future: asyncio.Future = loop.create_future()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPProtocol(response_future),
            remote_addr=(host, port)
        )
        
        try:
            transport.sendto(b'\x00', (host, port))
            logger.debug(f"UDP protocol created: {type(protocol).__name__}")
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            transport.close()
    except Exception:
        return None

def run_async(coro: Coroutine) -> Any:
    try:
        loop = asyncio.get_running_loop()
        return loop.create_task(coro)
    except RuntimeError:
        return asyncio.run(coro)

def cleanup():
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=True)
        _executor = None

