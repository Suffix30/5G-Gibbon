#!/usr/bin/env python3
import asyncio
import logging
from typing import (
    TypeVar, AsyncIterator, Iterator, Callable, Any, List, 
    Optional, Dict, Tuple, Generic, Union
)
from dataclasses import dataclass
import time
 
logger = logging.getLogger(__name__)

T = TypeVar('T')
R = TypeVar('R')

def chunked_range(start: int, end: int, chunk_size: int = 1000) -> Iterator[range]:
    for i in range(start, end, chunk_size):
        yield range(i, min(i + chunk_size, end))

def ip_range_generator(network: str, chunk_size: int = 256) -> Iterator[List[str]]:
    import ipaddress
    
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        hosts = list(net.hosts())
        
        for i in range(0, len(hosts), chunk_size):
            yield [str(h) for h in hosts[i:i + chunk_size]]
    except Exception as e:
        logger.error(f"Invalid network {network}: {e}")
        return

def port_range_generator(
    ports: Optional[List[int]] = None,
    chunk_size: int = 50
) -> Iterator[List[int]]:
    if ports is None:
        ports = [
            2152, 2123, 8805, 38412, 38472, 36412, 36422,
            7777, 80, 443, 27017, 9090, 3000,
            29500, 29501, 29502, 29503, 29504, 29505, 29518, 29519
        ]
    
    for i in range(0, len(ports), chunk_size):
        yield ports[i:i + chunk_size]

async def async_chunked_range(
    start: int,
    end: int,
    chunk_size: int = 1000
) -> AsyncIterator[range]:
    for chunk in chunked_range(start, end, chunk_size):
        yield chunk
        await asyncio.sleep(0)

async def async_ip_range(
    network: str,
    chunk_size: int = 256
) -> AsyncIterator[List[str]]:
    for chunk in ip_range_generator(network, chunk_size):
        yield chunk
        await asyncio.sleep(0)

@dataclass
class StreamStats:
    total_items: int = 0
    processed_items: int = 0
    successful_items: int = 0
    failed_items: int = 0
    start_time: float = 0.0
    
    @property
    def elapsed(self) -> float:
        if self.start_time > 0:
            return time.time() - self.start_time
        return 0.0
    
    @property
    def rate(self) -> float:
        if self.elapsed > 0:
            return self.processed_items / self.elapsed
        return 0.0
    
    @property
    def progress(self) -> float:
        if self.total_items > 0:
            return self.processed_items / self.total_items * 100
        return 0.0

class StreamProcessor(Generic[T, R]):
    def __init__(
        self,
        processor: Callable[[T], R],
        chunk_size: int = 100,
        max_memory_items: int = 10000,
        on_result: Optional[Callable[[R], None]] = None,
        on_error: Optional[Callable[[T, Exception], None]] = None
    ):
        self.processor = processor
        self.chunk_size = chunk_size
        self.max_memory_items = max_memory_items
        self.on_result = on_result
        self.on_error = on_error
        self.stats = StreamStats()
        self._results: List[R] = []
        self._cancel = False
    
    def process_sync(self, items: Iterator[T]) -> List[R]:
        self.stats = StreamStats(start_time=time.time())
        self._results = []
        self._cancel = False
        
        buffer: List[R] = []
        
        for item in items:
            if self._cancel:
                break
            
            try:
                result = self.processor(item)
                self.stats.processed_items += 1
                
                if result is not None:
                    self.stats.successful_items += 1
                    
                    if self.on_result:
                        self.on_result(result)
                    
                    buffer.append(result)
                    
                    if len(buffer) >= self.chunk_size:
                        self._results.extend(buffer)
                        buffer = []
                        
                        if len(self._results) > self.max_memory_items:
                            self._results = self._results[-self.max_memory_items:]
                
            except Exception as e:
                self.stats.failed_items += 1
                if self.on_error:
                    self.on_error(item, e)
                logger.debug(f"Processing error: {e}")
        
        if buffer:
            self._results.extend(buffer)
        
        return self._results
    
    def cancel(self):
        self._cancel = True

class AsyncStreamProcessor(Generic[T, R]):
    def __init__(
        self,
        processor: Callable[[T], Any],
        concurrency: int = 50,
        chunk_size: int = 100,
        max_memory_items: int = 10000,
        on_result: Optional[Callable[[R], None]] = None,
        on_error: Optional[Callable[[T, Exception], None]] = None
    ):
        self.processor = processor
        self.concurrency = concurrency
        self.chunk_size = chunk_size
        self.max_memory_items = max_memory_items
        self.on_result = on_result
        self.on_error = on_error
        self.stats = StreamStats()
        self._results: List[R] = []
        self._lock = asyncio.Lock()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._cancel_event = asyncio.Event()
    
    async def _process_item(self, item: T) -> Optional[R]:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        
        if self._cancel_event.is_set():
            return None
        
        async with self._semaphore:
            try:
                if asyncio.iscoroutinefunction(self.processor):
                    result = await self.processor(item)
                else:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, self.processor, item)
                
                async with self._lock:
                    self.stats.processed_items += 1
                
                if result is not None:
                    async with self._lock:
                        self.stats.successful_items += 1
                        self._results.append(result)
                        
                        if len(self._results) > self.max_memory_items:
                            self._results = self._results[-self.max_memory_items:]
                    
                    if self.on_result:
                        self.on_result(result)
                
                return result
                
            except Exception as e:
                async with self._lock:
                    self.stats.processed_items += 1
                    self.stats.failed_items += 1
                
                if self.on_error:
                    self.on_error(item, e)
                logger.debug(f"Async processing error: {e}")
                return None
    
    async def process(
        self,
        items: List[T],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[R]:
        self.stats = StreamStats(total_items=len(items), start_time=time.time())
        self._results = []
        self._cancel_event.clear()
        
        for i in range(0, len(items), self.chunk_size):
            if self._cancel_event.is_set():
                break
            
            chunk = items[i:i + self.chunk_size]
            tasks = [self._process_item(item) for item in chunk]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            if progress_callback:
                progress_callback(self.stats.processed_items, self.stats.total_items)
        
        return self._results
    
    async def process_stream(
        self,
        item_generator: AsyncIterator[T],
        progress_callback: Optional[Callable[[int], None]] = None
    ) -> List[R]:
        self.stats = StreamStats(start_time=time.time())
        self._results = []
        self._cancel_event.clear()
        
        chunk: List[T] = []
        
        async for item in item_generator:
            if self._cancel_event.is_set():
                break
            
            chunk.append(item)
            self.stats.total_items += 1
            
            if len(chunk) >= self.chunk_size:
                tasks = [self._process_item(i) for i in chunk]
                await asyncio.gather(*tasks, return_exceptions=True)
                
                if progress_callback:
                    progress_callback(self.stats.processed_items)
                
                chunk = []
        
        if chunk:
            tasks = [self._process_item(i) for i in chunk]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            if progress_callback:
                progress_callback(self.stats.processed_items)
        
        return self._results
    
    def cancel(self):
        self._cancel_event.set()
    
    @property
    def results(self) -> List[R]:
        return self._results

class ResultBuffer(Generic[T]):
    def __init__(
        self,
        max_size: int = 10000,
        flush_callback: Optional[Callable[[List[T]], None]] = None,
        flush_threshold: int = 1000
    ):
        self.max_size = max_size
        self.flush_callback = flush_callback
        self.flush_threshold = flush_threshold
        self._buffer: List[T] = []
        self._lock = asyncio.Lock()
        self._total_flushed = 0
    
    async def add(self, item: T):
        async with self._lock:
            self._buffer.append(item)
            
            if len(self._buffer) >= self.flush_threshold:
                await self._flush()
    
    async def add_many(self, items: List[T]):
        async with self._lock:
            self._buffer.extend(items)
            
            if len(self._buffer) >= self.flush_threshold:
                await self._flush()
    
    async def _flush(self):
        if self._buffer and self.flush_callback:
            to_flush = self._buffer[:self.flush_threshold]
            self._buffer = self._buffer[self.flush_threshold:]
            self._total_flushed += len(to_flush)
            
            try:
                self.flush_callback(to_flush)
            except Exception as e:
                logger.error(f"Flush callback error: {e}")
    
    async def flush_all(self):
        async with self._lock:
            if self._buffer and self.flush_callback:
                self._total_flushed += len(self._buffer)
                try:
                    self.flush_callback(self._buffer)
                except Exception as e:
                    logger.error(f"Final flush error: {e}")
            self._buffer = []
    
    @property
    def size(self) -> int:
        return len(self._buffer)
    
    @property
    def total_processed(self) -> int:
        return self._total_flushed + len(self._buffer)

def create_teid_generator(
    start: int,
    end: int,
    chunk_size: int = 1000
) -> Iterator[List[int]]:
    for chunk_range in chunked_range(start, end, chunk_size):
        yield list(chunk_range)

def create_seid_generator(
    start: int,
    end: int,
    chunk_size: int = 1000
) -> Iterator[List[int]]:
    for chunk_range in chunked_range(start, end, chunk_size):
        yield list(chunk_range)

async def create_async_teid_generator(
    start: int,
    end: int,
    chunk_size: int = 1000
) -> AsyncIterator[int]:
    for teid in range(start, end):
        yield teid
        if (teid - start) % chunk_size == 0:
            await asyncio.sleep(0)


def get_stream_stats(start: int, end: int, chunk_size: int) -> Dict[str, Union[int, float]]:
    total = end - start
    chunks = (total + chunk_size - 1) // chunk_size
    return {
        "total": total,
        "chunks": chunks,
        "chunk_size": chunk_size,
        "estimated_time": total * 0.001
    }


def create_range_tuple(start: int, end: int) -> Tuple[int, int, int]:
    return (start, end, end - start)

