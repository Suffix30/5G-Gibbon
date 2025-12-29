#!/usr/bin/env python3
import logging
from contextlib import contextmanager
import time
from functools import wraps
from typing import Optional
 
logger = logging.getLogger(__name__)

class ResourceManager:
    def __init__(self):
        self.active_operations = {}
    
    @contextmanager
    def managed_socket(self, sock_type, timeout=None):
        import socket as socket_module
        sock = None
        try:
            sock = socket_module.socket(socket_module.AF_INET, sock_type)
            if timeout:
                sock.settimeout(timeout)
            yield sock
        except socket_module.timeout:
            logger.warning("Socket operation timed out")
            raise
        except socket_module.error as e:
            logger.error(f"Socket error: {e}")
            raise
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    @contextmanager
    def managed_operation(self, operation_name):
        start_time = time.time()
        try:
            yield
        except KeyboardInterrupt:
            logger.warning(f"Operation {operation_name} interrupted by user")
            raise
        except Exception as e:
            logger.error(f"Operation {operation_name} failed: {e}", exc_info=True)
            raise
        finally:
            duration = time.time() - start_time
            logger.debug(f"Operation {operation_name} completed in {duration:.2f}s")

def retry_with_backoff(max_retries=3, initial_delay=1.0, backoff_factor=2.0):
    import socket as socket_module
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception: Optional[Exception] = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (ConnectionError, TimeoutError, socket_module.timeout) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in {delay}s...")
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        logger.error(f"All {max_retries} attempts failed")
            
            if last_exception is not None:
                raise last_exception
            raise RuntimeError(f"All {max_retries} retry attempts exhausted")
        return wrapper
    return decorator

