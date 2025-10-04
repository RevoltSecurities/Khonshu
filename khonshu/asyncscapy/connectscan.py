import asyncio
import socket
import sys
import time
import random
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from khonshu import Request, Response


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    TIMEOUT = "timeout"


class OSCompatibility:
    """Handle OS-specific socket configurations"""

    @staticmethod
    def configure_socket(sock: socket.socket) -> None:
        """Configure socket for optimal performance across OS"""
        try:
            # Common socket options that work across platforms
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Platform-specific optimizations
            if sys.platform.startswith('linux'):
                # Linux-specific optimizations
                if hasattr(socket, 'SO_REUSEPORT'):
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except OSError:
                        pass

                # Set TCP_NODELAY for faster connection attempts
                if hasattr(socket, 'IPPROTO_TCP') and hasattr(socket, 'TCP_NODELAY'):
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except OSError:
                        pass

            elif sys.platform == 'darwin':  # macOS
                # macOS-specific optimizations
                if hasattr(socket, 'SO_NOSIGPIPE'):
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
                    except OSError:
                        pass

            elif sys.platform in ('win32', 'cygwin', 'cli'):  # Windows
                # Windows-specific optimizations
                try:
                    # Set socket to non-blocking mode for better async performance
                    sock.setblocking(False)
                except OSError:
                    pass

        except Exception:
            # If any OS-specific config fails, continue with defaults
            pass


class CircuitBreaker:
    """Fixed circuit breaker pattern for port scanning workloads"""

    def __init__(self, failure_threshold: int = 100, reset_timeout: int = 300):
        # Much higher threshold for port scanning (many ports will be closed)
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.consecutive_timeouts = 0  # Only count timeouts, not connection refused
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half-open

    def should_attempt(self) -> bool:
        """Check if we should attempt connection"""
        current_time = time.time()

        if self.state == "open":
            if current_time - self.last_failure_time > self.reset_timeout:
                self.state = "half-open"
                return True
            return False

        return True

    def record_success(self) -> None:
        """Record successful connection"""
        self.consecutive_timeouts = 0  # Reset on any success
        self.state = "closed"

    def record_timeout(self) -> None:
        """Record timeout failure (only timeouts count for circuit breaking)"""
        self.consecutive_timeouts += 1
        self.last_failure_time = time.time()

        if self.consecutive_timeouts >= self.failure_threshold:
            self.state = "open"

    def record_connection_refused(self) -> None:
        """Record connection refused (doesn't count toward circuit breaking)"""
        # Connection refused is normal in port scanning, don't trip circuit breaker
        pass


class ResourceManager:
    """Manage connection resources and limits - optimized for port scanning"""

    def __init__(self, max_connections: int = 2000, max_per_host: int = 1000):
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self.active_connections = 0
        self.host_connections: Dict[str, int] = {}
        self.connection_semaphore = asyncio.Semaphore(max_connections)
        self.host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()

    async def acquire_connection(self, host: str) -> Tuple[bool, Optional[str]]:
        """Acquire connection slot for host"""
        await self.connection_semaphore.acquire()

        async with self._lock:
            if host not in self.host_semaphores:
                self.host_semaphores[host] = asyncio.Semaphore(self.max_per_host)

            host_semaphore = self.host_semaphores[host]

        try:
            await asyncio.wait_for(host_semaphore.acquire(), timeout=2.0)  # Increased timeout
            async with self._lock:
                self.host_connections[host] = self.host_connections.get(host, 0) + 1
                self.active_connections += 1
            return True, None
        except asyncio.TimeoutError:
            self.connection_semaphore.release()
            return False, "host_limit_exceeded"

    async def release_connection(self, host: str) -> None:
        """Release connection slot for host"""
        async with self._lock:
            if host in self.host_connections:
                self.host_connections[host] = max(0, self.host_connections[host] - 1)
            self.active_connections = max(0, self.active_connections - 1)

            if host in self.host_semaphores:
                self.host_semaphores[host].release()

        self.connection_semaphore.release()


class RetryManager:
    """Handle retry logic optimized for port scanning"""

    def __init__(self, max_retries: int = 2, base_delay: float = 0.05, max_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay  # Shorter delays for port scanning
        self.max_delay = max_delay

    def get_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and jitter"""
        if attempt == 0:
            return 0

        # Exponential backoff: base_delay * 2^(attempt-1)
        delay = self.base_delay * (2 ** (attempt - 1))
        delay = min(delay, self.max_delay)

        # Add jitter (±20%)
        jitter = delay * 0.2 * (random.random() * 2 - 1)
        return max(0, delay + jitter)

    async def execute_with_retry(self, coro_func, *args, **kwargs):
        """Execute coroutine with retry logic"""
        last_exception = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                delay = self.get_delay(attempt)
                await asyncio.sleep(delay)

            try:
                return await coro_func(*args, **kwargs)
            except Exception as e:
                last_exception = e

                # Don't retry connection refused (port is definitely closed)
                if isinstance(e, ConnectionRefusedError):
                    break

                # Don't retry certain OS errors that indicate permanent failures
                if isinstance(e, OSError):
                    if hasattr(e, 'errno'):
                        # Don't retry on permanent network errors
                        if e.errno in (113, 111, 101):  # No route to host, Connection refused, Network unreachable
                            break

                continue

        raise last_exception


class AsyncConnectScanner:
    """Fixed async TCP connect scanner with accurate port detection"""

    def __init__(self,
                 timeout: float = 5.0,  # Reasonable default
                 retries: int = 2,
                 max_connections: int = 2000,  # Higher for port scanning
                 max_per_host: int = 1000,  # Much higher for port scanning
                 enable_circuit_breaker: bool = False):  # Disabled by default for port scanning

        self.base_timeout = timeout
        self.timeout = timeout  # Use timeout as-is, no OS adjustments
        self.retries = retries
        self.enable_circuit_breaker = enable_circuit_breaker

        # Resource management
        self.resource_manager = ResourceManager(max_connections, max_per_host)
        self.retry_manager = RetryManager(max_retries=retries)

        # Circuit breakers per host (with high thresholds)
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._cb_lock = asyncio.Lock()

        # Statistics
        self.stats = {
            "total_scans": 0,
            "successful_connections": 0,
            "connection_refused": 0,
            "timeouts": 0,
            "filtered_ports": 0,
            "circuit_breaker_trips": 0
        }

    def _now(self) -> str:
        """Get current timestamp"""
        return datetime.now().astimezone().isoformat()

    async def _get_circuit_breaker(self, host: str) -> Optional[CircuitBreaker]:
        """Get or create circuit breaker for host"""
        if not self.enable_circuit_breaker:
            return None

        async with self._cb_lock:
            if host not in self.circuit_breakers:
                self.circuit_breakers[host] = CircuitBreaker()
            return self.circuit_breakers[host]

    async def _create_connection(self, host: str, port: int) -> Tuple[
        Optional[Any], Optional[Any], float, Optional[str]]:
        """Create connection with proper error handling"""
        start_time = time.time()

        try:
            # Create connection with standard settings
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host,
                    port=port,
                    family=socket.AF_UNSPEC,  # Allow both IPv4 and IPv6
                    flags=socket.AI_ADDRCONFIG  # Use addresses configured on system
                ),
                timeout=self.timeout
            )

            rtt = (time.time() - start_time) * 1000  # Convert to milliseconds
            return reader, writer, rtt, None

        except asyncio.TimeoutError:
            rtt = (time.time() - start_time) * 1000
            return None, None, rtt, "timeout"
        except ConnectionRefusedError:
            rtt = (time.time() - start_time) * 1000
            return None, None, rtt, "connection_refused"
        except OSError as e:
            rtt = (time.time() - start_time) * 1000
            # Map specific OS errors
            if hasattr(e, 'errno'):
                if e.errno == 111:  # Connection refused on Linux
                    return None, None, rtt, "connection_refused"
                elif e.errno == 113:  # No route to host
                    return None, None, rtt, "no_route"
                elif e.errno == 101:  # Network unreachable
                    return None, None, rtt, "network_unreachable"
            return None, None, rtt, f"os_error_{e.errno if hasattr(e, 'errno') else 'unknown'}"
        except Exception as e:
            rtt = (time.time() - start_time) * 1000
            return None, None, rtt, f"unknown_error_{type(e).__name__}"

    async def _scan_port(self, request: Request) -> Response:
        """Internal port scanning with accurate state detection"""
        # Acquire resources
        acquired, acquire_error = await self.resource_manager.acquire_connection(request.ip)
        if not acquired:
            return Response(
                ip=request.ip,
                port=request.port,
                type="connect",
                status="filtered",
                timestamp=self._now(),
                domain=request.domain,
                error=acquire_error
            )

        try:
            # Check circuit breaker
            circuit_breaker = await self._get_circuit_breaker(request.ip)
            if circuit_breaker and not circuit_breaker.should_attempt():
                self.stats["circuit_breaker_trips"] += 1
                return Response(
                    ip=request.ip,
                    port=request.port,
                    type="connect",
                    status="filtered",
                    timestamp=self._now(),
                    domain=request.domain,
                    error="circuit_breaker_open"
                )

            # Attempt connection with retry
            reader, writer, rtt, error = await self.retry_manager.execute_with_retry(
                self._create_connection, request.ip, request.port
            )

            if reader and writer:
                # Successfully connected - PORT IS DEFINITELY OPEN
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass  # Ignore cleanup errors

                if circuit_breaker:
                    circuit_breaker.record_success()

                self.stats["successful_connections"] += 1
                return Response(
                    ip=request.ip,
                    port=request.port,
                    type="connect",
                    status="open",
                    timestamp=self._now(),
                    domain=request.domain,
                    interface=request.interface
                )
            else:
                # Connection failed - classify the failure properly
                if error == "timeout":
                    # Timeout = filtered (firewall/no response)
                    if circuit_breaker:
                        circuit_breaker.record_timeout()
                    self.stats["timeouts"] += 1
                    status = "filtered"
                elif error == "connection_refused":
                    # Connection refused = closed (definitive negative response)
                    if circuit_breaker:
                        circuit_breaker.record_connection_refused()
                    self.stats["connection_refused"] += 1
                    status = "closed"
                elif error in ["no_route", "network_unreachable"]:
                    # Network issues = filtered
                    if circuit_breaker:
                        circuit_breaker.record_timeout()
                    self.stats["filtered_ports"] += 1
                    status = "filtered"
                else:
                    # Other errors = filtered
                    if circuit_breaker:
                        circuit_breaker.record_timeout()
                    self.stats["filtered_ports"] += 1
                    status = "filtered"

                return Response(
                    ip=request.ip,
                    port=request.port,
                    type="connect",
                    status=status,
                    timestamp=self._now(),
                    domain=request.domain,
                    interface=request.interface
                )

        except Exception as e:
            # Any unexpected exception = filtered
            if circuit_breaker:
                circuit_breaker.record_timeout()

            self.stats["filtered_ports"] += 1
            return Response(
                ip=request.ip,
                port=request.port,
                type="connect",
                status="filtered",
                timestamp=self._now(),
                domain=request.domain,
                interface=request.interface,
                error=f"exception_{type(e).__name__}"
            )
        finally:
            # Always release resources
            await self.resource_manager.release_connection(request.ip)

    async def scan(self, request: Request) -> Response:
        """
        Performs accurate TCP connect scan with proper port state detection.

        Port State Classification:
        +--------------------------------+----------------+
        | Connect Scan Result            | Port State     |
        +--------------------------------+----------------+
        | Connection established         | open           |
        | Connection refused (ECONNREF)  | closed         |
        | Timeout / No response          | filtered       |
        | Network unreachable            | filtered       |
        | Circuit breaker open           | filtered       |
        | Resource limit exceeded        | filtered       |
        +--------------------------------+----------------+

        Returns: Response with accurate status: "open", "closed", or "filtered"
        """
        self.stats["total_scans"] += 1
        return await self._scan_port(request)

    async def scan_multiple(self, requests: list[Request], concurrency: int = 100) -> list[Response]:
        """Scan multiple ports with controlled concurrency"""
        semaphore = asyncio.Semaphore(concurrency)

        async def scan_with_semaphore(request: Request) -> Response:
            async with semaphore:
                return await self.scan(request)

        tasks = [scan_with_semaphore(request) for request in requests]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def get_stats(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        total = self.stats["total_scans"]
        success_rate = (self.stats["successful_connections"] / total * 100) if total > 0 else 0
        open_rate = (self.stats["successful_connections"] / total * 100) if total > 0 else 0
        closed_rate = (self.stats["connection_refused"] / total * 100) if total > 0 else 0
        filtered_rate = ((self.stats["timeouts"] + self.stats["filtered_ports"]) / total * 100) if total > 0 else 0

        return {
            **self.stats,
            "open_rate_percent": round(open_rate, 2),
            "closed_rate_percent": round(closed_rate, 2),
            "filtered_rate_percent": round(filtered_rate, 2),
            "active_connections": self.resource_manager.active_connections,
            "circuit_breakers_active": len([cb for cb in self.circuit_breakers.values() if cb.state == "open"])
        }

    async def cleanup(self) -> None:
        """Cleanup resources"""
        # Reset circuit breakers
        async with self._cb_lock:
            self.circuit_breakers.clear()

        # Reset stats
        self.stats = {
            "total_scans": 0,
            "successful_connections": 0,
            "connection_refused": 0,
            "timeouts": 0,
            "filtered_ports": 0,
            "circuit_breaker_trips": 0
        }


# Example usage and testing
async def main():
    """Example usage of the fixed scanner"""
    scanner = AsyncConnectScanner(
        timeout=3.0,
        retries=1,
        max_connections=1000,
        max_per_host=200,
        enable_circuit_breaker=False  # Disabled for port scanning
    )

    # Test single scan
    request = Request(ip="104.18.36.214", port=443, domain="hackerone.com", type="connect")
    response = await scanner.scan(request)
    print(f"Single scan result: {response}")

    # Test multiple scans on same host
    requests = [
        Request(ip="104.18.36.214", port=80, domain="hackerone.com", type="connect"),
        Request(ip="104.18.36.214", port=443, domain="hackerone.com", type="connect"),
        Request(ip="104.18.36.214", port=8080, domain="hackerone.com", type="connect"),
        Request(ip="104.18.36.214", port=8443, domain="hackerone.com", type="connect"),
        Request(ip="104.18.36.214", port=22, domain="hackerone.com", type="connect"),
        Request(ip="104.18.36.214", port=23, domain="hackerone.com", type="connect"),
    ]

    responses = await scanner.scan_multiple(requests, concurrency=10)
    print(f"\nMultiple scan results: {len(responses)} responses")
    for response in responses:
        print(f"{response.domain}:{response.port} = {response.status}")

    # Show stats
    stats = scanner.get_stats()
    print(f"\nScanner stats:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    await scanner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())