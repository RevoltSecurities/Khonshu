import os
import asyncio
from revoltutils import AsyncDiskCache
import time

class DiskManager:
    """High-performance disk-based resume manager - only caches OPEN ports for scalability"""

    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        # Only cache OPEN ports - never cache all scanned ports or completed hosts
        self.open_ports_cache = AsyncDiskCache(directory=os.path.join(cache_dir, "open_ports"))
        self.alive_hosts_cache = AsyncDiskCache(directory=os.path.join(cache_dir, "alive_hosts"))
        self.dead_hosts_cache = AsyncDiskCache(directory=os.path.join(cache_dir, "dead_hosts"))
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Initialize resume manager"""
        os.makedirs(os.path.join(self.cache_dir, "open_ports"), exist_ok=True)
        os.makedirs(os.path.join(self.cache_dir, "alive_hosts"), exist_ok=True)
        os.makedirs(os.path.join(self.cache_dir, "dead_hosts"), exist_ok=True)

    async def stop(self) -> None:
        await self.open_ports_cache.close()
        await self.alive_hosts_cache.close()
        await self.dead_hosts_cache.close()

    async def is_port_open(self, ip: str, port: int) -> bool:
        """Check if port is already known to be open"""
        port_key = f"{ip}:{port}"
        return await self.open_ports_cache.contains(port_key)

    async def get_open_port_info(self, ip: str, port: int) -> dict:
        """Get cached open port information"""
        port_key = f"{ip}:{port}"
        return await self.open_ports_cache.get(port_key)

    async def mark_port_open(self, ip: str, port: int, status: str, domain: str = None) -> None:
        """Mark port as open - only cache open ports for performance"""
        if status in ["open"]:  # Only cache meaningful positive results
            port_key = f"{ip}:{port}"
            await self.open_ports_cache.add(port_key, {
                "ip": ip, "port": port, "status": status, "domain": domain, "timestamp": time.time()
            })

    async def is_host_alive(self, ip: str) -> bool:
        """Check if host is known to be alive"""
        return await self.alive_hosts_cache.contains(ip)

    async def is_host_dead(self, ip: str) -> bool:
        """Check if host is known to be dead"""
        return await self.dead_hosts_cache.contains(ip)

    async def mark_host_alive(self, ip: str) -> None:
        """Mark host as alive"""
        await self.alive_hosts_cache.add(ip, {"status": "alive", "timestamp": time.time()})

    async def mark_host_dead(self, ip: str) -> None:
        """Mark host as dead"""
        await self.dead_hosts_cache.add(ip, {"status": "dead", "timestamp": time.time()})