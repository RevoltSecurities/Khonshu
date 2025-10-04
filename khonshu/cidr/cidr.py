from revoltutils import AsyncQueue
import asyncio
import ipaddress
from typing import AsyncGenerator

class NETStreamer:
    def __init__(self, max_size=1000) -> None:
        self.max = max_size
        self.channel = AsyncQueue(maxsize=self.max)
        self._stop_event = asyncio.Event()
        self._producer_task = None

    async def _produce_ips(self, cidr: str):
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            return
        for ip in network.hosts():
            await self.channel.put(str(ip))
            if self._stop_event.is_set(): # produce till event is set
                break

        await self.channel.put(None)  # Signal to indicate end of stream to break the while loop

    async def stream(self, cidr: str) -> AsyncGenerator[str, None]:
        self._stop_event.clear()
        self._producer_task = asyncio.create_task(self._produce_ips(cidr))

        while True:
            ip = await self.channel.get()
            if ip is None:  # we received the signal to break the loop
                break
            yield ip

    def stop(self):
        """Stops ongoing streaming of IPs gracefully"""
        self._stop_event.set()
        if self._producer_task:
            self._producer_task.cancel()