from aioping import ping as aioping_ping
from khonshu import PINGAlive
from scapy.all import sr1, conf
from scapy.layers.inet import IP, ICMP
from datetime import datetime
from typing import Optional
import asyncio
conf.verb = 0

class AioICMP:
    def __init__(self, timeout: float = 2.0, retries: int = 3, method: str = "echo"):
        self.timeout = timeout
        self.retries = retries
        self.method = method.lower()

        if self.method not in ("echo", "timestamp", "address-mask", "mask"):
            raise ValueError("Invalid ICMP method. Choose from: echo, timestamp, address-mask")

    def _scapy_send(self, host: str, icmp_type: int, expected_reply_type: int, ping_type: str) -> PINGAlive:
        pkt = IP(dst=host) / ICMP(type=icmp_type)
        for _ in range(self.retries):
            start = datetime.now()
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(ICMP) and reply.getlayer(ICMP).type == expected_reply_type:
                ms = (datetime.now() - start).total_seconds() * 1000
                return PINGAlive(host=host, status="alive", ms=ms, type=ping_type)
        return PINGAlive(host=host, status="dead", ms=None, type=ping_type)

    async def ping(self, host: str) -> Optional[PINGAlive]:
        if self.method == "echo":
            for _ in range(self.retries):
                try:
                    delay: float = await aioping_ping(host, timeout=self.timeout)
                    if delay:
                        return PINGAlive(host=host, status="alive", ms=delay, type="icmp echo")
                except Exception:
                    continue
            return PINGAlive(host=host, status="dead", ms=None, type="icmp echo")

        if self.method == "timestamp":
            return await asyncio.to_thread(self._scapy_send, host, 13, 14, "icmp timestamp")
        elif self.method in ("address-mask", "mask"):
            return await asyncio.to_thread(self._scapy_send, host, 17, 18, "icmp address mask")