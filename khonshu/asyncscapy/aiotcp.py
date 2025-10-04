from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, TCP, Packet
from khonshu import PINGAlive
from datetime import datetime
from typing import Optional, List
import asyncio
conf.verb = 0

class AioTCP:
    def __init__(self, timeout: float = 10.0, method: str = "syn", ports: List[int] = [80, 443, 8080], retries: int = 3) -> None:
        if method not in ("syn", "ack"):
            raise ValueError("method should be 'syn' or 'ack' for TCP ping")
        self.method = method
        self.timeout = timeout
        self.ports = ports
        self.retries = retries

    async def _ping(self, host: str, port: int) -> Optional[PINGAlive]:
        flags = "S" if self.method == "syn" else "A"
        pkt = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags=flags)

        for _ in range(self.retries):
            start = datetime.now()
            response: Packet = await asyncio.to_thread(sr1, pkt, timeout=self.timeout)
            ms = (datetime.now() - start).total_seconds() * 1000

            if response and response.haslayer(TCP):
                tcp = response.getlayer(TCP)
                if self.method == "syn" and tcp.flags in [0x12, 0x14]:  # SYN-ACK or RST
                    return PINGAlive(host=host, status="alive", type="syn", port=port, ms=ms)
                elif self.method == "ack" and tcp.flags & 0x4 == 0x4:  # RST
                    return PINGAlive(host=host, status="alive", type="ack", port=port, ms=ms)
        return None

    async def ping(self, host: str) -> PINGAlive:
        for port in self.ports:
            result = await self._ping(host, port)
            if result:
                return result
        return PINGAlive(host=host, status="dead", type=self.method, port=None, ms=None)
