from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, TCP, Packet
from khonshu import PINGAlive
from datetime import datetime
from typing import Optional, List
import asyncio

conf.verb = 0

class AioTCP:
    def __init__(
        self,
        timeout: float = 2.0,
        method: str = "syn",
        ports: List[int] = [80, 443, 8080],
        retries: int = 3,
    ) -> None:
        if method not in ("syn", "ack"):
            raise ValueError("method must be 'syn' or 'ack'")
        self.method = method
        self.timeout = timeout
        self.event_out = self.timeout + 1.5
        self.ports = ports
        self.retries = retries
        self.flag = "S" if method == "syn" else "A"

    def _send_sync(self, pkt, timeout):
        return sr1(pkt, timeout=timeout)

    async def _scan(self, host: str, port: int) -> Optional[PINGAlive]:
        pkt = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags=self.flag)

        for _ in range(self.retries):
            start = datetime.now()
            try:
                response: Packet = await asyncio.wait_for(
                    asyncio.to_thread(self._send_sync, pkt, self.timeout),
                    timeout=self.event_out
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

            ms = (datetime.now() - start).total_seconds() * 1000
            if response and response.haslayer(TCP):
                tcp = response[TCP]
                if self.method == "syn" and tcp.flags in (0x12, 0x14):  # SYN+ACK or RST
                    return PINGAlive(host=host, status="alive", type="syn", port=port, ms=ms)
                elif self.method == "ack" and tcp.flags & 0x04 == 0x04:  # RST
                    return PINGAlive(host=host, status="alive", type="ack", port=port, ms=ms)
        return None

    async def ping(self, host: str) -> PINGAlive:
        for port in self.ports:
            result = await self._scan(host, port)
            if result:
                return result
        return PINGAlive(host=host, status="dead", type=self.method, port=None, ms=None)
