from aioping import ping as aioping_ping
from khonshu import PINGAlive
from scapy.all import sr1, conf
from scapy.layers.inet import IP, ICMP
from datetime import datetime
import asyncio
conf.verb = 0

class AioICMP:
    def __init__(self, timeout: float = 2.0, retries: int = 3, method: str = "echo"):
        self.timeout = timeout
        self.retries = retries
        self.method = method.lower()

        if self.method not in ("echo", "timestamp", "address-mask", "mask"):
            raise ValueError("Invalid ICMP method. Choose from: echo, timestamp, address-mask")

    def _send_scapy(self, host: str, icmp_type: int, reply_type: int, label: str) -> PINGAlive:
        pkt = IP(dst=host) / ICMP(type=icmp_type)
        for _ in range(self.retries):
            start = datetime.now()
            try:
                response = sr1(pkt, timeout=self.timeout, verbose=0)
            except Exception:
                continue
            if response and response.haslayer(ICMP):
                icmp = response.getlayer(ICMP)
                if icmp.type == reply_type:
                    ms = (datetime.now() - start).total_seconds() * 1000
                    return PINGAlive(host=host, status="alive", type=label, ms=ms)
        return PINGAlive(host=host, status="dead", type=label, ms=None)

    async def ping(self, host: str) -> PINGAlive:
        if self.method == "echo":
            for _ in range(self.retries):
                try:
                    delay = await aioping_ping(host, timeout=self.timeout)
                    if delay is not None:
                        return PINGAlive(host=host, status="alive", type="icmp-echo", ms=delay * 1000)
                except Exception:
                    continue
            return PINGAlive(host=host, status="dead", type="icmp-echo", ms=None)

        elif self.method == "timestamp":
            return await asyncio.to_thread(
                self._send_scapy, host, 13, 14, "icmp-timestamp"
            )

        elif self.method in ("address-mask", "mask"):
            return await asyncio.to_thread(
                self._send_scapy, host, 17, 18, "icmp-address-mask"
            )