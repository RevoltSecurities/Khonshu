from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, TCP, ICMP
from typing import Optional
from datetime import datetime
import asyncio
from khonshu import Request, Response

conf.verb = 0

class AsyncWindowsScanner:
    def __init__(self, timeout: float = 2.0, retries: int = 1):
        self.timeout = timeout
        self.retries = retries
        self.event_out = self.timeout + 1.5

    def _send_sync(self, pkt, timeout):
        return sr1(pkt, timeout=timeout)

    async def scan(self, request: Request) -> Optional[Response]:
        """
        TCP Window Scan (-sW) — Detects open ports based on TCP RST window size.

        +-------------------------------+--------------+
        |     TCP RST w/ win > 0       |    OPEN      |
        |     TCP RST w/ win == 0      |    CLOSED    |
        |     ICMP unreachable         |   FILTERED   |
        |     No response              |   FILTERED   |
        +-------------------------------+--------------+
        """
        pkt = IP(dst=request.ip) / TCP(sport=RandShort(), dport=request.port, flags="A")

        for _ in range(self.retries):
            try:
                answer = await asyncio.wait_for(
                    asyncio.to_thread(self._send_sync, pkt, self.timeout),
                    timeout=self.event_out
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

            if answer:
                if answer.haslayer(TCP):
                    tcp = answer[TCP]
                    if tcp.flags & 0x14 == 0x14:  # TCP RST
                        status = "open" if tcp.window > 0 else "closed"
                        return self._make_response(request, status)
                elif answer.haslayer(ICMP):
                    icmp = answer[ICMP]
                    if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                        return self._make_response(request, "filtered")

        return self._make_response(request, "filtered")

    def _make_response(self, request: Request, status: str) -> Response:
        return Response(
            ip=request.ip,
            port=request.port,
            type="windows",
            status=status,
            timestamp=datetime.now().astimezone().isoformat(),
            domain=request.domain,
        )
