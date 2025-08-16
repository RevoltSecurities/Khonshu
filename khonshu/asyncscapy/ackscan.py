from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, TCP, ICMP
from typing import Optional
from datetime import datetime
from khonshu import Request, Response
import asyncio

conf.verb = 0

class AsyncAckScanner:
    def __init__(self, timeout: float = 2.0, retries: int = 1):
        self.timeout = timeout
        self.retries = retries
        self.event_out = self.timeout + 1.5

    def _send_sync(self, pkt, timeout):
        """Run Scapy's blocking sr1 in thread-safe way"""
        return sr1(pkt, timeout=timeout)

    async def scan(self, request: Request) -> Optional[Response]:
        """
        Nmap-style ACK interpretation:
        +--------------------------+-------------+
        | Response                 | State       |
        +--------------------------+-------------+
        | TCP RST                  | unfiltered  |
        | ICMP unreachable (3/1-13)| filtered    |
        | No response              | filtered    |
        +--------------------------+-------------+
        """
        source_port = RandShort()
        ackpkt = IP(dst=request.ip) / TCP(sport=source_port, dport=request.port, flags="A")

        for _ in range(self.retries):
            try:
                answer = await asyncio.wait_for(
                    asyncio.to_thread(self._send_sync, ackpkt, self.timeout),
                    timeout=self.event_out
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

            if answer:
                if answer.haslayer(TCP):
                    tcp = answer[TCP]
                    if tcp.flags & 0x04 == 0x04:  # RST
                        return self._make_response(request, "unfiltered")
                elif answer.haslayer(ICMP):
                    icmp = answer[ICMP]
                    if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                        return self._make_response(request, "filtered")

        return self._make_response(request, "filtered")

    def _make_response(self, request: Request, status: str) -> Response:
        return Response(
            ip=request.ip,
            port=request.port,
            type="ack",
            status=status,
            timestamp=datetime.now().astimezone().isoformat(),
            domain=request.domain,
        )
