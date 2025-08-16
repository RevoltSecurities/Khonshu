from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, UDP, ICMP
from typing import Optional
from datetime import datetime
import asyncio
from khonshu import Request, Response
conf.verb = 0

class AsyncUdpScanner:
    def __init__(self, timeout: float = 2.0, retries: int = 3):
        self.timeout = timeout
        self.retries = retries
        self.event_out = self.timeout + 1.5

    def _send_sync(self, pkt, timeout):
        return sr1(pkt, timeout=timeout)

    async def scan(self, request: Request) -> Optional[Response]:
        """
        UDP scan following Nmap logic:

        +---------------------------------------------+------------------+
        |               Response Type                 |   Port State     |
        +---------------------------------------------+------------------+
        | UDP response                                | OPEN             |
        | ICMP Type 3 Code 3 (Port unreachable)       | CLOSED           |
        | ICMP Type 3 Code 1,2,9,10,13                | FILTERED         |
        | No response after retries                   | OPEN|FILTERED    |
        +---------------------------------------------+------------------+
        """
        udp_pkt = IP(dst=request.ip) / UDP(sport=RandShort(), dport=request.port)

        for _ in range(self.retries):
            try:
                answer = await asyncio.wait_for(
                    asyncio.to_thread(self._send_sync, udp_pkt, self.timeout),
                    timeout=self.event_out
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

            if answer:
                if answer.haslayer(UDP):
                    return self._make_response(request, "open")
                elif answer.haslayer(ICMP):
                    icmp = answer[ICMP]
                    if icmp.type == 3:
                        if icmp.code == 3:
                            return self._make_response(request, "closed")
                        elif icmp.code in [1, 2, 9, 10, 13]:
                            return self._make_response(request, "filtered")

        return self._make_response(request, "open|filtered")

    def _make_response(self, request: Request, status: str) -> Response:
        return Response(
            ip=request.ip,
            port=request.port,
            type="udp",
            status=status,
            timestamp=datetime.now().astimezone().isoformat(),
            domain=request.domain,
        )