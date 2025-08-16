from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, TCP, ICMP
from typing import Optional
from datetime import datetime
from khonshu import Request, Response
import asyncio
conf.verb = 0

class AsyncSynScanner:
    def __init__(self, timeout: float = 2.0, retries: int = 1):
        self.timeout = timeout
        self.retries = retries
        self.event_out = self.timeout + 1.5

    def _send_sync(self, pkt, timeout):
        """Run Scapy's blocking sr1 in thread-safe way"""
        return sr1(pkt, timeout=timeout)

    async def scan(self, request: Request) -> Optional[Response]:
        """
               Method for performing a SYN scan on a single port using Scapy.
               This function sends a crafted TCP SYN packet and interprets the response
               based on standard TCP behavior, following Nmap's SYN scan model (-sS).
               The scan detects whether a port is open or filtered, with optional support
               for detecting closed ports based on TCP RST responses.

               Port status is determined as follows:

               +------------------------------------------+------------------+
               |              Response Type               |   Port State     |
               |------------------------------------------|------------------|
               | TCP SYN+ACK (flags = 0x12)               | OPEN             |
               | TCP RST (flags = 0x14)                   | CLOSED (optional)|
               | ICMP unreachable                         | FILTERED         |
               |   (type 3, code 1, 2, 3, 9, 10, or 13)   |                  |
               | No response after retries                | FILTERED         |
               +------------------------------------------+------------------+

               Notes:
               - Ports are marked OPEN if a SYN/ACK is received.
               - Ports are marked CLOSED if an RST is received (only if `show_closed=True`).
               - Ports are marked FILTERED if no response or certain ICMP errors are received.
               - This logic mimics the behavior used by Nmap's SYN scan (-sS)

               reference link: https://nmap.org/book/synscan.html

               Returns:
                   Response: A dataclass containing the port scan result, or None
                             if the result is filtered/closed and not requested.
        """
        source_port = RandShort()
        synpkt = IP(dst=request.ip) / TCP(sport=source_port, dport=request.port, flags="S")

        for _ in range(self.retries):
            try:
                # Offload blocking sr1() into a thread
                answer = await asyncio.wait_for(
                    asyncio.to_thread(self._send_sync, synpkt, self.timeout),
                    timeout=self.event_out
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

            if answer:
                if answer.haslayer(TCP):
                    tcp = answer[TCP]
                    if tcp.flags & 0x12 == 0x12:  # SYN+ACK
                        return self._make_response(request, "open")
                    elif tcp.flags & 0x14 == 0x14:  # RST
                        return self._make_response(request, "closed")
                elif answer.haslayer(ICMP):
                    icmp = answer[ICMP]
                    if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                        return self._make_response(request, "filtered")

        return self._make_response(request, "filtered")

    def _make_response(self, request: Request, status: str) -> Response:
        return Response(
            ip=request.ip,
            port=request.port,
            type="syn",
            status=status,
            timestamp=datetime.now().astimezone().isoformat(),
            domain=request.domain,
        )