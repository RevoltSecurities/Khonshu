from scapy.all import sr1, RandShort, conf
from scapy.layers.inet import IP, TCP, ICMP
from typing import Optional
from datetime import datetime
import asyncio
from khonshu import Request, Response
conf.verb = 0

class AsyncStealthFlagScanner:
    SUPPORTED_SCANS = {
        "null": 0,
        "fin": "F",
        "xmas": "FPU",
    }

    def __init__(self, scan_type: str = "null", timeout: float = 2.0, retries: int = 1):
        scan_type = scan_type.lower()
        if scan_type not in self.SUPPORTED_SCANS:
            raise ValueError(f"Unsupported scan type: {scan_type}. Choose from {list(self.SUPPORTED_SCANS.keys())}")
        self.scan_type = scan_type
        self.timeout = timeout
        self.retries = retries
        self.event_out = self.timeout + 1.5

    def _send_sync(self, pkt, timeout):
        return sr1(pkt, timeout=timeout)

    def _build_packet(self, dst_ip: str, dst_port: int):
        sport = RandShort()
        flags = self.SUPPORTED_SCANS[self.scan_type]
        return IP(dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags=flags)

    async def scan(self, request: Request) -> Optional[Response]:
        """
        FIN/NULL/Xmas scan interpretation:
        +--------------------------+------------------+
        | Response                 | State            |
        +--------------------------+------------------+
        | TCP RST (0x14)           | closed           |
        | ICMP unreachable (3/x)   | filtered         |
        | No response              | open|filtered    |
        +--------------------------+------------------+
        """
        pkt = self._build_packet(request.ip, request.port)

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
                    if tcp.flags & 0x14 == 0x14:  # RST
                        return self._make_response(request, "closed")
                elif answer.haslayer(ICMP):
                    icmp = answer[ICMP]
                    if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                        return self._make_response(request, "filtered")

        return self._make_response(request, "open|filtered")

    def _make_response(self, request: Request, status: str) -> Response:
        return Response(
            ip=request.ip,
            port=request.port,
            type=self.scan_type,
            status=status,
            timestamp=datetime.now().astimezone().isoformat(),
            domain=request.domain,
        )
