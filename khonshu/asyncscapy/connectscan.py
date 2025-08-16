from typing import Optional
import asyncio
import socket
from datetime import datetime
from khonshu import Request, Response

class AsyncConnectScanner:
    def __init__(self, timeout: float = 10.0, retries: int = 2):
        self.timeout = timeout
        self.retries = retries

    def _now(self) -> str:
        return datetime.now().astimezone().isoformat()

    async def scan(self, request: Request) -> Optional[Response]:
        """
            Performs a full TCP connect scan using asyncio. Classifies ports based on:

            +------------------------------+--------------+
            |     Connect Scan Result     |  Port State  |
            +------------------------------+--------------+
            | Connection success           | OPEN         |
            | Connection refused           | CLOSED       |
            | Timeout / unreachable error  | FILTERED     |
            +------------------------------+--------------+

            Nmap Connect Scan Reference: https://nmap.org/book/synscan.html
        """
        for _ in range(self.retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=request.ip, port=request.port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return Response(
                    ip=request.ip,
                    port=request.port,
                    type="connect",
                    status="open",
                    timestamp=self._now(),
                    domain=request.domain,
                )

            except (ConnectionRefusedError, asyncio.TimeoutError, socket.timeout, OSError):
                    return Response(
                    ip=request.ip,
                    port=request.port,
                    type="connect",
                    status="closed",
                    timestamp=self._now(),
                    domain=request.domain,
                    )
            except Exception:
                continue

        # All retries exhausted, so we assume filtered
        return Response(
            ip=request.ip,
            port=request.port,
            type="connect",
            status="filtered",
            timestamp=self._now(),
            domain=request.domain,
        )

