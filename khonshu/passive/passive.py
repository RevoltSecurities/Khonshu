from shodanx.modules.shodaninternetdb.shodaninternetdb import ShodanxInternetDB
from khonshu import Request, Response
from httpx import AsyncClient
from typing import Optional, List
from datetime import datetime

class PassiveScanner:
    def __init__(self) -> None:
        self.client = AsyncClient(verify=False)
        self.scanner = ShodanxInternetDB(session=self.client)

    def _now(self) -> str:
        return datetime.now().astimezone().isoformat()

    async def scan(self, request: Request) -> Optional[List[Response]]:
        result = await self.scanner.search(ip=request.ip)
        if not result or "ports" not in result or not result["ports"]:
            return None

        responses = []
        for port in result["ports"]:
            responses.append(Response(
                port=port,
                timestamp=self._now(),
                ip=request.ip,
                domain=request.domain,
                status="open",
                type="passive"
            ))
        return responses