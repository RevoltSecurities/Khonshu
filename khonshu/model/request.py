from typing import Optional
from dataclasses import dataclass

@dataclass
class Request:
    ip: str
    port: Optional[int] = 80
    type: str = "connect"
    domain: Optional[str] = None
    interface: Optional[str] = None
    scan_id: Optional[str] = None
