"""from typing import Optional
from dataclasses import dataclass

@dataclass
class Request:
    ip: str                              # Target IP address
    port: Optional[int] = 80                       # Target port number
    type: str = "connect"                # Scan type: connect, syn, ack, xmas, null, fin, etc.
    domain: Optional[str] = None         # Original domain if resolved from one
    interface: Optional[str] = None      # Interface to use (e.g., eth0)
    scan_id: Optional[str] = None        # Optional tracking ID for the scan"""

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

    def __str__(self) -> str:
        # Use "::" as separator to allow empty fields
        return "::".join([
            self.ip,
            str(self.port) if self.port is not None else "",
            self.type,
            self.domain if self.domain is not None else "",
            self.interface if self.interface is not None else "",
            self.scan_id if self.scan_id is not None else "",
        ])

    @staticmethod
    def from_str(s: str) -> "Request":
        parts = s.strip().split("::")
        # Ensure list has at least 6 elements, fill missing with ''
        parts += [""] * (6 - len(parts))
        ip, port, type_, domain, interface, scan_id = parts
        return Request(
            ip=ip,
            port=int(port) if port else None,
            type=type_,
            domain=domain or None,
            interface=interface or None,
            scan_id=scan_id or None,
        )
