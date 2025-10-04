from typing import Optional
from dataclasses import dataclass

@dataclass
class Response:
    ip: str                               # IP
    port: int                             # Scanned port
    type: str                             # scan type
    status: str                           # open / filtered  (only open preferred)
    timestamp: str                   # Scan completed timestamp
    domain: Optional[str] = None          # Domain if provided in the request
    interface: Optional[str] = None       # Interface we used