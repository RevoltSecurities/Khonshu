from dataclasses import dataclass
from typing import  Optional

@dataclass
class PINGAlive:
    host:                 str
    status:               str
    type:                 str
    port:   Optional[int] = None
    ms: Optional[float]   = None

@dataclass
class ARPPing:
    ip:     str
    mac:    str
    status: str = "alive"
