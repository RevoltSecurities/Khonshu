from dataclasses import dataclass

@dataclass
class InterfaceInfo:
    name: str
    status: str
    ip: str
    mac: str