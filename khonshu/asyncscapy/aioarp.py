from typing import List
from scapy.all import ARP, Ether, srp,conf
from khonshu import ARPPing
import asyncio
conf.verb = 0

class AioARP:
    def __init__(self, timeout: float = 10.0, retries: int = 2, interface:str = None):
        self.timeout = timeout
        self.retries = retries
        self.interface = interface

    async def scan(self, cidr: str = "192.168.1.0/24") -> List[ARPPing]:
        def _arp_scan():
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
            ans, _ = srp(pkt, timeout=self.timeout, retry=self.retries, iface=self.interface)
            return [
                ARPPing(ip=r.psrc, mac=r.hwsrc, status="alive")
                for _, r in ans
            ]
        return await asyncio.to_thread(_arp_scan)