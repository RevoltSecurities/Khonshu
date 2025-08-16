from typing import List
import psutil
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
from rich.console import Console
from rich.table import Table
from khonshu import InterfaceInfo

class InterfaceManager:
    def __init__(self):
        self.console = Console()

    def list_interfaces(self) -> List[InterfaceInfo]:
        net_if_stats = psutil.net_if_stats()
        interfaces = []

        for iface in get_if_list():
            try:
                status = "UP" if net_if_stats.get(iface, None) and net_if_stats[iface].isup else "DOWN"
                ip = get_if_addr(iface)
                mac = get_if_hwaddr(iface)
                interfaces.append(InterfaceInfo(name=iface, status=status, ip=ip, mac=mac))
            except Exception:
                interfaces.append(InterfaceInfo(name=iface, status="UNKNOWN", ip="N/A", mac="N/A"))
        return interfaces

    def display_map(self):
        table = Table(title="Network Interfaces", show_lines=True)
        table.add_column("Interface", style="cyan bold")
        table.add_column("Status", style="green bold")
        table.add_column("IP Address", style="yellow")
        table.add_column("MAC Address", style="magenta")
        for iface in self.list_interfaces():
            table.add_row(iface.name, iface.status, iface.ip, iface.mac)
        self.console.print(table)

    def display_interfaces(self):
        self.display_map()