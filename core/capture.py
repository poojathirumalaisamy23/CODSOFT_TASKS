"""Packet capture engine — wraps Scapy sniff()."""
from scapy.all import sniff, conf
from typing import Callable


class PacketCapture:
    def __init__(
        self,
        interface: str,
        bpf_filter: str = "ip",
        packet_count: int = 0,
        promiscuous: bool = True,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.promiscuous = promiscuous
        self._running = False

    @staticmethod
    def list_interfaces() -> list:
        """Return available network interfaces (Windows-safe)."""
        try:
            # Windows path (Scapy 2.7.0+)
            from scapy.arch.windows import get_windows_if_list
            return [i["name"] for i in get_windows_if_list()]
        except Exception:
            # Fallback for Linux/macOS
            from scapy.all import get_if_list
            return get_if_list()

    def start(self, callback: Callable):
        """Begin capturing. callback(packet) is called per packet."""
        self._running = True
        conf.promisc = self.promiscuous
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=callback,
            store=False,
            count=self.packet_count,
            stop_filter=lambda _: not self._running,
        )

    def stop(self):
        self._running = False