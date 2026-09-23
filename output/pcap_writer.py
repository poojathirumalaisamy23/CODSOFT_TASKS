"""PCAP export for Wireshark inspection."""
from pathlib import Path
from scapy.utils import wrpcap


class PcapWriter:
    def __init__(self, path: str, buffer_size: int = 100):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.buffer = []
        self.buffer_size = buffer_size

    def add(self, packet):
        self.buffer.append(packet)
        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        wrpcap(str(self.path), self.buffer, append=True)
        self.buffer.clear()