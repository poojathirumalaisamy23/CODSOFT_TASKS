"""Detects TCP port scans."""
from collections import defaultdict, deque
from time import time
from typing import Optional
from detection.base import BaseDetector
from output.alerts import Alert, Severity


class PortScanDetector(BaseDetector):
    name = "PORT_SCAN"

    def __init__(self, config: dict):
        super().__init__(config)
        self.threshold = config.get("unique_ports_threshold", 15)
        self.window = config.get("time_window_seconds", 5)
        self.severity = Severity(config.get("severity", "HIGH"))
        # {src_ip: {dst_ip: deque[(timestamp, dst_port)]}}
        self._tracker: dict = defaultdict(lambda: defaultdict(deque))
        self._alerted: set = set()

    def process(self, packet_info: dict) -> Optional[Alert]:
        if not self.enabled or packet_info.get("protocol") != "TCP":
            return None

        src = packet_info["src_ip"]
        dst = packet_info["dst_ip"]
        dport = packet_info.get("dst_port")
        flags = packet_info.get("tcp_flags") or ""

        # Only count SYN packets (scan indicators)
        if "S" not in flags or "A" in flags or dport is None:
            return None

        now = time()
        key = (src, dst)
        tracker = self._tracker[src][dst]
        tracker.append((now, dport))

        # Drop entries older than the window
        while tracker and now - tracker[0][0] > self.window:
            tracker.popleft()

        unique_ports = {p for _, p in tracker}

        if len(unique_ports) >= self.threshold and key not in self._alerted:
            self._alerted.add(key)
            return Alert(
                rule=self.name,
                severity=self.severity,
                src_ip=src,
                dst_ip=dst,
                message=f"Port scan detected: {len(unique_ports)} unique ports in {self.window}s",
                metadata={"unique_ports": len(unique_ports), "window": self.window},
            )
        return None