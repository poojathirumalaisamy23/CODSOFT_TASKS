"""Detection engine — dispatches packets to all detectors."""
from core.dissector import dissect
from detection.port_scan import PortScanDetector
from typing import Optional


class DetectionEngine:
    def __init__(self, config: dict):
        dcfg = config.get("detection", {})
        self.detectors = []

        if dcfg.get("port_scan", {}).get("enabled"):
            self.detectors.append(PortScanDetector(dcfg["port_scan"]))
        # We'll add ARP/DNS/brute force later

    def handle(self, packet):
        info = dissect(packet)
        if not info:
            return None, None
        for detector in self.detectors:
            alert = detector.process(info)
            if alert:
                return info, alert
        return info, None