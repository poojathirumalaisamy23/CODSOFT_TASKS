"""Base detector interface."""
from abc import ABC, abstractmethod
from typing import Optional
from output.alerts import Alert


class BaseDetector(ABC):
    name: str = "base"

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)

    @abstractmethod
    def process(self, packet_info: dict) -> Optional[Alert]:
        """Inspect one packet. Return an Alert if a threat is detected."""
        ...