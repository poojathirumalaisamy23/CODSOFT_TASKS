"""Alert data model + severity levels."""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from colorama import Fore, Style, init

init(autoreset=True)


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


COLORS = {
    Severity.LOW: Fore.CYAN,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.HIGH: Fore.RED,
    Severity.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
}


@dataclass
class Alert:
    rule: str
    severity: Severity
    src_ip: str
    dst_ip: str = ""
    message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def pretty(self) -> str:
        color = COLORS.get(self.severity, "")
        return (
            f"{color}[{self.severity.value}]{Style.RESET_ALL} "
            f"{self.rule} | {self.src_ip} -> {self.dst_ip} | {self.message}"
        )