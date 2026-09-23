"""JSON line logger for alerts."""
import json
from pathlib import Path
from output.alerts import Alert


class AlertLogger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", buffering=1)

    def write(self, alert: Alert):
        self._fh.write(json.dumps(alert.to_dict()) + "\n")

    def close(self):
        self._fh.close()