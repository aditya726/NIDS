"""Append-only alert storage for dashboard reads and auditability."""

from __future__ import annotations

from collections import deque
import json
from pathlib import Path
from typing import Any

from .models import SecurityAlert


class AlertStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, alert: SecurityAlert) -> None:
        with self.path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(alert.to_dict(), separators=(",", ":")) + "\n")

    def read_latest(self, limit: int = 100) -> tuple[list[dict[str, Any]], int]:
        if limit < 1:
            raise ValueError("limit must be positive")
        recent: deque[dict[str, Any]] = deque(maxlen=limit)
        total = 0
        if not self.path.exists():
            return [], 0
        with self.path.open("r", encoding="utf-8") as source:
            for line in source:
                if line.strip():
                    recent.append(json.loads(line))
                    total += 1
        return list(reversed(recent)), total
