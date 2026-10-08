"""Durable local history and optional Redis Stream publishing."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol
import json
from collections import deque

from .models import PacketEvent


class EventSink(Protocol):
    def write(self, event: PacketEvent) -> None: ...


class JsonlEventStore:
    """Append-only JSONL storage for historical replay and auditability."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: PacketEvent) -> None:
        with self.path.open("a", encoding="utf-8") as output:
            output.write(event.to_json() + "\n")

    def read(self, offset: int = 0, limit: int = 100) -> tuple[list[PacketEvent], int]:
        """Read a bounded page from historical events."""
        if offset < 0 or limit < 1:
            raise ValueError("offset must be non-negative and limit must be positive")
        events: list[PacketEvent] = []
        total = 0
        if not self.path.exists():
            return events, total

        with self.path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                total += 1
                if offset <= total - 1 < offset + limit:
                    try:
                        events.append(PacketEvent.from_mapping(json.loads(line)))
                    except (json.JSONDecodeError, ValueError) as exc:
                        raise ValueError(
                            f"invalid historical event at {self.path}:{line_number}: {exc}"
                        ) from exc
        return events, total

    def read_latest(self, limit: int = 100) -> tuple[list[PacketEvent], int]:
        """Read the newest bounded page without loading the whole history."""
        if limit < 1:
            raise ValueError("limit must be positive")
        if not self.path.exists():
            return [], 0
        recent: deque[PacketEvent] = deque(maxlen=limit)
        total = 0
        with self.path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    recent.append(PacketEvent.from_mapping(json.loads(line)))
                except (json.JSONDecodeError, ValueError) as exc:
                    raise ValueError(
                        f"invalid historical event at {self.path}:{line_number}: {exc}"
                    ) from exc
                total += 1
        return list(reversed(recent)), total


class RedisStreamSink:
    """Publish normalized events to a Redis Stream when configured."""

    def __init__(self, client: object, stream: str = "nids:raw-events") -> None:
        self.client = client
        self.stream = stream

    def write(self, event: PacketEvent) -> None:
        add = getattr(self.client, "xadd", None)
        if add is None:
            raise TypeError("Redis client must provide xadd")
        add(self.stream, {"event": event.to_json()})
