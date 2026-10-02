"""Layer 2 ingestion orchestration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .models import PacketEvent
from .storage import EventSink


@dataclass
class PacketIngestor:
    """Fan captured events out to local history and configured downstream sinks."""

    sinks: list[EventSink] = field(default_factory=list)

    def ingest(self, events: Iterable[PacketEvent]) -> int:
        count = 0
        for event in events:
            self._validate(event)
            for sink in self.sinks:
                sink.write(event)
            count += 1
        return count

    @staticmethod
    def _validate(event: PacketEvent) -> None:
        if not isinstance(event, PacketEvent):
            raise TypeError("ingestor accepts PacketEvent instances only")
        if not event.capture_source:
            raise ValueError("packet event capture_source cannot be empty")
