"""Stable event contracts shared by capture sources and downstream consumers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
import json


@dataclass(frozen=True, slots=True)
class PacketEvent:
    """A normalized packet/flow event suitable for storage and queueing."""

    timestamp: str
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    packet_length: int
    capture_source: str
    packet_id: str | None = None
    raw: Mapping[str, Any] | None = None

    @classmethod
    def now(cls, **kwargs: Any) -> "PacketEvent":
        """Create an event with a UTC timestamp when a source has no timestamp."""
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PacketEvent":
        """Validate and deserialize a persisted or externally supplied event."""
        required = {
            "timestamp",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "packet_length",
            "capture_source",
        }
        missing = required.difference(value)
        if missing:
            raise ValueError(f"packet event is missing fields: {sorted(missing)}")
        packet_length = value["packet_length"]
        if not isinstance(packet_length, int) or packet_length < 0:
            raise ValueError("packet_length must be a non-negative integer")
        return cls(
            timestamp=str(value["timestamp"]),
            source_ip=value["source_ip"],
            destination_ip=value["destination_ip"],
            source_port=value["source_port"],
            destination_port=value["destination_port"],
            protocol=value["protocol"],
            packet_length=packet_length,
            capture_source=str(value["capture_source"]),
            packet_id=value.get("packet_id"),
            raw=value.get("raw"),
        )
