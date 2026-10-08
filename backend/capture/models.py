"""Stable event contracts shared by capture sources and downstream consumers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
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
    schema_version: int = 1
    packet_id: str | None = None
    raw: Mapping[str, Any] | None = None
    event_type: str | None = None
    duration: float | None = None
    source_bytes: int | None = None
    destination_bytes: int | None = None
    source_packets: int | None = None
    destination_packets: int | None = None
    alert_signature: str | None = None
    alert_category: str | None = None
    alert_severity: int | None = None
    event_id: str | None = None
    correlation_key: str | None = None
    event_source: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        source = self.event_source or self.capture_source
        object.__setattr__(self, "event_source", source)
        if not self.event_id:
            object.__setattr__(self, "event_id", self._make_event_id())
        if not self.correlation_key:
            object.__setattr__(self, "correlation_key", self._make_correlation_key())

    def _make_event_id(self) -> str:
        identity = "|".join(
            str(value)
            for value in (
                self.event_source,
                self.packet_id,
                self.timestamp,
                self.source_ip,
                self.destination_ip,
                self.source_port,
                self.destination_port,
                self.protocol,
                self.event_type,
            )
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]

    def _make_correlation_key(self) -> str:
        """Identify observations of the same bidirectional flow across sensors."""
        endpoints = sorted(
            (
                f"{self.source_ip or ''}:{self.source_port or ''}",
                f"{self.destination_ip or ''}:{self.destination_port or ''}",
            )
        )
        return "|".join((self.protocol or "", *endpoints))

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
            schema_version=int(value.get("schema_version", 1)),
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
            event_type=value.get("event_type"),
            duration=value.get("duration"),
            source_bytes=value.get("source_bytes"),
            destination_bytes=value.get("destination_bytes"),
            source_packets=value.get("source_packets"),
            destination_packets=value.get("destination_packets"),
            alert_signature=value.get("alert_signature"),
            alert_category=value.get("alert_category"),
            alert_severity=value.get("alert_severity"),
            event_id=value.get("event_id"),
            correlation_key=value.get("correlation_key"),
            event_source=value.get("event_source"),
        )
