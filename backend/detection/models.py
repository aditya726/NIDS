"""Stable output contract for Layer 4 detections."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    event_id: str
    timestamp: str
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    capture_source: str
    risk_score: float
    severity: str
    supervised_probability: float
    anomaly_score: float
    is_anomaly: bool
    detected_by: tuple[str, ...]
    explanation: str
    packet: dict[str, Any]
    model_features: dict[str, float]
    model_status: str = "ready"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["detected_by"] = list(self.detected_by)
        return value
