"""Adapter between normalized Layer 1-3 events and the prototype ML models."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..capture.models import PacketEvent
from .ml_pipeline import (
    calculate_risk,
    predict_anomaly,
    predict_flow,
    prepare_dataset,
    save_preprocessing,
    split_and_scale,
    train_isolation_forest,
    train_random_forest,
)
from .models import SecurityAlert


FEATURE_COLUMNS = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Destination Port",
    "Flow Bytes/s",
    "Packet Length Mean",
)


class DetectionEngine:
    """Score each normalized event with the Random Forest + Isolation Forest pair."""

    def __init__(
        self,
        artifact_dir: str | Path,
        *,
        sample_path: str | Path | None = None,
        auto_train: bool = True,
    ) -> None:
        self.artifact_dir = Path(artifact_dir)
        self.sample_path = Path(sample_path) if sample_path else None
        self.auto_train = auto_train
        self._models: tuple[Any, Any, Any, dict[str, Any]] | None = None
        self._status = "not-loaded"
        self._error: str | None = None

    @property
    def status(self) -> dict[str, Any]:
        return {
            "status": self._status,
            "available": self._models is not None,
            "artifact_dir": str(self.artifact_dir),
            "error": self._error,
        }

    def _load(self) -> tuple[Any, Any, Any, dict[str, Any]]:
        if self._models is not None:
            return self._models
        try:
            import joblib
        except ImportError as exc:
            self._status = "unavailable"
            self._error = "ML dependencies are not installed; install the ml extra."
            raise RuntimeError(self._error) from exc

        required = (
            self.artifact_dir / "random_forest.joblib",
            self.artifact_dir / "isolation_forest.joblib",
            self.artifact_dir / "scaler.joblib",
            self.artifact_dir / "preprocessing.joblib",
        )
        if not all(path.exists() for path in required):
            if not self.auto_train or self.sample_path is None:
                self._status = "unavailable"
                self._error = "ML artifacts are missing and automatic training is disabled."
                raise RuntimeError(self._error)
            self._train_from_sample()
        self._models = (
            joblib.load(required[0]),
            joblib.load(required[1]),
            joblib.load(required[2]),
            joblib.load(required[3]),
        )
        self._status = "ready"
        self._error = None
        return self._models

    def _train_from_sample(self) -> None:
        if self.sample_path is None or not self.sample_path.exists():
            self._status = "unavailable"
            self._error = "ML sample dataset is not available for bootstrap training."
            raise RuntimeError(self._error)
        try:
            import pandas as pd
        except ImportError as exc:
            self._status = "unavailable"
            self._error = "ML dependencies are not installed; install the ml extra."
            raise RuntimeError(self._error) from exc

        features, target, target_name, fill_values = prepare_dataset(
            pd.read_csv(self.sample_path), "Label"
        )
        x_train, _, y_train, _, scaler = split_and_scale(features, target)
        save_preprocessing(
            scaler, list(features.columns), fill_values, target_name, self.artifact_dir
        )
        train_random_forest(x_train, y_train, self.artifact_dir)
        train_isolation_forest(x_train, y_train, self.artifact_dir)

    @staticmethod
    def features_for(
        event: PacketEvent, flow_features: Mapping[str, float] | None = None
    ) -> dict[str, float]:
        duration_ms = max((event.duration or 0.0) * 1000.0, 0.0)
        total_bytes = (event.source_bytes or 0) + (event.destination_bytes or 0)
        bytes_per_second = total_bytes / max(event.duration or 0.001, 0.001)
        features = {
            "Flow Duration": duration_ms,
            "Total Fwd Packets": float(event.source_packets or 1),
            "Total Backward Packets": float(event.destination_packets or 1),
            "Destination Port": float(event.destination_port or 0),
            "Flow Bytes/s": bytes_per_second,
            "Packet Length Mean": float(event.packet_length),
            "Destination Port": float(event.destination_port or 0),
            "IP Version": float(event.ip_version or 4),
            "TTL": float(event.ttl or 0),
            "Payload Size": float(event.payload_size or 0),
        }
        if flow_features:
            features.update(flow_features)
        return features

    def score(
        self, event: PacketEvent, flow_features: Mapping[str, float] | None = None
    ) -> SecurityAlert:
        self._load()
        features = self.features_for(event, flow_features)
        supervised_probability = predict_flow(features, self.artifact_dir, self._models)
        anomaly = predict_anomaly(features, self.artifact_dir, self._models)
        risk = calculate_risk(
            supervised_probability, float(anomaly["anomaly_score"])
        )
        severity = str(risk["severity"])
        risk_score = float(risk["risk_score"])
        detected_by = tuple(
            name for name, active in (
                ("RANDOM_FOREST", supervised_probability >= 0.5),
                ("ISOLATION_FOREST", bool(anomaly["is_anomaly"])),
            ) if active
        )
        explanation = (
            "Known-attack classifier and behavioral anomaly detector agree."
            if len(detected_by) == 2
            else "Behavioral anomaly detector flagged this flow."
            if anomaly["is_anomaly"]
            else "Known-attack classifier raised the attack probability."
            if supervised_probability >= 0.5
            else "Both Layer 4 models consider this flow within the normal range."
        )
        return SecurityAlert(
            event_id=event.event_id or "",
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            protocol=event.protocol,
            capture_source=event.capture_source,
            risk_score=risk_score,
            severity=severity,
            supervised_probability=supervised_probability,
            anomaly_score=float(risk["anomaly_score"]),
            is_anomaly=bool(anomaly["is_anomaly"]),
            detected_by=detected_by,
            explanation=explanation,
            packet={
                "packet_id": event.packet_id,
                "event_type": event.event_type,
                "source_port": event.source_port,
                "destination_port": event.destination_port,
                "packet_length": event.packet_length,
                "duration": event.duration,
                "source_bytes": event.source_bytes,
                "destination_bytes": event.destination_bytes,
                "source_packets": event.source_packets,
                "destination_packets": event.destination_packets,
                "alert_signature": event.alert_signature,
                "alert_category": event.alert_category,
                "alert_severity": event.alert_severity,
                "correlation_key": event.correlation_key,
                "raw": event.raw,
            },
            model_features=features,
        )
