"""Contracts emitted by the cross-layer agentic workflow."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Incident:
    incident_id: str
    created_at: str
    status: str
    severity: str
    title: str
    summary: str
    confidence: float
    source_event_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    ticket: dict[str, Any]
    agent_status: str
    model: str
    attack_phase: str = "unknown"
    techniques: tuple[str, ...] = ()
    confidence_basis: tuple[str, ...] = ()
    metrics: dict[str, float] = field(default_factory=dict)
    correlation_key: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    executive_brief: str = ""
    adversary_profile: dict[str, Any] = field(default_factory=dict)
    mitre_tactics: tuple[dict[str, Any], ...] = ()
    forensic_breakdown: dict[str, Any] = field(default_factory=dict)
    iocs: tuple[dict[str, Any], ...] = ()
    playbook: tuple[dict[str, Any], ...] = ()
    layer_trace: dict[str, Any] = field(default_factory=dict)
    mitigation_status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["source_event_ids"] = list(self.source_event_ids)
        value["evidence"] = list(self.evidence)
        value["recommended_actions"] = list(self.recommended_actions)
        value["techniques"] = list(self.techniques)
        value["confidence_basis"] = list(self.confidence_basis)
        value["mitre_tactics"] = list(self.mitre_tactics)
        value["iocs"] = list(self.iocs)
        value["playbook"] = list(self.playbook)
        return value

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        def as_tuple(val: Any) -> tuple[Any, ...]:
            if isinstance(val, (list, tuple)):
                return tuple(val)
            if val is None:
                return ()
            return (val,)

        return cls(
            incident_id=str(data.get("incident_id", "")),
            created_at=str(data.get("created_at", "")),
            status=str(data.get("status", "open")),
            severity=str(data.get("severity", "MEDIUM")),
            title=str(data.get("title", "Security Incident")),
            summary=str(data.get("summary", "")),
            confidence=float(data.get("confidence", 0.5)),
            source_event_ids=tuple(str(x) for x in data.get("source_event_ids", ())),
            evidence=tuple(str(x) for x in data.get("evidence", ())),
            recommended_actions=tuple(str(x) for x in data.get("recommended_actions", ())),
            ticket=dict(data.get("ticket") or {}),
            agent_status=str(data.get("agent_status", "analyzed")),
            model=str(data.get("model", "mistral:7b")),
            attack_phase=str(data.get("attack_phase", "unknown")),
            techniques=tuple(str(x) for x in data.get("techniques", ())),
            confidence_basis=tuple(str(x) for x in data.get("confidence_basis", ())),
            metrics={k: float(v) for k, v in (data.get("metrics") or {}).items()},
            correlation_key=data.get("correlation_key"),
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            executive_brief=str(data.get("executive_brief", "")),
            adversary_profile=dict(data.get("adversary_profile") or {}),
            mitre_tactics=as_tuple(data.get("mitre_tactics", ())),
            forensic_breakdown=dict(data.get("forensic_breakdown") or {}),
            iocs=as_tuple(data.get("iocs", ())),
            playbook=as_tuple(data.get("playbook", ())),
            layer_trace=dict(data.get("layer_trace") or {}),
            mitigation_status=str(data.get("mitigation_status", "pending")),
        )


@dataclass
class InvestigationState:
    event: dict[str, Any]
    alert: dict[str, Any]
    flow_features: dict[str, float]
    related_alerts: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    analysis: dict[str, Any] = field(default_factory=dict)
    ticket: dict[str, Any] = field(default_factory=dict)
    incident: Incident | None = None
