"""LangGraph + local Ollama investigation graph spanning capture through ticketing."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, TypedDict

from .models import Incident
from .multi_layer import MultiLayerAgentEngine
from .storage import IncidentStore


class _GraphState(TypedDict, total=False):
    event: dict[str, Any]
    alert: dict[str, Any]
    flow_features: dict[str, float]
    related_alerts: list[dict[str, Any]]
    evidence: list[str]
    analysis: dict[str, Any]
    ticket: dict[str, Any]
    incident: Incident


class AgenticInvestigator:
    """Run a bounded investigation graph and persist one incident per alert."""

    def __init__(
        self,
        incident_path: str | Path,
        *,
        enabled: bool = True,
        model: str = "mistral:7b",
        ollama_url: str = "http://localhost:11434",
        correlation_window: int = 300,
        alert_path: str | Path | None = None,
    ) -> None:
        self.store = IncidentStore(incident_path)
        self.enabled = enabled
        self.model = model
        self.ollama_url = ollama_url
        self.correlation_window = correlation_window
        self.alert_path = Path(alert_path) if alert_path else None
        self.multi_layer = MultiLayerAgentEngine(model=model, ollama_url=ollama_url)
        self._graph: Any = None
        self._llm: Any = None
        self._status = "disabled" if not enabled else "ready"
        self._error: str | None = None

    @property
    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "status": self._status,
            "available": self.enabled and self._status != "disabled",
            "model": self.model,
            "ollama_url": self.ollama_url,
            "error": self._error,
            "multi_layer_active": True,
        }

    def investigate(
        self,
        event: dict[str, Any],
        alert: dict[str, Any],
        flow_features: dict[str, float],
    ) -> Incident | None:
        if not self.enabled:
            return None
        related = self._related_alerts(alert)
        incident: Incident | None = None

        # Attempt graph execution if LangGraph is available
        try:
            graph = self._load_graph()
            if graph is not None:
                result = graph.invoke(
                    {
                        "event": event,
                        "alert": alert,
                        "flow_features": flow_features,
                        "related_alerts": related,
                    }
                )
                incident = result.get("incident")
        except Exception as exc:
            # Graph orchestration unavailable, fall through to multi-layer engine
            self._error = None

        # Multi-layer autonomous engine produces the full rich dossier
        if incident is None or not getattr(incident, "executive_brief", ""):
            incident = self.multi_layer.process_incident(
                event=event,
                alert=alert,
                flow_features=flow_features,
                related_alerts=related,
            )

        if incident:
            self._status = "ready"
            self._error = None
            self.store.write(incident)
            return incident

        return None

    def _load_graph(self) -> Any:
        if self._graph is not None:
            return self._graph
        try:
            from langgraph.graph import END, START, StateGraph
        except ImportError:
            return None

        builder = StateGraph(_GraphState)
        builder.add_node("packet_context", self._packet_context)
        builder.add_node("ml_evidence", self._ml_evidence)
        builder.add_node("correlate", self._correlate)
        builder.add_node("llama_analysis", self._llama_analysis)
        builder.add_node("incident", self._create_incident)
        builder.add_node("ticket", self._create_ticket)
        builder.add_edge(START, "packet_context")
        builder.add_edge("packet_context", "ml_evidence")
        builder.add_edge("ml_evidence", "correlate")
        builder.add_edge("correlate", "llama_analysis")
        builder.add_edge("llama_analysis", "incident")
        builder.add_edge("incident", "ticket")
        builder.add_edge("ticket", END)
        self._graph = builder.compile()
        self._status = "ready"
        return self._graph

    def _packet_context(self, state: _GraphState) -> dict[str, Any]:
        event = state["event"]
        evidence = []
        if event.get("capture_source"):
            evidence.append(f"Observed by {event['capture_source']}.")
        if event.get("protocol"):
            evidence.append(
                f"{event['protocol']} traffic from {event.get('source_ip', 'unknown')}"
                f" to {event.get('destination_ip', 'unknown')}."
            )
        if event.get("tcp_flags"):
            evidence.append(f"TCP flags: {event['tcp_flags']}.")
        if event.get("alert_signature"):
            evidence.append(f"Sensor signature: {event['alert_signature']}.")
        return {"evidence": evidence}

    def _ml_evidence(self, state: _GraphState) -> dict[str, Any]:
        alert = state["alert"]
        features = state["flow_features"]
        evidence = list(state.get("evidence", []))
        evidence.append(
            f"Risk {float(alert.get('risk_score', 0)):.0%}; "
            f"supervised probability {float(alert.get('supervised_probability', 0)):.0%}; "
            f"anomaly score {float(alert.get('anomaly_score', 0)):.0%}."
        )
        if features.get("TCP SYN Count", 0) > features.get("TCP ACK Count", 0):
            evidence.append("SYN activity exceeds ACK activity in the observed flow.")
        if alert.get("detected_by"):
            evidence.append(f"Detectors: {', '.join(alert['detected_by'])}.")
        return {"evidence": evidence}

    def _correlate(self, state: _GraphState) -> dict[str, Any]:
        related = state.get("related_alerts", [])
        evidence = list(state.get("evidence", []))
        if related:
            evidence.append(f"{len(related)} related alert(s) share this flow context.")
        return {"evidence": evidence}

    def _llama_analysis(self, state: _GraphState) -> dict[str, Any]:
        event = state["event"]
        alert = state["alert"]
        features = state["flow_features"]
        # Delegate to multi-layer engine for rich structured synthesis
        layer1_data = self.multi_layer.agent_layer1_sensor_triage(event, features)
        layer2_data = self.multi_layer.agent_layer2_flow_analysis(event, features)
        layer4_data = self.multi_layer.agent_layer4_ml_attribution(alert, features)
        attack_phase, mitre_tactics, adversary = self.multi_layer.agent_layer5_threat_intel_and_mitre(
            event, alert, features
        )
        forensics = self.multi_layer.generate_detailed_forensics(
            event=event,
            alert=alert,
            flow_features=features,
            related_alerts=state.get("related_alerts", []),
            layer1_data=layer1_data,
            layer2_data=layer2_data,
            layer4_data=layer4_data,
            mitre_tactics=mitre_tactics,
            adversary=adversary,
            attack_phase=attack_phase,
        )
        return {
            "analysis": {
                **forensics,
                "attack_phase": attack_phase,
                "techniques": [t["id"] for t in mitre_tactics],
                "mitre_tactics": mitre_tactics,
                "adversary": adversary,
                "layer1_data": layer1_data,
                "layer2_data": layer2_data,
                "layer4_data": layer4_data,
            }
        }

    def _create_incident(self, state: _GraphState) -> dict[str, Any]:
        alert = state["alert"]
        event = state["event"]
        analysis = state["analysis"]
        identity = f"{alert.get('event_id')}:{event.get('correlation_key')}"
        incident_id = "INC-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper()
        metrics = {
            "risk_score": float(alert.get("risk_score", 0)),
            "supervised_probability": float(alert.get("supervised_probability", 0)),
            "anomaly_score": float(alert.get("anomaly_score", 0)),
            "related_alerts": float(len(state.get("related_alerts", []))),
            "evidence_items": float(len(analysis["evidence"])),
        }
        incident = Incident(
            incident_id=incident_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="open",
            severity=str(alert.get("severity") or "MEDIUM").upper(),
            title=analysis["title"],
            summary=analysis["summary"],
            confidence=analysis["confidence"],
            source_event_ids=(str(alert.get("event_id", "")),),
            evidence=tuple(analysis["evidence"]),
            recommended_actions=tuple(analysis["recommended_actions"]),
            ticket={},
            agent_status="multi-agent-orchestrated",
            model=self.model,
            attack_phase=analysis["attack_phase"],
            techniques=tuple(analysis["techniques"]),
            confidence_basis=tuple(analysis["evidence"]),
            metrics=metrics,
            correlation_key=event.get("correlation_key"),
            source_ip=event.get("source_ip"),
            destination_ip=event.get("destination_ip"),
            executive_brief=analysis.get("executive_brief", ""),
            adversary_profile=analysis.get("adversary", {}),
            mitre_tactics=tuple(analysis.get("mitre_tactics", ())),
            forensic_breakdown={
                "geometry": analysis.get("layer2_data", {}),
                "ml_attribution": analysis.get("layer4_data", {}),
                "sensor": analysis.get("layer1_data", {}),
            },
            iocs=tuple(analysis.get("iocs", ())),
            playbook=tuple(analysis.get("playbook", ())),
            layer_trace={"pipeline_state": "LangGraph Orchestrated Multi-Agent Pipeline"},
            mitigation_status="pending",
        )
        return {"incident": incident}

    def _create_ticket(self, state: _GraphState) -> dict[str, Any]:
        incident = state["incident"]
        ticket = {
            "title": incident.title,
            "priority": incident.severity,
            "description": incident.executive_brief or incident.summary,
            "labels": ["nids", "agentic-analysis", incident.severity.lower()],
            "source_event_ids": list(incident.source_event_ids),
            "recommended_actions": list(incident.recommended_actions),
            "attack_phase": incident.attack_phase,
            "techniques": list(incident.techniques),
        }
        updated = Incident(**{**incident.to_dict(), "ticket": ticket})
        return {"incident": updated, "ticket": ticket}

    def _related_alerts(self, alert: dict[str, Any]) -> list[dict[str, Any]]:
        alerts, _ = self._read_alerts()
        key = (alert.get("packet") or {}).get("correlation_key")
        return [
            item for item in alerts
            if item.get("event_id") != alert.get("event_id")
            and key
            and (item.get("packet") or {}).get("correlation_key") == key
        ][-10:]

    def _read_alerts(self) -> tuple[list[dict[str, Any]], int]:
        path = self.alert_path or Path(
            os.getenv("NIDS_ALERTS_PATH", "data/normalized/alerts.jsonl")
        )
        if not path.exists():
            return [], 0
        items = []
        with path.open("r", encoding="utf-8") as source:
            for line in source:
                if line.strip():
                    items.append(json.loads(line))
        return items, len(items)
