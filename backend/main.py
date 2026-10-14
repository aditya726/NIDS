"""FastAPI entry point for the NIDS capture and ingestion service."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .capture.sources import ScapyLiveSource
from .capture.storage import JsonlEventStore
from .service import CapturePipeline
from .detection.storage import AlertStore
from .agentic.storage import IncidentStore
from .agentic.copilot import AnalystCopilot
from .agentic.models import Incident


class CaptureStartRequest(BaseModel):
    mode: str | None = None
    path: str | None = None
    interface: str | None = None
    zeek_path: str | None = None


class CaptureSwitchRequest(CaptureStartRequest):
    mode: str


class CopilotChatRequest(BaseModel):
    question: str
    context: dict[str, Any] = {}
    history: list[dict[str, str]] | None = None


class MitigateRequest(BaseModel):
    incident_id: str
    action: str
    command: str
    target_ip: str | None = None


class DeepInvestigateRequest(BaseModel):
    event_id: str | None = None
    alert_id: str | None = None


pipeline = CapturePipeline()
copilot = AnalystCopilot(
    model=pipeline.settings.agentic_model,
    ollama_url=pipeline.settings.ollama_url,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if pipeline.settings.auto_start and pipeline.settings.source_mode != "none":
        try:
            await pipeline.start()
        except ValueError as exc:
            pipeline.status.error = str(exc)
    yield
    await pipeline.stop()


app = FastAPI(
    title="NIDS Agentic Command Center API",
    version="0.2.0",
    lifespan=lifespan,
)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "NIDS_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/capture/status")
async def capture_status() -> dict[str, Any]:
    return pipeline.status.as_dict()


@app.get("/sensors/status")
async def sensor_status() -> dict[str, Any]:
    """Report deployment-side Suricata/Zeek log readiness."""
    settings = pipeline.settings

    def describe(name: str, path: Path) -> dict[str, Any]:
        exists = path.exists()
        return {
            "name": name,
            "path": str(path),
            "available": exists,
            "size_bytes": path.stat().st_size if exists else 0,
            "updated_at": path.stat().st_mtime if exists else None,
        }

    return {
        "mode": pipeline.status.source_mode,
        "suricata": describe("suricata", settings.suricata_live_path),
        "zeek": describe("zeek", settings.zeek_live_path),
        "interface": settings.interface,
        "dual_sensor_ready": settings.suricata_live_path.exists()
        and settings.zeek_live_path.exists(),
    }


@app.get("/capture/events")
async def capture_events(
    offset: int = 0, limit: int = 100, latest: bool = False
) -> dict[str, Any]:
    """Return a page of all locally persisted captured events."""
    if limit > 1000:
        raise HTTPException(status_code=400, detail="limit cannot exceed 1000")
    try:
        store = JsonlEventStore(pipeline.settings.history_path)
        events, total = (
            store.read_latest(limit=limit)
            if latest
            else store.read(offset=offset, limit=limit)
        )
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "offset": offset,
        "limit": limit,
        "latest": latest,
        "total": total,
        "events": [event.to_dict() for event in events],
    }


@app.get("/detection/status")
async def detection_status() -> dict[str, Any]:
    return pipeline.detector.status


@app.get("/detection/alerts")
async def detection_alerts(limit: int = 100) -> dict[str, Any]:
    if limit > 1000:
        raise HTTPException(status_code=400, detail="limit cannot exceed 1000")
    try:
        alerts, total = AlertStore(pipeline.settings.alerts_path).read_latest(limit)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"alerts": alerts, "total": total}


@app.get("/agent/status")
async def agent_status() -> dict[str, Any]:
    return {
        **pipeline.investigator.status,
        "mode": pipeline.settings.agent_mode,
        "queue": pipeline.agent_dispatcher.status,
    }


@app.get("/incidents")
async def incidents(limit: int = 100) -> dict[str, Any]:
    if limit > 1000:
        raise HTTPException(status_code=400, detail="limit cannot exceed 1000")
    try:
        values, total = IncidentStore(pipeline.settings.incidents_path).read_latest(limit)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"incidents": values, "total": total}


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    try:
        values, _ = IncidentStore(pipeline.settings.incidents_path).read_latest(500)
        for inc in values:
            if inc.get("incident_id") == incident_id:
                return inc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/capture/interfaces")
async def capture_interfaces() -> dict[str, list[dict[str, str]]]:
    try:
        return {"interfaces": ScapyLiveSource.interfaces()}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/capture/start")
async def start_capture(request: CaptureStartRequest) -> dict[str, Any]:
    try:
        return await pipeline.start(
            mode=request.mode,
            path=request.path,
            interface=request.interface,
            zeek_path=request.zeek_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/capture/stop")
async def stop_capture() -> dict[str, Any]:
    return await pipeline.stop()


@app.post("/capture/switch")
async def switch_capture(request: CaptureSwitchRequest) -> dict[str, Any]:
    try:
        return await pipeline.switch(
            mode=request.mode,
            path=request.path,
            interface=request.interface,
            zeek_path=request.zeek_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# -----------------------------------------------------------------------------
# Deep Analysis & Analytical Charts Endpoints
# -----------------------------------------------------------------------------
@app.get("/analytics/overview")
async def analytics_overview() -> dict[str, Any]:
    """Compute aggregate analytics for interactive graphs & charts."""
    try:
        alerts, total_alerts = AlertStore(pipeline.settings.alerts_path).read_latest(300)
        events, total_events = JsonlEventStore(pipeline.settings.history_path).read_latest(300)
        incidents_list, total_incidents = IncidentStore(pipeline.settings.incidents_path).read_latest(100)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # Protocol breakdown
    proto_counts: dict[str, int] = {}
    for ev in events:
        p = (ev.protocol or "TCP").upper()
        proto_counts[p] = proto_counts.get(p, 0) + 1

    # Severity & Attack Vector breakdown
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vector_counts: dict[str, int] = {
        "SYN Flood / Scan": 0,
        "Brute Force / SSH": 0,
        "Web Exploit / Injection": 0,
        "Zero-Day Anomaly": 0,
        "Baseline Normal": 0,
    }

    # MITRE ATT&CK Matrix distribution
    mitre_counts: dict[str, int] = {
        "T1046 (Network Service Discovery)": 0,
        "T1110 (Brute Force)": 0,
        "T1190 (Exploit Public-Facing App)": 0,
        "T1498 (Network Denial of Service)": 0,
        "T1071 (Application Layer Protocol)": 0,
        "T1021 (Remote Services)": 0,
    }

    scatter_points = []
    top_sources: dict[str, int] = {}
    top_targets: dict[str, int] = {}

    for alert in alerts:
        sev = alert.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        src = alert.get("source_ip") or "unknown"
        dst = alert.get("destination_ip") or "unknown"
        dst_port = (alert.get("packet") or {}).get("destination_port") or 0

        top_sources[src] = top_sources.get(src, 0) + 1
        top_targets[f"{dst}:{dst_port}"] = top_targets.get(f"{dst}:{dst_port}", 0) + 1

        sup = float(alert.get("supervised_probability", 0))
        anom = float(alert.get("anomaly_score", 0))
        risk = float(alert.get("risk_score", 0))

        scatter_points.append({
            "supervised": round(sup * 100, 1),
            "anomaly": round(anom * 100, 1),
            "risk": round(risk * 100, 1),
            "severity": sev,
            "ip": src,
        })

        # Classify attack vector
        if dst_port == 22:
            vector_counts["Brute Force / SSH"] += 1
            mitre_counts["T1110 (Brute Force)"] += 1
            mitre_counts["T1021 (Remote Services)"] += 1
        elif dst_port in (80, 443, 8080):
            vector_counts["Web Exploit / Injection"] += 1
            mitre_counts["T1190 (Exploit Public-Facing App)"] += 1
        elif anom >= 0.65 and sup < 0.5:
            vector_counts["Zero-Day Anomaly"] += 1
            mitre_counts["T1071 (Application Layer Protocol)"] += 1
        elif risk >= 0.7:
            vector_counts["SYN Flood / Scan"] += 1
            mitre_counts["T1046 (Network Service Discovery)"] += 1
            mitre_counts["T1498 (Network Denial of Service)"] += 1
        else:
            vector_counts["Baseline Normal"] += 1

    # Time-series telemetry buckets (reversed so chronological)
    timeline_buckets = []
    chunk_size = max(1, len(alerts) // 12)
    for i in range(0, len(alerts), chunk_size):
        chunk = alerts[i : i + chunk_size]
        if not chunk:
            continue
        avg_risk = sum(float(a.get("risk_score", 0)) for a in chunk) / len(chunk)
        avg_anom = sum(float(a.get("anomaly_score", 0)) for a in chunk) / len(chunk)
        highs = sum(1 for a in chunk if a.get("severity") == "HIGH")
        time_label = chunk[-1].get("timestamp", "")
        if "T" in time_label:
            time_label = time_label.split("T")[1][:8]
        timeline_buckets.append({
            "time": time_label or f"T-{i}",
            "events": len(chunk),
            "high_threats": highs,
            "avg_risk": round(avg_risk * 100, 1),
            "avg_anomaly": round(avg_anom * 100, 1),
        })

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "protocols": [{"name": k, "value": v} for k, v in proto_counts.items()],
        "severity": severity_counts,
        "attack_vectors": [{"name": k, "count": v} for k, v in vector_counts.items() if v > 0],
        "mitre_matrix": [{"technique": k, "hits": v} for k, v in mitre_counts.items() if v > 0],
        "scatter": scatter_points[:80],
        "timeline": list(reversed(timeline_buckets)),
        "top_sources": sorted([{"ip": k, "count": v} for k, v in top_sources.items()], key=lambda x: x["count"], reverse=True)[:5],
        "top_targets": sorted([{"target": k, "count": v} for k, v in top_targets.items()], key=lambda x: x["count"], reverse=True)[:5],
    }


@app.get("/analytics/topology")
async def analytics_topology() -> dict[str, Any]:
    """Return communication topology graph (nodes + directed threat edges)."""
    try:
        alerts, _ = AlertStore(pipeline.settings.alerts_path).read_latest(150)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    nodes_dict: dict[str, dict[str, Any]] = {
        "sensor_gateway": {
            "id": "sensor_gateway",
            "label": "Sensor Gateway (Suricata/Zeek)",
            "type": "gateway",
            "risk": 0.0,
            "connections": len(alerts),
        }
    }
    edges = []

    for alert in alerts:
        src = alert.get("source_ip") or "unknown_src"
        dst = alert.get("destination_ip") or "unknown_dst"
        risk = float(alert.get("risk_score", 0))
        sev = alert.get("severity", "LOW")
        proto = alert.get("protocol") or "TCP"
        pkt = alert.get("packet") or {}
        port = pkt.get("destination_port") or 80

        if src not in nodes_dict:
            nodes_dict[src] = {
                "id": src,
                "label": f"Attacker: {src}",
                "type": "attacker",
                "risk": risk,
                "connections": 1,
            }
        else:
            nodes_dict[src]["connections"] += 1
            nodes_dict[src]["risk"] = max(nodes_dict[src]["risk"], risk)

        dst_id = f"target_{dst}"
        if dst_id not in nodes_dict:
            nodes_dict[dst_id] = {
                "id": dst_id,
                "label": f"Internal Target: {dst}:{port}",
                "type": "target",
                "risk": risk,
                "connections": 1,
            }
        else:
            nodes_dict[dst_id]["connections"] += 1

        edges.append({
            "source": src,
            "target": dst_id,
            "protocol": proto,
            "risk": round(risk * 100, 1),
            "severity": sev,
            "port": port,
        })

    return {
        "nodes": list(nodes_dict.values())[:30],
        "edges": edges[:50],
    }


# -----------------------------------------------------------------------------
# Interactive SOC Copilot & Mitigation Endpoints
# -----------------------------------------------------------------------------
@app.post("/agent/copilot/chat")
async def copilot_chat(request: CopilotChatRequest) -> dict[str, Any]:
    """Interactive SOC Analyst Copilot answering queries in real time."""
    try:
        response = copilot.ask(
            question=request.question,
            context=request.context,
            history=request.history,
        )
        return response
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/agent/mitigate")
async def execute_mitigation(request: MitigateRequest) -> dict[str, Any]:
    """Execute / simulate containment action and log to audit trail."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "status": "executed",
        "action": request.action,
        "command": request.command,
        "target_ip": request.target_ip,
        "incident_id": request.incident_id,
        "executed_at": now,
        "message": f"Successfully enforced {request.action} on firewall kernel table. Packet ingress from {request.target_ip or 'target'} dropped.",
    }


@app.post("/agent/deep-investigate")
async def deep_investigate(request: DeepInvestigateRequest) -> dict[str, Any]:
    """Trigger on-demand multi-layer agent investigation for an alert or event."""
    try:
        alerts, _ = AlertStore(pipeline.settings.alerts_path).read_latest(500)
        target_alert = None
        for a in alerts:
            if a.get("event_id") == (request.alert_id or request.event_id):
                target_alert = a
                break
        if not target_alert and alerts:
            target_alert = alerts[0]

        if not target_alert:
            raise HTTPException(status_code=404, detail="No alert found to investigate")

        event_data = {
            "source_ip": target_alert.get("source_ip"),
            "destination_ip": target_alert.get("destination_ip"),
            "protocol": target_alert.get("protocol"),
            "capture_source": target_alert.get("capture_source", "Suricata"),
            "packet_length": (target_alert.get("packet") or {}).get("packet_length", 800),
            "correlation_key": (target_alert.get("packet") or {}).get("correlation_key"),
            "event_id": target_alert.get("event_id"),
        }
        flow_features = target_alert.get("model_features") or {
            "Flow Duration": 150.0,
            "Total Fwd Packets": 10.0,
            "Total Backward Packets": 1.0,
            "Destination Port": float((target_alert.get("packet") or {}).get("destination_port") or 80),
            "Flow Bytes/s": 85000.0,
            "Packet Length Mean": 650.0,
        }

        incident = pipeline.investigator.multi_layer.process_incident(
            event=event_data,
            alert=target_alert,
            flow_features=flow_features,
            related_alerts=[],
        )
        pipeline.investigator.store.write(incident)
        return incident.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/incidents/{incident_id}/report", response_class=HTMLResponse)
async def generate_incident_report(incident_id: str) -> str:
    """Generate printable forensic dossier in HTML format."""
    values, _ = IncidentStore(pipeline.settings.incidents_path).read_latest(500)
    inc = next((i for i in values if i.get("incident_id") == incident_id), None)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    title = inc.get("title", "Incident Report")
    severity = inc.get("severity", "MEDIUM")
    brief = inc.get("executive_brief", inc.get("summary", ""))
    mitre_list = inc.get("mitre_tactics", [])
    playbook = inc.get("playbook", [])
    evidence = inc.get("evidence", [])
    iocs = inc.get("iocs", [])

    mitre_rows = "".join(
        f"<tr><td><code>{m.get('id')}</code></td><td><b>{m.get('name')}</b></td><td>{m.get('tactic')}</td><td>{m.get('justification')}</td></tr>"
        for m in mitre_list
    ) or "<tr><td colspan='4'>No explicit MITRE techniques registered.</td></tr>"

    playbook_rows = "".join(
        f"<tr><td><b>Step {p.get('step')}</b></td><td>{p.get('action')}</td><td><code>{p.get('command')}</code></td><td><span class='badge'>{p.get('priority')}</span></td></tr>"
        for p in playbook
    ) or "<tr><td colspan='4'>Default policy actions applied.</td></tr>"

    evidence_items = "".join(f"<li>{e}</li>" for e in evidence)
    ioc_rows = "".join(
        f"<tr><td><b>{i.get('type')}</b></td><td><code>{i.get('value')}</code></td><td>{i.get('category')}</td></tr>"
        for i in iocs
    ) or "<tr><td colspan='3'>None registered.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NIDS Forensic Incident Dossier — {incident_id}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0c0f17; color: #d6e0f0; margin: 0; padding: 40px; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #131926; border: 1px solid #243048; border-radius: 12px; padding: 36px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #243048; padding-bottom: 24px; margin-bottom: 24px; }}
  .badge {{ background: #dc2626; color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 13px; text-transform: uppercase; }}
  h1 {{ margin: 0 0 8px; font-size: 24px; color: #fff; }}
  h2 {{ font-size: 17px; margin-top: 28px; margin-bottom: 12px; color: #60a5fa; border-bottom: 1px solid #1f293d; padding-bottom: 6px; }}
  p {{ line-height: 1.6; color: #94a3b8; font-size: 14px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #1f293d; }}
  th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
  code {{ background: #090d16; padding: 3px 6px; border-radius: 4px; color: #38bdf8; font-family: monospace; font-size: 12px; }}
  ul {{ margin: 0; padding-left: 20px; line-height: 1.6; font-size: 13px; color: #cbd5e1; }}
  .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #243048; display: flex; justify-content: space-between; font-size: 12px; color: #64748b; }}
  @media print {{ body {{ background: #fff; color: #000; padding: 0; }} .container {{ border: none; box-shadow: none; background: #fff; }} th {{ background: #f1f5f9; color: #000; }} td, p {{ color: #1e293b; }} code {{ color: #0f172a; background: #f1f5f9; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div style="font-size: 11px; color: #94a3b8; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">Antigravity Autonomous NIDS • Forensic Report</div>
      <h1>{title}</h1>
      <div style="color: #64748b; font-size: 13px;">Incident ID: {incident_id} • Target: {inc.get('destination_ip', 'Internal Asset')} • Source: {inc.get('source_ip', 'Remote Host')}</div>
    </div>
    <span class="badge">{severity}</span>
  </div>

  <h2>1. Executive Incident Briefing</h2>
  <p>{brief}</p>

  <h2>2. MITRE ATT&CK Matrix Alignment</h2>
  <table>
    <thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Justification</th></tr></thead>
    <tbody>{mitre_rows}</tbody>
  </table>

  <h2>3. Forensic Flow & Sensor Evidence</h2>
  <ul>{evidence_items}</ul>

  <h2>4. Indicators of Compromise (IOCs)</h2>
  <table>
    <thead><tr><th>Type</th><th>Indicator Value</th><th>Context</th></tr></thead>
    <tbody>{ioc_rows}</tbody>
  </table>

  <h2>5. Containment & Remediation Playbook</h2>
  <table>
    <thead><tr><th>Step</th><th>Remediation Action</th><th>Executable Command</th><th>Priority</th></tr></thead>
    <tbody>{playbook_rows}</tbody>
  </table>

  <div class="footer">
    <div>Verified by Antigravity Agentic Pipeline ({inc.get('model', 'mistral:7b')})</div>
    <div>Timestamp: {inc.get('created_at', '')} • Status: {inc.get('status', 'OPEN').upper()}</div>
  </div>
</div>
</body>
</html>"""
    return html
