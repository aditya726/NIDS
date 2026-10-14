import React, { useState } from "react";
import {
  AlertTriangle,
  BrainCircuit,
  Check,
  ChevronRight,
  Copy,
  Download,
  ExternalLink,
  Flame,
  Globe,
  Layers,
  MessageSquare,
  Play,
  RotateCw,
  Search,
  Server,
  Shield,
  Terminal,
  Ticket,
  X,
  Zap,
} from "lucide-react";
import { api, Incident, PlaybookStep, Status } from "../api";

export function IncidentWorkbench({
  incidents,
  agent,
  onOpenCopilot,
}: {
  incidents: Incident[];
  agent: Status["agent"];
  onOpenCopilot: (incident: Incident) => void;
}) {
  const [selected, setSelected] = useState<Incident | null>(null);
  const [mitigatedSteps, setMitigatedSteps] = useState<Record<string, boolean>>({});
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [mitigatingStep, setMitigatingStep] = useState<string | null>(null);

  const severityCounts = ["HIGH", "MEDIUM", "LOW"].map(
    (sev) => incidents.filter((i) => i.severity === sev).length
  );

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleMitigate = async (incident: Incident, step: PlaybookStep) => {
    const key = `${incident.incident_id}-${step.step}`;
    setMitigatingStep(key);
    try {
      await api.mitigate({
        incident_id: incident.incident_id,
        action: step.action,
        command: step.command,
        target_ip: incident.source_ip || undefined,
      });
      setMitigatedSteps((prev) => ({ ...prev, [key]: true }));
    } catch (err) {
      alert(`Mitigation simulation error: ${err instanceof Error ? err.message : "Unknown"}`);
    } finally {
      setMitigatingStep(null);
    }
  };

  const exportStix = (incident: Incident) => {
    const stix = {
      type: "bundle",
      id: `bundle--${incident.incident_id.toLowerCase()}`,
      spec_version: "2.1",
      objects: [
        {
          type: "indicator",
          id: `indicator--${incident.incident_id.toLowerCase()}`,
          created: incident.created_at,
          name: incident.title,
          description: incident.executive_brief || incident.summary,
          indicator_types: ["malicious-activity"],
          pattern: `[ipv4-addr:value = '${incident.source_ip || "0.0.0.0"}']`,
          pattern_type: "stix",
          confidence: Math.round(incident.confidence * 100),
        },
      ],
    };
    const blob = new Blob([JSON.stringify(stix, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `STIX_${incident.incident_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section className="panel event-page incident-page">
      <div className="panel-title">
        <div>
          <span className="overline">AUTONOMOUS MULTI-AGENT INVESTIGATION</span>
          <h3>Forensic Incident Workbench</h3>
          <p className="panel-subtitle">
            Deep descriptive reasoning, MITRE ATT&CK alignment, and interactive containment playbooks.
          </p>
        </div>
        <div className="stream-summary">
          <span className={`live-indicator ${agent?.available ? "" : "agent-waiting"}`}>
            <i /> {agent?.available ? "SWARM ONLINE" : agent?.status?.toUpperCase() || "AGENT STAGED"}
          </span>
          <span className="count">{incidents.length} active dossiers</span>
        </div>
      </div>

      <div className="agent-banner">
        <BrainCircuit size={20} color="#38bdf8" />
        <div>
          <b style={{ color: "#38bdf8" }}>
            Multi-Layer Agentic Swarm ({agent?.model || "mistral:7b"})
          </b>
          <span>
            Layer 1 Capture Triage → Layer 2 Flow Vectorizer → Layer 4 ML Disambiguator → Layer 5 Deep Forensics → Layer 6 Memory
          </span>
          <small>
            Autonomous end-to-end investigation pipeline active. Forensic reasoning is generated deterministically and enriched via local LLM.
          </small>
        </div>
        <span className="agent-queue">{agent?.available ? "READY" : "STAGED"}</span>
      </div>

      {/* Analytics Summary Bar */}
      <div className="case-analytics">
        <div className="case-analytics-chart">
          <div
            className="severity-donut"
            style={{
              background: `conic-gradient(#ed7c68 0 ${(severityCounts[0] / Math.max(incidents.length, 1)) * 100}%, #e6b46b ${(severityCounts[0] / Math.max(incidents.length, 1)) * 100}% ${((severityCounts[0] + severityCounts[1]) / Math.max(incidents.length, 1)) * 100}%, #91c9a9 ${((severityCounts[0] + severityCounts[1]) / Math.max(incidents.length, 1)) * 100}% 100%)`,
            }}
          >
            <b>{incidents.length}</b>
            <small>CASES</small>
          </div>
        </div>
        <div className="case-analytics-legend">
          <b>SEVERITY PROFILE</b>
          <span>
            <i className="high" /> HIGH <strong>{severityCounts[0]}</strong>
          </span>
          <span>
            <i className="medium" /> MEDIUM <strong>{severityCounts[1]}</strong>
          </span>
          <span>
            <i className="low" /> LOW <strong>{severityCounts[2]}</strong>
          </span>
        </div>
        <div className="case-analytics-note">
          <b>How the Agent Swarm Operates</b>
          <span>
            Unlike minimal rule alerts, the multi-layer swarm correlates historical telemetry, dissects model feature weights,
            evaluates blast radius, and prepares actionable firewall playbooks with single-click enforcement.
          </span>
        </div>
      </div>

      {/* Incident List */}
      <div className="incident-list">
        {incidents.map((incident) => (
          <button
            className={`incident-card ${selected?.incident_id === incident.incident_id ? "active-card" : ""}`}
            key={incident.incident_id}
            onClick={() => setSelected(incident)}
          >
            <span className={`severity-dot ${incident.severity.toLowerCase()}`} />
            <div>
              <b>{incident.title}</b>
              <span>
                {incident.source_ip || "unknown"} → {incident.destination_ip || "unknown"} · {incident.attack_phase || "analysis"} ·{" "}
                {incident.evidence.length} evidence items · {(incident.confidence * 100).toFixed(0)}% confidence
              </span>
            </div>
            <strong>{incident.severity}</strong>
            <ChevronRight size={16} />
          </button>
        ))}
        {!incidents.length && (
          <div className="empty">No security incidents detected yet. Normal traffic flowing nominal.</div>
        )}
      </div>

      {/* Deep Incident Detail Modal / Drawer */}
      {selected && (
        <>
          <button
            className="detail-backdrop"
            aria-label="Close incident detail"
            onClick={() => setSelected(null)}
          />
          <aside className="event-detail incident-detail" style={{ maxWidth: 840 }}>
            <div className="detail-heading">
              <div>
                <span className="overline">AGENTIC FORENSIC DOSSIER / FULL DISCLOSURE</span>
                <h4 style={{ fontSize: 16 }}>{selected.title}</h4>
                <p>
                  {selected.incident_id} · STATUS: {selected.status.toUpperCase()} · AGENT: {selected.model}
                </p>
              </div>
              <button
                className="icon-btn"
                aria-label="Close incident detail"
                onClick={() => setSelected(null)}
              >
                <X size={16} />
              </button>
            </div>

            {/* Severity & Confidence Banner */}
            <div className="detail-status" style={{ justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span className={`severity-dot ${selected.severity.toLowerCase()}`} />
                <b>{selected.severity} SEVERITY</b>
                <span>{(selected.confidence * 100).toFixed(0)}% Model Confidence</span>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="btn-mitigate"
                  style={{ background: "#38bdf8", color: "#0f172a" }}
                  onClick={() => onOpenCopilot(selected)}
                >
                  <MessageSquare size={12} /> Ask Copilot
                </button>
                <a
                  className="btn-mitigate"
                  style={{ textDecoration: "none", background: "#1e293b", color: "#f8fafc", border: "1px solid #334155" }}
                  href={api.reportUrl(selected.incident_id)}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Download size={12} /> Dossier PDF
                </a>
              </div>
            </div>

            {/* Adversary Profile Card */}
            {selected.adversary_profile && (
              <div className="adversary-card">
                <div>
                  <span>Adversary Profile</span>
                  <b>{selected.adversary_profile.actor_category || "Opportunistic Actor"}</b>
                </div>
                <div>
                  <span>Kill-Chain Stage</span>
                  <b style={{ color: "#f43f5e" }}>{selected.adversary_profile.kill_chain_stage || selected.attack_phase}</b>
                </div>
                <div>
                  <span>Sophistication</span>
                  <b>{selected.adversary_profile.sophistication || "Moderate"}</b>
                </div>
                <div>
                  <span>Adversary Intent</span>
                  <b style={{ color: "#38bdf8" }}>{selected.adversary_profile.intent || "Probing"}</b>
                </div>
              </div>
            )}

            {/* 1. Executive Incident Briefing */}
            <div className="executive-dossier">
              <div className="dossier-tag">
                <BrainCircuit size={13} /> 1. Executive Threat Assessment
              </div>
              <p style={{ margin: 0 }}>
                {selected.executive_brief || selected.summary}
              </p>
            </div>

            {/* 2. Forensic Flow Geometry & ML Disambiguation */}
            <div className="incident-section">
              <div className="raw-heading">
                <span><Server size={13} /> 2. FORENSIC FLOW & TELEMETRY BREAKDOWN</span>
                <span>LAYER 1-4 TRACE</span>
              </div>
              <div className="case-metrics">
                <div>
                  <span>RISK INDEX</span>
                  <b>{((selected.metrics?.risk_score || selected.confidence) * 100).toFixed(0)}%</b>
                </div>
                <div>
                  <span>SUPERVISED (RF)</span>
                  <b>{((selected.metrics?.supervised_probability || 0.7) * 100).toFixed(0)}%</b>
                </div>
                <div>
                  <span>ANOMALY (IF)</span>
                  <b>{((selected.metrics?.anomaly_score || 0.6) * 100).toFixed(0)}%</b>
                </div>
                <div>
                  <span>HISTORICAL ENCOUNTERS</span>
                  <b>{selected.metrics?.historical_encounters || 1}</b>
                </div>
              </div>
              <div className="detection-explanation" style={{ whiteSpace: "pre-wrap" }}>
                {selected.summary}
              </div>
            </div>

            {/* 3. MITRE ATT&CK Matrix Alignment */}
            <div className="incident-section">
              <div className="raw-heading">
                <span><Layers size={13} /> 3. MITRE ATT&CK MAPPINGS</span>
                <span>{selected.mitre_tactics?.length || selected.techniques?.length || 0} TECHNIQUES</span>
              </div>
              <div style={{ display: "grid", gap: 8, marginTop: 8 }}>
                {(selected.mitre_tactics || []).map((tactic) => (
                  <div key={tactic.id} className="mitre-technique-card" style={{ cursor: "default" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <b>{tactic.id} — {tactic.name}</b>
                      <span className="mitre-hits-pill" style={{ margin: 0 }}>{tactic.tactic}</span>
                    </div>
                    <span style={{ marginTop: 4 }}>{tactic.justification}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* 4. Indicators of Compromise (IOCs) */}
            <div className="incident-section">
              <div className="raw-heading">
                <span><Shield size={13} /> 4. EXTRACTED INDICATORS OF COMPROMISE</span>
                <span>AUDIT READY</span>
              </div>
              <div className="iocs-grid">
                {(selected.iocs || []).map((ioc, idx) => (
                  <div key={idx} className="ioc-card">
                    <small>{ioc.category} ({ioc.type})</small>
                    <code>{ioc.value}</code>
                    <button
                      className="row-action"
                      style={{ marginTop: 4, alignSelf: "flex-start", padding: "2px 6px" }}
                      onClick={() => handleCopy(ioc.value)}
                    >
                      {copiedText === ioc.value ? <><Check size={10} /> Copied</> : <><Copy size={10} /> Copy</>}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* 5. Interactive Remediation Playbook */}
            <div className="incident-section">
              <div className="raw-heading">
                <span><Terminal size={13} /> 5. INTERACTIVE REMEDIATION PLAYBOOK</span>
                <span>SINGLE-CLICK ENFORCEMENT</span>
              </div>
              <div className="playbook-container">
                {(selected.playbook || []).map((step) => {
                  const stepKey = `${selected.incident_id}-${step.step}`;
                  const isDone = !!mitigatedSteps[stepKey];
                  const isLoading = mitigatingStep === stepKey;
                  return (
                    <div className="playbook-card" key={step.step}>
                      <div className="playbook-header">
                        <div className="playbook-step-title">
                          <span className="step-num">{step.step}</span>
                          <b>{step.action}</b>
                        </div>
                        <span className="playbook-priority">{step.priority}</span>
                      </div>
                      <p className="playbook-desc">{step.description}</p>
                      <div className="playbook-cmd-box">
                        <code>{step.command}</code>
                        <button
                          className="row-action"
                          onClick={() => handleCopy(step.command)}
                        >
                          {copiedText === step.command ? <><Check size={10} /> Copied</> : <><Copy size={10} /> Copy</>}
                        </button>
                      </div>
                      <div className="playbook-actions">
                        <button
                          className={`btn-mitigate ${isDone ? "executed" : ""}`}
                          disabled={isDone || isLoading}
                          onClick={() => handleMitigate(selected, step)}
                        >
                          {isDone ? (
                            <>
                              <Check size={12} /> ENFORCED ON FIREWALL
                            </>
                          ) : isLoading ? (
                            <>
                              <RotateCw size={12} className="spin" /> Executing…
                            </>
                          ) : (
                            <>
                              <Play size={12} /> Simulate & Enforce Rule
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Action Bar Footer */}
            <div style={{ display: "flex", gap: 10, marginTop: 24, paddingTop: 16, borderTop: "1px solid #233145" }}>
              <button
                className="btn-mitigate"
                style={{ background: "#10b981" }}
                onClick={() => exportStix(selected)}
              >
                <Download size={12} /> Export STIX 2.1 Threat Intel
              </button>
              <button
                className="btn secondary"
                onClick={() => setSelected(null)}
              >
                Close Dossier
              </button>
            </div>
          </aside>
        </>
      )}
    </section>
  );
}
