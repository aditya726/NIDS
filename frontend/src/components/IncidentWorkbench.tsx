import React, { useState } from "react";
import {
  AlertTriangle,
  BrainCircuit,
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  CircleStop,
  Copy,
  Download,
  ExternalLink,
  FileCode,
  FileText,
  Globe,
  Layers,
  Maximize2,
  Minimize2,
  MessageSquare,
  Play,
  RotateCw,
  Search,
  Server,
  Shield,
  SlidersHorizontal,
  Terminal,
  X,
  Zap,
} from "lucide-react";
import { api, Incident, PlaybookStep, Status } from "../api";

export function IncidentWorkbench({
  incidents,
  agent,
  onOpenCopilot,
  onToggleAgent,
}: {
  incidents: Incident[];
  agent: Status["agent"];
  onOpenCopilot: (incident: Incident) => void;
  onToggleAgent?: () => Promise<void> | void;
}) {
  const [selected, setSelected] = useState<Incident | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<
    "all" | "executive" | "forensics" | "mitre" | "iocs" | "playbook" | "raw"
  >("all");
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
  const [mitigatedSteps, setMitigatedSteps] = useState<Record<string, boolean>>({});
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [mitigatingStep, setMitigatingStep] = useState<string | null>(null);
  const [isTogglingSwarm, setIsTogglingSwarm] = useState(false);
  const [iocFilter, setIocFilter] = useState("");

  const severityCounts = ["HIGH", "MEDIUM", "LOW"].map(
    (sev) => incidents.filter((i) => i.severity === sev).length
  );

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const toggleSection = (id: string) => {
    setCollapsedSections((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleToggleAgentSwarm = async () => {
    setIsTogglingSwarm(true);
    try {
      if (onToggleAgent) {
        await onToggleAgent();
      } else {
        await api.agentToggle();
      }
    } catch (err) {
      alert(`Agent toggle failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setIsTogglingSwarm(false);
    }
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
        ...(incident.iocs || []).map((ioc, idx) => ({
          type: "indicator",
          id: `indicator--ioc-${incident.incident_id.toLowerCase()}-${idx}`,
          created: incident.created_at,
          name: `${ioc.category}: ${ioc.value}`,
          indicator_types: ["malicious-activity"],
          pattern: `[${ioc.type.toLowerCase()}:value = '${ioc.value}']`,
          pattern_type: "stix",
          confidence: Math.round(incident.confidence * 100),
        })),
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

  const isPaused = agent?.paused || agent?.status === "paused" || !agent?.enabled;

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
          <span className={`live-indicator ${!isPaused ? "" : "agent-waiting"}`}>
            <i style={{ background: isPaused ? "#f59e0b" : undefined }} />{" "}
            {isPaused ? "SWARM PAUSED" : agent?.available ? "SWARM ACTIVE" : agent?.status?.toUpperCase() || "AGENT STAGED"}
          </span>
          <span className="count">{incidents.length} active dossiers</span>
        </div>
      </div>

      {/* Agent Banner with Manual Pause / Resume Swarm Controls */}
      <div
        className="agent-banner"
        style={{
          borderLeft: isPaused ? "4px solid #f59e0b" : "4px solid #38bdf8",
          background: isPaused ? "linear-gradient(135deg, #2b1f14 0%, #1c1510 100%)" : undefined,
        }}
      >
        <BrainCircuit size={24} color={isPaused ? "#f59e0b" : "#38bdf8"} />
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <b style={{ color: isPaused ? "#f59e0b" : "#38bdf8", fontSize: 15 }}>
              Multi-Layer Agentic Swarm ({agent?.model || "mistral:7b"})
            </b>
            <span
              style={{
                fontSize: 11,
                padding: "2px 8px",
                borderRadius: 4,
                background: isPaused ? "#451a03" : "#0c4a6e",
                color: isPaused ? "#fbbf24" : "#38bdf8",
                fontWeight: 700,
              }}
            >
              {isPaused ? "HOLD / PAUSED" : "CONTINUOUS SWARM LIVE"}
            </span>
          </div>
          <span style={{ fontSize: 13, color: "#d1c7bc" }}>
            Layer 1 Capture Triage → Layer 2 Flow Vectorizer → Layer 4 ML Disambiguator → Layer 5 Deep Forensics → Layer 6 Memory
          </span>
          <small style={{ fontSize: 12 }}>
            {isPaused
              ? "Autonomous deep reasoning is temporarily suspended. Core packet capture and ML anomaly detection continue running unhindered."
              : "Autonomous end-to-end investigation pipeline active. Forensic reasoning is synthesized deterministically and enriched via local LLM."}
          </small>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end" }}>
          {/* Manual Stop / Pause Button */}
          <button
            className={`btn-swarm-toggle ${isPaused ? "paused" : "running"}`}
            disabled={isTogglingSwarm}
            onClick={handleToggleAgentSwarm}
            title={
              isPaused
                ? "Resume autonomous multi-agent deep reasoning and dossier generation"
                : "Manually stop/pause autonomous agent processing (prevents LLM/GPU overload during packet bursts)"
            }
          >
            {isTogglingSwarm ? (
              <>
                <RotateCw size={14} className="spin" /> Updating…
              </>
            ) : isPaused ? (
              <>
                <Play size={14} /> Resume Agent Swarm
              </>
            ) : (
              <>
                <CircleStop size={14} /> Stop Agent Swarm
              </>
            )}
          </button>

          <span className="agent-queue" style={{ fontSize: 11, color: isPaused ? "#f59e0b" : "#a3e635" }}>
            Queue: {agent?.queue?.queued ?? 0} | Done: {agent?.queue?.completed ?? 0}
          </span>
        </div>
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
                {incident.evidence?.length || 0} evidence items · {((incident.confidence || 0) * 100).toFixed(0)}% confidence
              </span>
            </div>
            <strong>{incident.severity}</strong>
            <ChevronRight size={18} />
          </button>
        ))}
        {!incidents.length && (
          <div className="empty" style={{ fontSize: 14 }}>
            No security incidents detected yet. Normal traffic flowing nominal.
          </div>
        )}
      </div>

      {/* Deep Incident Detail Modal / Drawer with Expandable Workstation View */}
      {selected && (
        <>
          <button
            className="detail-backdrop"
            aria-label="Close incident detail"
            onClick={() => setSelected(null)}
          />
          <aside
            className={`event-detail incident-detail ${isExpanded ? "expanded" : ""}`}
          >
            {/* Header & Control Actions */}
            <div className="detail-heading">
              <div style={{ flex: 1 }}>
                <span className="overline" style={{ fontSize: 12 }}>
                  AGENTIC FORENSIC DOSSIER / FULL DISCLOSURE
                </span>
                <h4 style={{ fontSize: 20, margin: "6px 0 6px" }}>{selected.title}</h4>
                <p style={{ fontSize: 13, color: "#94a3b8" }}>
                  {selected.incident_id} · STATUS: <b>{selected.status.toUpperCase()}</b> · MODEL:{" "}
                  <b>{selected.model}</b> · TARGET: <b>{selected.destination_ip || "Internal"}</b>
                </p>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {/* Expand / Maximize Button */}
                <button
                  className="icon-btn"
                  title={isExpanded ? "Restore side drawer view" : "Maximize to full-screen workstation view"}
                  onClick={() => setIsExpanded(!isExpanded)}
                  style={{ width: 38, height: 38 }}
                >
                  {isExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                </button>
                <button
                  className="icon-btn"
                  aria-label="Close incident detail"
                  onClick={() => setSelected(null)}
                  style={{ width: 38, height: 38 }}
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Severity, Confidence & Action Header Bar */}
            <div className="detail-status" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span className={`severity-dot ${selected.severity.toLowerCase()}`} />
                <b style={{ fontSize: 14 }}>{selected.severity} SEVERITY</b>
                <span style={{ fontSize: 13 }}>{((selected.confidence || 0) * 100).toFixed(0)}% Confidence</span>
                {selected.adversary_profile?.kill_chain_stage && (
                  <span
                    style={{
                      background: "#3b1d28",
                      color: "#fb7185",
                      border: "1px solid #e11d4840",
                      padding: "2px 8px",
                      borderRadius: 12,
                      fontSize: 11,
                      fontWeight: 600,
                    }}
                  >
                    {selected.adversary_profile.kill_chain_stage}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  className="btn-mitigate"
                  style={{ background: "#38bdf8", color: "#0f172a" }}
                  onClick={() => onOpenCopilot(selected)}
                >
                  <MessageSquare size={13} /> Ask Copilot
                </button>
                <a
                  className="btn-mitigate"
                  style={{ textDecoration: "none", background: "#1e293b", color: "#f8fafc", border: "1px solid #334155" }}
                  href={api.reportUrl(selected.incident_id)}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Download size={13} /> HTML Dossier
                </a>
                <button
                  className="btn-mitigate"
                  style={{ background: "#10b981", color: "#064e3b" }}
                  onClick={() => exportStix(selected)}
                >
                  <Shield size={13} /> STIX 2.1
                </button>
              </div>
            </div>

            {/* Dossier Navigation Tabs */}
            <div className="dossier-tabs">
              <button
                className={`dossier-tab-btn ${activeTab === "all" ? "active" : ""}`}
                onClick={() => setActiveTab("all")}
              >
                <FileText size={13} /> All Sections
              </button>
              <button
                className={`dossier-tab-btn ${activeTab === "executive" ? "active" : ""}`}
                onClick={() => setActiveTab("executive")}
              >
                <BrainCircuit size={13} /> 1. Executive Brief
              </button>
              <button
                className={`dossier-tab-btn ${activeTab === "forensics" ? "active" : ""}`}
                onClick={() => setActiveTab("forensics")}
              >
                <Server size={13} /> 2. Telemetry & L1-6 Trace
              </button>
              <button
                className={`dossier-tab-btn ${activeTab === "mitre" ? "active" : ""}`}
                onClick={() => setActiveTab("mitre")}
              >
                <Layers size={13} /> 3. MITRE ATT&CK ({selected.mitre_tactics?.length || 0})
              </button>
              <button
                className={`dossier-tab-btn ${activeTab === "iocs" ? "active" : ""}`}
                onClick={() => setActiveTab("iocs")}
              >
                <Shield size={13} /> 4. IOCs ({selected.iocs?.length || 0})
              </button>
              <button
                className={`dossier-tab-btn ${activeTab === "playbook" ? "active" : ""}`}
                onClick={() => setActiveTab("playbook")}
              >
                <Terminal size={13} /> 5. Playbook ({selected.playbook?.length || 0})
              </button>
              <button
                className={`dossier-tab-btn ${activeTab === "raw" ? "active" : ""}`}
                onClick={() => setActiveTab("raw")}
              >
                <FileCode size={13} /> 6. Raw Data
              </button>
            </div>

            {/* Adversary Profile Banner (Always Visible on Executive / All) */}
            {(activeTab === "all" || activeTab === "executive") && selected.adversary_profile && (
              <div className="adversary-card">
                <div>
                  <span>Adversary Profile</span>
                  <b>{selected.adversary_profile.actor_category || "Opportunistic Threat Actor"}</b>
                </div>
                <div>
                  <span>Kill-Chain Stage</span>
                  <b style={{ color: "#f43f5e" }}>
                    {selected.adversary_profile.kill_chain_stage || selected.attack_phase || "Active Exploitation"}
                  </b>
                </div>
                <div>
                  <span>Sophistication</span>
                  <b>{selected.adversary_profile.sophistication || "Moderate"}</b>
                </div>
                <div>
                  <span>Adversary Intent</span>
                  <b style={{ color: "#38bdf8" }}>{selected.adversary_profile.intent || "Probing / Reconnaissance"}</b>
                </div>
              </div>
            )}

            {/* 1. Executive Incident Briefing */}
            {(activeTab === "all" || activeTab === "executive") && (
              <div className="executive-dossier">
                <div
                  className="section-toggle-header"
                  onClick={() => toggleSection("executive")}
                >
                  <div className="dossier-tag">
                    <BrainCircuit size={15} /> 1. Executive Threat Assessment & Storyline
                  </div>
                  {collapsedSections["executive"] ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
                </div>
                {!collapsedSections["executive"] && (
                  <div style={{ marginTop: 8 }}>
                    <p style={{ margin: 0, fontSize: 14, lineHeight: 1.7, color: "#e2e8f0" }}>
                      {selected.executive_brief || selected.summary}
                    </p>
                    {selected.recommended_actions && selected.recommended_actions.length > 0 && (
                      <div style={{ marginTop: 14, borderTop: "1px solid #23354d", paddingTop: 10 }}>
                        <b style={{ fontSize: 13, color: "#38bdf8" }}>Key Immediate Recommendations:</b>
                        <ul style={{ margin: "6px 0 0", paddingLeft: 20, color: "#cbd5e1", fontSize: 13 }}>
                          {selected.recommended_actions.map((act, i) => (
                            <li key={i}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* 2. Forensic Flow Geometry & ML Disambiguation */}
            {(activeTab === "all" || activeTab === "forensics") && (
              <div className="incident-section">
                <div
                  className="raw-heading section-toggle-header"
                  onClick={() => toggleSection("forensics")}
                >
                  <span>
                    <Server size={14} /> 2. FORENSIC FLOW & TELEMETRY BREAKDOWN
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>LAYER 1-4 TRACE</span>
                    {collapsedSections["forensics"] ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
                  </div>
                </div>

                {!collapsedSections["forensics"] && (
                  <>
                    <div className="case-metrics">
                      <div>
                        <span>RISK INDEX</span>
                        <b>{(((selected.metrics?.risk_score ?? selected.confidence) || 0) * 100).toFixed(0)}%</b>
                      </div>
                      <div>
                        <span>SUPERVISED RF</span>
                        <b>{(((selected.metrics?.supervised_probability ?? 0.7) || 0) * 100).toFixed(0)}%</b>
                      </div>
                      <div>
                        <span>ANOMALY IF</span>
                        <b>{(((selected.metrics?.anomaly_score ?? 0.6) || 0) * 100).toFixed(0)}%</b>
                      </div>
                      <div>
                        <span>HISTORICAL ENCOUNTERS</span>
                        <b>{selected.metrics?.historical_encounters ?? 1}</b>
                      </div>
                    </div>

                    <div className="detection-explanation" style={{ whiteSpace: "pre-wrap", fontSize: 13, lineHeight: 1.6 }}>
                      {selected.summary}
                    </div>

                    {/* Layer 1 to Layer 6 Trace Breakdown */}
                    {selected.layer_trace && (
                      <div style={{ marginTop: 14 }}>
                        <b style={{ fontSize: 13, color: "#e2e8f0", display: "flex", alignItems: "center", gap: 6 }}>
                          <SlidersHorizontal size={13} color="#38bdf8" /> Multi-Layer Pipeline Execution Trace
                        </b>
                        <div className="layer-trace-grid">
                          {Boolean(selected.layer_trace.layer_1_capture) && (
                            <div className="layer-trace-card">
                              <b>L1: Sensor Ingestion</b>
                              <pre>{JSON.stringify(selected.layer_trace.layer_1_capture, null, 2)}</pre>
                            </div>
                          )}
                          {Boolean(selected.layer_trace.layer_2_flow) && (
                            <div className="layer-trace-card">
                              <b>L2: Flow Normalization</b>
                              <pre>{JSON.stringify(selected.layer_trace.layer_2_flow, null, 2)}</pre>
                            </div>
                          )}
                          {Boolean(selected.layer_trace.layer_3_triage) && (
                            <div className="layer-trace-card">
                              <b>L3: Stream Priority</b>
                              <pre>{JSON.stringify(selected.layer_trace.layer_3_triage, null, 2)}</pre>
                            </div>
                          )}
                          {Boolean(selected.layer_trace.layer_4_attribution) && (
                            <div className="layer-trace-card">
                              <b>L4: ML Disambiguation</b>
                              <pre>{JSON.stringify(selected.layer_trace.layer_4_attribution, null, 2)}</pre>
                            </div>
                          )}
                          {Boolean(selected.layer_trace.layer_6_memory) && (
                            <div className="layer-trace-card">
                              <b>L6: Attacker Memory</b>
                              <pre>{JSON.stringify(selected.layer_trace.layer_6_memory, null, 2)}</pre>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* 3. MITRE ATT&CK Matrix Alignment */}
            {(activeTab === "all" || activeTab === "mitre") && (
              <div className="incident-section">
                <div
                  className="raw-heading section-toggle-header"
                  onClick={() => toggleSection("mitre")}
                >
                  <span>
                    <Layers size={14} /> 3. MITRE ATT&CK MATRIX ALIGNMENT
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span>{selected.mitre_tactics?.length || 0} TECHNIQUES</span>
                    {collapsedSections["mitre"] ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
                  </div>
                </div>

                {!collapsedSections["mitre"] && (
                  <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
                    {(selected.mitre_tactics || []).map((tactic) => (
                      <div key={tactic.id} className="mitre-technique-card" style={{ cursor: "default" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <b style={{ fontSize: 14 }}>
                            {tactic.id} — {tactic.name}
                          </b>
                          <span className="mitre-hits-pill" style={{ margin: 0 }}>
                            {tactic.tactic}
                          </span>
                        </div>
                        <span style={{ marginTop: 6, fontSize: 13, color: "#cbd5e1", lineHeight: 1.5 }}>
                          {tactic.justification}
                        </span>
                        <a
                          href={`https://attack.mitre.org/techniques/${tactic.id}/`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            alignSelf: "flex-start",
                            color: "#38bdf8",
                            fontSize: 11,
                            textDecoration: "none",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 4,
                            marginTop: 4,
                          }}
                        >
                          MITRE Matrix Reference <ExternalLink size={10} />
                        </a>
                      </div>
                    ))}
                    {!selected.mitre_tactics?.length && (
                      <div className="empty" style={{ fontSize: 13 }}>
                        No specific MITRE techniques registered for this flow.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* 4. Indicators of Compromise (IOCs) */}
            {(activeTab === "all" || activeTab === "iocs") && (
              <div className="incident-section">
                <div
                  className="raw-heading section-toggle-header"
                  onClick={() => toggleSection("iocs")}
                >
                  <span>
                    <Shield size={14} /> 4. EXTRACTED INDICATORS OF COMPROMISE (IOCS)
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span>AUDIT READY</span>
                    {collapsedSections["iocs"] ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
                  </div>
                </div>

                {!collapsedSections["iocs"] && (
                  <>
                    <div style={{ margin: "10px 0 6px" }}>
                      <input
                        type="text"
                        placeholder="Filter IOCs by IP, domain, hash, category…"
                        value={iocFilter}
                        onChange={(e) => setIocFilter(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#0d131f",
                          border: "1px solid #233145",
                          borderRadius: 4,
                          padding: "8px 12px",
                          color: "#f8fafc",
                          fontSize: 13,
                          outline: "none",
                        }}
                      />
                    </div>
                    <div className="iocs-grid">
                      {(selected.iocs || [])
                        .filter(
                          (ioc) =>
                            !iocFilter ||
                            ioc.value.toLowerCase().includes(iocFilter.toLowerCase()) ||
                            ioc.category.toLowerCase().includes(iocFilter.toLowerCase())
                        )
                        .map((ioc, idx) => (
                          <div key={idx} className="ioc-card">
                            <small>{ioc.category} ({ioc.type})</small>
                            <code style={{ fontSize: 13 }}>{ioc.value}</code>
                            <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
                              <button
                                className="row-action"
                                style={{ padding: "4px 8px" }}
                                onClick={() => handleCopy(ioc.value)}
                              >
                                {copiedText === ioc.value ? (
                                  <>
                                    <Check size={11} /> Copied
                                  </>
                                ) : (
                                  <>
                                    <Copy size={11} /> Copy
                                  </>
                                )}
                              </button>
                              {ioc.type.toLowerCase().includes("ipv4") && (
                                <a
                                  className="row-action"
                                  style={{ padding: "4px 8px", textDecoration: "none" }}
                                  href={`https://www.virustotal.com/gui/ip-address/${ioc.value}`}
                                  target="_blank"
                                  rel="noreferrer"
                                >
                                  VT <ExternalLink size={10} />
                                </a>
                              )}
                            </div>
                          </div>
                        ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* 5. Interactive Remediation Playbook */}
            {(activeTab === "all" || activeTab === "playbook") && (
              <div className="incident-section">
                <div
                  className="raw-heading section-toggle-header"
                  onClick={() => toggleSection("playbook")}
                >
                  <span>
                    <Terminal size={14} /> 5. INTERACTIVE REMEDIATION PLAYBOOK
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span>SINGLE-CLICK ENFORCEMENT</span>
                    {collapsedSections["playbook"] ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
                  </div>
                </div>

                {!collapsedSections["playbook"] && (
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
                              <b style={{ fontSize: 14 }}>{step.action}</b>
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
                              {copiedText === step.command ? (
                                <>
                                  <Check size={11} /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy size={11} /> Copy
                                </>
                              )}
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
                                  <Check size={13} /> ENFORCED ON FIREWALL KERNEL
                                </>
                              ) : isLoading ? (
                                <>
                                  <RotateCw size={13} className="spin" /> Executing…
                                </>
                              ) : (
                                <>
                                  <Play size={13} /> Simulate & Enforce Rule
                                </>
                              )}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* 6. Raw Data / JSON Inspector */}
            {(activeTab === "all" || activeTab === "raw") && (
              <div className="incident-section">
                <div
                  className="raw-heading section-toggle-header"
                  onClick={() => toggleSection("raw")}
                >
                  <span>
                    <FileCode size={14} /> 6. COMPLETE DOSSIER RAW JSON (SIEM / SOAR AUDIT)
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <button
                      className="row-action"
                      style={{ padding: "3px 8px" }}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopy(JSON.stringify(selected, null, 2));
                      }}
                    >
                      {copiedText === JSON.stringify(selected, null, 2) ? (
                        <>
                          <Check size={10} /> Copied JSON
                        </>
                      ) : (
                        <>
                          <Copy size={10} /> Copy JSON
                        </>
                      )}
                    </button>
                    {collapsedSections["raw"] ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
                  </div>
                </div>

                {!collapsedSections["raw"] && (
                  <pre
                    style={{
                      maxHeight: isExpanded ? 460 : 260,
                      overflow: "auto",
                      background: "#080d16",
                      border: "1px solid #1e2c3e",
                      padding: 14,
                      borderRadius: 6,
                      fontSize: 12,
                      color: "#94d2bd",
                    }}
                  >
                    {JSON.stringify(selected, null, 2)}
                  </pre>
                )}
              </div>
            )}

            {/* Action Bar Footer */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginTop: 24,
                paddingTop: 18,
                borderTop: "1px solid #233145",
              }}
            >
              <div style={{ display: "flex", gap: 10 }}>
                <button
                  className="btn-mitigate"
                  style={{ background: "#10b981", color: "#064e3b" }}
                  onClick={() => exportStix(selected)}
                >
                  <Download size={13} /> Export STIX 2.1 Threat Intel
                </button>
                <a
                  className="btn-mitigate"
                  style={{ textDecoration: "none", background: "#1e293b", color: "#f8fafc", border: "1px solid #334155" }}
                  href={api.reportUrl(selected.incident_id)}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Download size={13} /> Printable HTML Report
                </a>
              </div>

              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="btn secondary"
                  onClick={() => setIsExpanded(!isExpanded)}
                >
                  {isExpanded ? "Collapse View" : "Maximize View"}
                </button>
                <button
                  className="btn secondary"
                  onClick={() => setSelected(null)}
                >
                  Close Dossier
                </button>
              </div>
            </div>
          </aside>
        </>
      )}
    </section>
  );
}
