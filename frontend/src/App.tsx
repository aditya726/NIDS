import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Boxes,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleStop,
  Database,
  Flame,
  Gauge,
  Layers,
  LayoutDashboard,
  LoaderCircle,
  MessageSquare,
  Network,
  Play,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  Wifi,
  X,
} from "lucide-react";
import {
  Alert,
  AnalyticsOverview,
  AnalyticsTopology,
  api,
  Event,
  Incident,
  Mode,
  SensorStatus,
  Status,
} from "./api";
import { ThreatAnalytics } from "./components/ThreatAnalytics";
import { IncidentWorkbench } from "./components/IncidentWorkbench";
import { ArchitectureBlueprint } from "./components/ArchitectureBlueprint";
import { CopilotDrawer } from "./components/CopilotDrawer";

type View =
  | "overview"
  | "analytics"
  | "incidents"
  | "detections"
  | "events"
  | "sensors"
  | "blueprint"
  | "infrastructure";

const nav: { id: View; label: string; icon: typeof Radio }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "analytics", label: "Threat Analytics", icon: BarChart3 },
  { id: "incidents", label: "Agentic Incidents", icon: BrainCircuit },
  { id: "detections", label: "Detection Log", icon: AlertTriangle },
  { id: "events", label: "Event Stream", icon: Activity },
  { id: "sensors", label: "Sensors", icon: Shield },
  { id: "blueprint", label: "Architecture (L1-L8)", icon: Layers },
  { id: "infrastructure", label: "Infrastructure", icon: Server },
];

const modes: { id: Mode; label: string; detail: string }[] = [
  { id: "sensors", label: "Suricata + Zeek", detail: "Production dual sensor" },
  { id: "suricata_live", label: "Suricata", detail: "IDS telemetry" },
  { id: "zeek_live", label: "Zeek", detail: "Network metadata" },
  { id: "live", label: "Scapy fallback", detail: "Development capture" },
];

const emptyStatus: Status = {
  running: false,
  source_mode: "none",
  processed_events: 0,
  last_event: null,
  error: null,
  broker: "unknown",
  detected_alerts: 0,
  ml: null,
  agent: null,
};

function App() {
  const [view, setView] = useState<View>("overview");
  const [status, setStatus] = useState<Status>(emptyStatus);
  const [sensors, setSensors] = useState<SensorStatus | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [interfaces, setInterfaces] = useState<{ name: string; description: string }[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null);
  const [topology, setTopology] = useState<AnalyticsTopology | null>(null);
  const [mode, setMode] = useState<Mode>("sensors");
  const [iface, setIface] = useState("");
  const [busy, setBusy] = useState(false);
  const [online, setOnline] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [copilotIncident, setCopilotIncident] = useState<Incident | null>(null);
  const [toast, setToast] = useState<{ text: string; error?: boolean } | null>(null);

  const notify = (text: string, error = false) => {
    setToast({ text, error });
    window.setTimeout(() => setToast(null), 3600);
  };

  const refresh = useCallback(
    async (quiet = true) => {
      try {
        const [
          health,
          nextStatus,
          history,
          sensorStatus,
          detection,
          agentStatus,
          alertHistory,
          incidentHistory,
          analyticsData,
          topologyData,
        ] = await Promise.all([
          api.health(),
          api.status(),
          api.events(),
          api.sensors(),
          api.detection(),
          api.agent(),
          api.alerts(),
          api.incidents(),
          api.analyticsOverview().catch(() => null),
          api.analyticsTopology().catch(() => null),
        ]);

        setOnline(health.status === "ok");
        setStatus({ ...nextStatus, ml: detection, agent: agentStatus });
        setEvents(history.events);
        setTotal(history.total);
        setSensors(sensorStatus);
        setAlerts(alertHistory.alerts);
        setIncidents(incidentHistory.incidents);
        if (analyticsData) setOverview(analyticsData);
        if (topologyData) setTopology(topologyData);
      } catch (error) {
        setOnline(false);
        if (!quiet) notify(error instanceof Error ? error.message : "Backend unavailable", true);
      }
    },
    []
  );

  useEffect(() => {
    void refresh(false);
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    api
      .interfaces()
      .then((result) => {
        setInterfaces(result.interfaces);
        setIface(
          result.interfaces.find((item) => /wi-?fi|wireless/i.test(item.description))?.name ||
            result.interfaces[0]?.name ||
            ""
        );
      })
      .catch(() => undefined);
  }, []);

  const payload: Record<string, string> = mode === "live" ? { mode, interface: iface } : { mode };

  const action = async (kind: "start" | "stop" | "switch") => {
    setBusy(true);
    try {
      const result =
        kind === "stop"
          ? await api.stop()
          : kind === "start"
          ? await api.start(payload)
          : await api.switch(payload);
      setStatus(result);
      notify(kind === "stop" ? "Pipeline stopped" : `${mode} sensor active`);
      await refresh();
    } catch (error) {
      notify(error instanceof Error ? error.message : "Operation failed", true);
    } finally {
      setBusy(false);
    }
  };

  const toggleAgentSwarm = async () => {
    try {
      const res = await api.agentToggle();
      setStatus((prev) => ({
        ...prev,
        agent: res.agent,
      }));
      const isPausedNow = res.agent.paused || res.agent.status === "paused" || !res.agent.enabled;
      notify(isPausedNow ? "Agentic Swarm PAUSED (Capture remains active)" : "Agentic Swarm RESUMED");
      await refresh();
    } catch (err) {
      notify(err instanceof Error ? err.message : "Failed to toggle agent", true);
    }
  };

  const selected = modes.find((item) => item.id === mode) ?? modes[0];

  return (
    <div className="shell">
      <aside className="rail">
        <div className="wordmark">
          <div className="mark">
            <Network size={18} />
          </div>
          <div>
            <b>NIDS</b>
            <small>AUTONOMOUS DEFENSE CONSOLE</small>
          </div>
        </div>

        <div className="rail-label">COMMAND & CONTROL</div>
        {nav.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`nav-link ${view === id ? "current" : ""}`}
            onClick={() => setView(id)}
          >
            <Icon size={17} />
            {label}
            {id === "incidents" && incidents.length > 0 && <span>{incidents.length}</span>}
            {id === "events" && <span>{total}</span>}
          </button>
        ))}

        <div className="rail-label lower">AI SWARM STATUS</div>
        <div
          className="rail-system"
          style={{ cursor: "pointer" }}
          onClick={toggleAgentSwarm}
          title={status.agent?.paused ? "Click to resume autonomous AI swarm" : "Click to pause autonomous AI swarm"}
        >
          <span
            className={`signal ${status.agent?.available && !status.agent?.paused ? "on" : ""}`}
            style={{ background: status.agent?.paused ? "#f59e0b" : undefined }}
          />
          <div>
            <small>{status.agent?.paused ? "SWARM ON HOLD" : "AGENTIC BRAIN"}</small>
            <b>{status.agent?.paused ? "Paused (Click to Start)" : status.agent?.available ? status.agent.model : "Mistral 7B Staged"}</b>
          </div>
        </div>
        <div className="rail-system">
          <span className={`signal ${online ? "on" : ""}`} />
          <div>
            <small>CONTROL API</small>
            <b>{online ? "Connected (8000)" : "Offline"}</b>
          </div>
        </div>
        <div className="rail-system">
          <span className={`signal ${status.broker === "redis" ? "on" : ""}`} />
          <div>
            <small>EVENT BUS</small>
            <b>{status.broker === "redis" ? "Redis Streams" : "Local Mode"}</b>
          </div>
        </div>
      </aside>

      <main className="workspace">
        <header className="header">
          <div>
            <div className="crumb">
              OPERATIONS <ChevronRight size={12} /> {nav.find((item) => item.id === view)?.label.toUpperCase()}
            </div>
            <h1>{view === "overview" ? "Command Center" : nav.find((item) => item.id === view)?.label}</h1>
          </div>
          <div className="header-actions">
            {/* Manual Stop / Resume Agentic Swarm Button */}
            <button
              className={`btn-swarm-toggle ${status.agent?.paused || status.agent?.status === "paused" || !status.agent?.enabled ? "paused" : "running"}`}
              onClick={toggleAgentSwarm}
              title={
                status.agent?.paused || status.agent?.status === "paused" || !status.agent?.enabled
                  ? "Resume autonomous multi-layer agent investigations"
                  : "Manually stop/pause autonomous multi-layer agent investigations"
              }
            >
              {status.agent?.paused || status.agent?.status === "paused" || !status.agent?.enabled ? (
                <>
                  <Play size={13} /> Resume Swarm
                </>
              ) : (
                <>
                  <CircleStop size={13} /> Stop Swarm
                </>
              )}
            </button>

            <button
              className="btn-mitigate"
              style={{ background: "#0284c7", color: "#fff", padding: "6px 12px" }}
              onClick={() => {
                setCopilotIncident(incidents[0] || null);
                setCopilotOpen(true);
              }}
            >
              <BrainCircuit size={14} /> AI Copilot
            </button>
            <span className="clock">
              <span className={`signal ${online ? "on" : ""}`} />
              {online ? "LIVE TELEMETRY" : "OFFLINE"}
            </span>
            <button className="icon-btn" onClick={() => void refresh(false)}>
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        {status.running && (
          <div className="capture-status-strip" role="status">
            <span className="capture-pulse">
              <Radio size={14} />
            </span>
            <strong>{status.source_mode.toUpperCase()} SENSOR ACTIVE</strong>
            <span>
              {status.processed_events.toLocaleString()} events captured · ML detection live · Continuous Layer 1-8 Agentic synthesis
            </span>
            <i className="capture-scan" />
          </div>
        )}

        {view === "overview" && (
          <Overview
            status={status}
            events={events}
            alerts={alerts}
            incidents={incidents}
            overview={overview}
            sensors={sensors}
            onNavigate={setView}
          />
        )}

        {view === "analytics" && (
          <ThreatAnalytics
            overview={overview}
            topology={topology}
            onInspectIp={() => setView("detections")}
          />
        )}

        {view === "incidents" && (
          <IncidentWorkbench
            incidents={incidents}
            agent={status.agent}
            onOpenCopilot={(inc) => {
              setCopilotIncident(inc);
              setCopilotOpen(true);
            }}
            onToggleAgent={toggleAgentSwarm}
          />
        )}

        {view === "blueprint" && <ArchitectureBlueprint status={status} />}

        {view === "sensors" && (
          <section className="page-grid">
            <SensorControl
              mode={mode}
              setMode={setMode}
              iface={iface}
              setIface={setIface}
              interfaces={interfaces}
              selected={selected}
              busy={busy}
              running={status.running}
              action={action}
            />
            <SensorPanel sensors={sensors} />
          </section>
        )}

        {view === "events" && <Events events={events} total={total} />}
        {view === "detections" && <Detections alerts={alerts} total={alerts.length} />}
        {view === "infrastructure" && <Infrastructure status={status} online={online} sensors={sensors} />}

        {toast && (
          <div className={`toast ${toast.error ? "danger" : "success"}`} role="status">
            <span className="toast-icon">
              {toast.error ? <AlertTriangle size={19} /> : <CheckCircle2 size={19} />}
            </span>
            <span className="toast-copy">
              <b>{toast.error ? "CAPTURE ERROR" : "CAPTURE UPDATE"}</b>
              {toast.text}
            </span>
            <button aria-label="Dismiss notification" onClick={() => setToast(null)}>
              <X size={15} />
            </button>
          </div>
        )}

        {/* Copilot Chat Drawer */}
        <CopilotDrawer
          isOpen={copilotOpen}
          onClose={() => setCopilotOpen(false)}
          activeIncident={copilotIncident}
        />
      </main>
    </div>
  );
}

function Overview({
  status,
  events,
  alerts,
  incidents,
  overview,
  sensors,
  onNavigate,
}: {
  status: Status;
  events: Event[];
  alerts: Alert[];
  incidents: Incident[];
  overview: AnalyticsOverview | null;
  sensors: SensorStatus | null;
  onNavigate: (view: View) => void;
}) {
  return (
    <>
      <section className="hero">
        <div>
          <div className="overline">AUTONOMOUS MULTI-LAYER DEFENSE / REAL-TIME</div>
          <h2>From Raw Network Packets to Human-Readable Intelligence.</h2>
          <p>Unified telemetry from Suricata + Zeek with continuous Agentic AI reasoning.</p>
        </div>
        <div className={`hero-state ${status.running ? "active" : ""}`}>
          <Radio size={20} />
          <div>
            <small>PIPELINE STATUS</small>
            <b>{status.running ? "CAPTURING" : "STANDBY"}</b>
            <span>{status.source_mode}</span>
          </div>
        </div>
      </section>

      <div className="metrics">
        <Metric icon={Activity} label="Processed Packets" value={status.processed_events.toLocaleString()} hint="Sensor telemetry" />
        <Metric
          icon={AlertTriangle}
          label="Threat Signals"
          value={alerts.filter((alert) => alert.severity !== "LOW").length.toLocaleString()}
          hint="Layer 4 hybrid ML alerts"
        />
        <Metric
          icon={Database}
          label="Agentic Incidents"
          value={incidents.length.toLocaleString()}
          hint="Layer 5 forensic dossiers"
        />
        <Metric
          icon={Gauge}
          label="Agentic Engine"
          value={status.agent?.available ? "SWARM ONLINE" : status.agent?.enabled ? "READY" : "OFF"}
          hint={status.agent?.available ? status.agent.model : "Mistral 7B + Heuristics"}
        />
      </div>

      {/* Quick Visual Vector Banner */}
      {overview && overview.attack_vectors.length > 0 && (
        <div className="executive-dossier" style={{ margin: "14px 0" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span className="dossier-tag" style={{ margin: 0 }}>
              <Flame size={13} color="#f43f5e" /> Active Threat Signature Distribution
            </span>
            <button className="text-btn" onClick={() => onNavigate("analytics")}>
              View Full Analytics & Charts <ChevronRight size={14} />
            </button>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {overview.attack_vectors.map((vec) => (
              <span
                key={vec.name}
                className="model-tag"
                style={{ padding: "6px 10px", fontSize: 11, background: "#182232", border: "1px solid #28394e" }}
              >
                <b>{vec.name}</b>: {vec.count} occurrences
              </span>
            ))}
          </div>
        </div>
      )}

      <LayerPipeline status={status} sensors={sensors} />

      <div className="overview-grid">
        <section className="panel">
          <div className="panel-title">
            <div>
              <span className="overline">LATEST TELEMETRY</span>
              <h3>Packet activity stream</h3>
            </div>
            <button className="text-btn" onClick={() => onNavigate("events")}>
              View all <ChevronRight size={14} />
            </button>
          </div>
          <div className="event-list">
            {events.slice(0, 6).map((event, index) => (
              <EventRow key={`${event.timestamp}-${index}`} event={event} />
            ))}
            {!events.length && <Empty text="No events persisted yet" />}
          </div>
        </section>

        <section className="panel">
          <div className="panel-title">
            <div>
              <span className="overline">LAYER 4-5 / THREAT TRIAGE</span>
              <h3>Active Threat Signals</h3>
            </div>
            <span className="count">{alerts.length} recent</span>
          </div>
          <div className="alert-list">
            {alerts
              .filter((alert) => alert.severity !== "LOW")
              .slice(0, 5)
              .map((alert, index) => (
                <AlertRow alert={alert} key={`${alert.event_id}-${index}`} />
              ))}
            {!alerts.some((alert) => alert.severity !== "LOW") && <Empty text="No active threats detected" />}
          </div>
        </section>
      </div>
    </>
  );
}

function LayerPipeline({ status, sensors }: { status: Status; sensors: SensorStatus | null }) {
  const layers: [string, string, boolean][] = [
    ["L1", "CAPTURE", status.running],
    ["L2", "NORMALIZE", status.processed_events > 0],
    ["L3", "STREAM", status.broker === "redis" || status.processed_events > 0],
    ["L4", "DETECT", !!status.ml?.available],
    ["L5", "AGENTIC SWARM", !!status.agent?.available],
  ];
  return (
    <section className="layer-pipeline panel">
      <div>
        <span className="overline">END-TO-END DEFENSE PIPELINE</span>
        <h3>Continuous telemetry & autonomous reasoning path</h3>
      </div>
      <div className="layer-track">
        {layers.map(([index, label, ready], position) => (
          <div className="layer-step" key={index}>
            <span className={`layer-node ${ready ? "ready" : ""}`}>{index}</span>
            <b>{label}</b>
            {position < layers.length - 1 && <span className="layer-connector" />}
          </div>
        ))}
      </div>
      <small>
        {sensors?.dual_sensor_ready
          ? "Dual sensor plane connected (Suricata + Zeek)"
          : "Sensor plane active"} · {status.detected_alerts} elevated signals evaluated
      </small>
    </section>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  return (
    <div className="alert-row">
      <span className={`severity-dot ${alert.severity.toLowerCase()}`} />
      <div>
        <b>
          {alert.source_ip || "unknown"} <small>→</small> {alert.destination_ip || "unknown"}
        </b>
        <span>
          {alert.severity} · risk {(alert.risk_score * 100).toFixed(0)}% ·{" "}
          {alert.detected_by.join(" + ") || "baseline"}
        </span>
      </div>
      <strong>{new Date(alert.timestamp).toLocaleTimeString()}</strong>
    </div>
  );
}

function Detections({ alerts, total }: { alerts: Alert[]; total: number }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"ALL" | Alert["severity"]>("ALL");
  const [selected, setSelected] = useState<Alert | null>(null);

  const filtered = alerts.filter((alert) => {
    const matchesSeverity = severity === "ALL" || alert.severity === severity;
    const haystack = JSON.stringify(alert).toLowerCase();
    return matchesSeverity && haystack.includes(query.toLowerCase());
  });

  return (
    <section className="panel event-page detection-page">
      <div className="panel-title">
        <div>
          <span className="overline">LAYER 4 / AUDITABLE MODEL OUTPUT</span>
          <h3>Detection log</h3>
          <p className="panel-subtitle">Every record links model decisions to the normalized packet and original sensor payload.</p>
        </div>
        <div className="stream-summary">
          <span className="live-indicator">
            <i /> LIVE DETECTIONS
          </span>
          <span className="count">{total.toLocaleString()} stored records</span>
        </div>
      </div>
      <div className="stream-toolbar detection-toolbar">
        <label className="search-box">
          <Search size={14} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter IP, event id, sensor, detector..."
          />
        </label>
        <select
          className="severity-filter"
          value={severity}
          onChange={(event) => setSeverity(event.target.value as "ALL" | Alert["severity"])}
        >
          <option value="ALL">All severity</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <span className="count">{filtered.length} visible</span>
      </div>
      <div className="table-wrap">
        <table className="detection-table">
          <thead>
            <tr>
              <th>TIME</th>
              <th>SEVERITY</th>
              <th>FLOW</th>
              <th>RISK</th>
              <th>MODELS</th>
              <th>SENSOR</th>
              <th>DETAIL</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((alert, index) => (
              <tr
                className={selected?.event_id === alert.event_id ? "selected-row" : ""}
                key={`${alert.event_id}-${index}`}
                onClick={() => setSelected(alert)}
              >
                <td>
                  <b>{new Date(alert.timestamp).toLocaleTimeString()}</b>
                  <small>{new Date(alert.timestamp).toLocaleDateString()}</small>
                </td>
                <td>
                  <span className={`severity-badge ${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                </td>
                <td>
                  <b>
                    {alert.source_ip || "unknown"} <small>→</small> {alert.destination_ip || "unknown"}
                  </b>
                  <small>
                    {alert.protocol || "unknown"} · {alert.packet?.destination_port ?? "—"}
                  </small>
                </td>
                <td>
                  <strong>{(alert.risk_score * 100).toFixed(0)}%</strong>
                  <small>
                    RF {(alert.supervised_probability * 100).toFixed(0)}% · IF {(alert.anomaly_score * 100).toFixed(0)}%
                  </small>
                </td>
                <td>
                  {alert.detected_by.length ? (
                    alert.detected_by.map((model) => (
                      <span className="model-tag" key={model}>
                        {model.replace("_", " ")}
                      </span>
                    ))
                  ) : (
                    <span className="baseline-tag">BASELINE</span>
                  )}
                </td>
                <td>
                  <span className="sensor-tag">{alert.capture_source}</span>
                  <small>{alert.packet?.event_type || "legacy event"}</small>
                </td>
                <td>
                  <button
                    className="row-action"
                    onClick={(event) => {
                      event.stopPropagation();
                      setSelected(alert);
                    }}
                  >
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && <Empty text={query ? "No detections match this filter" : "No detections recorded yet"} />}
      </div>
      {selected && <DetectionDetail alert={selected} onClose={() => setSelected(null)} />}
    </section>
  );
}

function DetectionDetail({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  return (
    <>
      <button className="detail-backdrop" aria-label="Close detection detail" onClick={onClose} />
      <aside className="event-detail detection-detail" aria-label="Detection detail panel">
        <div className="detail-heading">
          <div>
            <span className="overline">DETECTION INSPECTOR</span>
            <h4>{alert.severity} security signal</h4>
            <p>Linked event {alert.event_id}</p>
          </div>
          <button className="icon-btn" aria-label="Close detection detail" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="detection-score">
          <div>
            <span>RISK SCORE</span>
            <b>{(alert.risk_score * 100).toFixed(1)}%</b>
          </div>
          <div>
            <span>RANDOM FOREST</span>
            <b>{(alert.supervised_probability * 100).toFixed(1)}%</b>
          </div>
          <div>
            <span>ISOLATION FOREST</span>
            <b>{(alert.anomaly_score * 100).toFixed(1)}%</b>
          </div>
        </div>
        <div className="detail-status">
          <span className={`severity-dot ${alert.severity.toLowerCase()}`} />
          <b>{alert.detected_by.join(" + ") || "BASELINE"}</b>
          <span>{alert.capture_source}</span>
        </div>
        <div className="detection-explanation">{alert.explanation}</div>
        <div className="raw-heading">
          <span>PACKET CONTEXT</span>
          <span>JSON</span>
        </div>
        <pre>{JSON.stringify(alert.packet ?? { note: "Legacy alert created before packet context was stored." }, null, 2)}</pre>
        <div className="raw-heading">
          <span>DERIVED ML FEATURES</span>
          <span>JSON</span>
        </div>
        <pre>{JSON.stringify(alert.model_features ?? { note: "Legacy alert created before feature snapshots were stored." }, null, 2)}</pre>
      </aside>
    </>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="metric">
      <Icon size={17} />
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}

function SensorControl({
  mode,
  setMode,
  iface,
  setIface,
  interfaces,
  selected,
  busy,
  running,
  action,
}: any) {
  return (
    <section className="panel control-panel">
      <div className="panel-title">
        <div>
          <span className="overline">CAPTURE CONTROL</span>
          <h3>Sensor orchestration</h3>
        </div>
        <span className={`status-pill ${running ? "live" : ""} ${busy ? "working" : ""}`}>
          <i /> {busy ? "STARTING" : running ? "ACTIVE" : "IDLE"}
        </span>
      </div>
      <div className="mode-list">
        {modes.map((item) => (
          <button
            className={mode === item.id ? "mode active" : "mode"}
            onClick={() => setMode(item.id)}
            key={item.id}
          >
            <span className="mode-index">0{modes.indexOf(item) + 1}</span>
            <span>
              <b>{item.label}</b>
              <small>{item.detail}</small>
            </span>
            <ChevronRight size={16} />
          </button>
        ))}
      </div>
      {mode === "live" && (
        <label className="field">
          <span>MONITORED INTERFACE</span>
          <select value={iface} onChange={(e) => setIface(e.target.value)}>
            <option value="">Select adapter</option>
            {interfaces.map((item: any) => (
              <option key={item.name} value={item.name}>
                {item.description} ({item.name})
              </option>
            ))}
          </select>
        </label>
      )}
      <div className="sensor-note">
        <Wifi size={16} />
        <div>
          <b>Interface-driven capture</b>
          <p>Suricata and Zeek run on the sensor host and emit live telemetry. No PCAP path is required for production mode.</p>
        </div>
      </div>
      <div className="actions">
        <button className="btn secondary" onClick={() => action("stop")} disabled={busy || !running}>
          <CircleStop size={15} /> Stop
        </button>
        <button
          className={`btn primary ${busy ? "loading" : ""}`}
          onClick={() => action(running ? "switch" : "start")}
          disabled={busy || (mode === "live" && !iface)}
        >
          {busy ? (
            <>
              <LoaderCircle size={16} className="spin" /> Connecting sensors…
            </>
          ) : (
            <>
              <Play size={15} />
              {running ? "Switch source" : "Start sensor plane"}
            </>
          )}
        </button>
      </div>
      {busy && (
        <div className="capture-progress" role="status">
          <span className="progress-scan" />
          <span>
            Contacting FastAPI capture worker and attaching <b>{mode}</b>…
          </span>
        </div>
      )}
    </section>
  );
}

function SensorPanel({ sensors }: { sensors: SensorStatus | null }) {
  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <span className="overline">DEPLOYMENT HEALTH</span>
          <h3>Sensor readiness</h3>
        </div>
        <Boxes size={18} />
      </div>
      <SensorLine label="Suricata" ok={!!sensors?.suricata.available} detail={sensors?.suricata.path || "Not configured"} />
      <SensorLine label="Zeek" ok={!!sensors?.zeek.available} detail={sensors?.zeek.path || "Not configured"} />
      <div className="callout">
        <Shield size={18} />
        <p>
          <b>Production topology</b>
          <br />
          Run both sensors on Linux/Kali with access to the monitored interface or SPAN/TAP. This FastAPI node consumes their live structured output.
        </p>
      </div>
    </section>
  );
}

function SensorLine({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <div className="sensor-line">
      <span className={`sensor-icon ${ok ? "ok" : ""}`}>{ok ? "✓" : "–"}</span>
      <div>
        <b>{label}</b>
        <small>{detail}</small>
      </div>
      <em className={ok ? "ok-text" : ""}>{ok ? "READY" : "STAGED"}</em>
    </div>
  );
}

function Events({ events, total }: { events: Event[]; total: number }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Event | null>(null);

  const filtered = events.filter((event) => JSON.stringify(event).toLowerCase().includes(query.toLowerCase()));

  return (
    <section className="panel event-page">
      <div className="panel-title">
        <div>
          <span className="overline">NORMALIZED TELEMETRY / NEWEST FIRST</span>
          <h3>Event stream</h3>
          <p className="panel-subtitle">Polling the append-only history every 3 seconds. New packets appear at the top.</p>
        </div>
        <div className="stream-summary">
          <span className="live-indicator">
            <i /> LIVE FEED
          </span>
          <span className="count">{total.toLocaleString()} total records</span>
        </div>
      </div>
      <div className="stream-toolbar">
        <label className="search-box">
          <Search size={14} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter IP, port, sensor, protocol, event id..."
          />
        </label>
        <span className="count">
          {filtered.length} visible / {events.length} loaded
        </span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>TIME</th>
              <th>SENSOR / TYPE</th>
              <th>SOURCE</th>
              <th>DESTINATION</th>
              <th>PROTO</th>
              <th>BYTES</th>
              <th>DETAIL</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((event, index) => (
              <tr
                className={selected === event ? "selected-row" : ""}
                key={`${event.timestamp}-${event.packet_id || index}`}
                onClick={() => setSelected(event)}
              >
                <td>
                  <b>{new Date(event.timestamp).toLocaleTimeString()}</b>
                  <small>{new Date(event.timestamp).toLocaleDateString()}</small>
                </td>
                <td>
                  <span className="sensor-tag">{event.capture_source}</span>
                  <small>{event.event_type || "network event"}</small>
                </td>
                <td>
                  {event.source_ip || "—"}:{event.source_port || "—"}
                </td>
                <td>
                  {event.destination_ip || "—"}:{event.destination_port || "—"}
                </td>
                <td>{event.protocol || "—"}</td>
                <td>{event.packet_length.toLocaleString()}</td>
                <td>
                  <button
                    className="row-action"
                    onClick={(click) => {
                      click.stopPropagation();
                      setSelected(event);
                    }}
                  >
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && <Empty text={query ? "No events match this filter" : "No persisted telemetry available"} />}
      </div>
      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}
    </section>
  );
}

function EventDetail({ event, onClose }: { event: Event; onClose: () => void }) {
  const fields = [
    ["Timestamp", new Date(event.timestamp).toLocaleString()],
    ["Capture source", event.capture_source],
    ["Event type", event.event_type || "network event"],
    ["Flow id", event.packet_id || "not supplied"],
    ["Source", `${event.source_ip || "unknown"}:${event.source_port || "—"}`],
    ["Destination", `${event.destination_ip || "unknown"}:${event.destination_port || "—"}`],
    ["Protocol", event.protocol || "unknown"],
    ["Packet bytes", event.packet_length.toLocaleString()],
    ["Duration", event.duration == null ? "not supplied" : `${event.duration}s`],
    ["Source bytes", event.source_bytes == null ? "not supplied" : event.source_bytes.toLocaleString()],
    ["Destination bytes", event.destination_bytes == null ? "not supplied" : event.destination_bytes.toLocaleString()],
  ];
  return (
    <>
      <button className="detail-backdrop" aria-label="Close packet inspection" onClick={onClose} />
      <aside className="event-detail" aria-label="Packet inspection panel">
        <div className="detail-heading">
          <div>
            <span className="overline">PACKET INSPECTOR</span>
            <h4>Event details</h4>
            <p>Normalized sensor observation</p>
          </div>
          <button className="icon-btn" aria-label="Close packet inspection" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="detail-status">
          <span className="signal on" />
          <b>{event.capture_source.toUpperCase()}</b>
          <span>{event.event_type || "network event"}</span>
        </div>
        <div className="detail-grid">
          {fields.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <b>{value}</b>
            </div>
          ))}
        </div>
        <div className="raw-heading">
          <span>RAW EVENT</span>
          <span>JSON</span>
        </div>
        <pre>{JSON.stringify(event, null, 2)}</pre>
      </aside>
    </>
  );
}

function EventRow({ event }: { event: Event }) {
  return (
    <div className="event-row">
      <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
      <span className="event-dot" />
      <div>
        <b>
          {event.source_ip || "unknown"} <small>→</small> {event.destination_ip || "unknown"}
        </b>
        <span>
          {event.capture_source} · {event.protocol || "—"} · {event.packet_length} bytes
        </span>
      </div>
    </div>
  );
}

function Infrastructure({
  status,
  online,
  sensors,
}: {
  status: Status;
  online: boolean;
  sensors: SensorStatus | null;
}) {
  return (
    <div className="infra-grid">
      <div className="panel">
        <span className="overline">CONTROL API</span>
        <h3>Backend service</h3>
        <SensorLine label="FastAPI" ok={online} detail="HTTP control plane" />
        <SensorLine label="Capture worker" ok={status.running} detail={status.source_mode} />
        <SensorLine label="Agent Swarm" ok={!!status.agent?.available} detail={status.agent?.model || "Local model"} />
      </div>
      <div className="panel">
        <span className="overline">MESSAGE FABRIC</span>
        <h3>Redis stream</h3>
        <SensorLine label="Redis" ok={status.broker === "redis"} detail="nids:raw-events" />
        <div className="callout">
          <Database size={18} />
          <p>Normalized events are persisted locally and published to the stream for the ML worker.</p>
        </div>
      </div>
      <div className="panel">
        <span className="overline">SENSOR OUTPUT</span>
        <h3>Deployment files</h3>
        <SensorLine label="Suricata EVE" ok={!!sensors?.suricata.available} detail={sensors?.suricata.path || "Not found"} />
        <SensorLine label="Zeek conn" ok={!!sensors?.zeek.available} detail={sensors?.zeek.path || "Not found"} />
      </div>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>;
}

export default App;
