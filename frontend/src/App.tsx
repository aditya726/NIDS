import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, Boxes, ChevronRight, CircleStop, Database,
  Gauge, LayoutDashboard, Network, Play, Radio, RefreshCw, Search, Server,
  Shield, Wifi, X,
} from "lucide-react";
import { api, Event, Mode, SensorStatus, Status } from "./api";

type View = "overview" | "sensors" | "events" | "infrastructure";
const nav: { id: View; label: string; icon: typeof Radio }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "sensors", label: "Sensors", icon: Shield },
  { id: "events", label: "Event stream", icon: Activity },
  { id: "infrastructure", label: "Infrastructure", icon: Server },
];
const modes: { id: Mode; label: string; detail: string }[] = [
  { id: "sensors", label: "Suricata + Zeek", detail: "Production dual sensor" },
  { id: "suricata_live", label: "Suricata", detail: "IDS telemetry" },
  { id: "zeek_live", label: "Zeek", detail: "Network metadata" },
  { id: "live", label: "Scapy fallback", detail: "Development capture" },
];

const emptyStatus: Status = { running: false, source_mode: "none", processed_events: 0, last_event: null, error: null, broker: "unknown" };

function App() {
  const [view, setView] = useState<View>("overview");
  const [status, setStatus] = useState<Status>(emptyStatus);
  const [sensors, setSensors] = useState<SensorStatus | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [interfaces, setInterfaces] = useState<{ name: string; description: string }[]>([]);
  const [mode, setMode] = useState<Mode>("sensors");
  const [iface, setIface] = useState("");
  const [busy, setBusy] = useState(false);
  const [online, setOnline] = useState(false);
  const [toast, setToast] = useState<{ text: string; error?: boolean } | null>(null);
  const notify = (text: string, error = false) => { setToast({ text, error }); window.setTimeout(() => setToast(null), 3600); };
  const refresh = useCallback(async (quiet = true) => {
    try {
      const [health, nextStatus, history, sensorStatus] = await Promise.all([api.health(), api.status(), api.events(), api.sensors()]);
      setOnline(health.status === "ok"); setStatus(nextStatus); setEvents(history.events); setTotal(history.total); setSensors(sensorStatus);
    } catch (error) { setOnline(false); if (!quiet) notify(error instanceof Error ? error.message : "Backend unavailable", true); }
  }, []);
  useEffect(() => { void refresh(false); const timer = window.setInterval(() => void refresh(), 3000); return () => window.clearInterval(timer); }, [refresh]);
  useEffect(() => { api.interfaces().then((result) => { setInterfaces(result.interfaces); setIface(result.interfaces.find((item) => /wi-?fi|wireless/i.test(item.description))?.name || result.interfaces[0]?.name || ""); }).catch(() => undefined); }, []);
  const payload: Record<string, string> = mode === "live" ? { mode, interface: iface } : { mode };
  const action = async (kind: "start" | "stop" | "switch") => {
    setBusy(true);
    try { const result = kind === "stop" ? await api.stop() : kind === "start" ? await api.start(payload) : await api.switch(payload); setStatus(result); notify(kind === "stop" ? "Pipeline stopped" : `${mode} sensor active`); await refresh(); }
    catch (error) { notify(error instanceof Error ? error.message : "Operation failed", true); } finally { setBusy(false); }
  };
  const selected = modes.find((item) => item.id === mode) ?? modes[0];
  const protocolCounts = useMemo(() => events.reduce<Record<string, number>>((acc, event) => { const key = event.protocol || "unknown"; acc[key] = (acc[key] || 0) + 1; return acc; }, {}), [events]);
  return <div className="shell">
    <aside className="rail">
      <div className="wordmark"><div className="mark"><Network size={18}/></div><div><b>ARGUS</b><small>NIDS CONTROL PLANE</small></div></div>
      <div className="rail-label">WORKSPACE</div>
      {nav.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-link ${view === id ? "current" : ""}`} onClick={() => setView(id)}><Icon size={17}/>{label}{id === "events" && <span>{total}</span>}</button>)}
      <div className="rail-label lower">SYSTEM</div>
      <div className="rail-system"><span className={`signal ${online ? "on" : ""}`}/><div><small>CONTROL API</small><b>{online ? "Connected" : "Offline"}</b></div></div>
      <div className="rail-system"><span className={`signal ${status.broker === "redis" ? "on" : ""}`}/><div><small>EVENT BUS</small><b>{status.broker === "redis" ? "Redis online" : "Local mode"}</b></div></div>
    </aside>
    <main className="workspace">
      <header className="header"><div><div className="crumb">OPERATIONS <ChevronRight size={12}/> {nav.find((item) => item.id === view)?.label.toUpperCase()}</div><h1>{view === "overview" ? "Command center" : nav.find((item) => item.id === view)?.label}</h1></div><div className="header-actions"><span className="clock"><span className={`signal ${online ? "on" : ""}`}/>{online ? "LIVE" : "OFFLINE"}</span><button className="icon-btn" onClick={() => void refresh(false)}><RefreshCw size={16}/></button></div></header>
      {view === "overview" && <Overview status={status} events={events} total={total} sensors={sensors} onNavigate={setView}/>}
      {view === "sensors" && <section className="page-grid"><SensorControl mode={mode} setMode={setMode} iface={iface} setIface={setIface} interfaces={interfaces} selected={selected} busy={busy} running={status.running} action={action}/><SensorPanel sensors={sensors}/></section>}
      {view === "events" && <Events events={events} total={total}/>}
      {view === "infrastructure" && <Infrastructure status={status} online={online} sensors={sensors}/>}
      {toast && <div className={`toast ${toast.error ? "danger" : ""}`}><span>{toast.error ? <AlertTriangle size={16}/> : <Shield size={16}/>}</span>{toast.text}<button onClick={() => setToast(null)}><X size={14}/></button></div>}
    </main>
  </div>;
}

function Overview({ status, events, total, sensors, onNavigate }: { status: Status; events: Event[]; total: number; sensors: SensorStatus | null; onNavigate: (view: View) => void }) {
  return <><section className="hero"><div><div className="overline">NETWORK DEFENSE / REAL-TIME</div><h2>See the signal before it becomes an incident.</h2><p>Unified telemetry from your Suricata and Zeek sensor plane.</p></div><div className={`hero-state ${status.running ? "active" : ""}`}><Radio size={20}/><div><small>PIPELINE</small><b>{status.running ? "CAPTURING" : "STANDBY"}</b><span>{status.source_mode}</span></div></div></section>
    <div className="metrics"><Metric icon={Activity} label="Processed events" value={status.processed_events.toLocaleString()} hint="Current run"/><Metric icon={Database} label="Event history" value={total.toLocaleString()} hint="Persisted records"/><Metric icon={Shield} label="Sensor plane" value={sensors?.dual_sensor_ready ? "READY" : "STAGED"} hint="Suricata + Zeek"/><Metric icon={Gauge} label="Bus" value={status.broker === "redis" ? "ONLINE" : "LOCAL"} hint="Redis Stream"/></div>
    <div className="overview-grid"><section className="panel"><div className="panel-title"><div><span className="overline">LATEST TELEMETRY</span><h3>Packet activity</h3></div><button className="text-btn" onClick={() => onNavigate("events")}>View all <ChevronRight size={14}/></button></div><div className="event-list">{events.slice(0, 6).map((event, index) => <EventRow key={`${event.timestamp}-${index}`} event={event}/>) }{!events.length && <Empty text="No events persisted yet"/>}</div></section><section className="panel"><div className="panel-title"><div><span className="overline">SENSOR PLANE</span><h3>Readiness</h3></div><button className="text-btn" onClick={() => onNavigate("sensors")}>Manage <ChevronRight size={14}/></button></div><SensorLine label="Suricata" ok={!!sensors?.suricata.available} detail={sensors?.suricata.available ? "EVE output detected" : "Awaiting sensor output"}/><SensorLine label="Zeek" ok={!!sensors?.zeek.available} detail={sensors?.zeek.available ? "Connection log detected" : "Awaiting sensor output"}/><SensorLine label="Redis stream" ok={status.broker === "redis"} detail={status.broker === "redis" ? "nids:raw-events" : "Optional / unavailable"}/><div className="protocol-box"><span className="overline">RECENT PROTOCOL MIX</span>{Object.entries(events.reduce<Record<string, number>>((a, e) => { const k = e.protocol || "unknown"; a[k] = (a[k] || 0) + 1; return a; }, {})).slice(0, 4).map(([key, value]) => <div className="bar-row" key={key}><span>{key}</span><i><b style={{ width: `${Math.min(100, value / Math.max(1, events.length) * 100)}%` }}/></i><em>{value}</em></div>)}</div></section></div></>;
}
function Metric({ icon: Icon, label, value, hint }: { icon: typeof Activity; label: string; value: string; hint: string }) { return <div className="metric"><Icon size={17}/><span>{label}</span><strong>{value}</strong><small>{hint}</small></div>; }
function SensorControl({ mode, setMode, iface, setIface, interfaces, selected, busy, running, action }: any) { return <section className="panel control-panel"><div className="panel-title"><div><span className="overline">CAPTURE CONTROL</span><h3>Sensor orchestration</h3></div><span className={`status-pill ${running ? "live" : ""}`}><i/> {running ? "ACTIVE" : "IDLE"}</span></div><div className="mode-list">{modes.map((item) => <button className={mode === item.id ? "mode active" : "mode"} onClick={() => setMode(item.id)} key={item.id}><span className="mode-index">0{modes.indexOf(item) + 1}</span><span><b>{item.label}</b><small>{item.detail}</small></span><ChevronRight size={16}/></button>)}</div>{mode === "live" && <label className="field"><span>MONITORED INTERFACE</span><select value={iface} onChange={(e) => setIface(e.target.value)}><option value="">Select adapter</option>{interfaces.map((item: any) => <option key={item.name} value={item.name}>{item.description} ({item.name})</option>)}</select></label>}<div className="sensor-note"><Wifi size={16}/><div><b>Interface-driven capture</b><p>Suricata and Zeek run on the sensor host and emit live telemetry. No PCAP path is required for production mode.</p></div></div><div className="actions"><button className="btn secondary" onClick={() => action("stop")} disabled={busy || !running}><CircleStop size={15}/> Stop</button><button className="btn primary" onClick={() => action(running ? "switch" : "start")} disabled={busy || (mode === "live" && !iface)}><Play size={15}/>{running ? "Switch source" : "Start sensor plane"}</button></div></section>; }
function SensorPanel({ sensors }: { sensors: SensorStatus | null }) { return <section className="panel"><div className="panel-title"><div><span className="overline">DEPLOYMENT HEALTH</span><h3>Sensor readiness</h3></div><Boxes size={18}/></div><SensorLine label="Suricata" ok={!!sensors?.suricata.available} detail={sensors?.suricata.path || "Not configured"}/><SensorLine label="Zeek" ok={!!sensors?.zeek.available} detail={sensors?.zeek.path || "Not configured"}/><div className="callout"><Shield size={18}/><p><b>Production topology</b><br/>Run both sensors on Linux/Kali with access to the monitored interface or SPAN/TAP. This FastAPI node consumes their live structured output.</p></div></section>; }
function SensorLine({ label, ok, detail }: { label: string; ok: boolean; detail: string }) { return <div className="sensor-line"><span className={`sensor-icon ${ok ? "ok" : ""}`}>{ok ? "✓" : "–"}</span><div><b>{label}</b><small>{detail}</small></div><em className={ok ? "ok-text" : ""}>{ok ? "READY" : "STAGED"}</em></div>; }
function Events({ events, total }: { events: Event[]; total: number }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Event | null>(null);
  const filtered = events.filter((event) => JSON.stringify(event).toLowerCase().includes(query.toLowerCase()));
  return <section className="panel event-page">
    <div className="panel-title"><div><span className="overline">NORMALIZED TELEMETRY / NEWEST FIRST</span><h3>Event stream</h3><p className="panel-subtitle">Polling the append-only history every 3 seconds. New packets appear at the top.</p></div><div className="stream-summary"><span className="live-indicator"><i/> LIVE FEED</span><span className="count">{total.toLocaleString()} total records</span></div></div>
    <div className="stream-toolbar"><label className="search-box"><Search size={14}/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter IP, port, sensor, protocol, event id..." /></label><span className="count">{filtered.length} visible / {events.length} loaded</span></div>
    <div className="table-wrap"><table><thead><tr><th>TIME</th><th>SENSOR / TYPE</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>BYTES</th><th>DETAIL</th></tr></thead><tbody>{filtered.map((event, index) => <tr className={selected === event ? "selected-row" : ""} key={`${event.timestamp}-${event.packet_id || index}`} onClick={() => setSelected(event)}><td><b>{new Date(event.timestamp).toLocaleTimeString()}</b><small>{new Date(event.timestamp).toLocaleDateString()}</small></td><td><span className="sensor-tag">{event.capture_source}</span><small>{event.event_type || "network event"}</small></td><td>{event.source_ip || "—"}:{event.source_port || "—"}</td><td>{event.destination_ip || "—"}:{event.destination_port || "—"}</td><td>{event.protocol || "—"}</td><td>{event.packet_length.toLocaleString()}</td><td><button className="row-action" onClick={(click) => { click.stopPropagation(); setSelected(event); }}>Inspect</button></td></tr>)}</tbody></table>{!filtered.length && <Empty text={query ? "No events match this filter" : "No persisted telemetry available"}/>}</div>
    {selected && <EventDetail event={selected} onClose={() => setSelected(null)}/>}
  </section>;
}
function EventDetail({ event, onClose }: { event: Event; onClose: () => void }) {
  const fields = [["Timestamp", new Date(event.timestamp).toLocaleString()], ["Capture source", event.capture_source], ["Event type", event.event_type || "network event"], ["Flow id", event.packet_id || "not supplied"], ["Source", `${event.source_ip || "unknown"}:${event.source_port || "—"}`], ["Destination", `${event.destination_ip || "unknown"}:${event.destination_port || "—"}`], ["Protocol", event.protocol || "unknown"], ["Packet bytes", event.packet_length.toLocaleString()], ["Duration", event.duration == null ? "not supplied" : `${event.duration}s`], ["Source bytes", event.source_bytes == null ? "not supplied" : event.source_bytes.toLocaleString()], ["Destination bytes", event.destination_bytes == null ? "not supplied" : event.destination_bytes.toLocaleString()]];
  return <div className="event-detail"><div className="detail-heading"><div><span className="overline">SELECTED EVENT</span><h4>Packet and flow metadata</h4></div><button className="icon-btn" onClick={onClose}><X size={14}/></button></div><div className="detail-grid">{fields.map(([label, value]) => <div key={label}><span>{label}</span><b>{value}</b></div>)}</div><pre>{JSON.stringify(event, null, 2)}</pre></div>;
}
function EventRow({ event }: { event: Event }) { return <div className="event-row"><span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span><span className="event-dot"/><div><b>{event.source_ip || "unknown"} <small>→</small> {event.destination_ip || "unknown"}</b><span>{event.capture_source} · {event.protocol || "—"} · {event.packet_length} bytes</span></div></div>; }
function Infrastructure({ status, online, sensors }: { status: Status; online: boolean; sensors: SensorStatus | null }) { return <div className="infra-grid"><div className="panel"><span className="overline">CONTROL API</span><h3>Backend service</h3><SensorLine label="FastAPI" ok={online} detail="HTTP control plane" /><SensorLine label="Capture worker" ok={status.running} detail={status.source_mode} /></div><div className="panel"><span className="overline">MESSAGE FABRIC</span><h3>Redis stream</h3><SensorLine label="Redis" ok={status.broker === "redis"} detail="nids:raw-events" /><div className="callout"><Database size={18}/><p>Normalized events are persisted locally and published to the stream for the ML worker.</p></div></div><div className="panel"><span className="overline">SENSOR OUTPUT</span><h3>Deployment files</h3><SensorLine label="Suricata EVE" ok={!!sensors?.suricata.available} detail={sensors?.suricata.path || "Not found"} /><SensorLine label="Zeek conn" ok={!!sensors?.zeek.available} detail={sensors?.zeek.path || "Not found"} /></div></div>; }
function Empty({ text }: { text: string }) { return <div className="empty">{text}</div>; }
export default App;
