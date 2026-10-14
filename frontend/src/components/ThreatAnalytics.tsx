import React, { useState } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ZAxis,
} from "recharts";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Flame,
  Globe2,
  Layers,
  Network,
  Radio,
  Search,
  Shield,
  Zap,
} from "lucide-react";
import { AnalyticsOverview, AnalyticsTopology } from "../api";

const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#06b6d4", "#10b981", "#8b5cf6"];

type SubTab = "charts" | "topology" | "mitre";

export function ThreatAnalytics({
  overview,
  topology,
  onInspectIp,
}: {
  overview: AnalyticsOverview | null;
  topology: AnalyticsTopology | null;
  onInspectIp?: (ip: string) => void;
}) {
  const [subTab, setSubTab] = useState<SubTab>("charts");
  const [selectedMitre, setSelectedMitre] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  if (!overview) {
    return (
      <div className="empty">
        <Activity size={24} className="spin" style={{ margin: "0 auto 12px" }} />
        Aggregating deep threat telemetry & model distributions…
      </div>
    );
  }

  return (
    <div className="analytics-page">
      <div className="analytics-hero">
        <div>
          <div className="overline">LAYER 4-8 TELEMETRY & PATTERN ANALYSIS</div>
          <h2>Autonomous Threat Intelligence & ML Diagnostics</h2>
          <p>
            Real-time multi-dimensional correlation: traffic velocity, attack vectors, model consensus, and network topology.
          </p>
          <div className="analytics-subnav">
            <button
              className={subTab === "charts" ? "active" : ""}
              onClick={() => setSubTab("charts")}
            >
              <BarChart3 size={14} /> Analytics & ML Diagnostics
            </button>
            <button
              className={subTab === "topology" ? "active" : ""}
              onClick={() => setSubTab("topology")}
            >
              <Network size={14} /> Communication Topology Map
            </button>
            <button
              className={subTab === "mitre" ? "active" : ""}
              onClick={() => setSubTab("mitre")}
            >
              <Layers size={14} /> MITRE ATT&CK Matrix Explorer
            </button>
          </div>
        </div>
        <div className="hero-state active">
          <Activity size={20} />
          <div>
            <small>ANALYTICS ENGINE</small>
            <b>{overview.total_alerts.toLocaleString()}</b>
            <span>Total Signals Processed</span>
          </div>
        </div>
      </div>

      {subTab === "charts" && (
        <div className="charts-grid">
          {/* Chart 1: Threat Velocity & Ingestion Cadence */}
          <div className="chart-card chart-card-full">
            <div className="chart-header">
              <div>
                <b>
                  <Flame size={15} color="#f43f5e" /> Traffic Velocity & Elevated Threat Spikes
                </b>
                <small>Chronological packet ingestion throughput vs high-risk security alerts</small>
              </div>
              <span className="chart-badge">LIVE STREAM TELEMETRY</span>
            </div>
            <div className="chart-body" style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={overview.timeline} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                  <YAxis stroke="#475569" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 4, fontSize: 11 }}
                    itemStyle={{ color: "#f8fafc" }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11, paddingTop: 6 }} />
                  <Area
                    type="monotone"
                    dataKey="events"
                    name="Ingested Packets / Events"
                    stroke="#38bdf8"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorEvents)"
                  />
                  <Area
                    type="monotone"
                    dataKey="high_threats"
                    name="Elevated Threat Detections"
                    stroke="#f43f5e"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorThreats)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 2: Attack Vector Distribution */}
          <div className="chart-card">
            <div className="chart-header">
              <div>
                <b>
                  <Shield size={15} color="#eab308" /> Attack Vector & Signature Breakdown
                </b>
                <small>Categorization across brute-force, web exploits, floods, and zero-day anomalies</small>
              </div>
              <span className="chart-badge">CLASSIFICATION MATRIX</span>
            </div>
            <div className="chart-body" style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={overview.attack_vectors}
                    dataKey="count"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    label={(entry) => (entry?.name ? String(entry.name).split("/")[0] : "")}
                  >
                    {overview.attack_vectors.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 4, fontSize: 11 }}
                  />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 3: ML Model Disagreement & Anomaly Radar / Scatter */}
          <div className="chart-card">
            <div className="chart-header">
              <div>
                <b>
                  <Zap size={15} color="#38bdf8" /> Supervised Classifier vs Behavioral Anomaly (Radar)
                </b>
                <small>Random Forest probability (%) vs Isolation Forest / Autoencoder score (%)</small>
              </div>
              <span className="chart-badge">PARALLEL INFERENCE</span>
            </div>
            <div className="chart-body" style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 10 }}>
                  <XAxis
                    type="number"
                    dataKey="supervised"
                    name="Supervised Probability"
                    unit="%"
                    domain={[0, 100]}
                    stroke="#475569"
                    tick={{ fontSize: 10, fill: "#94a3b8" }}
                  />
                  <YAxis
                    type="number"
                    dataKey="anomaly"
                    name="Anomaly Score"
                    unit="%"
                    domain={[0, 100]}
                    stroke="#475569"
                    tick={{ fontSize: 10, fill: "#94a3b8" }}
                  />
                  <ZAxis range={[40, 100]} />
                  <Tooltip
                    cursor={{ strokeDasharray: "3 3" }}
                    contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 4, fontSize: 11 }}
                  />
                  <Scatter name="Threat Points" data={overview.scatter} fill="#38bdf8">
                    {overview.scatter.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          entry.severity === "HIGH"
                            ? "#ef4444"
                            : entry.severity === "MEDIUM"
                            ? "#eab308"
                            : "#10b981"
                        }
                      />
                    ))}
                  </Scatter>
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 4: Top Targeted Exposure Ports */}
          <div className="chart-card">
            <div className="chart-header">
              <div>
                <b>
                  <Radio size={15} color="#8b5cf6" /> Most Targeted Assets & Port Exposures
                </b>
                <small>Volume of elevated security signals mapped to internal listener ports</small>
              </div>
              <span className="chart-badge">DESTINATION VECTOR</span>
            </div>
            <div className="chart-body" style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={overview.top_targets} layout="vertical" margin={{ top: 5, right: 20, left: 40, bottom: 5 }}>
                  <XAxis type="number" stroke="#475569" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                  <YAxis type="category" dataKey="target" stroke="#475569" tick={{ fontSize: 10, fill: "#cbd5e1" }} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 4, fontSize: 11 }}
                  />
                  <Bar dataKey="count" name="Targeted Incidents" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 5: Top Attacker IPs */}
          <div className="chart-card">
            <div className="chart-header">
              <div>
                <b>
                  <Globe2 size={15} color="#ef4444" /> Adversary Source IP Frequency
                </b>
                <small>Top persistent external hosts initiating unauthorized flows</small>
              </div>
              <span className="chart-badge">REPEAT OFFENDERS</span>
            </div>
            <div className="chart-body" style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={overview.top_sources} layout="vertical" margin={{ top: 5, right: 20, left: 45, bottom: 5 }}>
                  <XAxis type="number" stroke="#475569" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                  <YAxis type="category" dataKey="ip" stroke="#475569" tick={{ fontSize: 10, fill: "#cbd5e1" }} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 4, fontSize: 11 }}
                  />
                  <Bar dataKey="count" name="Attack Events" fill="#ef4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* View 2: Interactive Network Topology Map */}
      {subTab === "topology" && (
        <div className="chart-card chart-card-full">
          <div className="chart-header">
            <div>
              <b>
                <Network size={16} color="#38bdf8" /> Real-Time Node Communication Topology
              </b>
              <small>
                Live graphical trace: Attacker Hosts (Red) → Sensor Plane Gateway (Purple) → Defended Internal Assets (Cyan).
                Click on any node to view forensic socket details.
              </small>
            </div>
            <div className="topology-legend">
              <span>
                <i style={{ background: "#ef4444" }} /> Remote Attacker
              </span>
              <span>
                <i style={{ background: "#8b5cf6" }} /> Suricata/Zeek Gateway
              </span>
              <span>
                <i style={{ background: "#06b6d4" }} /> Protected Internal Server
              </span>
            </div>
          </div>

          <div className="topology-box">
            <svg className="topology-svg" viewBox="0 0 800 380">
              {/* Central Gateway */}
              <circle cx="400" cy="190" r="32" fill="#1e1b4b" stroke="#8b5cf6" strokeWidth="2.5" />
              <text x="400" y="194" fill="#c084fc" fontSize="10" fontWeight="bold" textAnchor="middle">
                GATEWAY
              </text>
              <text x="400" y="206" fill="#94a3b8" fontSize="8" textAnchor="middle">
                L1-L3 SENSOR
              </text>

              {/* Attacker Nodes on Left */}
              {(topology?.nodes.filter((n) => n.type === "attacker").slice(0, 6) || []).map((node, idx, arr) => {
                const y = 50 + (idx * 300) / Math.max(1, arr.length - 1);
                return (
                  <g
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    style={{ cursor: "pointer" }}
                  >
                    <line
                      x1="120"
                      y1={y}
                      x2="370"
                      y2="190"
                      stroke="#ef4444"
                      strokeWidth={node.risk > 0.7 ? "2" : "1"}
                      strokeDasharray={node.risk > 0.7 ? "4 3" : undefined}
                      strokeOpacity="0.6"
                    />
                    <circle cx="120" cy={y} r="16" fill="#450a0a" stroke="#ef4444" strokeWidth="2" />
                    <text x="120" y={y + 3} fill="#fca5a5" fontSize="8" textAnchor="middle">
                      ATK
                    </text>
                    <text x="95" y={y + 4} fill="#cbd5e1" fontSize="9" textAnchor="end">
                      {node.label.replace("Attacker: ", "")}
                    </text>
                  </g>
                );
              })}

              {/* Target Nodes on Right */}
              {(topology?.nodes.filter((n) => n.type === "target").slice(0, 6) || []).map((node, idx, arr) => {
                const y = 50 + (idx * 300) / Math.max(1, arr.length - 1);
                return (
                  <g
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    style={{ cursor: "pointer" }}
                  >
                    <line
                      x1="430"
                      y1="190"
                      x2="680"
                      y2={y}
                      stroke="#06b6d4"
                      strokeWidth="1.5"
                      strokeOpacity="0.6"
                    />
                    <circle cx="680" cy={y} r="16" fill="#083344" stroke="#06b6d4" strokeWidth="2" />
                    <text x="680" y={y + 3} fill="#67e8f9" fontSize="8" textAnchor="middle">
                      HOST
                    </text>
                    <text x="705" y={y + 4} fill="#cbd5e1" fontSize="9" textAnchor="start">
                      {node.label.replace("Internal Target: ", "")}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {selectedNode && (
            <div className="adversary-card" style={{ marginTop: 14 }}>
              <div>
                <span>Selected Topology Node</span>
                <b>{selectedNode.label}</b>
              </div>
              <div>
                <span>Node Role / Classification</span>
                <b>{selectedNode.type.toUpperCase()}</b>
              </div>
              <div>
                <span>Active Risk Weight</span>
                <b>{(selectedNode.risk * 100).toFixed(0)}%</b>
              </div>
              <div>
                <span>Action</span>
                <button
                  className="btn-mitigate"
                  style={{ alignSelf: "flex-start", marginTop: 4 }}
                  onClick={() => {
                    if (onInspectIp) onInspectIp(selectedNode.id);
                  }}
                >
                  <Search size={12} /> Inspect In Feed
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* View 3: MITRE ATT&CK Matrix Explorer */}
      {subTab === "mitre" && (
        <div className="chart-card chart-card-full">
          <div className="chart-header">
            <div>
              <b>
                <Layers size={16} color="#f43f5e" /> MITRE ATT&CK Enterprise Matrix Navigator
              </b>
              <small>Mapped adversary tactics & techniques verified by the Layer 5 Agent Swarm</small>
            </div>
            <span className="chart-badge">FRAMEWORK v14</span>
          </div>

          <div className="mitre-explorer">
            <div className="mitre-col">
              <div className="mitre-col-title">Reconnaissance</div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1046" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1046")}
              >
                <b>T1046</b>
                <span>Network Service Discovery</span>
                <span className="mitre-hits-pill">Active Probes</span>
              </div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1595" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1595")}
              >
                <b>T1595</b>
                <span>Active Scanning: Port Scans</span>
              </div>
            </div>

            <div className="mitre-col">
              <div className="mitre-col-title">Initial Access</div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1190" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1190")}
              >
                <b>T1190</b>
                <span>Exploit Public-Facing App</span>
                <span className="mitre-hits-pill">Web Vectors</span>
              </div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1078" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1078")}
              >
                <b>T1078</b>
                <span>Valid Accounts / Abuse</span>
              </div>
            </div>

            <div className="mitre-col">
              <div className="mitre-col-title">Credential Access</div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1110.001" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1110.001")}
              >
                <b>T1110.001</b>
                <span>Password Guessing / SSH</span>
                <span className="mitre-hits-pill">Brute Force</span>
              </div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1110.003" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1110.003")}
              >
                <b>T1110.003</b>
                <span>Password Spraying</span>
              </div>
            </div>

            <div className="mitre-col">
              <div className="mitre-col-title">Lateral Movement</div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1021.002" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1021.002")}
              >
                <b>T1021.002</b>
                <span>Remote Services: SMB Shares</span>
                <span className="mitre-hits-pill">Internal Spread</span>
              </div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1021.004" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1021.004")}
              >
                <b>T1021.004</b>
                <span>Remote Services: SSH</span>
              </div>
            </div>

            <div className="mitre-col">
              <div className="mitre-col-title">Impact & C2</div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1498.001" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1498.001")}
              >
                <b>T1498.001</b>
                <span>Network DoS: Direct Flood</span>
                <span className="mitre-hits-pill">SYN Spikes</span>
              </div>
              <div
                className={`mitre-technique-card ${selectedMitre === "T1071.001" ? "selected" : ""}`}
                onClick={() => setSelectedMitre("T1071.001")}
              >
                <b>T1071.001</b>
                <span>Web / C2 Beaconing Protocol</span>
              </div>
            </div>
          </div>

          {selectedMitre && (
            <div className="executive-dossier" style={{ marginTop: 16 }}>
              <div className="dossier-tag">
                <Shield size={13} /> MITRE Technical Breakdown: {selectedMitre}
              </div>
              <p>
                <b>Behavioral Signature:</b> Traffic patterns exhibit non-random volumetric clustering aligned with technique{" "}
                <code>{selectedMitre}</code>. The hybrid ML engine identified deliberate packet geometry manipulation designed to probe
                service availability while attempting to minimize detection footprint.
              </p>
              <p>
                <b>SOC Analyst Action:</b> Review the related flow records in the Detection Log to correlate ingress timestamps with
                local application daemon authentication events.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
