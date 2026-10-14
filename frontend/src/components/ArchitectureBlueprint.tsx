import React from "react";
import {
  Activity,
  Boxes,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Database,
  Flame,
  Globe,
  Layers,
  MessageSquare,
  Network,
  Radio,
  Server,
  Shield,
  Zap,
} from "lucide-react";
import { Status } from "../api";

export function ArchitectureBlueprint({ status }: { status: Status }) {
  const layers = [
    {
      id: "L1",
      name: "Layer 1: Sensor & Capture Plane",
      role: "SensorTelemetryAgent",
      tech: "Suricata EVE + Zeek + Scapy (Dual Sensor)",
      status: status.running ? "ACTIVE" : "STANDBY",
      statusOk: status.running,
      description:
        "Passive packet capture & telemetry ingestion. The autonomous Ingestion Agent dynamically monitors buffer drop counters, measures frame arrival cadence, and synthesizes adaptive BPF capture rules (e.g. 'ip and host X and tcp') to throttle non-critical flows during DDoS spikes without dropping forensic packets.",
      icon: Radio,
    },
    {
      id: "L2",
      name: "Layer 2: Flow Normalization & Profiling",
      role: "FlowProfileAgent",
      tech: "Python Flow Aggregator (5-Tuple Vectorizer)",
      status: status.processed_events > 0 ? "STREAMING" : "IDLE",
      statusOk: status.processed_events > 0,
      description:
        "Transforms heterogeneous raw events into unified flow feature vectors. The Flow Profiler Agent calculates packet geometry, byte asymmetry coefficients (Fwd vs Bwd), SYN/ACK handshake completion ratios, and payload entropy to identify anomalous micro-bursts before model scoring.",
      icon: Activity,
    },
    {
      id: "L3",
      name: "Layer 3: Message Broker & Priority Dispatch",
      role: "StreamTriageAgent",
      tech: "Redis Streams (nids:raw-events) / Local Buffer",
      status: status.broker === "redis" ? "REDIS STREAM" : "LOCAL QUEUE",
      statusOk: true,
      description:
        "Shock-absorber layer decoupling 10Gbps+ line-rate packet capture from ML/AI processing. The Stream Triage Agent analyzes flow entropy and dynamically routes high-risk flows to the Low-Latency Fast Path while batching benign telemetry for bulk baseline updating.",
      icon: Database,
    },
    {
      id: "L4",
      name: "Layer 4: Hybrid Parallel ML Inference Funnel",
      role: "MLDisambiguationAgent",
      tech: "Supervised Random Forest/XGBoost + Unsupervised Isolation Forest/Autoencoder",
      status: status.ml?.available ? "MODELS READY" : "BOOTSTRAPPING",
      statusOk: !!status.ml?.available,
      description:
        "Dual-engine parallel detection. The Supervised classifier identifies known attack signatures (DDoS, Brute Force, Web Exploits), while the Unsupervised model flags zero-day anomalies via reconstruction error. The ML Disambiguation Agent explains model consensus and calculates feature attribution weights.",
      icon: Cpu,
    },
    {
      id: "L5",
      name: "Layer 5: Multi-Agent Deep Forensic Swarm (The Brain)",
      role: "LangGraph / Ollama Mistral 7B Swarm",
      tech: "LangGraph + Mistral:7b + Heuristic Correlation Collective",
      status: status.agent?.available ? "SWARM ONLINE" : "STAGED",
      statusOk: !!status.agent?.available,
      description:
        "Autonomous multi-agent investigation collective: (1) Correlation Agent groups alerts by host and time window; (2) MITRE ATT&CK Agent maps tactics and techniques (T1046, T1190, T1110, T1498); (3) Forensic Reasoning Agent generates deep multi-paragraph threat briefings; (4) Playbook Agent synthesizes executable iptables and nftables containment commands.",
      icon: BrainCircuit,
    },
    {
      id: "L6",
      name: "Layer 6: Contextual Memory & Attacker Tracking",
      role: "ThreatMemoryAgent",
      tech: "Redis Session Cache + In-Memory Historical Store",
      status: "ACTIVE",
      statusOk: true,
      description:
        "Persistent memory across incident lifecycles. Tracks repeat offender IPs across time windows, maintains subnet threat score aggregations, records historical encounter counts, and enriches new signals with prior investigation context.",
      icon: Server,
    },
    {
      id: "L7",
      name: "Layer 7: Automated Response & Validation",
      role: "ResponseValidationAgent",
      tech: "FastAPI REST + WebSocket Push + STIX 2.1 Export",
      status: "ONLINE",
      statusOk: true,
      description:
        "Safety barrier and containment executor. Evaluates blast radius before policy enforcement, simulates kernel iptables drop rules, exports machine-readable STIX 2.1 bundles, and generates compliance-ready downloadable forensic incident dossiers.",
      icon: Shield,
    },
    {
      id: "L8",
      name: "Layer 8: Live Command Center & Analyst Copilot",
      role: "AnalystCopilotAgent",
      tech: "React 18 + Vite + Recharts + Interactive Copilot Drawer",
      status: "INTERACTIVE",
      statusOk: true,
      description:
        "Real-time SOC operations interface. Delivers dynamic threat velocity charts, network communication topology maps, interactive MITRE ATT&CK explorer, interactive remediation playbooks with single-click rule enforcement, and a real-time conversational AI copilot.",
      icon: Globe,
    },
  ];

  return (
    <div className="analytics-page">
      <div className="analytics-hero">
        <div>
          <div className="overline">CROSS-LAYER ARCHITECTURE BLUEPRINT</div>
          <h2>End-to-End Multi-Layer Agentic AI Workflow</h2>
          <p>
            How autonomous agents operate collectively from Layer 1 (Raw Packet Capture) through Layer 8 (Interactive Command Center).
          </p>
        </div>
        <div className="hero-state active">
          <BrainCircuit size={20} />
          <div>
            <small>ARCHITECTURE</small>
            <b>8 LAYERS</b>
            <span>Continuous Agentic Oversight</span>
          </div>
        </div>
      </div>

      <div className="executive-dossier" style={{ margin: "4px 0 16px" }}>
        <div className="dossier-tag">
          <Shield size={13} /> The Paradigm Shift: Why Agentic AI Belongs in Every Layer
        </div>
        <p>
          In traditional NIDS prototypes, AI is relegated solely to the very end as a passive summarizer of noisy alerts.
          In the <b>Antigravity Agentic Architecture</b>, specialized AI agents act as intelligent orchestrators throughout the entire data path:
          tuning sensor BPF filters at Layer 1 to prevent buffer overflows, measuring flow geometry at Layer 2, prioritizing stream buffers at Layer 3,
          disambiguating model disagreements at Layer 4, synthesizing deep forensic narratives and MITRE mappings at Layer 5, tracking repeat offenders in Layer 6,
          validating blast radius in Layer 7, and empowering human analysts via real-time interactive copilots at Layer 8.
        </p>
      </div>

      <div className="arch-view-grid">
        {layers.map((layer) => {
          const Icon = layer.icon;
          return (
            <div className="arch-card" key={layer.id}>
              <div className="arch-layer-id">{layer.id}</div>
              <div className="arch-layer-info">
                <b>{layer.name}</b>
                <span>Role: {layer.role}</span>
                <span style={{ color: "#38bdf8", fontSize: 9 }}>Tech: {layer.tech}</span>
              </div>
              <div className="arch-layer-desc">{layer.description}</div>
              <div className="arch-layer-status" style={!layer.statusOk ? { background: "#2a1b18", color: "#f87171", borderColor: "#f8717140" } : {}}>
                {layer.status}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
