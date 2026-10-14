export type Mode = "sensors" | "suricata_live" | "zeek_live" | "live" | "pcap";

export type AgentStatus = {
  enabled: boolean;
  status: string;
  available: boolean;
  paused?: boolean;
  model: string;
  ollama_url: string;
  error: string | null;
  mode?: string;
  queue?: { queued: number; submitted: number; completed: number; failed: number; dropped: number };
};

export type Status = {
  running: boolean;
  source_mode: string;
  processed_events: number;
  last_event: Event | null;
  error: string | null;
  broker: string;
  detected_alerts: number;
  ml: DetectionStatus | null;
  agent: AgentStatus | null;
};

export type DetectionStatus = {
  status: string;
  available: boolean;
  artifact_dir: string;
  error: string | null;
};

export type Alert = {
  event_id: string;
  timestamp: string;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string | null;
  capture_source: string;
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH";
  supervised_probability: number;
  anomaly_score: number;
  is_anomaly: boolean;
  detected_by: string[];
  explanation: string;
  packet?: {
    packet_id?: string | null;
    event_type?: string | null;
    source_port?: number | null;
    destination_port?: number | null;
    packet_length?: number;
    duration?: number | null;
    source_bytes?: number | null;
    destination_bytes?: number | null;
    source_packets?: number | null;
    destination_packets?: number | null;
    alert_signature?: string | null;
    alert_category?: string | null;
    alert_severity?: number | null;
    correlation_key?: string | null;
    raw?: Record<string, unknown> | null;
  };
  model_features?: Record<string, number>;
  model_status: string;
};

export type SensorStatus = {
  mode: string;
  interface: string | null;
  dual_sensor_ready: boolean;
  suricata: { name: string; path: string; available: boolean; size_bytes: number; updated_at: number | null };
  zeek: { name: string; path: string; available: boolean; size_bytes: number; updated_at: number | null };
};

export type Event = {
  timestamp: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  packet_length: number;
  capture_source: string;
  packet_id?: string | null;
  event_type?: string | null;
  duration?: number | null;
  source_bytes?: number | null;
  destination_bytes?: number | null;
};

export type CaptureResponse = Status;

export type MitreTactic = {
  id: string;
  name: string;
  tactic: string;
  justification: string;
};

export type IOC = {
  type: string;
  value: string;
  category: string;
  confidence: string;
};

export type PlaybookStep = {
  step: number;
  action: string;
  command: string;
  type: string;
  priority: string;
  description: string;
  executed?: boolean;
};

export type AdversaryProfile = {
  actor_category?: string;
  kill_chain_stage?: string;
  sophistication?: string;
  intent?: string;
};

export type Incident = {
  incident_id: string;
  created_at: string;
  status: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  title: string;
  summary: string;
  confidence: number;
  source_event_ids: string[];
  evidence: string[];
  recommended_actions: string[];
  ticket: Record<string, unknown>;
  agent_status: string;
  model: string;
  attack_phase?: string;
  techniques?: string[];
  confidence_basis?: string[];
  metrics?: Record<string, number>;
  correlation_key: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  executive_brief?: string;
  adversary_profile?: AdversaryProfile;
  mitre_tactics?: MitreTactic[];
  forensic_breakdown?: {
    geometry?: Record<string, unknown>;
    ml_attribution?: Record<string, unknown>;
    sensor?: Record<string, unknown>;
  };
  iocs?: IOC[];
  playbook?: PlaybookStep[];
  layer_trace?: Record<string, unknown>;
  mitigation_status?: string;
};

export type AnalyticsOverview = {
  total_events: number;
  total_alerts: number;
  total_incidents: number;
  protocols: { name: string; value: number }[];
  severity: { HIGH: number; MEDIUM: number; LOW: number };
  attack_vectors: { name: string; count: number }[];
  mitre_matrix: { technique: string; hits: number }[];
  scatter: { supervised: number; anomaly: number; risk: number; severity: string; ip: string }[];
  timeline: { time: string; events: number; high_threats: number; avg_risk: number; avg_anomaly: number }[];
  top_sources: { ip: string; count: number }[];
  top_targets: { target: string; count: number }[];
};

export type TopologyNode = {
  id: string;
  label: string;
  type: "attacker" | "target" | "gateway";
  risk: number;
  connections: number;
  geo?: {
    latitude: number;
    longitude: number;
    city?: string | null;
    country?: string | null;
    country_code?: string | null;
  } | null;
};

export type TopologyEdge = {
  source: string;
  target: string;
  protocol: string;
  risk: number;
  severity: string;
  port: number;
  event_id?: string;
  timestamp?: string;
};

export type AnalyticsTopology = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  generated_at?: string;
  geoip_enabled?: boolean;
  geoip_available?: boolean;
  geoip_resolved_nodes?: number;
  geoip_status?: "ready" | "database_not_configured" | "database_unavailable";
};

export type RuntimeTelemetry = {
  source: string;
  host: string;
  platform: string;
  connections: {
    local: string;
    remote: string;
    status: string;
    pid: number | null;
  }[];
  traceroute: { available: boolean; reason?: string };
  generated_at: string;
};

const base = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${base}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

export const api = {
  health: () => request<{ status: string }>("/health"),
  status: () => request<Status>("/capture/status"),
  sensors: () => request<SensorStatus>("/sensors/status"),
  interfaces: () => request<{ interfaces: { name: string; description: string }[] }>("/capture/interfaces"),
  events: () => request<{ events: Event[]; total: number; latest: boolean }>("/capture/events?latest=true&limit=100"),
  detection: () => request<DetectionStatus>("/detection/status"),
  agent: () => request<AgentStatus>("/agent/status"),
  incidents: () => request<{ incidents: Incident[]; total: number }>("/incidents?limit=100"),
  alerts: () => request<{ alerts: Alert[]; total: number }>("/detection/alerts?limit=250"),
  start: (payload: Record<string, string>) => request<CaptureResponse>("/capture/start", { method: "POST", body: JSON.stringify(payload) }),
  stop: () => request<CaptureResponse>("/capture/stop", { method: "POST", body: "{}" }),
  switch: (payload: Record<string, string>) => request<CaptureResponse>("/capture/switch", { method: "POST", body: JSON.stringify(payload) }),
  analyticsOverview: () => request<AnalyticsOverview>("/analytics/overview"),
  analyticsTopology: () => request<AnalyticsTopology>("/analytics/topology"),
  analyticsRuntime: () => request<RuntimeTelemetry>("/analytics/runtime"),
  copilotChat: (payload: { question: string; context: Record<string, unknown> }) =>
    request<{ answer: string; mode: string; model: string }>("/agent/copilot/chat", { method: "POST", body: JSON.stringify(payload) }),
  mitigate: (payload: { incident_id: string; action: string; command: string; target_ip?: string }) =>
    request<{ status: string; action: string; message: string; executed_at: string }>("/agent/mitigate", { method: "POST", body: JSON.stringify(payload) }),
  deepInvestigate: (payload: { alert_id?: string; event_id?: string }) =>
    request<Incident>("/agent/deep-investigate", { method: "POST", body: JSON.stringify(payload) }),
  agentPause: () => request<{ status: string; agent: AgentStatus; pipeline: Status }>("/agent/pause", { method: "POST", body: "{}" }),
  agentResume: () => request<{ status: string; agent: AgentStatus; pipeline: Status }>("/agent/resume", { method: "POST", body: "{}" }),
  agentToggle: () => request<{ status: string; agent: AgentStatus; pipeline: Status }>("/agent/toggle", { method: "POST", body: "{}" }),
  reportUrl: (incidentId: string) => `${base}/incidents/${incidentId}/report`,
};
