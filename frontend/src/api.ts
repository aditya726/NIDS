export type Mode = "sensors" | "suricata_live" | "zeek_live" | "live" | "pcap";
export type Status = { running: boolean; source_mode: string; processed_events: number; last_event: Event | null; error: string | null; broker: string };
export type SensorStatus = { mode: string; interface: string | null; dual_sensor_ready: boolean; suricata: { name: string; path: string; available: boolean; size_bytes: number; updated_at: number | null }; zeek: { name: string; path: string; available: boolean; size_bytes: number; updated_at: number | null } };
export type Event = { timestamp: string; source_ip: string | null; destination_ip: string | null; source_port: number | null; destination_port: number | null; protocol: string | null; packet_length: number; capture_source: string; packet_id?: string | null; event_type?: string | null; duration?: number | null; source_bytes?: number | null; destination_bytes?: number | null };
export type CaptureResponse = Status;
const base = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${base}${path}`, { headers: { "Content-Type": "application/json" }, ...init });
  if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.detail || `Request failed (${response.status})`); }
  return response.json();
}
export const api = {
  health: () => request<{ status: string }>("/health"),
  status: () => request<Status>("/capture/status"),
  sensors: () => request<SensorStatus>("/sensors/status"),
  interfaces: () => request<{ interfaces: { name: string; description: string }[] }>("/capture/interfaces"),
  events: () => request<{ events: Event[]; total: number; latest: boolean }>("/capture/events?latest=true&limit=100"),
  start: (payload: Record<string, string>) => request<CaptureResponse>("/capture/start", { method: "POST", body: JSON.stringify(payload) }),
  stop: () => request<CaptureResponse>("/capture/stop", { method: "POST", body: "{}" }),
  switch: (payload: Record<string, string>) => request<CaptureResponse>("/capture/switch", { method: "POST", body: JSON.stringify(payload) })
};
