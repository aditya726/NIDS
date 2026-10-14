import React, { useState } from "react";
import {
  BrainCircuit,
  Check,
  Copy,
  CornerDownLeft,
  Flame,
  LoaderCircle,
  MessageSquare,
  Send,
  Shield,
  Sparkles,
  Terminal,
  X,
} from "lucide-react";
import { api, Incident } from "../api";

export function CopilotDrawer({
  isOpen,
  onClose,
  activeIncident,
}: {
  isOpen: boolean;
  onClose: () => void;
  activeIncident: Incident | null;
}) {
  const [messages, setMessages] = useState<
    { role: "user" | "agent"; text: string; time: string }[]
  >([
    {
      role: "agent",
      text: "👋 Greetings Analyst. I am the Antigravity Agentic Copilot. I have loaded context for the active network telemetry and ML detection models. Ask me about threat mechanics, blast radius, firewall rules, or packet forensics.",
      time: new Date().toLocaleTimeString(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (!isOpen) return null;

  const handleSend = async (questionText?: string) => {
    const q = (questionText || input).trim();
    if (!q || loading) return;

    const userMsg = { role: "user" as const, text: q, time: new Date().toLocaleTimeString() };
    setMessages((prev) => [...prev, userMsg]);
    if (!questionText) setInput("");
    setLoading(true);

    try {
      const contextPayload: Record<string, unknown> = activeIncident
        ? {
            incident_id: activeIncident.incident_id,
            source_ip: activeIncident.source_ip,
            destination_ip: activeIncident.destination_ip,
            severity: activeIncident.severity,
            attack_phase: activeIncident.attack_phase,
            techniques: activeIncident.techniques,
            risk_score: activeIncident.metrics?.risk_score,
            confidence: activeIncident.confidence,
            summary: activeIncident.summary,
            adversary: activeIncident.adversary_profile,
          }
        : {
            mode: "general_telemetry",
            note: "Operating on active pipeline telemetry.",
          };

      const res = await api.copilotChat({ question: q, context: contextPayload });
      setMessages((prev) => [
        ...prev,
        { role: "agent", text: res.answer, time: new Date().toLocaleTimeString() },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "agent",
          text: `⚠️ Copilot encounter error: ${err instanceof Error ? err.message : "Service unavailable"}`,
          time: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const copyText = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const quickPrompts = [
    "🛡️ Generate perimeter iptables rule",
    "🎯 Assess blast radius & subnet impact",
    "⚡ Explain the ML feature attribution",
    "🔍 What MITRE techniques are involved?",
    "📜 Generate a Suricata signature",
  ];

  return (
    <>
      <div className="detail-backdrop" onClick={onClose} />
      <aside className="copilot-drawer">
        <div className="copilot-header">
          <div>
            <h4>
              <BrainCircuit size={18} color="#38bdf8" /> SOC Agentic Copilot
            </h4>
            <small>
              {activeIncident
                ? `Context: ${activeIncident.incident_id} (${activeIncident.source_ip || "source"} → ${activeIncident.destination_ip || "target"})`
                : "Active Pipeline Context Loaded"}
            </small>
          </div>
          <button className="icon-btn" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="copilot-prompts">
          {quickPrompts.map((prompt) => (
            <button
              key={prompt}
              className="copilot-prompt-chip"
              onClick={() => handleSend(prompt)}
            >
              {prompt}
            </button>
          ))}
        </div>

        <div className="copilot-body">
          {messages.map((msg, index) => (
            <div key={index} className={`copilot-msg ${msg.role}`}>
              <div className="copilot-msg-bubble">
                <div style={{ whiteSpace: "pre-wrap" }}>{msg.text}</div>
                {msg.role === "agent" && (
                  <button
                    className="row-action"
                    style={{ marginTop: 8, padding: "2px 6px", fontSize: 9 }}
                    onClick={() => copyText(msg.text, index)}
                  >
                    {copiedIndex === index ? (
                      <>
                        <Check size={10} /> Copied
                      </>
                    ) : (
                      <>
                        <Copy size={10} /> Copy Response
                      </>
                    )}
                  </button>
                )}
              </div>
              <small style={{ color: "#64748b", fontSize: 9, alignSelf: msg.role === "user" ? "flex-end" : "flex-start" }}>
                {msg.time}
              </small>
            </div>
          ))}
          {loading && (
            <div className="copilot-msg agent">
              <div className="copilot-msg-bubble" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <LoaderCircle size={14} className="spin" />
                Thinking & generating forensic reasoning…
              </div>
            </div>
          )}
        </div>

        <div className="copilot-footer">
          <form
            className="copilot-input-form"
            onSubmit={(e) => {
              e.preventDefault();
              void handleSend();
            }}
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask Copilot about blast radius, iptables rules, payload..."
              disabled={loading}
            />
            <button type="submit" disabled={loading || !input.trim()}>
              <Send size={13} />
            </button>
          </form>
        </div>
      </aside>
    </>
  );
}
