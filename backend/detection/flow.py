"""Bounded bidirectional flow aggregation for packet and sensor events."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from ..capture.models import PacketEvent


@dataclass
class _FlowState:
    first_seen: float
    last_seen: float
    origin: tuple[str, int | None]
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    lengths: list[int] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0


class FlowAggregator:
    """Maintain bounded flow state and emit cumulative features per observation."""

    def __init__(self, *, idle_timeout: float = 120.0, max_flows: int = 100_000) -> None:
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        self._flows: dict[str, _FlowState] = {}

    def update(self, event: PacketEvent) -> dict[str, float]:
        now = _event_seconds(event) or monotonic()
        key = event.correlation_key or event.event_id or "unknown"
        state = self._flows.get(key)
        if state is None or now - state.last_seen > self.idle_timeout:
            state = _FlowState(
                first_seen=now,
                last_seen=now,
                origin=(event.source_ip or "", event.source_port),
            )
            self._flows[key] = state
        state.last_seen = max(state.last_seen, now)
        forward = (event.source_ip or "", event.source_port) == state.origin
        if forward:
            state.forward_packets += 1
            state.forward_bytes += event.packet_length
        else:
            state.backward_packets += 1
            state.backward_bytes += event.packet_length
        state.lengths.append(event.packet_length)
        state.lengths = state.lengths[-512:]
        flags = event.tcp_flags or ""
        state.syn_count += int("S" in flags)
        state.ack_count += int("A" in flags)
        state.fin_count += int("F" in flags)
        state.rst_count += int("R" in flags)
        if len(self._flows) > self.max_flows:
            oldest = min(self._flows, key=lambda item: self._flows[item].last_seen)
            self._flows.pop(oldest, None)
        duration = max(state.last_seen - state.first_seen, 0.001)
        total_bytes = state.forward_bytes + state.backward_bytes
        return {
            "Flow Duration": duration * 1000.0,
            "Total Fwd Packets": float(state.forward_packets),
            "Total Backward Packets": float(state.backward_packets),
            "Flow Bytes/s": total_bytes / duration,
            "Packet Length Mean": sum(state.lengths) / len(state.lengths),
            "Flow Total Bytes": float(total_bytes),
            "Flow Packets/s": (state.forward_packets + state.backward_packets) / duration,
            "Forward/Backward Byte Ratio": state.forward_bytes / max(state.backward_bytes, 1),
            "TCP SYN Count": float(state.syn_count),
            "TCP ACK Count": float(state.ack_count),
            "TCP FIN Count": float(state.fin_count),
            "TCP RST Count": float(state.rst_count),
        }


def _event_seconds(event: PacketEvent) -> float | None:
    from datetime import datetime

    try:
        return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
