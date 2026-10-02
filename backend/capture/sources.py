"""Layer 1 capture and replay adapters."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import json
import threading
import time
from typing import Any

from .models import PacketEvent


class JsonlReplaySource:
    """Replay normalized historical events from a JSONL file."""

    def __init__(self, path: str | Path, *, speed: float = 0.0) -> None:
        if speed < 0:
            raise ValueError("speed must be non-negative")
        self.path = Path(path)
        self.speed = speed

    def __iter__(self) -> Iterator[PacketEvent]:
        previous_timestamp: float | None = None
        with self.path.open("r", encoding="utf-8") as events:
            for line_number, line in enumerate(events, start=1):
                if not line.strip():
                    continue
                try:
                    event = PacketEvent.from_mapping(json.loads(line))
                except (json.JSONDecodeError, ValueError) as exc:
                    raise ValueError(
                        f"invalid event at {self.path}:{line_number}: {exc}"
                    ) from exc
                if self.speed:
                    current_timestamp = _timestamp_seconds(event.timestamp)
                    if previous_timestamp is not None:
                        time.sleep(max(0.0, current_timestamp - previous_timestamp) / self.speed)
                    previous_timestamp = current_timestamp
                yield event


class PcapReplaySource:
    """Replay a PCAP file through the same normalized event contract."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[PacketEvent]:
        try:
            from scapy.all import PcapReader
        except ImportError as exc:
            raise RuntimeError(
                "PCAP replay requires the optional 'capture' dependency: "
                "pip install .[capture]"
            ) from exc
        with PcapReader(str(self.path)) as reader:
            for packet in reader:
                event = _packet_to_event(packet, f"pcap:{self.path.name}")
                if event is not None:
                    yield event


class SuricataEveSource:
    """Read Suricata EVE JSON records and normalize packet/flow fields."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[PacketEvent]:
        with self.path.open("r", encoding="utf-8") as events:
            for line_number, line in enumerate(events, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    yield self._normalize(record)
                except (json.JSONDecodeError, ValueError, TypeError) as exc:
                    raise ValueError(
                        f"invalid Suricata EVE record at {self.path}:{line_number}: {exc}"
                    ) from exc

    @staticmethod
    def _normalize(record: dict[str, Any]) -> PacketEvent:
        timestamp = record.get("timestamp")
        if not timestamp:
            raise ValueError("timestamp is required")
        flow = record.get("flow") or {}
        length = record.get("packet_length", flow.get("bytes_toserver", 0))
        return PacketEvent(
            timestamp=str(timestamp),
            source_ip=record.get("src_ip"),
            destination_ip=record.get("dest_ip"),
            source_port=record.get("src_port"),
            destination_port=record.get("dest_port"),
            protocol=record.get("proto"),
            packet_length=int(length or 0),
            capture_source="suricata",
            packet_id=record.get("flow_id"),
            raw=record,
        )


def _timestamp_seconds(timestamp: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


class ScapyLiveSource:
    """Capture packets from a live interface (Kali/Linux or another Scapy host)."""

    def __init__(
        self,
        interface: str,
        *,
        packet_filter: str | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.interface = interface
        self.packet_filter = packet_filter
        self.stop_event = stop_event or threading.Event()

    def __iter__(self) -> Iterator[PacketEvent]:
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise RuntimeError(
                "live capture requires the optional 'capture' dependency: pip install .[capture]"
            ) from exc

        while not self.stop_event.is_set():
            packets = sniff(
                iface=self.interface,
                filter=self.packet_filter,
                count=1,
                store=True,
                timeout=1,
            )
            if not packets:
                continue
            event = _packet_to_event(packets[0], f"scapy:{self.interface}")
            if event is not None:
                yield event

    @staticmethod
    def interfaces() -> list[dict[str, str]]:
        """Return capture interfaces and adapter descriptions."""
        try:
            from scapy.all import IFACES
        except ImportError as exc:
            raise RuntimeError(
                "interface discovery requires Scapy: pip install .[capture]"
            ) from exc
        return [
            {
                "name": interface.name,
                "description": interface.description or interface.name,
            }
            for interface in IFACES.values()
        ]


def _packet_to_event(packet: Any, capture_source: str) -> PacketEvent | None:
    from scapy.all import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    return PacketEvent.now(
        source_ip=packet[IP].src,
        destination_ip=packet[IP].dst,
        source_port=getattr(transport, "sport", None),
        destination_port=getattr(transport, "dport", None),
        protocol=str(getattr(packet[IP], "proto", None)),
        packet_length=len(packet),
        capture_source=capture_source,
        raw={"summary": packet.summary()},
    )
