"""Layer 1 capture and replay adapters."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import json
import queue
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
        return SuricataLiveSource._normalize(record)


class SuricataLiveSource:
    """Tail Suricata EVE JSON from the current end without replaying old data."""

    def __init__(
        self,
        path: str | Path,
        *,
        stop_event: threading.Event,
        poll_interval: float = 0.25,
    ) -> None:
        self.path = Path(path)
        self.stop_event = stop_event
        self.poll_interval = poll_interval

    def __iter__(self) -> Iterator[PacketEvent]:
        yield from _tail_json_lines(
            self.path,
            self.stop_event,
            self._normalize,
            self.poll_interval,
            source_name="Suricata",
        )

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
            event_type=record.get("event_type"),
            # ``flow.end`` is an ISO timestamp, not a duration. Only ``age``
            # represents elapsed seconds in Suricata flow records.
            duration=_float_or_none(flow.get("age")),
            source_bytes=_int_or_none(flow.get("bytes_toserver")),
            destination_bytes=_int_or_none(flow.get("bytes_toclient")),
            source_packets=_int_or_none(flow.get("pkts_toserver")),
            destination_packets=_int_or_none(flow.get("pkts_toclient")),
            alert_signature=(record.get("alert") or {}).get("signature"),
            alert_category=(record.get("alert") or {}).get("category"),
            alert_severity=_int_or_none((record.get("alert") or {}).get("severity")),
        )


class ZeekLiveSource:
    """Tail Zeek JSON logs and normalize connection records in real time."""

    def __init__(
        self,
        path: str | Path,
        *,
        stop_event: threading.Event,
        poll_interval: float = 0.25,
    ) -> None:
        self.path = Path(path)
        self.stop_event = stop_event
        self.poll_interval = poll_interval

    def __iter__(self) -> Iterator[PacketEvent]:
        yield from _tail_json_lines(
            self.path,
            self.stop_event,
            self._normalize,
            self.poll_interval,
            source_name="Zeek",
        )

    @staticmethod
    def _normalize(record: dict[str, Any]) -> PacketEvent:
        timestamp = record.get("ts")
        if timestamp is None:
            raise ValueError("ts is required")
        return PacketEvent(
            timestamp=_zeek_timestamp(timestamp),
            source_ip=record.get("id.orig_h"),
            destination_ip=record.get("id.resp_h"),
            source_port=_int_or_none(record.get("id.orig_p")),
            destination_port=_int_or_none(record.get("id.resp_p")),
            protocol=record.get("proto"),
            packet_length=(_int_or_none(record.get("orig_bytes")) or 0)
            + (_int_or_none(record.get("resp_bytes")) or 0),
            capture_source="zeek",
            packet_id=record.get("uid"),
            raw=record,
            event_type="connection",
            duration=_float_or_none(record.get("duration")),
            source_bytes=_int_or_none(record.get("orig_bytes")),
            destination_bytes=_int_or_none(record.get("resp_bytes")),
            source_packets=_int_or_none(record.get("orig_pkts")),
            destination_packets=_int_or_none(record.get("resp_pkts")),
        )


class DualSensorLiveSource:
    """Consume Suricata and Zeek live logs concurrently as one source."""

    def __init__(
        self,
        suricata_path: str | Path,
        zeek_path: str | Path,
        *,
        stop_event: threading.Event,
    ) -> None:
        self.suricata_path = suricata_path
        self.zeek_path = zeek_path
        self.stop_event = stop_event

    def __iter__(self) -> Iterator[PacketEvent]:
        events: queue.Queue[PacketEvent | Exception] = queue.Queue()

        def pump(source: Iterator[PacketEvent]) -> None:
            try:
                for event in source:
                    if self.stop_event.is_set():
                        return
                    events.put(event)
            except Exception as exc:
                events.put(exc)

        threads = [
            threading.Thread(
                target=pump,
                args=(
                    iter(
                        SuricataLiveSource(
                            self.suricata_path,
                            stop_event=self.stop_event,
                        )
                    ),
                ),
                daemon=True,
            ),
            threading.Thread(
                target=pump,
                args=(
                    iter(ZeekLiveSource(self.zeek_path, stop_event=self.stop_event)),
                ),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        try:
            while not self.stop_event.is_set():
                try:
                    item = events.get(timeout=0.25)
                except queue.Empty:
                    continue
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            self.stop_event.set()
            for thread in threads:
                thread.join(timeout=2)


def _tail_json_lines(
    path: Path,
    stop_event: threading.Event,
    normalize: Any,
    poll_interval: float,
    *,
    source_name: str,
) -> Iterator[PacketEvent]:
    """Tail a rotating JSONL sensor log, starting at its current end."""
    handle: Any = None
    identity: tuple[int, int] | None = None
    try:
        while not stop_event.is_set():
            if not path.exists():
                stop_event.wait(poll_interval)
                continue
            current_identity = (path.stat().st_dev, path.stat().st_ino)
            if handle is None or identity != current_identity:
                if handle is not None:
                    handle.close()
                handle = path.open("r", encoding="utf-8")
                handle.seek(0, 2)
                identity = current_identity
            line = handle.readline()
            if not line:
                stop_event.wait(poll_interval)
                continue
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                yield normalize(record)
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                raise ValueError(f"invalid {source_name} live record: {exc}") from exc
    finally:
        if handle is not None:
            handle.close()


def _int_or_none(value: Any) -> int | None:
    return int(value) if value is not None and value != "-" else None


def _float_or_none(value: Any) -> float | None:
    return float(value) if value is not None and value != "-" else None


def _zeek_timestamp(value: Any) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


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
