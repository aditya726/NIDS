"""Automatic Layer 1-3 capture, normalization, persistence, and queueing."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
import threading
from typing import Any

from .capture.ingest import PacketIngestor
from .capture.models import PacketEvent
from .capture.sources import (
    JsonlReplaySource,
    PcapReplaySource,
    ScapyLiveSource,
    SuricataEveSource,
    SuricataLiveSource,
    DualSensorLiveSource,
    ZeekLiveSource,
)
from .capture.storage import EventSink, JsonlEventStore, RedisStreamSink
from .config import Settings


@dataclass
class PipelineStatus:
    running: bool = False
    source_mode: str = "none"
    processed_events: int = 0
    last_event: PacketEvent | None = None
    error: str | None = None
    broker: str = "not-configured"

    def as_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "source_mode": self.source_mode,
            "processed_events": self.processed_events,
            "last_event": self.last_event.to_dict() if self.last_event else None,
            "error": self.error,
            "broker": self.broker,
        }


class CapturePipeline:
    """Own the background worker that makes capture automatic for the API."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_environment()
        self.status = PipelineStatus()
        self._task: asyncio.Task[None] | None = None
        self._stop_event = threading.Event()

    async def start(
        self,
        *,
        mode: str | None = None,
        path: str | None = None,
        interface: str | None = None,
        zeek_path: str | None = None,
    ) -> dict[str, Any]:
        if self._task and not self._task.done():
            return self.status.as_dict()
        selected_mode = (mode or self.settings.source_mode).lower()
        selected_path = path or (
            str(self.settings.source_path) if self.settings.source_path else None
        )
        selected_interface = interface or self.settings.interface
        source = self._build_source(
            selected_mode,
            selected_path,
            selected_interface,
            zeek_path
            or (str(self.settings.zeek_path) if self.settings.zeek_path else None),
        )
        self._stop_event.clear()
        self.status = PipelineStatus(
            running=True,
            source_mode=selected_mode,
            broker="redis" if self.settings.redis_url else "local-only",
        )
        self._task = asyncio.create_task(self._run(source))
        return self.status.as_dict()

    async def stop(self) -> dict[str, Any]:
        if self._task and not self._task.done():
            self._stop_event.set()
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self.status.running = False
        return self.status.as_dict()

    async def switch(
        self,
        *,
        mode: str,
        path: str | None = None,
        interface: str | None = None,
        zeek_path: str | None = None,
    ) -> dict[str, Any]:
        """Stop the active source and start a different source."""
        await self.stop()
        return await self.start(
            mode=mode,
            path=path,
            interface=interface,
            zeek_path=zeek_path,
        )

    async def wait(self) -> None:
        if self._task:
            await self._task

    def _build_source(
        self,
        mode: str,
        path: str | None,
        interface: str | None,
        zeek_path: str | None = None,
    ) -> Iterator[PacketEvent]:
        if mode in {"jsonl", "replay"}:
            if not path:
                raise ValueError("path is required for jsonl replay")
            return iter(JsonlReplaySource(path))
        if mode == "pcap":
            if not path:
                raise ValueError("path is required for PCAP replay")
            return iter(PcapReplaySource(path))
        if mode in {"suricata", "eve"}:
            if not path:
                raise ValueError("path is required for Suricata EVE input")
            return iter(SuricataEveSource(path))
        if mode == "suricata_live":
            return iter(
                SuricataLiveSource(
                    path or self.settings.suricata_live_path,
                    stop_event=self._stop_event,
                )
            )
        if mode == "zeek_live":
            return iter(
                ZeekLiveSource(
                    path or self.settings.zeek_live_path,
                    stop_event=self._stop_event,
                )
            )
        if mode in {"sensors", "suricata_zeek"}:
            return iter(
                DualSensorLiveSource(
                    path or self.settings.suricata_live_path,
                    zeek_path or self.settings.zeek_live_path,
                    stop_event=self._stop_event,
                )
            )
        if mode == "live":
            if not interface:
                raise ValueError("interface is required for live capture")
            return iter(
                ScapyLiveSource(
                    interface,
                    packet_filter=self.settings.packet_filter,
                    stop_event=self._stop_event,
                )
            )
        raise ValueError(f"unsupported source mode: {mode}")

    async def _run(self, source: Iterator[PacketEvent]) -> None:
        try:
            sinks: list[EventSink] = [JsonlEventStore(self.settings.history_path)]
            if self.settings.redis_url:
                try:
                    import redis

                    client = redis.Redis.from_url(self.settings.redis_url)
                    client.ping()
                    sinks.append(RedisStreamSink(client, self.settings.redis_stream))
                except Exception as exc:
                    self.status.broker = "unavailable"
                    self.status.error = (
                        f"Redis unavailable; continuing with local history: {exc}"
                    )
            ingestor = PacketIngestor(sinks)
            await asyncio.to_thread(self._consume, source, ingestor)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.status.error = str(exc)
        finally:
            self.status.running = False

    def _consume(self, source: Iterator[PacketEvent], ingestor: PacketIngestor) -> None:
        for event in source:
            if self._stop_event.is_set():
                break
            ingestor.ingest([event])
            self.status.processed_events += 1
            self.status.last_event = event
