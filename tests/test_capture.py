import json
import asyncio
from pathlib import Path

import pytest

from backend.capture.ingest import PacketIngestor
from backend.capture.models import PacketEvent
from backend.capture.sources import JsonlReplaySource, SuricataEveSource
from backend.capture.storage import JsonlEventStore, RedisStreamSink
from backend.config import Settings
from backend.service import CapturePipeline
from backend.main import app


def event(**overrides):
    values = {
        "timestamp": "2026-10-02T06:53:24+00:00",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "source_port": 54321,
        "destination_port": 22,
        "protocol": "TCP",
        "packet_length": 128,
        "capture_source": "test",
    }
    values.update(overrides)
    return PacketEvent(**values)


def test_ingestor_persists_every_event(tmp_path: Path):
    history = tmp_path / "events.jsonl"
    ingestor = PacketIngestor([JsonlEventStore(history)])

    assert ingestor.ingest([event(), event(packet_id="second")]) == 2
    replayed = list(JsonlReplaySource(history))

    assert replayed == [event(), event(packet_id="second")]


def test_event_store_reads_paginated_history(tmp_path: Path):
    history = JsonlEventStore(tmp_path / "events.jsonl")
    history.write(event(packet_id="one"))
    history.write(event(packet_id="two"))

    events, total = history.read(offset=1, limit=1)

    assert total == 2
    assert [item.packet_id for item in events] == ["two"]


def test_replay_rejects_malformed_record(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text('{"packet_length": "not-an-int"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid event"):
        list(JsonlReplaySource(source))


def test_suricata_eve_source_normalizes_flow(tmp_path: Path):
    source = tmp_path / "eve.json"
    source.write_text(
        json.dumps(
            {
                "timestamp": "2026-10-02T06:53:24.000000+0000",
                "event_type": "flow",
                "flow_id": 42,
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "src_port": 40000,
                "dest_port": 443,
                "proto": "TCP",
                "packet_length": 512,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    [normalized] = list(SuricataEveSource(source))
    assert normalized.capture_source == "suricata"
    assert normalized.packet_id == 42
    assert normalized.destination_port == 443


def test_redis_sink_publishes_serialized_event():
    class FakeRedis:
        def __init__(self):
            self.calls = []

        def xadd(self, stream, values):
            self.calls.append((stream, values))

    client = FakeRedis()
    RedisStreamSink(client).write(event())

    assert client.calls[0][0] == "nids:raw-events"
    assert json.loads(client.calls[0][1]["event"])["source_ip"] == "192.168.1.10"


def test_ingestor_rejects_non_events():
    with pytest.raises(TypeError):
        PacketIngestor().ingest([{"source_ip": "bad"}])


def test_pipeline_builds_jsonl_source(tmp_path: Path):
    source_path = tmp_path / "events.jsonl"
    source_path.write_text(event().to_json() + "\n", encoding="utf-8")
    pipeline = CapturePipeline(Settings(history_path=tmp_path / "history.jsonl"))

    source = pipeline._build_source("jsonl", str(source_path), None)

    assert list(source) == [event()]


def test_pipeline_switches_from_one_source_to_another(tmp_path: Path):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_text(event(packet_id="first").to_json() + "\n", encoding="utf-8")
    second.write_text(event(packet_id="second").to_json() + "\n", encoding="utf-8")
    pipeline = CapturePipeline(Settings(history_path=tmp_path / "history.jsonl"))

    async def run():
        await pipeline.start(mode="jsonl", path=str(first))
        await pipeline.wait()
        await pipeline.switch(mode="jsonl", path=str(second))
        await pipeline.wait()
        return pipeline.status.as_dict()

    status = asyncio.run(run())

    assert status["source_mode"] == "jsonl"
    assert status["processed_events"] == 1
    assert status["last_event"]["packet_id"] == "second"


def test_api_exposes_capture_control_routes():
    routes = {route.path for route in app.routes}

    assert "/capture/interfaces" in routes
    assert "/capture/start" in routes
    assert "/capture/switch" in routes


def test_pipeline_keeps_local_ingestion_when_redis_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    class UnavailableRedis:
        @classmethod
        def from_url(cls, _: str):
            raise ConnectionError("connection refused")

    import sys
    import types

    monkeypatch.setitem(
        sys.modules,
        "redis",
        types.SimpleNamespace(Redis=UnavailableRedis),
    )
    source_path = tmp_path / "events.jsonl"
    source_path.write_text(event().to_json() + "\n", encoding="utf-8")
    pipeline = CapturePipeline(
        Settings(
            redis_url="redis://localhost:6379/0",
            history_path=tmp_path / "history.jsonl",
        )
    )

    async def run():
        await pipeline.start(mode="jsonl", path=str(source_path))
        await pipeline.wait()

    asyncio.run(run())

    assert pipeline.status.broker == "unavailable"
    assert pipeline.status.processed_events == 1
    assert pipeline.status.error is not None
    assert (tmp_path / "history.jsonl").exists()
