"""FastAPI entry point for the NIDS capture and ingestion service."""

from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .capture.sources import ScapyLiveSource
from .capture.storage import JsonlEventStore
from .service import CapturePipeline


class CaptureStartRequest(BaseModel):
    mode: str | None = None
    path: str | None = None
    interface: str | None = None
    zeek_path: str | None = None


class CaptureSwitchRequest(CaptureStartRequest):
    mode: str


pipeline = CapturePipeline()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if pipeline.settings.auto_start and pipeline.settings.source_mode != "none":
        try:
            await pipeline.start()
        except ValueError as exc:
            pipeline.status.error = str(exc)
    yield
    await pipeline.stop()


app = FastAPI(
    title="NIDS Capture and Ingestion API",
    version="0.1.0",
    lifespan=lifespan,
)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "NIDS_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/capture/status")
async def capture_status() -> dict[str, Any]:
    return pipeline.status.as_dict()


@app.get("/sensors/status")
async def sensor_status() -> dict[str, Any]:
    """Report deployment-side Suricata/Zeek log readiness."""
    settings = pipeline.settings

    def describe(name: str, path: Path) -> dict[str, Any]:
        exists = path.exists()
        return {
            "name": name,
            "path": str(path),
            "available": exists,
            "size_bytes": path.stat().st_size if exists else 0,
            "updated_at": path.stat().st_mtime if exists else None,
        }

    return {
        "mode": pipeline.status.source_mode,
        "suricata": describe("suricata", settings.suricata_live_path),
        "zeek": describe("zeek", settings.zeek_live_path),
        "interface": settings.interface,
        "dual_sensor_ready": settings.suricata_live_path.exists()
        and settings.zeek_live_path.exists(),
    }


@app.get("/capture/events")
async def capture_events(
    offset: int = 0, limit: int = 100, latest: bool = False
) -> dict[str, Any]:
    """Return a page of all locally persisted captured events."""
    if limit > 1000:
        raise HTTPException(status_code=400, detail="limit cannot exceed 1000")
    try:
        store = JsonlEventStore(pipeline.settings.history_path)
        events, total = (
            store.read_latest(limit=limit)
            if latest
            else store.read(offset=offset, limit=limit)
        )
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "offset": offset,
        "limit": limit,
        "latest": latest,
        "total": total,
        "events": [event.to_dict() for event in events],
    }


@app.get("/capture/interfaces")
async def capture_interfaces() -> dict[str, list[dict[str, str]]]:
    try:
        return {"interfaces": ScapyLiveSource.interfaces()}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/capture/start")
async def start_capture(request: CaptureStartRequest) -> dict[str, Any]:
    try:
        return await pipeline.start(
            mode=request.mode,
            path=request.path,
            interface=request.interface,
            zeek_path=request.zeek_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/capture/stop")
async def stop_capture() -> dict[str, Any]:
    return await pipeline.stop()


@app.post("/capture/switch")
async def switch_capture(request: CaptureSwitchRequest) -> dict[str, Any]:
    """Switch sources without restarting FastAPI."""
    try:
        return await pipeline.switch(
            mode=request.mode,
            path=request.path,
            interface=request.interface,
            zeek_path=request.zeek_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
