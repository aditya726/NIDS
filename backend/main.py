"""FastAPI entry point for the NIDS capture and ingestion service."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .capture.sources import ScapyLiveSource
from .capture.storage import JsonlEventStore
from .service import CapturePipeline


class CaptureStartRequest(BaseModel):
    mode: str | None = None
    path: str | None = None
    interface: str | None = None


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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/capture/status")
async def capture_status() -> dict[str, Any]:
    return pipeline.status.as_dict()


@app.get("/capture/events")
async def capture_events(offset: int = 0, limit: int = 100) -> dict[str, Any]:
    """Return a page of all locally persisted captured events."""
    if limit > 1000:
        raise HTTPException(status_code=400, detail="limit cannot exceed 1000")
    try:
        events, total = JsonlEventStore(pipeline.settings.history_path).read(
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "offset": offset,
        "limit": limit,
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
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
