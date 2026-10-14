"""Asynchronous agent job dispatch with a local worker and Redis-compatible jobs."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
import json
from threading import Lock
from typing import Any, Callable

from .graph import AgenticInvestigator


@dataclass(frozen=True, slots=True)
class AgentJob:
    event: dict[str, Any]
    alert: dict[str, Any]
    flow_features: dict[str, float]

    def to_json(self) -> str:
        return json.dumps(
            {
                "event": self.event,
                "alert": self.alert,
                "flow_features": self.flow_features,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, value: str) -> "AgentJob":
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ValueError("agent job must be a JSON object")
        return cls(
            event=dict(decoded["event"]),
            alert=dict(decoded["alert"]),
            flow_features={
                str(key): float(item)
                for key, item in dict(decoded["flow_features"]).items()
            },
        )


class AsyncAgentDispatcher:
    """Run investigations away from capture/ML threads with bounded concurrency."""

    def __init__(
        self,
        investigator: AgenticInvestigator,
        *,
        max_workers: int = 1,
        max_in_flight: int = 100,
        on_complete: Callable[[Any], None] | None = None,
    ) -> None:
        self.investigator = investigator
        self.max_in_flight = max_in_flight
        self.on_complete = on_complete
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="nids-agent",
        )
        self._futures: set[Future[Any]] = set()
        self._lock = Lock()
        self.submitted = 0
        self.completed = 0
        self.failed = 0
        self.dropped = 0

    @property
    def status(self) -> dict[str, int]:
        with self._lock:
            self._futures = {future for future in self._futures if not future.done()}
            return {
                "queued": len(self._futures),
                "submitted": self.submitted,
                "completed": self.completed,
                "failed": self.failed,
                "dropped": self.dropped,
            }

    def submit(self, job: AgentJob) -> bool:
        with self._lock:
            self._futures = {future for future in self._futures if not future.done()}
            if len(self._futures) >= self.max_in_flight:
                self.dropped += 1
                return False
            future = self._executor.submit(self._run, job)
            self._futures.add(future)
            self.submitted += 1
            future.add_done_callback(self._finished)
            return True

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _run(self, job: AgentJob) -> Any:
        return self.investigator.investigate(
            job.event, job.alert, job.flow_features
        )

    def _finished(self, future: Future[Any]) -> None:
        try:
            incident = future.result()
            with self._lock:
                self.completed += 1
            if incident is not None and self.on_complete:
                self.on_complete(incident)
        except Exception:
            with self._lock:
                self.failed += 1
