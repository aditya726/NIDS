"""Redis Streams consumer-group support for normalized sensor events."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
import time
from typing import Any

from .capture.models import PacketEvent


EventHandler = Callable[[PacketEvent], None]


class RedisEventConsumer:
    """Read normalized events and acknowledge them only after processing."""

    def __init__(
        self,
        client: object,
        handler: EventHandler,
        *,
        stream: str = "nids:raw-events",
        group: str = "nids-workers",
        consumer: str = "worker-1",
        batch_size: int = 100,
        block_ms: int = 1000,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if block_ms < 0:
            raise ValueError("block_ms must be non-negative")
        self.client = client
        self.handler = handler
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.batch_size = batch_size
        self.block_ms = block_ms
        self._ensure_group()

    def _ensure_group(self) -> None:
        try:
            self.client.xgroup_create(
                name=self.stream,
                groupname=self.group,
                id="0",
                mkstream=True,
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def consume_once(self) -> int:
        """Process one batch; failed messages remain pending for retry."""
        records = self.client.xreadgroup(
            groupname=self.group,
            consumername=self.consumer,
            streams={self.stream: ">"},
            count=self.batch_size,
            block=self.block_ms,
        )
        processed = 0
        for _, messages in records or []:
            for message_id, fields in messages:
                event = self._decode_event(fields)
                self.handler(event)
                self.client.xack(self.stream, self.group, message_id)
                processed += 1
        return processed

    def run_forever(self, stop: Callable[[], bool] | None = None) -> None:
        """Continue consuming until ``stop`` returns true."""
        should_stop = stop or (lambda: False)
        while not should_stop():
            self.consume_once()

    @staticmethod
    def _decode_event(fields: Mapping[Any, Any]) -> PacketEvent:
        payload = fields.get("event")
        if payload is None:
            payload = fields.get(b"event")
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        if not isinstance(payload, str):
            raise ValueError("Redis message is missing an event JSON payload")
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("Redis event payload is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("Redis event payload must be a JSON object")
        return PacketEvent.from_mapping(decoded)


def wait_for_redis(client: object, *, interval: float = 1.0) -> None:
    """Wait until Redis is reachable for a standalone worker startup."""
    if interval <= 0:
        raise ValueError("interval must be positive")
    while True:
        try:
            client.ping()
            return
        except Exception:
            time.sleep(interval)
