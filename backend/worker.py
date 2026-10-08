"""Standalone Redis consumer entry point.

Run with:
    python -m backend.worker
"""

from __future__ import annotations

import logging
import os

from .capture.models import PacketEvent
from .redis_consumer import RedisEventConsumer

logging.basicConfig(level=os.getenv("NIDS_LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


def handle_event(event: PacketEvent) -> None:
    """Temporary processing boundary for the future ML detection worker."""
    logger.info(
        "received event_id=%s source=%s correlation_key=%s",
        event.event_id,
        event.event_source,
        event.correlation_key,
    )


def main() -> None:
    import redis

    client = redis.Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    consumer = RedisEventConsumer(
        client,
        handle_event,
        stream=os.getenv("NIDS_REDIS_STREAM", "nids:raw-events"),
        group=os.getenv("NIDS_REDIS_GROUP", "nids-workers"),
        consumer=os.getenv("NIDS_REDIS_CONSUMER", "worker-1"),
    )
    consumer.run_forever()


if __name__ == "__main__":
    main()
