"""Standalone Redis consumer entry point.

Run with:
    python -m backend.worker
"""

from __future__ import annotations

import logging
import os

from .capture.models import PacketEvent
from .config import Settings
from .detection.engine import DetectionEngine
from .detection.storage import AlertStore
from .redis_consumer import RedisEventConsumer

logging.basicConfig(level=os.getenv("NIDS_LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


settings = Settings.from_environment()
detector = DetectionEngine(
    settings.ml_artifact_dir,
    sample_path=settings.ml_sample_path,
    auto_train=settings.ml_auto_train,
)
alert_store = AlertStore(settings.alerts_path)


def handle_event(event: PacketEvent) -> None:
    """Score a Redis event and persist the resulting Layer 4 alert."""
    alert = detector.score(event)
    alert_store.write(alert)
    logger.info(
        "scored event_id=%s source=%s severity=%s risk=%.3f",
        event.event_id,
        event.event_source,
        alert.severity,
        alert.risk_score,
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
