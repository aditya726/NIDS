"""Standalone Redis agent worker.

Run with:
    python -m backend.agent_worker
"""

from __future__ import annotations

import logging
import os

from .agentic.graph import AgenticInvestigator
from .agentic.queue import AgentJob
from .config import Settings

logging.basicConfig(level=os.getenv("NIDS_LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


def main() -> None:
    import redis

    settings = Settings.from_environment()
    investigator = AgenticInvestigator(
        settings.incidents_path,
        enabled=settings.agentic_enabled,
        model=settings.agentic_model,
        ollama_url=settings.ollama_url,
        alert_path=settings.alerts_path,
    )
    client = redis.Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    stream = os.getenv("NIDS_AGENT_STREAM", "nids:agent-jobs")
    group = os.getenv("NIDS_AGENT_GROUP", "nids-agent-workers")
    consumer = os.getenv("NIDS_AGENT_CONSUMER", "agent-1")
    try:
        client.xgroup_create(name=stream, groupname=group, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    logger.info("agent worker listening on %s", stream)
    while True:
        records = client.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: ">"},
            count=10,
            block=1000,
        )
        for _, messages in records or []:
            for message_id, fields in messages:
                payload = fields.get(b"job") or fields.get("job")
                if isinstance(payload, bytes):
                    payload = payload.decode("utf-8")
                if not isinstance(payload, str):
                    raise ValueError("agent Redis message is missing job payload")
                job = AgentJob.from_json(payload)
                incident = investigator.investigate(
                    job.event, job.alert, job.flow_features
                )
                if incident is not None:
                    logger.info(
                        "created incident_id=%s severity=%s",
                        incident.incident_id,
                        incident.severity,
                    )
                client.xack(stream, group, message_id)


if __name__ == "__main__":
    main()
