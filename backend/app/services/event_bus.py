import json
import logging
from datetime import datetime, timezone

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)
_redis_client: redis.Redis | None = None


def _get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def publish_event(payload: dict) -> None:
    encoded = json.dumps(payload)
    try:
        _get_redis_client().publish(settings.event_channel, encoded)
    except Exception:
        logger.exception("event_bus_publish_failed payload=%s", encoded)

    logger.info("event_bus=%s", encoded)


def publish_scan_completed_event(*, tenant_id: str, scan_run_id: str, target_url: str, findings_count: int) -> None:
    payload = {
        "event_type": "scan.completed",
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
        "target_url": target_url,
        "findings_count": findings_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    publish_event(payload)


def publish_incident_created_event(*, tenant_id: str, incident_id: str, actor_id: str, honeytoken_id: str) -> None:
    payload = {
        "event_type": "incident.created",
        "tenant_id": tenant_id,
        "incident_id": incident_id,
        "actor_id": actor_id,
        "honeytoken_id": honeytoken_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    publish_event(payload)
