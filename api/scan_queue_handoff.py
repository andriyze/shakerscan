"""Preserve recorded Scan uncertainty when queue acknowledgement is lost."""

import logging

from fastapi import HTTPException
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

try:
    from job_queue import RouteCapacityExceeded
except ModuleNotFoundError:
    from api.job_queue import RouteCapacityExceeded


async def enqueue_recorded_scan(
    *, redis, queue_name, payload, scan_id, job_id, target,
    enqueue, mark_failed, capacity_http_error, command_result_id=None,
):
    try:
        enqueue(redis, queue_name, payload)
    except RouteCapacityExceeded as exc:
        # The queue's capacity rejection occurs before insertion, unlike a
        # transport error which can follow an accepted Redis write.
        await mark_failed(
            scan_id,
            "Scan was not queued because the fleet placement-route registry is at capacity.",
            command_result_id,
        )
        raise capacity_http_error(exc) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail={
            "error": "scan_queue_outcome_unknown",
            "scan_id": scan_id,
            "message": "The scan was recorded, but queue acceptance is uncertain. "
                       "Check this scan; do not submit a replacement.",
        }) from exc
    # This informational hash is not queue acceptance authority. Failure here
    # must not report the already accepted job as a rejected submission.
    try:
        redis.hset(f"job:{job_id}", mapping={"status": "queued", "target": target})
    except (RedisError, OSError):
        logger.warning("Queue accepted a recorded Scan but its informational job hash was not saved")
