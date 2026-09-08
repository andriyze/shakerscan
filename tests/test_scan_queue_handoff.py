"""Submission handoff fixtures: no scanner or target network execution."""

from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

try:
    from scan_queue_handoff import RouteCapacityExceeded, enqueue_recorded_scan
except ModuleNotFoundError:
    from api.scan_queue_handoff import RouteCapacityExceeded, enqueue_recorded_scan

try:
    from job_queue import enqueue_job
except ModuleNotFoundError:
    from api.job_queue import enqueue_job


@pytest.mark.asyncio
@pytest.mark.parametrize("accepted", [False, True])
async def test_uncertain_queue_write_never_marks_recorded_scan_failed(accepted):
    queued = []
    redis = Mock()
    failed = AsyncMock()

    def enqueue(*args):
        if accepted:
            queued.append(args[2])
        raise TimeoutError("sensitive queue connection detail")

    with pytest.raises(HTTPException) as caught:
        await enqueue_recorded_scan(
            redis=redis, queue_name="scan_jobs", payload={"job_id": "fixture-job"},
            scan_id="fixture-scan", job_id="fixture-job", target="fixture.invalid",
            enqueue=enqueue, mark_failed=failed, capacity_http_error=Mock(),
        )
    assert caught.value.status_code == 503
    assert caught.value.detail["error"] == "scan_queue_outcome_unknown"
    assert caught.value.detail["scan_id"] == "fixture-scan"
    assert "sensitive" not in str(caught.value.detail)
    assert len(queued) == int(accepted)
    failed.assert_not_awaited()
    redis.hset.assert_not_called()


@pytest.mark.asyncio
async def test_capacity_rejection_is_definitive():
    failed = AsyncMock()
    error = HTTPException(status_code=429, detail="capacity")
    with pytest.raises(HTTPException) as caught:
        await enqueue_recorded_scan(
            redis=Mock(), queue_name="scan_jobs", payload={}, scan_id="fixture-scan",
            job_id="fixture-job", target="fixture.invalid",
            enqueue=Mock(side_effect=RouteCapacityExceeded("scan_jobs", 1)),
            mark_failed=failed, capacity_http_error=lambda exc: error,
            command_result_id="fixture-command",
        )
    assert caught.value is error
    failed.assert_awaited_once()
    assert failed.call_args.args[0] == "fixture-scan"
    assert failed.call_args.args[2] == "fixture-command"


@pytest.mark.asyncio
async def test_real_enqueue_path_retains_accepted_message_after_lost_ack():
    class LostAcknowledgement:
        def __init__(self):
            self.messages = []

        def xreadgroup(self, *args, **kwargs):
            raise AssertionError("submission must not consume jobs")

        def xgroup_create(self, *args, **kwargs):
            return True

        def xadd(self, name, fields):
            self.messages.append((name, fields))
            raise TimeoutError("accepted write acknowledgement lost")

    redis = LostAcknowledgement()
    failed = AsyncMock()
    with pytest.raises(HTTPException) as caught:
        await enqueue_recorded_scan(
            redis=redis, queue_name="scan_jobs", payload={"scan_id": "fixture-scan"},
            scan_id="fixture-scan", job_id="fixture-job", target="fixture.invalid",
            enqueue=enqueue_job, mark_failed=failed, capacity_http_error=Mock(),
        )
    assert caught.value.detail["error"] == "scan_queue_outcome_unknown"
    assert len(redis.messages) == 1
    failed.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata_failure", [False, True])
async def test_accepted_queue_write_survives_metadata_failure(metadata_failure):
    redis = Mock()
    if metadata_failure:
        redis.hset.side_effect = TimeoutError("metadata acknowledgement lost")
    enqueue = Mock(return_value="1-0")
    failed = AsyncMock()
    await enqueue_recorded_scan(
        redis=redis, queue_name="scan_jobs", payload={}, scan_id="fixture-scan",
        job_id="fixture-job", target="fixture.invalid", enqueue=enqueue,
        mark_failed=failed, capacity_http_error=Mock(),
    )
    enqueue.assert_called_once()
    redis.hset.assert_called_once()
    failed.assert_not_awaited()
