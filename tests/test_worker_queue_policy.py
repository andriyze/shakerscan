import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from worker_queue_policy import base_worker_queue_keys  # noqa: E402


QUEUES = {
    "scan_queue": "scan_jobs",
    "retest_queue": "retest_jobs",
    "broker_queue": "broker_ingest_jobs",
    "device_queue": "device_scan_jobs",
    "agent_tool_queue": "agent_tool_jobs",
}


def test_web_dast_workers_never_consume_agent_scanner_jobs():
    queues = base_worker_queue_keys(
        device_only=False,
        agent_tool_only=False,
        device_queue_enabled=False,
        **QUEUES,
    )

    assert queues == ["scan_jobs", "retest_jobs", "broker_ingest_jobs"]
    assert "agent_tool_jobs" not in queues


def test_agent_tool_worker_consumes_only_its_dedicated_queue():
    assert base_worker_queue_keys(
        device_only=False,
        agent_tool_only=True,
        device_queue_enabled=True,
        **QUEUES,
    ) == ["agent_tool_jobs"]


def test_device_worker_and_optional_device_fallback_do_not_gain_agent_queue():
    assert base_worker_queue_keys(
        device_only=True,
        agent_tool_only=False,
        device_queue_enabled=True,
        **QUEUES,
    ) == ["device_scan_jobs"]
    assert base_worker_queue_keys(
        device_only=False,
        agent_tool_only=False,
        device_queue_enabled=True,
        **QUEUES,
    ) == ["scan_jobs", "retest_jobs", "broker_ingest_jobs", "device_scan_jobs"]


def test_worker_roles_are_mutually_exclusive():
    with pytest.raises(ValueError):
        base_worker_queue_keys(
            device_only=True,
            agent_tool_only=True,
            device_queue_enabled=False,
            **QUEUES,
        )
