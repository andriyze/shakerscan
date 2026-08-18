"""Pure queue-selection policy for isolated ShakerScan worker roles."""

from __future__ import annotations


def worker_role(*, device_only: bool, agent_tool_only: bool) -> tuple[str, str]:
    """Return the public worker kind and its isolated build registry key."""
    if device_only and agent_tool_only:
        raise ValueError("a worker cannot be both device-only and agent-tool-only")
    if device_only:
        return "device", "shakerscan:device_worker_build"
    if agent_tool_only:
        return "agent_tool", "shakerscan:agent_tool_worker_build"
    return "web_dast", "shakerscan:worker_build"


def base_worker_queue_keys(
    *,
    device_only: bool,
    agent_tool_only: bool,
    device_queue_enabled: bool,
    scan_queue: str,
    retest_queue: str,
    broker_queue: str,
    device_queue: str,
    agent_tool_queue: str,
) -> list[str]:
    """Return the queues one worker role is allowed to consume.

    External agent scanners are intentionally isolated from ordinary Web DAST
    workers.  A dedicated agent-tool worker is mandatory for that queue.
    """
    worker_role(device_only=device_only, agent_tool_only=agent_tool_only)
    if device_only:
        selected = [device_queue]
    elif agent_tool_only:
        selected = [agent_tool_queue]
    else:
        selected = [scan_queue, retest_queue, broker_queue]
        if device_queue_enabled:
            selected.append(device_queue)
    return list(dict.fromkeys(selected))
