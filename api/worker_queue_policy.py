"""Pure queue-selection policy for isolated ShakerScan worker roles."""

from __future__ import annotations

import asyncio
from collections.abc import Callable


async def heartbeat_worker_build_report(
    reporter: Callable[[], None], *, interval_seconds: float,
) -> None:
    """Refresh identity independently of queue work so busy workers do not age out."""
    while True:
        await asyncio.sleep(interval_seconds)
        await asyncio.to_thread(reporter)


async def finish_cancelled_task(task: asyncio.Task[object]) -> None:
    """Join a background task after its owner has requested cancellation."""
    try:
        await task
    except asyncio.CancelledError:
        pass


def worker_role(
    *, device_only: bool, agent_tool_only: bool, model_intake_only: bool = False
) -> tuple[str, str]:
    """Return the public worker kind and its isolated build registry key."""
    if sum((bool(device_only), bool(agent_tool_only), bool(model_intake_only))) > 1:
        raise ValueError("a worker may hold at most one dedicated role")
    if device_only:
        return "device", "shakerscan:device_worker_build"
    if agent_tool_only:
        return "agent_tool", "shakerscan:agent_tool_worker_build"
    if model_intake_only:
        return "model_intake", MODEL_INTAKE_WORKER_BUILD_REGISTRY_KEY
    return "web_dast", "shakerscan:worker_build"


# The Model Intake worker's toolchain, by the path the dedicated image installs it at. The worker
# reports which of these resolve so the control plane can tell "a Model Intake worker registered"
# from "a Model Intake worker that can actually scan an artifact" -- a worker started from the
# plain scanner image registers too, but every path below is missing there.
MODEL_INTAKE_WORKER_TOOL_COMMANDS: dict[str, str] = {
    "trivy": "/opt/tools/trivy",
    "osv-scanner": "/opt/tools/osv-scanner",
    "semgrep": "/opt/tools/semgrep",
    "modelscan": "/opt/tools/modelscan",
    "fickling": "/opt/tools/fickling",
    "pip-audit-offline": "/opt/tools/pip-audit-offline",
}
MODEL_INTAKE_WORKER_REQUIRED_TOOLS = frozenset(MODEL_INTAKE_WORKER_TOOL_COMMANDS)


def worker_tool_commands(default: dict[str, str], *, model_intake_only: bool) -> dict[str, str]:
    """The tool->command table one worker role reports from; the Model Intake role adds its
    toolchain paths so readiness can require them, not just registration."""
    commands = dict(default)
    if model_intake_only:
        commands.update(MODEL_INTAKE_WORKER_TOOL_COMMANDS)
    return commands
MODEL_INTAKE_WORKER_BUILD_REGISTRY_KEY = "shakerscan:model_intake_worker_build"


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
    model_intake_only: bool = False,
    model_intake_queue: str = "model_intake_jobs",
) -> list[str]:
    """Return the queues one worker role is allowed to consume.

    External agent scanners and Model Intake artifact scanners are intentionally isolated from
    ordinary Web DAST workers. Each needs its own dedicated worker: a Web DAST worker never
    consumes the agent-tool or Model Intake queue, so the toolchains those jobs require do not have
    to live in the general scanner runtime.
    """
    worker_role(
        device_only=device_only,
        agent_tool_only=agent_tool_only,
        model_intake_only=model_intake_only,
    )
    if device_only:
        selected = [device_queue]
    elif agent_tool_only:
        selected = [agent_tool_queue]
    elif model_intake_only:
        selected = [model_intake_queue]
    else:
        selected = [scan_queue, retest_queue, broker_queue]
        if device_queue_enabled:
            selected.append(device_queue)
    return list(dict.fromkeys(selected))
