"""Executable fixed-stage scheduler for canonical deterministic Scan.

Stage outputs remain worker-private until a caller deliberately places them in a
report.  The public history records only status, timing, adapter identity, output
keys, and canonical capability names so secrets cannot leak through orchestration
telemetry.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import re
import time
from typing import Any, Awaitable, Callable, Mapping

from ..executor import NATIVE_SCAN_STAGES, NativeScanExecution


SCAN_STAGE_EXECUTION_SCHEMA = "canonical-scan-stage-execution/v1"
STAGE_STATUSES = frozenset({
    "completed", "partial", "skipped", "failed", "cancelled",
})
_PUBLIC_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


class ScanStageExecutionError(RuntimeError):
    """The fixed graph could not complete without violating its contract."""

    def __init__(
        self,
        message: str,
        *,
        stage_name: str,
        history: tuple[dict[str, Any], ...],
    ) -> None:
        super().__init__(message)
        self.stage_name = stage_name
        self.history = history


class ScanStageCancelled(ScanStageExecutionError):
    """Cancellation stopped the graph before another stage could start."""


@dataclass(frozen=True)
class ScanStageRunResult:
    """One stage adapter result plus its private downstream output."""

    output: Mapping[str, Any] = field(default_factory=dict)
    status: str = "completed"
    reason: str | None = None
    adapter: str = "native_worker"
    capability_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in STAGE_STATUSES:
            raise ValueError("stage adapter status is invalid")
        if not isinstance(self.output, Mapping):
            raise TypeError("stage output must be a mapping")
        if self.reason is not None and not _PUBLIC_TOKEN_RE.fullmatch(
            str(self.reason)
        ):
            raise ValueError("stage reason must be a content-free token")
        if not _PUBLIC_TOKEN_RE.fullmatch(str(self.adapter)):
            raise ValueError("stage adapter must be a content-free token")
        names = tuple(str(item).strip() for item in self.capability_names)
        if (
            any(not _PUBLIC_TOKEN_RE.fullmatch(item) for item in names)
            or len(set(names)) != len(names)
        ):
            raise ValueError("stage capability names must be unique non-empty strings")
        object.__setattr__(self, "capability_names", names)


@dataclass
class ScanStageContext:
    """Worker-private state shared only across one fixed Scan graph."""

    execution: NativeScanExecution
    target_url: str
    options: Mapping[str, Any]
    scan_id: str
    job_id: str
    outputs: dict[str, Mapping[str, Any]] = field(default_factory=dict)

    def output(self, stage_name: str) -> Mapping[str, Any]:
        value = self.outputs.get(stage_name)
        if value is None:
            raise KeyError(f"Scan stage output is unavailable: {stage_name}")
        return value


ScanStageRunner = Callable[[ScanStageContext], Awaitable[ScanStageRunResult]]


def _history_digest(rows: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _elapsed_ms(started: float, finished: float) -> int:
    return max(0, int(round((finished - started) * 1_000)))


async def execute_scan_stage_graph(
    context: ScanStageContext,
    runners: Mapping[str, ScanStageRunner],
    *,
    cancel_requested: Callable[[], bool] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Execute every enabled stage exactly once in the canonical fixed order."""
    expected = set(NATIVE_SCAN_STAGES)
    unknown = set(runners) - expected
    if unknown:
        raise ValueError(
            "unknown canonical Scan stage runner(s): "
            + ", ".join(sorted(str(item) for item in unknown))
        )

    history: list[dict[str, Any]] = []
    stage_rows = context.execution.stage_rows()
    for index, stage in enumerate(stage_rows):
        name = str(stage["name"])
        enabled = bool(stage["enabled"])
        if not enabled:
            context.outputs[name] = {}
            history.append({
                "index": index,
                "name": name,
                "enabled": False,
                "status": "skipped",
                "reason": str(stage.get("reason") or "policy_disabled")[:200],
                "adapter": None,
                "capability_names": [],
                "output_keys": [],
                "elapsed_ms": 0,
            })
            continue

        if cancel_requested is not None and cancel_requested():
            row = {
                "index": index,
                "name": name,
                "enabled": True,
                "status": "cancelled",
                "reason": "scan_cancel_requested",
                "adapter": None,
                "capability_names": [],
                "output_keys": [],
                "elapsed_ms": 0,
            }
            history.append(row)
            raise ScanStageCancelled(
                f"canonical Scan cancelled before stage {name}",
                stage_name=name,
                history=tuple(history),
            )

        runner = runners.get(name)
        if runner is None:
            raise ScanStageExecutionError(
                f"enabled canonical Scan stage has no runner: {name}",
                stage_name=name,
                history=tuple(history),
            )
        started = monotonic()
        try:
            result = await runner(context)
            if not isinstance(result, ScanStageRunResult):
                raise TypeError("stage runner returned an invalid result")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            finished = monotonic()
            history.append({
                "index": index,
                "name": name,
                "enabled": True,
                "status": "failed",
                "reason": f"stage_adapter_error:{type(exc).__name__}",
                "adapter": None,
                "capability_names": [],
                "output_keys": [],
                "elapsed_ms": _elapsed_ms(started, finished),
            })
            raise ScanStageExecutionError(
                f"canonical Scan stage failed: {name}",
                stage_name=name,
                history=tuple(history),
            ) from exc
        finished = monotonic()
        private_output = dict(result.output)
        output_keys = [str(key) for key in private_output]
        if any(not _PUBLIC_TOKEN_RE.fullmatch(key) for key in output_keys):
            raise ScanStageExecutionError(
                f"canonical Scan stage emitted an invalid output key: {name}",
                stage_name=name,
                history=tuple(history),
            )
        context.outputs[name] = private_output
        history.append({
            "index": index,
            "name": name,
            "enabled": True,
            "status": result.status,
            "reason": str(result.reason) if result.reason else None,
            "adapter": str(result.adapter),
            "capability_names": list(result.capability_names),
            "output_keys": sorted(output_keys),
            "elapsed_ms": _elapsed_ms(started, finished),
        })
        if result.status == "cancelled":
            raise ScanStageCancelled(
                f"canonical Scan cancelled during stage {name}",
                stage_name=name,
                history=tuple(history),
            )
        if result.status == "failed":
            raise ScanStageExecutionError(
                f"canonical Scan stage reported failure: {name}",
                stage_name=name,
                history=tuple(history),
            )

    status = (
        "partial" if any(row["status"] == "partial" for row in history)
        else "completed"
    )
    public = {
        "schema_version": SCAN_STAGE_EXECUTION_SCHEMA,
        "status": status,
        "execution_plan_digest": context.execution.execution_plan.digest,
        "target_binding_digest": context.execution.target_binding.digest,
        "stages": history,
    }
    public["history_digest"] = _history_digest(history)
    return public
