#!/usr/bin/env python3
"""V2 worker entrypoint preserving queue/database plumbing from ``worker``.

The legacy module still owns fleet leasing, cancellation, checkpointing, evidence,
and persistence. This entrypoint replaces deterministic Scan dispatch so V2 jobs
are admitted from their immutable execution plan before any scanner process starts.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import worker as _worker
from scan.worker_dispatch import (
    execution_result_metadata,
    is_deterministic_dast,
    prepare_worker_dispatch,
)


_original_run_scan = _worker.run_scan


def _cleanup_completed_discovery_sidecar(scan_id: str | None) -> None:
    """Remove the recovery manifest after its completed result is durably returned."""
    if not scan_id:
        return
    sidecar = Path(_worker.RESULTS_DIR) / f"{scan_id}_checkpoint.json.endpoint-manifest.json"
    try:
        sidecar.unlink(missing_ok=True)
    except OSError:
        # Artifact cleanup must never replace an otherwise valid scan result.
        pass


async def run_scan_v2(
    target: str,
    options: dict,
    scan_id: str | None = None,
    job_id: str | None = None,
    progress_callback: Any = None,
    persist_checkpoint_artifacts: bool = True,
) -> dict:
    if not is_deterministic_dast(options):
        return await _original_run_scan(
            target,
            options,
            scan_id=scan_id,
            job_id=job_id,
            progress_callback=progress_callback,
            persist_checkpoint_artifacts=persist_checkpoint_artifacts,
        )

    prepared, admission = prepare_worker_dispatch(options)
    if not admission.canonical and os.getenv(
        "SHAKERSCAN_DISABLE_LEGACY_SCAN_EXECUTION", ""
    ).strip().lower() in {"1", "true", "yes", "on"}:
        raise ValueError(
            "legacy deterministic Scan execution is disabled; submit a canonical V2 plan"
        )

    result = await _original_run_scan(
        target,
        prepared,
        scan_id=scan_id,
        job_id=job_id,
        progress_callback=progress_callback,
        persist_checkpoint_artifacts=persist_checkpoint_artifacts,
    )
    metadata = execution_result_metadata(admission)
    if metadata is not None and isinstance(result, dict):
        result = dict(result)
        result["scan_execution"] = metadata
    if isinstance(result, dict):
        _cleanup_completed_discovery_sidecar(scan_id)
    return result


# All calls inside worker.py resolve this global at runtime, including shards and
# device web child scans, while non-DAST run kinds are explicitly delegated above.
_worker.run_scan = run_scan_v2


def main() -> None:
    _worker.main()


if __name__ == "__main__":
    main()
