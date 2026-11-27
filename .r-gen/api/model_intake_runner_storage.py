"""Disk accounting, admission, and bounded cleanup for the Firecracker runner."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
from typing import Any


GIB = 1024**3
MIB = 1024**2


def _integer(environment: dict[str, str], name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(environment.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def runner_drive_sizes(
    subject_bytes: int,
    mode: str,
    requested_output_bytes: int | None,
    environment: dict[str, str] | None = None,
) -> dict[str, int]:
    """Return the exact image sizes used by ``FirecrackerRunner``."""
    env = dict(environment or os.environ)
    input_payload = max(0, int(subject_bytes)) + MIB  # bounded job.json/filesystem overhead
    max_input = _integer(env, "MODEL_INTAKE_RUNNER_MAX_INPUT_BYTES", 128 * GIB, 64 * MIB)
    if input_payload > max_input:
        raise ValueError("runner subject exceeds the configured input quota")
    input_image = max(
        256 * MIB,
        ((input_payload * 13 // 10 + 128 * MIB + 4095) // 4096) * 4096,
    )
    default_output = 512 * MIB if mode == "runtime" else max(GIB, input_payload * 13 // 10)
    max_output = _integer(env, "MODEL_INTAKE_RUNNER_MAX_OUTPUT_BYTES", 256 * GIB, 64 * MIB)
    requested = max(int(requested_output_bytes or default_output), 64 * MIB)
    if requested > max_output:
        raise ValueError("requested runner output disk exceeds the configured output quota")
    output_image = requested
    return {
        "input_payload_bytes": input_payload,
        "input_image_bytes": input_image,
        "output_image_bytes": output_image,
        "max_input_bytes": max_input,
        "max_output_bytes": max_output,
    }


def path_size(path: Path, *, physical: bool = True) -> int:
    """Count regular files without following symlinks or crossing hidden roots.

    UI usage and cleanup receipts use allocated blocks. Admission uses logical
    bytes because copying a sparse untrusted file can materialize every zero.
    """
    try:
        if path.is_symlink():
            return 0
        if path.is_file():
            stat = path.stat()
            blocks = getattr(stat, "st_blocks", None)
            return blocks * 512 if physical and blocks is not None else stat.st_size
        if not path.is_dir():
            return 0
    except OSError:
        return 0
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        base = Path(root)
        dirs[:] = [name for name in dirs if not (base / name).is_symlink()]
        for name in files:
            candidate = base / name
            try:
                if not candidate.is_symlink() and candidate.is_file():
                    stat = candidate.stat()
                    blocks = getattr(stat, "st_blocks", None)
                    total += blocks * 512 if physical and blocks is not None else stat.st_size
            except OSError:
                continue
    return total


def _filesystem(path: Path, reserve_percent: int, reserve_floor_bytes: int) -> dict[str, int]:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    usage = shutil.disk_usage(path)
    return {
        "device": path.stat().st_dev,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "reserve_bytes": max(reserve_floor_bytes, usage.total * reserve_percent // 100),
    }


def storage_plan(
    *,
    subject_bytes: int,
    mode: str,
    requested_output_bytes: int | None,
    work_root: Path,
    conversion_root: Path,
    component_bytes: int = 0,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Conservatively admit a job before it creates any large copies."""
    env = dict(environment or os.environ)
    sizes = runner_drive_sizes(subject_bytes, mode, requested_output_bytes, env)
    reserve_percent = min(50, _integer(env, "MODEL_INTAKE_RUNNER_DISK_RESERVE_PERCENT", 10))
    reserve_floor = _integer(env, "MODEL_INTAKE_RUNNER_MIN_FREE_BYTES", 10 * GIB)
    work_fs = _filesystem(work_root, reserve_percent, reserve_floor)
    conversion_fs = _filesystem(conversion_root, reserve_percent, reserve_floor)

    # Current runner layout: one staging tree, two input images (host+jail),
    # two output images plus one extracted output tree, and jailed kernel/rootfs.
    work_peak = (
        sizes["input_payload_bytes"]
        + 2 * sizes["input_image_bytes"]
        + 3 * sizes["output_image_bytes"]
        + max(0, int(component_bytes))
        + 256 * MIB
    )
    conversion_persist = sizes["output_image_bytes"] if mode == "conversion" else 0
    same_device = work_fs["device"] == conversion_fs["device"]
    work_required = work_peak + (conversion_persist if same_device else 0)
    conversion_required = 0 if same_device else conversion_persist
    work_sufficient = work_fs["free_bytes"] - work_required >= work_fs["reserve_bytes"]
    conversion_sufficient = conversion_fs["free_bytes"] - conversion_required >= conversion_fs["reserve_bytes"]
    sufficient = work_sufficient and conversion_sufficient
    reason = None
    if not work_sufficient:
        reason = "runner scratch filesystem does not have enough free space after its safety reserve"
    elif not conversion_sufficient:
        reason = "converted-model filesystem does not have enough free space after its safety reserve"
    return {
        "subject_bytes": subject_bytes,
        "mode": mode,
        **sizes,
        "estimated_peak_scratch_bytes": work_peak,
        "estimated_persisted_conversion_bytes": conversion_persist,
        "work_filesystem": work_fs,
        "conversion_filesystem": conversion_fs,
        "same_filesystem": same_device,
        "required_work_bytes": work_required,
        "required_conversion_bytes": conversion_required,
        "sufficient": sufficient,
        "reason": reason,
    }


def _terminal_job(path: Path) -> bool:
    try:
        import json

        value = json.loads(path.read_text())
        return value.get("state") in {"completed", "failed", "cancelled"}
    except (OSError, ValueError):
        return False


def _old_enough(path: Path, age_seconds: int, now: float) -> bool:
    try:
        return now - path.stat().st_mtime >= age_seconds
    except OSError:
        return False


def cleanup_candidates(
    *,
    work_root: Path,
    job_root: Path,
    active: bool,
    force_inactive_work: bool,
    environment: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    env = dict(environment or os.environ)
    now = datetime.now(timezone.utc).timestamp()
    work_age = _integer(env, "MODEL_INTAKE_RUNNER_WORK_RETENTION_HOURS", 24) * 3600
    job_age = _integer(env, "MODEL_INTAKE_RUNNER_JOB_RETENTION_DAYS", 30) * 86400
    candidates: list[dict[str, Any]] = []
    if not active and work_root.is_dir():
        for path in work_root.iterdir():
            if (
                path.is_dir()
                and not path.is_symlink()
                and re.fullmatch(r"mi-[0-9a-f]{24}", path.name)
                and (force_inactive_work or _old_enough(path, work_age, now))
            ):
                candidates.append({"category": "scratch", "path": path, "bytes": path_size(path)})
    if job_root.is_dir():
        for path in job_root.glob("*.json"):
            if _terminal_job(path) and _old_enough(path, job_age, now):
                candidates.append({"category": "job_metadata", "path": path, "bytes": path_size(path)})
    return candidates


def cleanup_storage(candidates: list[dict[str, Any]], *, dry_run: bool) -> dict[str, Any]:
    summary: dict[str, dict[str, int]] = {}
    skipped = 0
    for item in candidates:
        path = item["path"]
        if not dry_run:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    path.unlink()
                except OSError:
                    pass
            if path.exists() or path.is_symlink():
                skipped += 1
                continue
        bucket = summary.setdefault(item["category"], {"items": 0, "bytes": 0})
        bucket["items"] += 1
        bucket["bytes"] += int(item["bytes"])
    return {
        "dry_run": dry_run,
        "items": sum(value["items"] for value in summary.values()),
        "bytes": sum(value["bytes"] for value in summary.values()),
        "categories": summary,
        "skipped_items": skipped,
    }


def storage_report(
    *,
    work_root: Path,
    job_root: Path,
    conversion_root: Path,
    active: bool,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = dict(environment or os.environ)
    reserve_percent = min(50, _integer(env, "MODEL_INTAKE_RUNNER_DISK_RESERVE_PERCENT", 10))
    reserve_floor = _integer(env, "MODEL_INTAKE_RUNNER_MIN_FREE_BYTES", 10 * GIB)
    filesystem = _filesystem(work_root, reserve_percent, reserve_floor)
    conversion_filesystem = _filesystem(conversion_root, reserve_percent, reserve_floor)
    reclaimable = cleanup_storage(
        cleanup_candidates(
            work_root=work_root,
            job_root=job_root,
            active=active,
            force_inactive_work=True,
            environment=env,
        ),
        dry_run=True,
    )
    return {
        "schema_version": "model-intake-runner-storage/v1",
        "available": True,
        "filesystem": filesystem,
        "conversion_filesystem": conversion_filesystem,
        "same_filesystem": filesystem["device"] == conversion_filesystem["device"],
        "usage": {
            "scratch_bytes": path_size(work_root),
            "job_metadata_bytes": path_size(job_root),
            "converted_models_bytes": path_size(conversion_root),
        },
        "reclaimable": reclaimable,
        "limits": {
            "max_input_bytes": _integer(env, "MODEL_INTAKE_RUNNER_MAX_INPUT_BYTES", 128 * GIB),
            "max_output_bytes": _integer(env, "MODEL_INTAKE_RUNNER_MAX_OUTPUT_BYTES", 256 * GIB),
            "reserve_percent": reserve_percent,
            "reserve_floor_bytes": reserve_floor,
        },
        "automatic_cleanup": {
            "enabled": env.get("MODEL_INTAKE_RUNNER_AUTO_CLEANUP", "true").lower() == "true",
            "scratch_retention_hours": _integer(env, "MODEL_INTAKE_RUNNER_WORK_RETENTION_HOURS", 24),
            "job_retention_days": _integer(env, "MODEL_INTAKE_RUNNER_JOB_RETENTION_DAYS", 30),
            "scope": "inactive scratch and expired terminal job metadata",
        },
        "active_job": active,
        "converted_models_auto_deleted": False,
    }
