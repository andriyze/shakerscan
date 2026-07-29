"""Safe retention planning/execution for content-addressed model quarantine."""

from __future__ import annotations

import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _objects(root: Path) -> list[dict[str, Any]]:
    resolved_root = root.resolve()
    sha_root = resolved_root / "sha256"
    if not sha_root.exists():
        return []
    objects = []
    for prefix in sha_root.iterdir():
        if prefix.is_symlink() or not prefix.is_dir() or not re.fullmatch(r"[0-9a-f]{2}", prefix.name):
            continue
        for path in prefix.iterdir():
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                continue
            digest = path.name.lower()
            if not SHA256_RE.fullmatch(digest) or digest[:2] != prefix.name:
                continue
            if resolved_root not in path.resolve().parents:
                continue
            objects.append({
                "digest": digest,
                "path": str(path),
                "size_bytes": metadata.st_size,
                "modified_at": datetime.fromtimestamp(metadata.st_mtime, timezone.utc),
            })
    return objects


def plan_cleanup(
    root: Path,
    *,
    protected_digests: set[str] | None = None,
    retention_days: int = 30,
    max_total_bytes: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    protected = {str(item).removeprefix("sha256:").lower() for item in (protected_digests or set())}
    current = now or datetime.now(timezone.utc)
    retention_days = max(1, min(int(retention_days), 3650))
    objects = _objects(root)
    total_bytes = sum(item["size_bytes"] for item in objects)
    candidates: dict[str, dict[str, Any]] = {}
    for item in objects:
        age_days = max(0, (current - item["modified_at"]).days)
        if item["digest"] not in protected and age_days >= retention_days:
            candidates[item["digest"]] = {**item, "age_days": age_days, "reason": "retention_expired"}
    projected = total_bytes - sum(item["size_bytes"] for item in candidates.values())
    if max_total_bytes is not None:
        quota = max(0, int(max_total_bytes))
        for item in sorted(objects, key=lambda value: (value["modified_at"], value["digest"])):
            if projected <= quota:
                break
            if item["digest"] in protected or item["digest"] in candidates:
                continue
            age_days = max(0, (current - item["modified_at"]).days)
            candidates[item["digest"]] = {**item, "age_days": age_days, "reason": "quota_eviction"}
            projected -= item["size_bytes"]
    public_candidates = [
        {key: value for key, value in item.items() if key != "path"}
        for item in sorted(candidates.values(), key=lambda value: (value["modified_at"], value["digest"]))
    ]
    for item in public_candidates:
        item["modified_at"] = item["modified_at"].isoformat()
    return {
        "schema_version": "model-intake-retention/v1",
        "root": str(root.resolve()),
        "objects": len(objects),
        "total_bytes": total_bytes,
        "protected_objects": sum(1 for item in objects if item["digest"] in protected),
        "candidate_count": len(public_candidates),
        "candidate_bytes": sum(item["size_bytes"] for item in public_candidates),
        "projected_bytes": projected,
        "retention_days": retention_days,
        "max_total_bytes": max_total_bytes,
        "candidates": public_candidates,
    }


def execute_cleanup(root: Path, plan: dict[str, Any]) -> dict[str, Any]:
    resolved_root = root.resolve()
    if str(resolved_root) != str(plan.get("root") or ""):
        raise ValueError("cleanup plan root does not match configured quarantine root")
    deleted = []
    skipped = []
    for item in plan.get("candidates", []):
        digest = str(item.get("digest") or "").lower()
        if not SHA256_RE.fullmatch(digest):
            skipped.append({"digest": digest, "reason": "invalid_digest"})
            continue
        path = resolved_root / "sha256" / digest[:2] / digest
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("candidate is not a regular file")
            if resolved_root not in path.resolve().parents:
                raise ValueError("candidate escaped quarantine root")
            if metadata.st_size != int(item.get("size_bytes") or -1):
                raise ValueError("candidate changed after preview")
            os.unlink(path)
            deleted.append({"digest": digest, "size_bytes": metadata.st_size})
            try:
                path.parent.rmdir()
            except OSError:
                pass
        except (FileNotFoundError, ValueError, OSError) as exc:
            skipped.append({"digest": digest, "reason": f"{type(exc).__name__}: {exc}"})
    return {
        "deleted_count": len(deleted),
        "deleted_bytes": sum(item["size_bytes"] for item in deleted),
        "deleted": deleted,
        "skipped": skipped,
    }


__all__ = ["execute_cleanup", "plan_cleanup"]
