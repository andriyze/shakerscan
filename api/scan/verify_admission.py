"""Admission of a verify Scan: only checks the intelligence in force names, only on an active
template Scan. Manifest binding and execution rules live in ``verify_templates``."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Callable, Mapping, Sequence

from .verify_templates import VerifyTemplatesError, normalized_verify_template_ids

_TEMPLATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


def snapshot_check_ids(snapshot: Mapping[str, Any]) -> frozenset[str]:
    """Template ids the intelligence snapshot in force names as checks for some CVE."""
    ids: set[str] = set()
    for record in snapshot.get("advisories") or ():
        if not isinstance(record, Mapping):
            continue
        for check in list(record.get("checks") or ())[:5]:
            if isinstance(check, Mapping) and check.get("kind") == "nuclei_template":
                value = str(check.get("id") or "").strip().lower()
                if _TEMPLATE_ID.fullmatch(value):
                    ids.add(value)
    return frozenset(ids)


_CHECK_IDS: dict[str, frozenset[str]] = {}


def _check_ids_in_force(load_snapshot: Callable[[], Mapping[str, Any]]) -> frozenset[str]:
    snapshot = load_snapshot()
    key = str(snapshot.get("snapshot_sha256") or "")
    cached = _CHECK_IDS.get(key)
    if cached is None:
        cached = snapshot_check_ids(snapshot) if snapshot.get("status") == "available" else frozenset()
        _CHECK_IDS.clear()
        _CHECK_IDS[key] = cached
    return cached


def _load_snapshot() -> Mapping[str, Any]:
    try:
        from exposure.service_intel import load_service_intelligence
    except ModuleNotFoundError:  # package import
        from ..exposure.service_intel import load_service_intelligence
    return load_service_intelligence()[0]


async def admit_verify_templates(
    values: Any, execution_plan: Any, *,
    load_snapshot: Callable[[], Mapping[str, Any]] = _load_snapshot,
) -> dict[str, Any]:
    """Options for an admitted verify request, or ``{}`` when none was asked for.

    Raises ``fastapi.HTTPException`` 422 with a reason the client can act on.
    """
    from fastapi import HTTPException

    try:
        ids = normalized_verify_template_ids(values)
    except VerifyTemplatesError as exc:
        raise HTTPException(status_code=422, detail={"error": "verify_templates_invalid", "message": str(exc)}) from exc
    if not ids:
        return {}
    policy = execution_plan.policy
    families = set(execution_plan.resolved_families or policy.include_families)
    if not policy.active_testing or "nuclei_active" not in families or "nuclei_active" in set(policy.exclude_families):
        raise HTTPException(status_code=422, detail={
            "error": "verify_templates_need_active_templates",
            "message": "verify_templates runs active checks: set policy.active_testing=true and include the nuclei_active family.",
        })
    known = await asyncio.to_thread(_check_ids_in_force, load_snapshot)
    unknown = [item for item in ids if item not in known]
    if unknown:
        raise HTTPException(status_code=422, detail={
            "error": "verify_templates_not_a_known_check",
            "message": "Only checks the vulnerability intelligence in force names for a CVE can be verified.",
            "template_ids": unknown,
        })
    return {"verify_templates": list(ids)}


def compile_scan_template_manifest(*, scan_id: str, policy: Any, target_binding_digest: str,
                                   verify_template_ids: Sequence[str] = (), builder: Callable[..., Any]) -> Any:
    """Freeze passive templates and the active pack allowed by policy (or the verify set)."""
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    passive_enabled = "nuclei_passive" in include and "nuclei_passive" not in exclude
    active_enabled = "nuclei_active" in include and "nuclei_active" not in exclude
    if not passive_enabled and not active_enabled:
        return None
    return builder(
        scan_id=scan_id, target_binding_digest=target_binding_digest,
        include_active=policy.active_testing and active_enabled,
        verify_template_ids=tuple(verify_template_ids or ()),
    )
