"""Fail-closed reconstruction of a persisted ``scan-job/v2`` queue message.

Redis carries only the canonical, secret-free authority envelope. The worker loads
the private compatibility options from PostgreSQL after proving that the envelope,
plan, target binding, opaque input references, and DNS snapshot still agree.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Mapping, Sequence
import urllib.parse

try:
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package import through api.scan
    from ..runtime.models import TargetBinding

from .jobs import (
    CanonicalScanJob,
    CanonicalScanJobError,
    SCAN_JOB_SCHEMA,
    admitted_credential_profile_ids,
    admitted_request_collection_job_refs,
)


class CanonicalScanJobMaterializationError(RuntimeError):
    """A canonical queue message cannot be proven against durable Scan state."""


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise CanonicalScanJobMaterializationError(f"{name} is invalid JSON") from exc
        if isinstance(decoded, Mapping):
            return dict(decoded)
    raise CanonicalScanJobMaterializationError(f"{name} must be an object")


def _row_value(row: Mapping[str, Any], name: str) -> Any:
    try:
        return row[name]
    except (KeyError, TypeError) as exc:
        raise CanonicalScanJobMaterializationError(
            f"persisted Scan is missing {name}"
        ) from exc


def _runtime_target(target_url: str, *, scheme_inferred: bool) -> str:
    if not scheme_inferred:
        return target_url
    parsed = urllib.parse.urlsplit(target_url)
    host = str(parsed.hostname or "")
    if not host:
        raise CanonicalScanJobMaterializationError("persisted Scan target URL is invalid")
    display = f"[{host}]" if ":" in host else host
    return f"{display}:{parsed.port}" if parsed.port else display


def materialize_canonical_scan_job(
    queue_payload: Mapping[str, Any],
    persisted_row: Mapping[str, Any],
    *,
    resolved_addresses: Sequence[str],
) -> dict[str, Any]:
    """Validate a queue envelope and return the existing worker's private input shape."""
    try:
        job = CanonicalScanJob.from_payload(queue_payload)
        stored_payload = _json_object(
            _row_value(persisted_row, "scan_job_payload"), name="scan_job_payload"
        )
        stored_job = CanonicalScanJob.from_payload(stored_payload)
    except CanonicalScanJobError as exc:
        raise CanonicalScanJobMaterializationError(str(exc)) from exc

    if stored_job.payload() != job.payload():
        raise CanonicalScanJobMaterializationError(
            "queued scan-job/v2 payload does not match its persisted payload"
        )
    stored_digest = str(_row_value(persisted_row, "scan_job_digest") or "").lower()
    if stored_digest != job.payload_digest:
        raise CanonicalScanJobMaterializationError(
            "persisted scan-job/v2 digest does not match its payload"
        )
    if str(_row_value(persisted_row, "job_id") or "") != job.job_id:
        raise CanonicalScanJobMaterializationError("queued job identity changed after admission")
    if str(_row_value(persisted_row, "scan_generation") or "") != "v2":
        raise CanonicalScanJobMaterializationError("canonical queue job requires a V2 Scan row")
    if str(_row_value(persisted_row, "target_id") or "") != job.target.target_id:
        raise CanonicalScanJobMaterializationError("queued target identity changed after admission")

    options = _json_object(_row_value(persisted_row, "options"), name="Scan options")
    if options.get("scan_execution_plan") != job.execution_plan.canonical_dict():
        raise CanonicalScanJobMaterializationError(
            "persisted Scan execution plan does not match scan-job/v2"
        )
    if str(options.get("scan_execution_plan_digest") or "").lower() != job.execution_plan.digest:
        raise CanonicalScanJobMaterializationError(
            "persisted Scan execution-plan digest does not match scan-job/v2"
        )
    policy = _json_object(_row_value(persisted_row, "policy_json"), name="policy_json")
    budget = _json_object(_row_value(persisted_row, "budget_json"), name="budget_json")
    canonical_plan = job.execution_plan.canonical_dict()
    if policy != canonical_plan["policy"] or budget != canonical_plan["budget"]:
        raise CanonicalScanJobMaterializationError(
            "persisted Scan policy or budget does not match scan-job/v2"
        )

    guard = _json_object(options.get("runtime_scope_guard"), name="runtime_scope_guard")
    try:
        persisted_binding = TargetBinding(
            target_id=str(guard.get("target_id") or ""),
            target_kind=str(guard.get("target_kind") or ""),
            canonical_host=guard.get("canonical_host"),
            allowed_origins=tuple(guard.get("allowed_origins") or ()),
            allowed_addresses=tuple(guard.get("allowed_addresses") or ()),
            allowed_root_domains=tuple(guard.get("allowed_root_domains") or ()),
            environment=str(guard.get("environment") or "unknown"),
            scope_receipt_id=str(guard.get("scope_receipt_id") or "") or None,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalScanJobMaterializationError(
            f"persisted runtime target binding is invalid: {exc}"
        ) from exc
    if persisted_binding != job.target:
        raise CanonicalScanJobMaterializationError(
            "persisted runtime target binding does not match scan-job/v2"
        )

    target_url = str(_row_value(persisted_row, "target_url") or "")
    parsed = urllib.parse.urlsplit(target_url)
    canonical_host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if parsed.scheme.lower() not in {"http", "https"} or canonical_host != job.target.canonical_host:
        raise CanonicalScanJobMaterializationError(
            "persisted Scan target URL does not match scan-job/v2"
        )
    durable_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    if durable_origin not in job.target.allowed_origins:
        raise CanonicalScanJobMaterializationError(
            "persisted Scan target origin exceeds the frozen scan-job/v2 target binding"
        )
    try:
        current_addresses = {
            str(ipaddress.ip_address(str(item).strip()))
            for item in resolved_addresses if str(item).strip()
        }
    except ValueError as exc:
        raise CanonicalScanJobMaterializationError(
            "runtime DNS returned an invalid address for scan-job/v2"
        ) from exc
    frozen_addresses = set(job.target.allowed_addresses)
    if not current_addresses or not frozen_addresses or not current_addresses.issubset(frozen_addresses):
        raise CanonicalScanJobMaterializationError(
            "runtime DNS resolution exceeds the frozen scan-job/v2 target binding"
        )

    try:
        persisted_collections = admitted_request_collection_job_refs(
            [
                dict(item)
                for item in options.get("request_collections") or ()
                if isinstance(item, Mapping)
            ]
        )
        persisted_credentials = admitted_credential_profile_ids(
            [
                dict(item)
                for item in options.get("credential_profile_refs") or ()
                if isinstance(item, Mapping)
            ]
        )
    except CanonicalScanJobError as exc:
        raise CanonicalScanJobMaterializationError(str(exc)) from exc
    if persisted_collections != job.request_collections:
        raise CanonicalScanJobMaterializationError(
            "persisted request collection references do not match scan-job/v2"
        )
    if persisted_credentials != job.credential_profile_ids:
        raise CanonicalScanJobMaterializationError(
            "persisted credential profile references do not match scan-job/v2"
        )

    return {
        "job_id": job.job_id,
        "scan_id": job.scan_id,
        "target": _runtime_target(
            target_url, scheme_inferred=bool(options.get("target_scheme_inferred"))
        ),
        "options": options,
        "submitted_at": job.created_at,
        "_canonical_queue_payload": job.payload(),
        "_canonical_scan_job_digest": job.payload_digest,
        "_canonical_queue_schema": SCAN_JOB_SCHEMA,
    }
