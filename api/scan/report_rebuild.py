"""Strict offline input contract for deterministic Scan report reconstruction."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from .action_plan import ScanActionPlan
from .capability_result import CapabilityResultReference
from .continuation import ScanPlanRevision
from .finalizer import finalize_scan_report


SCAN_REPORT_REBUILD_BUNDLE_SCHEMA = "scan-report-rebuild-bundle/v1"


class ScanReportRebuildError(ValueError):
    """An offline evidence bundle is malformed, detached, or tampered."""


def build_scan_report_rebuild_bundle(
    *,
    plan: ScanActionPlan,
    target_url: str,
    action_results: Mapping[str, CapabilityResultReference],
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
    plan_revision: ScanPlanRevision,
    work_manifest_references: Sequence[Mapping[str, Any]] = (),
    expected_report_digest: str | None = None,
) -> dict[str, Any]:
    """Create the complete private input needed by the offline report builder."""
    return {
        "schema_version": SCAN_REPORT_REBUILD_BUNDLE_SCHEMA,
        "target_url": str(target_url),
        "plan": plan.canonical_dict(),
        "plan_revision": plan_revision.canonical_dict(),
        "action_results": {
            action_id: result.canonical_dict()
            for action_id, result in sorted(action_results.items())
        },
        "observations": {
            action_id: [dict(item) for item in rows]
            for action_id, rows in sorted(observations.items())
        },
        "work_manifest_references": [
            dict(item) for item in work_manifest_references
        ],
        "expected_report_digest": (
            str(expected_report_digest).lower()
            if expected_report_digest is not None else None
        ),
    }


def rebuild_scan_report(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild and verify a Scan report using only the supplied frozen bundle."""
    expected_fields = {
        "schema_version", "target_url", "plan", "plan_revision",
        "action_results", "observations", "work_manifest_references",
        "expected_report_digest",
    }
    if not isinstance(bundle, Mapping) or set(bundle) != expected_fields:
        raise ScanReportRebuildError("offline report bundle fields are invalid")
    if bundle.get("schema_version") != SCAN_REPORT_REBUILD_BUNDLE_SCHEMA:
        raise ScanReportRebuildError("offline report bundle schema is unsupported")
    try:
        plan = ScanActionPlan.from_dict(bundle["plan"])
        revision = ScanPlanRevision.from_dict(bundle["plan_revision"])
    except (TypeError, ValueError, KeyError) as exc:
        raise ScanReportRebuildError("offline report plan authority is invalid") from exc

    raw_results = bundle.get("action_results")
    raw_observations = bundle.get("observations")
    raw_manifests = bundle.get("work_manifest_references")
    if (
        not isinstance(raw_results, Mapping)
        or not isinstance(raw_observations, Mapping)
        or not isinstance(raw_manifests, list)
    ):
        raise ScanReportRebuildError("offline report evidence fields are invalid")
    try:
        action_results = {
            str(action_id): CapabilityResultReference.from_dict(value)
            for action_id, value in raw_results.items()
        }
        if any(
            action_id != result.action_id
            for action_id, result in action_results.items()
        ):
            raise ScanReportRebuildError(
                "offline result map key differs from its result authority"
            )
        observations = {
            str(action_id): tuple(dict(item) for item in rows)
            for action_id, rows in raw_observations.items()
            if isinstance(rows, list)
        }
        if set(observations) != set(raw_observations):
            raise ScanReportRebuildError("offline observations must be arrays")
        if set(observations) != set(action_results):
            raise ScanReportRebuildError(
                "offline observations must exactly cover action results"
            )
        for action_id, result in action_results.items():
            reference = result.observation_manifest_ref
            rows = observations[action_id]
            if reference is None:
                if rows:
                    raise ScanReportRebuildError(
                        "offline observations have no manifest authority"
                    )
                continue
            if len(rows) != reference.count:
                raise ScanReportRebuildError(
                    "offline observation count differs from its manifest"
                )
            content = json.dumps(
                list(rows), sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
            # Historical content-free zero-observation fixtures used an empty
            # object body. All persisted non-empty objects and current empty
            # arrays are checked byte-for-byte against their manifest.
            if reference.size_bytes and (
                len(content) != reference.size_bytes
                or hashlib.sha256(content).hexdigest() != reference.sha256
            ):
                raise ScanReportRebuildError(
                    "offline observations differ from their content digest"
                )
        manifests = tuple(dict(item) for item in raw_manifests)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ScanReportRebuildError):
            raise
        raise ScanReportRebuildError("offline report evidence is invalid") from exc

    report = finalize_scan_report(
        plan=plan,
        plan_revision=revision,
        target_url=str(bundle.get("target_url") or ""),
        action_results=action_results,
        observations=observations,
        work_manifest_references=manifests,
    )
    expected_digest = bundle.get("expected_report_digest")
    if expected_digest is not None and str(expected_digest).lower() != report["report_digest"]:
        raise ScanReportRebuildError(
            "rebuilt report digest differs from the expected report"
        )
    return report


def canonical_report_json(report: Mapping[str, Any]) -> str:
    """Render stable output suitable for digest comparison and archival."""
    return json.dumps(
        dict(report), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ) + "\n"
