"""Content-free semantic artifacts for real Scan placement parity gates."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


PARITY_ARTIFACT_SCHEMA = "scan-semantic-parity-artifact/v1"
PARITY_COMPARISON_SCHEMA = "scan-semantic-parity-comparison/v1"


def _object(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _array(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _budget(value: Any) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, raw in _object(value).items():
        try:
            amount = int(raw)
        except (TypeError, ValueError):
            continue
        if amount >= 0:
            result[str(name)] = amount
    return {name: result[name] for name in sorted(result)}


def _finding_identity(row: Mapping[str, Any]) -> str:
    fingerprint = str(row.get("fingerprint") or "").strip().lower()
    if fingerprint:
        return fingerprint
    material = {
        "tool": str(row.get("tool") or "").strip().lower(),
        "category": str(row.get("category") or "").strip().lower(),
        "url": str(row.get("url") or "").strip(),
        "parameter": str(row.get("parameter") or "").strip(),
        "title": str(row.get("title") or "").strip().lower(),
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    return f"derived:{hashlib.sha256(encoded).hexdigest()}"


def build_scan_semantic_parity_artifact(
    explanation: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Remove allowed runtime differences and retain only semantic Scan output.

    Worker identity, backend, receipts, object identifiers, timestamps, runtime
    duration, consumed budget, and content digests are intentionally excluded.
    The artifact can therefore compare executions without exposing target data.
    """
    coverage = _object(explanation.get("coverage"))
    reliability = _object(coverage.get("grade_reliability"))
    revision = _object(explanation.get("plan_revision"))
    actions = []
    for raw in _array(explanation.get("actions")):
        action = _object(raw)
        action_id = str(action.get("action_id") or "").strip()
        if not action_id:
            continue
        receipt = _object(action.get("receipt"))
        observation = _object(action.get("observation"))
        actions.append({
            "action_id": action_id,
            "ordinal": int(action.get("ordinal") or 0),
            "stage": str(action.get("stage") or "unknown"),
            "capability_name": str(action.get("capability_name") or "unknown"),
            "dependencies": [str(item) for item in _array(action.get("dependencies"))],
            "required": bool(action.get("required")),
            "supporting": bool(action.get("supporting")),
            "requested_budget": _budget(_object(action.get("budget")).get("reserved")),
            "terminal_status": str(action.get("status") or "missing"),
            "reason_code": (
                str(action.get("reason_code")) if action.get("reason_code") else None
            ),
            "output_schema": (
                str(action.get("output_schema")) if action.get("output_schema") else None
            ),
            "parser_schema": (
                str(receipt.get("parser_version"))
                if receipt.get("parser_version") else None
            ),
            "observation_present": bool(observation),
            "observation_count": int(observation.get("count") or 0),
        })
    actions.sort(key=lambda item: (item["ordinal"], item["action_id"]))

    optional_gaps = sorted(
        (
            str(item.get("action_id") or ""),
            str(item.get("reason_code") or ""),
            str(item.get("status") or ""),
        )
        for item in (
            _object(raw) for raw in _array(coverage.get("optional_gaps"))
        )
        if item.get("action_id")
    )
    artifact = {
        "schema_version": PARITY_ARTIFACT_SCHEMA,
        "plan_shape": {
            "revision": int(revision.get("revision") or 0),
            "has_continuation": bool(revision.get("continuation_plan_digest")),
        },
        "actions": actions,
        "finding_identities": sorted({
            _finding_identity(_object(row)) for row in findings
        }),
        "coverage": {
            "status": str(coverage.get("status") or "unknown"),
            "optional_gaps": [list(item) for item in optional_gaps],
            "active_zero_attempt_actions": sorted(
                str(item) for item in _array(
                    coverage.get("active_zero_attempt_actions")
                )
            ),
            "grade_reliability": {
                "reliable": reliability.get("reliable") is True,
                "reasons": sorted(
                    str(item) for item in _array(reliability.get("reasons"))
                ),
            },
        },
    }
    artifact["semantic_digest"] = hashlib.sha256(json.dumps(
        artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()
    return artifact


def _semantic_body(artifact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in dict(artifact).items()
        if key not in {"semantic_digest"}
    }


def _diff(left: Any, right: Any, *, path: str = "$") -> list[dict[str, Any]]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        differences: list[dict[str, Any]] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                differences.append({"path": f"{path}.{key}", "left": left.get(key), "right": right.get(key)})
            else:
                differences.extend(_diff(left[key], right[key], path=f"{path}.{key}"))
        return differences
    if isinstance(left, list) and isinstance(right, list):
        differences = []
        for index in range(max(len(left), len(right))):
            if index >= len(left) or index >= len(right):
                differences.append({
                    "path": f"{path}[{index}]",
                    "left": left[index] if index < len(left) else None,
                    "right": right[index] if index < len(right) else None,
                })
            else:
                differences.extend(_diff(left[index], right[index], path=f"{path}[{index}]"))
        return differences
    return [] if left == right else [{"path": path, "left": left, "right": right}]


def compare_scan_semantic_parity(
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare two or more already normalized real execution artifacts."""
    labels = sorted(str(label) for label in artifacts)
    if len(labels) < 2:
        raise ValueError("semantic parity comparison requires at least two artifacts")
    baseline = "local" if "local" in artifacts else labels[0]
    baseline_body = _semantic_body(artifacts[baseline])
    comparisons = []
    for label in labels:
        if label == baseline:
            continue
        differences = _diff(baseline_body, _semantic_body(artifacts[label]))
        comparisons.append({
            "baseline": baseline,
            "candidate": label,
            "consistent": not differences,
            "differences": differences[:200],
            "difference_count": len(differences),
        })
    return {
        "schema_version": PARITY_COMPARISON_SCHEMA,
        "baseline": baseline,
        "consistent": all(item["consistent"] for item in comparisons),
        "comparisons": comparisons,
    }


def parity_artifact_is_truthful(artifact: Mapping[str, Any]) -> bool:
    """A missing/failed required action must never yield a clean reliable grade."""
    required_incomplete = any(
        bool(action.get("required"))
        and str(action.get("terminal_status")) != "success"
        for action in _array(artifact.get("actions"))
        if isinstance(action, Mapping)
    )
    coverage = _object(artifact.get("coverage"))
    reliable = _object(coverage.get("grade_reliability")).get("reliable") is True
    clean = coverage.get("status") == "complete" and reliable
    return not (required_incomplete and clean)
