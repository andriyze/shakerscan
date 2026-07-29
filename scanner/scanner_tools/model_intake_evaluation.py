"""Provider-neutral embedding and retrieval-control evaluation.

The model runner is intentionally outside this module. It accepts bounded vectors and
data-plane observations produced by an approved runner, then computes the security
decision itself without retaining source text or embedding values in its report.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "model-intake-evaluation/v1"
MAX_CASES = 2_000
MAX_DIMENSIONS = 16_384
MAX_SPEC_BYTES = 20_000_000
REQUIRED_DELETION_LAYERS = {"source", "chunks", "vectors", "graph_edges", "cache", "replicas"}


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _case_ref(value: Any) -> str:
    return f"case:{_digest(str(value))[:16]}"


def _vector(value: Any) -> list[float] | None:
    if not isinstance(value, list) or not value or len(value) > MAX_DIMENSIONS:
        return None
    try:
        parsed = [float(item) for item in value]
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if all(math.isfinite(item) for item in parsed) else None


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return float("nan")
    left_norm = math.sqrt(sum(item * item for item in left))
    right_norm = math.sqrt(sum(item * item for item in right))
    if left_norm == 0 or right_norm == 0:
        return float("nan")
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 6)


def _authorized(document: dict[str, Any], principal: str, tenant: str) -> bool:
    classification = str(document.get("classification") or "").lower()
    principals = {str(item) for item in document.get("allowed_principals", []) if item is not None}
    return (
        bool(tenant)
        and str(document.get("tenant") or "") == tenant
        and (classification == "public" or principal in principals)
    )


def evaluate(spec: Any, *, artifact_sha256: str | None) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    def block(code: str, detail: str, case: Any = None) -> None:
        item = {"code": code, "detail": detail}
        if case is not None:
            item["case_ref"] = _case_ref(case)
        blockers.append(item)

    def warn(code: str, detail: str, case: Any = None) -> None:
        item = {"code": code, "detail": detail}
        if case is not None:
            item["case_ref"] = _case_ref(case)
        warnings.append(item)

    invalid_thresholds: set[str] = set()

    def threshold_number(name: str, default: float) -> float:
        try:
            value = float(thresholds.get(name, default))
            if not math.isfinite(value):
                raise ValueError
            return value
        except (TypeError, ValueError, OverflowError):
            if name not in invalid_thresholds:
                invalid_thresholds.add(name)
                block("threshold_invalid", f"Threshold {name} must be a finite number.")
            return default

    if not isinstance(spec, dict):
        return {
            "schema_version": SCHEMA_VERSION,
            "provenance_class": "shakerscan_generated",
            "status": "INDETERMINATE",
            "artifact_sha256": artifact_sha256,
            "blockers": [{"code": "evaluation_spec_missing", "detail": "No evaluation specification was supplied."}],
            "warnings": [],
            "started_at": started_at,
        }
    try:
        if len(json.dumps(spec, default=str).encode()) > MAX_SPEC_BYTES:
            raise ValueError("evaluation specification exceeds the 20 MB bound")
    except (TypeError, ValueError) as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "provenance_class": "shakerscan_generated",
            "status": "FAIL",
            "artifact_sha256": artifact_sha256,
            "blockers": [{"code": "evaluation_spec_invalid", "detail": str(exc)}],
            "warnings": [],
            "started_at": started_at,
        }

    thresholds = spec.get("thresholds") if isinstance(spec.get("thresholds"), dict) else {}
    required_thresholds = {"min_recall_at_k", "max_acl_leaks", "max_poisoned_top_k_rate", "min_stability_cosine"}
    missing_thresholds = sorted(required_thresholds - set(thresholds))
    if missing_thresholds:
        block("thresholds_missing", f"Predeclared thresholds are missing: {', '.join(missing_thresholds)}")

    documents_raw = spec.get("documents") if isinstance(spec.get("documents"), list) else []
    queries = spec.get("queries") if isinstance(spec.get("queries"), list) else []
    runtime_runs = spec.get("runtime_runs") if isinstance(spec.get("runtime_runs"), list) else []
    total_cases = len(documents_raw) + len(queries) + len(runtime_runs)
    if total_cases > MAX_CASES:
        block("case_limit_exceeded", f"Evaluation has {total_cases} cases; maximum is {MAX_CASES}.")

    documents: dict[str, dict[str, Any]] = {}
    dimensions: set[int] = set()
    invalid_vectors = 0
    zero_vectors = 0
    vector_fingerprints: dict[str, int] = {}
    missing_labels = 0
    for position, raw in enumerate(documents_raw[:MAX_CASES]):
        if not isinstance(raw, dict):
            invalid_vectors += 1
            continue
        document_id = str(raw.get("id") or f"document-{position}")
        vector = _vector(raw.get("vector"))
        if vector is None:
            invalid_vectors += 1
            continue
        if not raw.get("tenant") or not raw.get("classification") or not isinstance(raw.get("allowed_principals"), list):
            missing_labels += 1
        norm = math.sqrt(sum(item * item for item in vector))
        if norm == 0:
            zero_vectors += 1
        dimensions.add(len(vector))
        fingerprint = _digest([round(item, 8) for item in vector])
        vector_fingerprints[fingerprint] = vector_fingerprints.get(fingerprint, 0) + 1
        documents[document_id] = {**raw, "vector": vector}
    collisions = sum(count - 1 for count in vector_fingerprints.values() if count > 1)
    if invalid_vectors:
        block("invalid_vectors", f"{invalid_vectors} vectors were empty, non-finite, oversized, or non-numeric.")
    if zero_vectors:
        block("degenerate_vectors", f"{zero_vectors} document vectors have zero norm.")
    if len(dimensions) > 1:
        block("dimension_mismatch", f"Observed inconsistent embedding dimensions: {sorted(dimensions)}")
    expected_dimension = int(threshold_number("expected_dimension", 0)) if thresholds.get("expected_dimension") is not None else None
    if expected_dimension is not None and dimensions and dimensions != {expected_dimension}:
        block("unexpected_dimension", f"Observed {sorted(dimensions)}; expected {expected_dimension}.")
    if missing_labels:
        block("data_labels_missing", f"{missing_labels} records lack tenant, classification, or ACL propagation metadata.")
    max_collision_rate = threshold_number("max_collision_rate", 0.01)
    collision_rate = collisions / max(1, len(documents))
    if collision_rate > max_collision_rate:
        block("collision_rate_exceeded", f"Collision rate {collision_rate:.6f} exceeds {max_collision_rate:.6f}.")

    recalls: list[float] = []
    acl_leaks = 0
    poisoned_hits = 0
    sensitive_leaks = 0
    evaluated_queries = 0
    for position, raw in enumerate(queries[:MAX_CASES]):
        if not isinstance(raw, dict):
            continue
        query_id = raw.get("id") or f"query-{position}"
        vector = _vector(raw.get("vector"))
        principal = str(raw.get("principal") or "")
        tenant = str(raw.get("tenant") or "")
        if vector is None or not principal or not tenant:
            block("invalid_query", "Query is missing a finite vector, principal, or tenant.", query_id)
            continue
        try:
            top_k = max(1, min(int(raw.get("top_k") or threshold_number("top_k", 10)), 100))
        except (TypeError, ValueError, OverflowError):
            block("invalid_top_k", "Query top_k must be an integer from 1 through 100.", query_id)
            top_k = 10
        scored = [(doc_id, _cosine(vector, doc["vector"])) for doc_id, doc in documents.items()]
        scored = [(doc_id, score) for doc_id, score in scored if math.isfinite(score)]
        scored.sort(key=lambda item: (-item[1], item[0]))
        authorized_ranked = [doc_id for doc_id, _score in scored if _authorized(documents[doc_id], principal, tenant)][:top_k]
        returned_ids = [str(item) for item in raw.get("returned_ids", authorized_ranked)][:top_k]
        relevant = {str(item) for item in raw.get("relevant_ids", [])}
        if relevant:
            recalls.append(len(relevant.intersection(returned_ids)) / len(relevant))
        for document_id in returned_ids:
            document = documents.get(document_id)
            if document is None or not _authorized(document, principal, tenant):
                acl_leaks += 1
                if document and document.get("sensitive"):
                    sensitive_leaks += 1
            if document and document.get("poisoned"):
                poisoned_hits += 1
        evaluated_queries += 1

    mean_recall = sum(recalls) / len(recalls) if recalls else None
    if mean_recall is None:
        block("retrieval_quality_not_measured", "No query supplied non-empty relevant_ids.")
    elif mean_recall < threshold_number("min_recall_at_k", 1.0):
        block("retrieval_quality_below_threshold", f"Mean recall@k {mean_recall:.6f} is below the threshold.")
    if acl_leaks > int(threshold_number("max_acl_leaks", 0)):
        block("acl_retrieval_leak", f"Observed {acl_leaks} unauthorized retrieval results.")
    if sensitive_leaks:
        block("sensitive_retrieval_leak", f"Observed {sensitive_leaks} unauthorized sensitive results.")
    poisoned_rate = poisoned_hits / max(1, evaluated_queries)
    if poisoned_rate > threshold_number("max_poisoned_top_k_rate", 0.0):
        block("poisoning_threshold_exceeded", f"Poisoned top-k hit rate {poisoned_rate:.6f} exceeds policy.")

    stability_scores: list[float] = []
    latency_values: list[float] = []
    peak_rss_values: list[float] = []
    runs_by_case: dict[str, list[list[float]]] = {}
    for raw in runtime_runs[:MAX_CASES]:
        if not isinstance(raw, dict):
            continue
        vector = _vector(raw.get("vector"))
        case_id = str(raw.get("case_id") or "")
        if vector is not None and case_id:
            runs_by_case.setdefault(case_id, []).append(vector)
        for key, target in (("latency_ms", latency_values), ("peak_rss_mb", peak_rss_values)):
            try:
                value = float(raw.get(key))
                if math.isfinite(value) and value >= 0:
                    target.append(value)
            except (TypeError, ValueError):
                pass
    for vectors in runs_by_case.values():
        for candidate in vectors[1:]:
            score = _cosine(vectors[0], candidate)
            if math.isfinite(score):
                stability_scores.append(score)
    minimum_stability = min(stability_scores) if stability_scores else None
    if minimum_stability is None:
        block("stability_not_measured", "No case has comparable outputs from multiple runtime runs.")
    elif minimum_stability < threshold_number("min_stability_cosine", 1.0):
        block("stability_below_threshold", f"Minimum cross-runtime cosine {minimum_stability:.6f} is below policy.")
    p95_latency = _percentile(latency_values, 0.95)
    if thresholds.get("max_p95_latency_ms") is not None and (p95_latency is None or p95_latency > threshold_number("max_p95_latency_ms", 0)):
        block("latency_threshold_exceeded", "P95 latency is absent or exceeds policy.")
    peak_rss = max(peak_rss_values) if peak_rss_values else None
    if thresholds.get("max_peak_rss_mb") is not None and (peak_rss is None or peak_rss > threshold_number("max_peak_rss_mb", 0)):
        block("memory_threshold_exceeded", "Peak RSS is absent or exceeds policy.")

    controls = spec.get("data_plane_controls") if isinstance(spec.get("data_plane_controls"), dict) else {}
    index_digest = str(controls.get("index_model_sha256") or "").lower()
    if artifact_sha256 and index_digest != artifact_sha256.lower():
        block("index_model_digest_mismatch", "Vector index namespace is not bound to the reviewed model digest.")
    for test in controls.get("graph_boundary_tests", []) if isinstance(controls.get("graph_boundary_tests"), list) else []:
        if isinstance(test, dict) and not set(map(str, test.get("returned_node_ids", []))).issubset(set(map(str, test.get("allowed_node_ids", [])))):
            block("graph_authorization_boundary_crossed", "Graph traversal returned unauthorized nodes.", test.get("id"))
    for receipt in controls.get("deletion_receipts", []) if isinstance(controls.get("deletion_receipts"), list) else []:
        layers = receipt.get("layers") if isinstance(receipt, dict) and isinstance(receipt.get("layers"), dict) else {}
        missing = sorted(layer for layer in REQUIRED_DELETION_LAYERS if layers.get(layer) is not True)
        if missing:
            block("deletion_incomplete", f"Deletion receipt is missing layers: {', '.join(missing)}", receipt.get("source_id"))
    if not controls.get("authorization_before_search"):
        block("pre_query_authorization_missing", "The data plane did not attest authorization before similarity search.")
    if not controls.get("cache_key_includes_auth_context"):
        block("cache_auth_context_missing", "Retrieval cache keys do not bind tenant, principal, ACL, model digest, and index version.")
    if not controls.get("retrieved_content_is_untrusted"):
        warn("retrieved_content_boundary_missing", "Downstream handling did not confirm retrieved text is isolated from trusted instructions.")

    status = "FAIL" if blockers else "WARNING" if warnings else "PASS"
    report = {
        "schema_version": SCHEMA_VERSION,
        "provenance_class": "shakerscan_generated",
        "status": status,
        "suite_id": str(spec.get("suite_id") or ""),
        "suite_version": str(spec.get("suite_version") or ""),
        "artifact_sha256": artifact_sha256,
        "target_sha256": artifact_sha256,
        "input_spec_sha256": _digest(spec),
        "metrics": {
            "documents": len(documents),
            "queries": evaluated_queries,
            "dimension": next(iter(dimensions)) if len(dimensions) == 1 else None,
            "invalid_vectors": invalid_vectors,
            "zero_vectors": zero_vectors,
            "collision_rate": round(collision_rate, 8),
            "mean_recall_at_k": round(mean_recall, 8) if mean_recall is not None else None,
            "acl_leaks": acl_leaks,
            "sensitive_leaks": sensitive_leaks,
            "poisoned_top_k_rate": round(poisoned_rate, 8),
            "minimum_stability_cosine": round(minimum_stability, 8) if minimum_stability is not None else None,
            "latency_ms": {"p50": _percentile(latency_values, 0.50), "p95": p95_latency, "p99": _percentile(latency_values, 0.99)},
            "peak_rss_mb": peak_rss,
        },
        "thresholds": thresholds,
        "blockers": blockers,
        "warnings": warnings,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    report["evaluated_at"] = report["finished_at"]
    report["evidence_sha256"] = _digest(report)
    return report


def verify_report(report: Any, *, artifact_sha256: str | None) -> dict[str, Any]:
    """Verify a content-free report before a worker uses it as generated evidence."""
    if not isinstance(report, dict):
        return {
            "schema_version": SCHEMA_VERSION,
            "provenance_class": "shakerscan_generated",
            "status": "FAIL",
            "artifact_sha256": artifact_sha256,
            "blockers": [{"code": "evaluation_report_invalid", "detail": "Evaluation report is not an object."}],
            "warnings": [],
        }
    verified = dict(report)
    supplied_digest = verified.pop("evidence_sha256", None)
    blockers = list(verified.get("blockers") or [])
    if report.get("schema_version") != SCHEMA_VERSION:
        blockers.append({"code": "evaluation_schema_invalid", "detail": "Evaluation report schema is unsupported."})
    if supplied_digest != _digest(verified):
        blockers.append({"code": "evaluation_evidence_digest_mismatch", "detail": "Evaluation report was changed after generation."})
    observed = str(artifact_sha256 or "").lower()
    bound = str(report.get("artifact_sha256") or "").lower()
    if not observed or bound != observed:
        blockers.append({"code": "evaluation_artifact_digest_mismatch", "detail": "Evaluation is not bound to the complete observed artifact."})
    return {
        **report,
        "status": "FAIL" if blockers else report.get("status"),
        "blockers": blockers,
        "worker_verified": not blockers,
    }


__all__ = ["SCHEMA_VERSION", "evaluate", "verify_report"]
