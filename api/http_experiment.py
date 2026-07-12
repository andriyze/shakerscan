"""Bounded same-origin HTTP experiments for adaptive research episodes."""

from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx


HTTP_EXPERIMENT_VERSION = "http-experiment-2026-07-12.v1"
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
FORBIDDEN_HEADERS = {"authorization", "cookie", "host", "proxy-authorization", "x-api-key"}
MAX_STEPS = 4
MAX_BODY_BYTES = 32_768
MAX_REQUEST_JSON_BYTES = 16_384
MAX_RESPONSE_SAMPLE = 2_000


class ExperimentContractError(ValueError):
    pass


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ExperimentContractError("target_url_must_be_absolute_http")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.lower(), port


def _bounded_json_size(value: Any, *, limit: int = MAX_REQUEST_JSON_BYTES) -> None:
    try:
        encoded = json.dumps(value, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExperimentContractError("request_value_not_json_serializable") from exc
    if len(encoded) > limit:
        raise ExperimentContractError("request_value_exceeds_size_limit")


def normalize_experiment(target_url: str, raw: Any) -> dict[str, Any]:
    payload = raw if isinstance(raw, dict) else {}
    steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    if not 2 <= len(steps) <= MAX_STEPS:
        raise ExperimentContractError("experiment_requires_2_to_4_steps")
    target_origin = _origin(target_url)
    normalized_steps: list[dict[str, Any]] = []
    labels: set[str] = set()
    for index, item in enumerate(steps):
        if not isinstance(item, dict):
            raise ExperimentContractError(f"step_{index}_must_be_object")
        label = str(item.get("label") or f"step_{index + 1}").strip()[:80]
        if not label or label in labels:
            raise ExperimentContractError("step_labels_must_be_unique")
        labels.add(label)
        method = str(item.get("method") or "GET").strip().upper()
        if method not in ALLOWED_METHODS:
            raise ExperimentContractError(f"step_{index}_method_not_allowed")
        path = str(item.get("path") or "").strip()
        parsed_path = urlparse(path)
        if not path.startswith("/") or parsed_path.scheme or parsed_path.netloc or path.startswith("//"):
            raise ExperimentContractError(f"step_{index}_path_must_be_relative")
        if "\r" in path or "\n" in path:
            raise ExperimentContractError(f"step_{index}_path_contains_control_character")
        query = item.get("query") if isinstance(item.get("query"), dict) else {}
        headers = item.get("headers") if isinstance(item.get("headers"), dict) else {}
        normalized_headers: dict[str, str] = {}
        for key, value in list(headers.items())[:20]:
            name = str(key).strip()
            if not name or name.lower() in FORBIDDEN_HEADERS:
                raise ExperimentContractError(f"step_{index}_header_forbidden:{name.lower()}")
            header_value = str(value)[:1000]
            if "\r" in name or "\n" in name or "\r" in header_value or "\n" in header_value:
                raise ExperimentContractError(f"step_{index}_header_contains_control_character")
            normalized_headers[name[:120]] = header_value
        body = item.get("json_body")
        if body is not None and method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ExperimentContractError(f"step_{index}_body_not_allowed_for_method")
        _bounded_json_size(query)
        _bounded_json_size(body)
        url = urljoin(target_url, path)
        if _origin(url) != target_origin:
            raise ExperimentContractError(f"step_{index}_resolved_outside_target_origin")
        normalized_steps.append({
            "label": label,
            "method": method,
            "path": path,
            "query": {str(k)[:120]: v for k, v in list(query.items())[:30]},
            "headers": normalized_headers,
            "json_body": body,
            "url": url,
        })
    timeout_seconds = max(1, min(int(payload.get("timeout_seconds") or 10), 15))
    return {
        "version": HTTP_EXPERIMENT_VERSION,
        "target_url": target_url,
        "objective": str(payload.get("objective") or "").strip()[:1000],
        "expected_signal": str(payload.get("expected_signal") or "").strip()[:1000],
        "falsifier": str(payload.get("falsifier") or "").strip()[:1000],
        "timeout_seconds": timeout_seconds,
        "steps": normalized_steps,
    }


def _scrub_sample(value: str) -> str:
    text = value[:MAX_RESPONSE_SAMPLE]
    text = re.sub(r"(?i)(bearer\s+)[a-z0-9._~+/=-]+", r"\1<redacted>", text)
    text = re.sub(r'(?i)("?(?:token|secret|password|api[_-]?key)"?\s*[:=]\s*")[^"]+"', r'\1<redacted>"', text)
    return text


def response_summary(response: httpx.Response, body: bytes) -> dict[str, Any]:
    truncated = len(body) > MAX_BODY_BYTES
    bounded = body[:MAX_BODY_BYTES]
    text = bounded.decode(response.encoding or "utf-8", errors="replace")
    parsed_json: Any = None
    try:
        parsed_json = json.loads(text)
    except (TypeError, ValueError):
        pass
    json_keys = sorted(str(key)[:120] for key in parsed_json.keys())[:100] if isinstance(parsed_json, dict) else []
    return {
        "status": response.status_code,
        "content_type": str(response.headers.get("content-type") or "")[:200],
        "content_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_sample": _scrub_sample(text),
        "json_type": type(parsed_json).__name__ if parsed_json is not None else None,
        "json_keys": json_keys,
        "truncated": truncated,
        "location": str(response.headers.get("location") or "")[:500] or None,
    }


def compare_summaries(control: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    control_keys = set(control.get("json_keys") or [])
    candidate_keys = set(candidate.get("json_keys") or [])
    left = str(control.get("body_sample") or "")
    right = str(candidate.get("body_sample") or "")
    return {
        "status_changed": control.get("status") != candidate.get("status"),
        "status_delta": [control.get("status"), candidate.get("status")],
        "length_delta": int(candidate.get("content_length") or 0) - int(control.get("content_length") or 0),
        "body_changed": control.get("body_sha256") != candidate.get("body_sha256"),
        "body_similarity": round(SequenceMatcher(None, left, right).ratio(), 4),
        "json_keys_added": sorted(candidate_keys - control_keys)[:100],
        "json_keys_removed": sorted(control_keys - candidate_keys)[:100],
    }


async def execute_experiment(target_url: str, raw: Any) -> dict[str, Any]:
    experiment = normalize_experiment(target_url, raw)
    observations: list[dict[str, Any]] = []
    timeout = httpx.Timeout(experiment["timeout_seconds"])
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        for step in experiment["steps"]:
            try:
                response = await client.request(
                    step["method"],
                    step["url"],
                    params=step["query"],
                    headers=step["headers"],
                    json=step["json_body"] if step["json_body"] is not None else None,
                )
                body = await response.aread()
                summary = response_summary(response, body)
                observations.append({
                    "label": step["label"],
                    "request": {"method": step["method"], "path": step["path"], "query_keys": sorted(step["query"])},
                    "response": summary,
                    "error": None,
                })
            except httpx.HTTPError as exc:
                observations.append({
                    "label": step["label"],
                    "request": {"method": step["method"], "path": step["path"], "query_keys": sorted(step["query"])},
                    "response": None,
                    "error": type(exc).__name__,
                })
    control = observations[0].get("response") or {}
    comparisons = [
        {"control": observations[0]["label"], "candidate": item["label"], **compare_summaries(control, item.get("response") or {})}
        for item in observations[1:]
    ]
    return {
        "version": HTTP_EXPERIMENT_VERSION,
        "objective": experiment["objective"],
        "expected_signal": experiment["expected_signal"],
        "falsifier": experiment["falsifier"],
        "request_count": len(observations),
        "observations": observations,
        "comparisons": comparisons,
        "finding_created": False,
        "proof_state": "unverified_experiment_signal",
    }
