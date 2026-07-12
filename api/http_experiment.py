"""Bounded same-origin HTTP experiments for adaptive research episodes."""

from __future__ import annotations

import hashlib
import json
import re
import time
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx


HTTP_EXPERIMENT_VERSION = "http-experiment-2026-07-12.v2"
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
FORBIDDEN_HEADERS = {"authorization", "cookie", "host", "proxy-authorization", "x-api-key"}
MAX_STEPS = 4
MAX_BODY_BYTES = 32_768
MAX_REQUEST_JSON_BYTES = 16_384
MAX_RESPONSE_SAMPLE = 2_000
MAX_EXTRACTS_PER_STEP = 8
MAX_VARIABLES = 20
VARIABLE_PATTERN = re.compile(r"\$\{([A-Za-z][A-Za-z0-9_]{0,63})\}")
SENSITIVE_TOKENS = {"authorization", "cookie", "secret", "token", "password", "passwd", "api_key", "apikey"}


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


def _sensitive_name(value: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower())
    return any(token in normalized for token in SENSITIVE_TOKENS)


def _normalize_extracts(index: int, value: Any) -> list[dict[str, str]]:
    extracts = value if isinstance(value, list) else []
    if len(extracts) > MAX_EXTRACTS_PER_STEP:
        raise ExperimentContractError(f"step_{index}_too_many_extracts")
    normalized: list[dict[str, str]] = []
    for item in extracts:
        if not isinstance(item, dict):
            raise ExperimentContractError(f"step_{index}_extract_must_be_object")
        name = str(item.get("name") or "").strip()
        source = str(item.get("source") or "json").strip().lower()
        selector = str(item.get("path") if source == "json" else item.get("header") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
            raise ExperimentContractError(f"step_{index}_extract_name_invalid")
        if _sensitive_name(name) or _sensitive_name(selector):
            raise ExperimentContractError(f"step_{index}_extract_sensitive_value_forbidden")
        if source not in {"json", "header"}:
            raise ExperimentContractError(f"step_{index}_extract_source_not_allowed")
        if source == "json" and not selector.startswith("$."):
            raise ExperimentContractError(f"step_{index}_extract_json_path_invalid")
        if source == "header" and (not selector or selector.lower() in {"set-cookie", *FORBIDDEN_HEADERS}):
            raise ExperimentContractError(f"step_{index}_extract_header_forbidden")
        normalized.append({"name": name, "source": source, "selector": selector[:300]})
    return normalized


def _render_variables(value: Any, variables: dict[str, str]) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in variables:
                raise ExperimentContractError(f"variable_not_available:{name}")
            return variables[name]
        return VARIABLE_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_render_variables(item, variables) for item in value]
    if isinstance(value, dict):
        return {str(key): _render_variables(item, variables) for key, item in value.items()}
    return value


def _json_path_get(value: Any, path: str) -> Any:
    current = value
    for token in path[2:].split("."):
        match = re.fullmatch(r"([^\[\]]+)(?:\[(\d+)\])?", token)
        if not match or not isinstance(current, dict) or match.group(1) not in current:
            raise ExperimentContractError(f"extract_path_missing:{path}")
        current = current[match.group(1)]
        if match.group(2) is not None:
            if not isinstance(current, list) or int(match.group(2)) >= len(current):
                raise ExperimentContractError(f"extract_path_missing:{path}")
            current = current[int(match.group(2))]
    if current is None or isinstance(current, (dict, list)):
        raise ExperimentContractError(f"extract_value_must_be_scalar:{path}")
    return current


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
        if len(path.encode("utf-8")) > 2000:
            raise ExperimentContractError(f"step_{index}_path_exceeds_size_limit")
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
        form_body = item.get("form_body") if isinstance(item.get("form_body"), dict) else None
        if body is not None and form_body is not None:
            raise ExperimentContractError(f"step_{index}_multiple_body_types")
        if (body is not None or form_body is not None) and method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ExperimentContractError(f"step_{index}_body_not_allowed_for_method")
        _bounded_json_size(query)
        _bounded_json_size(body)
        _bounded_json_size(form_body)
        extracts = _normalize_extracts(index, item.get("extract"))
        select_json = [str(path)[:300] for path in (item.get("select_json") or []) if str(path).startswith("$.")][:20]
        select_headers = [
            str(name).strip().lower()[:120]
            for name in (item.get("select_headers") or [])
            if str(name).strip() and str(name).strip().lower() not in {"set-cookie", *FORBIDDEN_HEADERS}
        ][:20]
        role = str(item.get("role") or ("control" if index == 0 else "mutation")).strip().lower()
        if role not in {"control", "mutation", "verify"}:
            raise ExperimentContractError(f"step_{index}_role_not_allowed")
        compare_to = str(item.get("compare_to") or normalized_steps[0]["label"] if normalized_steps else "").strip()
        if index and compare_to not in labels:
            raise ExperimentContractError(f"step_{index}_compare_to_must_reference_prior_step")
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
            "form_body": form_body,
            "extract": extracts,
            "select_json": select_json,
            "select_headers": select_headers,
            "role": role,
            "compare_to": compare_to,
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


def response_summary(
    response: httpx.Response,
    body: bytes,
    *,
    selected_json_paths: list[str] | None = None,
    selected_headers: list[str] | None = None,
    elapsed_ms: int | None = None,
) -> dict[str, Any]:
    truncated = len(body) > MAX_BODY_BYTES
    bounded = body[:MAX_BODY_BYTES]
    text = bounded.decode(response.encoding or "utf-8", errors="replace")
    parsed_json: Any = None
    try:
        parsed_json = json.loads(text)
    except (TypeError, ValueError):
        pass
    json_keys = sorted(str(key)[:120] for key in parsed_json.keys())[:100] if isinstance(parsed_json, dict) else []
    selected_json: dict[str, Any] = {}
    for path in selected_json_paths or []:
        try:
            selected_json[path] = _json_path_get(parsed_json, path)
        except ExperimentContractError:
            selected_json[path] = None
    selected_response_headers = {
        name: str(response.headers.get(name) or "")[:1000]
        for name in selected_headers or []
    }
    return {
        "status": response.status_code,
        "content_type": str(response.headers.get("content-type") or "")[:200],
        "content_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_digest_scope": "prefix" if truncated else "complete",
        "body_sample": _scrub_sample(text),
        "json_type": type(parsed_json).__name__ if parsed_json is not None else None,
        "json_keys": json_keys,
        "truncated": truncated,
        "location": str(response.headers.get("location") or "")[:500] or None,
        "elapsed_ms": elapsed_ms,
        "selected_json": selected_json,
        "selected_headers": selected_response_headers,
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
        "selected_json_changed": {
            key: [control.get("selected_json", {}).get(key), candidate.get("selected_json", {}).get(key)]
            for key in sorted(set(control.get("selected_json") or {}) | set(candidate.get("selected_json") or {}))
            if control.get("selected_json", {}).get(key) != candidate.get("selected_json", {}).get(key)
        },
        "selected_headers_changed": {
            key: [control.get("selected_headers", {}).get(key), candidate.get("selected_headers", {}).get(key)]
            for key in sorted(set(control.get("selected_headers") or {}) | set(candidate.get("selected_headers") or {}))
            if control.get("selected_headers", {}).get(key) != candidate.get("selected_headers", {}).get(key)
        },
        "timing_delta_ms": int(candidate.get("elapsed_ms") or 0) - int(control.get("elapsed_ms") or 0),
    }


async def execute_experiment(target_url: str, raw: Any, *, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    experiment = normalize_experiment(target_url, raw)
    observations: list[dict[str, Any]] = []
    variables: dict[str, str] = {}
    timeout = httpx.Timeout(experiment["timeout_seconds"])
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False, transport=transport) as client:
        for step in experiment["steps"]:
            try:
                rendered_path = _render_variables(step["path"], variables)
                rendered_url = urljoin(target_url, rendered_path)
                if not str(rendered_path).startswith("/") or str(rendered_path).startswith("//") or _origin(rendered_url) != _origin(target_url):
                    raise ExperimentContractError("rendered_path_outside_target_origin")
                rendered_query = _render_variables(step["query"], variables)
                rendered_headers = _render_variables(step["headers"], variables)
                rendered_json = _render_variables(step["json_body"], variables)
                rendered_form = _render_variables(step["form_body"], variables)
                if len(str(rendered_path).encode("utf-8")) > 4000:
                    raise ExperimentContractError("rendered_path_exceeds_size_limit")
                _bounded_json_size(rendered_query)
                _bounded_json_size(rendered_json)
                _bounded_json_size(rendered_form)
                for name, value in rendered_headers.items():
                    if len(str(value).encode("utf-8")) > 1000 or "\r" in str(value) or "\n" in str(value):
                        raise ExperimentContractError(f"rendered_header_invalid:{name}")
                started = time.perf_counter()
                request = client.build_request(
                    step["method"],
                    rendered_url,
                    params=rendered_query,
                    headers=rendered_headers,
                    json=rendered_json if rendered_json is not None else None,
                    data=rendered_form if rendered_form is not None else None,
                )
                response = await client.send(request, stream=True)
                chunks: list[bytes] = []
                received = 0
                async for chunk in response.aiter_bytes():
                    remaining = MAX_BODY_BYTES + 1 - received
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    received += min(len(chunk), remaining)
                    if received > MAX_BODY_BYTES:
                        break
                await response.aclose()
                body = b"".join(chunks)
                elapsed_ms = round((time.perf_counter() - started) * 1000)
                summary = response_summary(
                    response,
                    body,
                    selected_json_paths=step["select_json"],
                    selected_headers=step["select_headers"],
                    elapsed_ms=elapsed_ms,
                )
                parsed_json: Any = None
                try:
                    parsed_json = json.loads(body[:MAX_BODY_BYTES].decode(response.encoding or "utf-8", errors="replace"))
                except (TypeError, ValueError):
                    pass
                extracted: dict[str, str] = {}
                for spec in step["extract"]:
                    value = (
                        _json_path_get(parsed_json, spec["selector"])
                        if spec["source"] == "json"
                        else response.headers.get(spec["selector"])
                    )
                    if value is None:
                        raise ExperimentContractError(f"extract_value_missing:{spec['name']}")
                    rendered_value = str(value)[:1000]
                    variables[spec["name"]] = rendered_value
                    extracted[spec["name"]] = rendered_value
                    if len(variables) > MAX_VARIABLES:
                        raise ExperimentContractError("experiment_variable_limit_exceeded")
                observations.append({
                    "label": step["label"],
                    "role": step["role"],
                    "compare_to": step["compare_to"],
                    "request": {
                        "method": step["method"],
                        "path": rendered_path,
                        "query_keys": sorted(rendered_query),
                        "body_kind": "json" if rendered_json is not None else "form" if rendered_form is not None else None,
                    },
                    "response": summary,
                    "extracted": extracted,
                    "error": None,
                })
            except (httpx.HTTPError, ExperimentContractError) as exc:
                observations.append({
                    "label": step["label"],
                    "role": step["role"],
                    "compare_to": step["compare_to"],
                    "request": {"method": step["method"], "path": step["path"], "query_keys": sorted(step["query"])},
                    "response": None,
                    "extracted": {},
                    "error": str(exc) if isinstance(exc, ExperimentContractError) else type(exc).__name__,
                })
    by_label = {item["label"]: item for item in observations}
    comparisons = []
    for item in observations[1:]:
        control_item = by_label.get(item.get("compare_to")) or observations[0]
        comparison = compare_summaries(control_item.get("response") or {}, item.get("response") or {})
        comparisons.append({
            "control": control_item["label"],
            "candidate": item["label"],
            "candidate_role": item["role"],
            "side_effect_check": item["role"] == "verify",
            **comparison,
        })
    return {
        "version": HTTP_EXPERIMENT_VERSION,
        "objective": experiment["objective"],
        "expected_signal": experiment["expected_signal"],
        "falsifier": experiment["falsifier"],
        "request_count": len(observations),
        "observations": observations,
        "comparisons": comparisons,
        "variable_names": sorted(variables),
        "finding_created": False,
        "proof_state": "unverified_experiment_signal",
    }
