"""Principal-bound bounded HTTP/browser workflows for adaptive research."""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin

import httpx

from http_experiment import (
    ALLOWED_METHODS,
    FORBIDDEN_HEADERS,
    MAX_BODY_BYTES,
    ExperimentContractError,
    _bounded_json_size,
    _contains_control_character,
    _json_path_get,
    _mapping_contains_control_character,
    _origin,
    _render_variables,
    _sensitive_name,
    _sensitive_object_key,
    _variable_references,
    compare_summaries,
    response_summary,
)


WORKFLOW_VERSION = "principal-workflow-2026-07-12.v1"
MAX_WORKFLOW_STEPS = 12
MAX_WORKFLOW_VARIABLES = 40
MAX_WORKFLOW_SECONDS = 180
ALLOWED_STEP_KINDS = {"http", "browser"}
ALLOWED_CHECKPOINTS = {"before", "mutation", "after", "action", "cleanup", "rollback"}
ALLOWED_BROWSER_ACTIONS = {"navigate", "click", "fill", "submit", "wait", "extract"}
PRINCIPAL_SLOT_PATTERN = re.compile(r"^(anonymous|user1|user2|admin|tenant:[A-Za-z0-9_.-]{1,80})$")


class WorkflowContractError(ExperimentContractError):
    pass


def _normalize_extracts(index: int, raw: Any, *, browser: bool) -> list[dict[str, str]]:
    items = raw if isinstance(raw, list) else []
    if len(items) > 8:
        raise WorkflowContractError(f"step_{index}_too_many_extracts")
    result: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            raise WorkflowContractError(f"step_{index}_extract_must_be_object")
        name = str(item.get("name") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) or _sensitive_name(name):
            raise WorkflowContractError(f"step_{index}_extract_name_invalid")
        if browser:
            selector = str(item.get("selector") or "").strip()
            attribute = str(item.get("attribute") or "text").strip()
            if not selector or len(selector) > 500 or len(attribute) > 120:
                raise WorkflowContractError(f"step_{index}_browser_extract_invalid")
            result.append({"name": name, "source": "browser", "selector": selector, "attribute": attribute})
            continue
        source = str(item.get("source") or "json").strip().lower()
        selector = str(item.get("path") if source == "json" else item.get("header") or "").strip()
        if source not in {"json", "header"}:
            raise WorkflowContractError(f"step_{index}_extract_source_not_allowed")
        if source == "json" and (not selector.startswith("$.") or _sensitive_name(selector)):
            raise WorkflowContractError(f"step_{index}_extract_json_path_invalid")
        if source == "header" and (
            not selector or selector.lower() in {"set-cookie", *FORBIDDEN_HEADERS} or _sensitive_name(selector)
        ):
            raise WorkflowContractError(f"step_{index}_extract_header_forbidden")
        result.append({"name": name, "source": source, "selector": selector})
    return result


def _normalize_mapping(index: int, field: str, raw: Any, *, max_items: int) -> dict[str, Any]:
    value = raw if isinstance(raw, dict) else {}
    result: dict[str, Any] = {}
    for key, item in list(value.items())[:max_items]:
        name = str(key).strip()
        if not name or len(name) > 120 or name in result or _sensitive_name(name):
            raise WorkflowContractError(f"step_{index}_{field}_key_forbidden")
        if _contains_control_character(name):
            raise WorkflowContractError(f"step_{index}_{field}_contains_control_character")
        values = item if isinstance(item, list) else [item]
        if not values or any(nested is None or isinstance(nested, (dict, list)) for nested in values):
            raise WorkflowContractError(f"step_{index}_{field}_value_must_be_scalar")
        normalized_values = [str(nested)[:1000] for nested in values]
        if any(_contains_control_character(nested) for nested in normalized_values):
            raise WorkflowContractError(f"step_{index}_{field}_contains_control_character")
        result[name] = normalized_values if isinstance(item, list) else normalized_values[0]
    return result


def normalize_workflow(target_url: str, raw: Any) -> dict[str, Any]:
    payload = raw if isinstance(raw, dict) else {}
    steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    if not 2 <= len(steps) <= MAX_WORKFLOW_STEPS:
        raise WorkflowContractError("workflow_requires_2_to_12_steps")
    target_origin = _origin(target_url)
    labels: set[str] = set()
    declared: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(steps):
        if not isinstance(item, dict):
            raise WorkflowContractError(f"step_{index}_must_be_object")
        label = str(item.get("label") or f"step_{index + 1}").strip()[:80]
        if not label or label in labels:
            raise WorkflowContractError("step_labels_must_be_unique")
        labels.add(label)
        kind = str(item.get("kind") or "http").strip().lower()
        if kind not in ALLOWED_STEP_KINDS:
            raise WorkflowContractError(f"step_{index}_kind_not_allowed")
        principal = str(item.get("principal") or "anonymous").strip().lower()
        if not PRINCIPAL_SLOT_PATTERN.fullmatch(principal):
            raise WorkflowContractError(f"step_{index}_principal_slot_invalid")
        checkpoint = str(item.get("checkpoint") or "action").strip().lower()
        if checkpoint not in ALLOWED_CHECKPOINTS:
            raise WorkflowContractError(f"step_{index}_checkpoint_invalid")
        compare_to = str(item.get("compare_to") or "").strip()
        if compare_to and compare_to not in labels:
            raise WorkflowContractError(f"step_{index}_compare_to_must_reference_prior_step")

        normalized_step: dict[str, Any] = {
            "label": label,
            "kind": kind,
            "principal": principal,
            "checkpoint": checkpoint,
            "compare_to": compare_to,
        }
        reference_values: list[Any] = []
        if kind == "http":
            method = str(item.get("method") or "GET").strip().upper()
            path = str(item.get("path") or "").strip()
            if method not in ALLOWED_METHODS:
                raise WorkflowContractError(f"step_{index}_method_not_allowed")
            if not path.startswith("/") or path.startswith("//") or len(path.encode()) > 2000:
                raise WorkflowContractError(f"step_{index}_path_must_be_relative")
            if _contains_control_character(path):
                raise WorkflowContractError(f"step_{index}_path_contains_control_character")
            rendered_url = urljoin(target_url, path)
            if _origin(rendered_url) != target_origin:
                raise WorkflowContractError(f"step_{index}_resolved_outside_target_origin")
            query = _normalize_mapping(index, "query", item.get("query"), max_items=30)
            headers = _normalize_mapping(index, "headers", item.get("headers"), max_items=20)
            for header in headers:
                if header.lower() in FORBIDDEN_HEADERS:
                    raise WorkflowContractError(f"step_{index}_header_forbidden")
            json_body = item.get("json_body")
            form_body = _normalize_mapping(index, "form_body", item.get("form_body"), max_items=50) if isinstance(item.get("form_body"), dict) else None
            if json_body is not None and form_body is not None:
                raise WorkflowContractError(f"step_{index}_multiple_body_types")
            if _sensitive_object_key(json_body):
                raise WorkflowContractError(f"step_{index}_json_body_sensitive_key_forbidden")
            _bounded_json_size(query)
            _bounded_json_size(json_body)
            _bounded_json_size(form_body)
            extracts = _normalize_extracts(index, item.get("extract"), browser=False)
            normalized_step.update({
                "method": method,
                "path": path,
                "query": query,
                "headers": headers,
                "json_body": json_body,
                "form_body": form_body,
                "extract": extracts,
            })
            reference_values.extend([path, query, headers, json_body, form_body])
        else:
            action = str(item.get("action") or "").strip().lower()
            if action not in ALLOWED_BROWSER_ACTIONS:
                raise WorkflowContractError(f"step_{index}_browser_action_not_allowed")
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            allowed_data = {
                "navigate": {"path"},
                "click": {"selector"},
                "fill": {"selector", "value"},
                "submit": {"selector"},
                "wait": {"selector", "timeout"},
                "extract": {"selector", "attribute"},
            }[action]
            unknown_data = sorted(set(data) - allowed_data)
            if unknown_data:
                raise WorkflowContractError(f"step_{index}_browser_data_field_not_allowed:{unknown_data[0]}")
            if _sensitive_object_key(data):
                raise WorkflowContractError(f"step_{index}_browser_sensitive_field_forbidden")
            if action == "navigate":
                path = str(data.get("path") or "").strip()
                if not path.startswith("/") or path.startswith("//") or _origin(urljoin(target_url, path)) != target_origin:
                    raise WorkflowContractError(f"step_{index}_browser_path_must_be_relative")
                if _contains_control_character(path):
                    raise WorkflowContractError(f"step_{index}_browser_path_contains_control_character")
            if action in {"click", "fill", "submit", "wait", "extract"}:
                selector = str(data.get("selector") or "").strip()
                if not selector or len(selector) > 500:
                    raise WorkflowContractError(f"step_{index}_browser_selector_required")
                if action == "fill" and _sensitive_name(selector):
                    raise WorkflowContractError(f"step_{index}_browser_sensitive_fill_forbidden")
            if action == "wait":
                try:
                    wait_timeout = int(data.get("timeout") or 5000)
                except (TypeError, ValueError) as exc:
                    raise WorkflowContractError(f"step_{index}_browser_wait_timeout_invalid") from exc
                if not 0 <= wait_timeout <= 10_000:
                    raise WorkflowContractError(f"step_{index}_browser_wait_timeout_invalid")
                data = {**data, "timeout": wait_timeout}
            _bounded_json_size(data, limit=4096)
            extracts = _normalize_extracts(index, item.get("extract"), browser=True)
            if action == "extract" and len(extracts) != 1:
                raise WorkflowContractError(f"step_{index}_browser_extract_requires_one_variable")
            if action != "extract" and extracts:
                raise WorkflowContractError(f"step_{index}_browser_extract_only_allowed_for_extract_action")
            normalized_step.update({"action": action, "data": data, "extract": extracts})
            reference_values.append(data)

        extract_names = [spec["name"] for spec in extracts]
        if len(extract_names) != len(set(extract_names)) or any(name in declared for name in extract_names):
            raise WorkflowContractError(f"step_{index}_extract_name_ambiguous")
        if len(declared) + len(extract_names) > MAX_WORKFLOW_VARIABLES:
            raise WorkflowContractError("workflow_variable_limit_exceeded")
        references = set().union(*(_variable_references(value) for value in reference_values)) if reference_values else set()
        missing = sorted(references - declared)
        if missing:
            raise WorkflowContractError(f"step_{index}_variable_not_declared:{missing[0]}")
        declared.update(extract_names)
        normalized.append(normalized_step)

    timeout_seconds = max(1, min(int(payload.get("timeout_seconds") or 30), MAX_WORKFLOW_SECONDS))
    return {
        "version": WORKFLOW_VERSION,
        "objective": str(payload.get("objective") or "").strip()[:1000],
        "expected_signal": str(payload.get("expected_signal") or "").strip()[:1000],
        "falsifier": str(payload.get("falsifier") or "").strip()[:1000],
        "target_url": target_url,
        "timeout_seconds": timeout_seconds,
        "steps": normalized,
    }


def validate_principal_contexts(contexts: dict[str, dict[str, Any]], used_slots: set[str]) -> list[dict[str, Any]]:
    nonanonymous = sorted(slot for slot in used_slots if slot != "anonymous")
    receipts: list[dict[str, Any]] = []
    profile_ids: dict[str, str] = {}
    identities: dict[str, str] = {}
    for slot in nonanonymous:
        context = contexts.get(slot)
        if not context:
            raise WorkflowContractError(f"principal_context_missing:{slot}")
        profile_id = str(context.get("profile_id") or "").strip()
        identity = str(context.get("identity_fingerprint") or "").strip()
        if not profile_id:
            raise WorkflowContractError(f"principal_profile_missing:{slot}")
        if len(nonanonymous) > 1 and not identity:
            raise WorkflowContractError(f"principal_identity_unverified:{slot}")
        if profile_id in profile_ids:
            raise WorkflowContractError(f"principal_profiles_not_distinct:{profile_ids[profile_id]}:{slot}")
        if identity and identity in identities:
            raise WorkflowContractError(f"principal_accounts_not_distinct:{identities[identity]}:{slot}")
        profile_ids[profile_id] = slot
        if identity:
            identities[identity] = slot
        receipts.append({
            "slot": slot,
            "principal_id": context.get("principal_id"),
            "profile_id": profile_id,
            "identity_fingerprint": identity or None,
            "role": context.get("role"),
            "tenant_id": context.get("tenant_id"),
            "identity_verified": bool(identity),
        })
    return receipts


BrowserAction = Callable[[str, str, dict[str, Any]], Awaitable[dict[str, Any]]]
CancelCheck = Callable[[], bool]


async def execute_workflow(
    target_url: str,
    raw: Any,
    *,
    principal_contexts: dict[str, dict[str, Any]],
    browser_action: BrowserAction | None = None,
    cancelled: CancelCheck | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    workflow = normalize_workflow(target_url, raw)
    used_slots = {step["principal"] for step in workflow["steps"]}
    receipts = validate_principal_contexts(principal_contexts, used_slots)
    variables: dict[str, str] = {}
    observations: list[dict[str, Any]] = []
    request_count = 0
    started = time.monotonic()
    timeout = httpx.Timeout(min(workflow["timeout_seconds"], 15))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False, transport=transport) as client:
        for step in workflow["steps"]:
            if (cancelled and cancelled()) or time.monotonic() - started > workflow["timeout_seconds"]:
                observations.append({"label": step["label"], "kind": step["kind"], "error": "workflow_cancelled_or_timed_out"})
                break
            extracted: dict[str, str] = {}
            response: dict[str, Any] | None = None
            request_view: dict[str, Any] = {"kind": step["kind"], "principal": step["principal"]}
            error: str | None = None
            try:
                if step["kind"] == "http":
                    path = _render_variables(step["path"], variables)
                    url = urljoin(target_url, path)
                    if not str(path).startswith("/") or str(path).startswith("//") or _origin(url) != _origin(target_url):
                        raise WorkflowContractError("rendered_path_outside_target_origin")
                    query = _render_variables(step["query"], variables)
                    headers = _render_variables(step["headers"], variables)
                    json_body = _render_variables(step["json_body"], variables)
                    form_body = _render_variables(step["form_body"], variables)
                    if len(str(path).encode()) > 4000:
                        raise WorkflowContractError("rendered_path_exceeds_size_limit")
                    if _contains_control_character(path):
                        raise WorkflowContractError("rendered_path_contains_control_character")
                    _bounded_json_size(query)
                    _bounded_json_size(json_body)
                    _bounded_json_size(form_body)
                    if any(
                        not str(name).strip()
                        or str(name).strip().lower() in FORBIDDEN_HEADERS
                        or _sensitive_name(name)
                        or _contains_control_character(name)
                        or _contains_control_character(value)
                        or not str(name).isascii()
                        or not str(value).isascii()
                        for name, value in headers.items()
                    ):
                        raise WorkflowContractError("rendered_header_forbidden")
                    if any(_sensitive_object_key(value) for value in (query, json_body, form_body)):
                        raise WorkflowContractError("rendered_sensitive_key_forbidden")
                    if _mapping_contains_control_character(query):
                        raise WorkflowContractError("rendered_query_contains_control_character")
                    context = principal_contexts.get(step["principal"], {})
                    auth_headers = context.get("headers") if isinstance(context.get("headers"), dict) else {}
                    cookies = context.get("cookies") if isinstance(context.get("cookies"), dict) else {}
                    headers = {**headers, **auth_headers}
                    request_view.update({"method": step["method"], "path": path, "query_keys": sorted(query), "body_kind": "json" if json_body is not None else "form" if form_body is not None else None})
                    request = client.build_request(step["method"], url, params=query, headers=headers, cookies=cookies, json=json_body, data=form_body)
                    request_count += 1
                    request_started = time.perf_counter()
                    http_response = await client.send(request, stream=True)
                    chunks: list[bytes] = []
                    received = 0
                    try:
                        async for chunk in http_response.aiter_bytes():
                            remaining = MAX_BODY_BYTES + 1 - received
                            if remaining <= 0:
                                break
                            chunks.append(chunk[:remaining])
                            received += min(len(chunk), remaining)
                            if received > MAX_BODY_BYTES:
                                break
                    finally:
                        await http_response.aclose()
                    body = b"".join(chunks)
                    response = response_summary(http_response, body, elapsed_ms=round((time.perf_counter() - request_started) * 1000))
                    parsed: Any = None
                    try:
                        parsed = json.loads(body[:MAX_BODY_BYTES].decode(http_response.encoding or "utf-8", errors="replace"))
                    except (TypeError, ValueError):
                        pass
                    for spec in step["extract"]:
                        value = _json_path_get(parsed, spec["selector"]) if spec["source"] == "json" else http_response.headers.get(spec["selector"])
                        if value is None:
                            raise WorkflowContractError(f"extract_value_missing:{spec['name']}")
                        rendered_value = str(value)[:1000]
                        if _contains_control_character(rendered_value):
                            raise WorkflowContractError(f"extract_value_contains_control_character:{spec['name']}")
                        extracted[spec["name"]] = rendered_value
                else:
                    if not browser_action:
                        raise WorkflowContractError("browser_runtime_unavailable")
                    data = _render_variables(step["data"], variables)
                    _bounded_json_size(data, limit=4096)
                    if _sensitive_object_key(data):
                        raise WorkflowContractError("rendered_browser_sensitive_field_forbidden")
                    if step["action"] == "navigate":
                        path = str(data.get("path") or "")
                        if not path.startswith("/") or path.startswith("//") or _origin(urljoin(target_url, path)) != _origin(target_url):
                            raise WorkflowContractError("rendered_browser_path_outside_target_origin")
                    if step["action"] == "fill" and _sensitive_name(data.get("selector")):
                        raise WorkflowContractError("rendered_browser_sensitive_fill_forbidden")
                    result = await browser_action(step["principal"], step["action"], data)
                    response = {"success": bool(result.get("success")), "url": result.get("url"), "value_present": result.get("value") is not None}
                    request_view.update({"action": step["action"], "selector": data.get("selector")})
                    if not result.get("success"):
                        raise WorkflowContractError(str(result.get("error") or "browser_action_failed"))
                    for spec in step["extract"]:
                        value = result.get("value")
                        if value is None or isinstance(value, (dict, list)):
                            raise WorkflowContractError(f"extract_value_missing:{spec['name']}")
                        rendered_value = str(value)[:1000]
                        if _contains_control_character(rendered_value):
                            raise WorkflowContractError(f"extract_value_contains_control_character:{spec['name']}")
                        extracted[spec["name"]] = rendered_value
                variables.update(extracted)
            except (httpx.InvalidURL, httpx.HTTPError, WorkflowContractError, UnicodeError, ValueError) as exc:
                error = str(exc) if isinstance(exc, WorkflowContractError) else type(exc).__name__
            observations.append({
                "label": step["label"], "kind": step["kind"], "principal": step["principal"],
                "checkpoint": step["checkpoint"], "compare_to": step["compare_to"],
                "request": request_view, "response": response,
                "extracted": {name: {"sha256": hashlib.sha256(value.encode()).hexdigest(), "length": len(value)} for name, value in extracted.items()} if not error else {},
                "error": error,
            })
    by_label = {item["label"]: item for item in observations}
    comparisons: list[dict[str, Any]] = []
    for item in observations:
        if not item.get("compare_to"):
            continue
        control = by_label.get(item["compare_to"], {})
        if item.get("kind") == "http" and control.get("kind") == "http":
            comparison = compare_summaries({} if control.get("error") else control.get("response") or {}, {} if item.get("error") else item.get("response") or {})
        else:
            comparison = {"comparable": not control.get("error") and not item.get("error"), "state_changed": control.get("response") != item.get("response")}
        comparisons.append({"control": item["compare_to"], "candidate": item["label"], **comparison})
    return {
        "version": WORKFLOW_VERSION,
        "objective": workflow["objective"],
        "expected_signal": workflow["expected_signal"],
        "falsifier": workflow["falsifier"],
        "request_count": request_count,
        "step_count": len(observations),
        "principal_receipts": receipts,
        "variable_names": sorted(variables),
        "observations": observations,
        "comparisons": comparisons,
        "cancelled": any(item.get("error") == "workflow_cancelled_or_timed_out" for item in observations),
        "finding_created": False,
        "proof_state": "unverified_workflow_signal",
    }
