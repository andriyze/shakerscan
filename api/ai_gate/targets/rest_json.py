from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ai_gate.budget import CHARS_PER_TOKEN_ESTIMATE


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def replace_placeholders(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for key, replacement in replacements.items():
            result = result.replace(f"{{{{{key}}}}}", replacement)
        return result
    if isinstance(value, list):
        return [replace_placeholders(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_placeholders(item, replacements) for key, item in value.items()}
    return value


def _extract_path_value(payload: Any, response_path: str | None) -> Any:
    if not response_path:
        return payload

    normalized = response_path.strip()
    if not normalized:
        return payload
    if normalized == "$":
        return payload

    if normalized.startswith("$."):
        normalized = normalized[2:]

    current = payload
    for part in normalized.split("."):
        if isinstance(current, list):
            try:
                index = int(part)
            except ValueError:
                return None
            if index < 0 or index >= len(current):
                return None
            current = current[index]
            continue

        if not isinstance(current, dict):
            return None

        if part not in current:
            return None
        current = current[part]

    return current


def _coerce_response_text(payload: Any, response_path: str | None) -> str:
    extracted = _extract_path_value(payload, response_path)
    if extracted is None and response_path:
        extracted = payload

    if isinstance(extracted, str):
        return extracted
    if isinstance(extracted, (int, float, bool)):
        return str(extracted)
    if isinstance(extracted, list):
        parts = [item for item in (_coerce_response_text(item, None) for item in extracted) if item]
        return "\n".join(parts)
    if isinstance(extracted, dict):
        for key in (
            "answer",
            "response",
            "result",
            "choices",
            "delta",
            "content",
            "message",
            "output_text",
            "output",
            "text",
        ):
            if key in extracted:
                preferred_text = _coerce_response_text(extracted[key], None)
                if preferred_text.strip():
                    return preferred_text
        return json.dumps(extracted, ensure_ascii=False)
    if extracted is None:
        return ""
    return str(extracted)


SECURITY_CONTEXT_KEYS = (
    "run_id",
    "run_type",
    "surface",
    "events",
    "output",
    "reasoning",
    "steps",
    "tool_calls",
    "handoffs",
    "tools_available",
    "sources",
    "retrieval_metadata",
    "runtime_state",
    "action",
    "selector",
    "performed",
    "policy",
    "warning",
    "deleted_at",
    "hidden_instructions",
    "oauth_scopes",
    "default_scopes",
    "high_risk_actions",
    "auth",
    "capabilities",
    "findings",
    "exfiltrated",
    "task",
    "approval_token_present",
    "caller_verified",
    "permissions_inherited",
    "parent_context_shared",
    "context_transferred",
    "requested_capabilities",
    "provenance_verified",
    "local_tools_enabled",
    "artifact_preview",
    "page_title",
    "target_url",
    "cookies_preview",
    "metadata_preview",
    "models",
    "runner_host",
    "auth_required",
    "rate_limit",
)


def _extract_security_context(payload: Any, response_path: str | None, response_text: str) -> str:
    if not response_path or not isinstance(payload, dict) or not response_text.strip():
        return response_text

    supplements: list[str] = []
    for key in SECURITY_CONTEXT_KEYS:
        if key not in payload:
            continue
        extra_text = _coerce_response_text(payload[key], None).strip()
        if not extra_text:
            continue
        supplements.append(f"{key}: {extra_text}")

    if not supplements:
        return response_text

    return response_text + "\n\n" + "\n".join(supplements)


def extract_response_text(raw_text: str, content_type: str, response_path: str | None) -> str:
    if "text/event-stream" in content_type:
        chunks: list[str] = []
        for line in raw_text.splitlines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            try:
                parsed = json.loads(data)
                text = _coerce_response_text(parsed, response_path)
            except json.JSONDecodeError:
                text = data
            if text:
                chunks.append(text)
        return "\n".join(chunks)

    if "json" in content_type:
        try:
            payload = json.loads(raw_text)
            response_text = _coerce_response_text(payload, response_path)
            return _extract_security_context(payload, response_path, response_text)
        except json.JSONDecodeError:
            return raw_text

    return raw_text


def build_headers(target: dict[str, Any]) -> dict[str, str]:
    headers = {}
    for key, value in as_dict(target.get("headers_template")).items():
        if isinstance(value, str) and key.strip():
            headers[key.strip()] = value

    credential = as_dict(target.get("credential"))
    auth_kind = credential.get("auth_kind") or "none"
    secret = credential.get("secret")
    header_name = credential.get("header_name")
    metadata = as_dict(credential.get("metadata_json"))

    if auth_kind == "multi_header":
        for pair in metadata.get("headers") or []:
            if isinstance(pair, dict):
                h_name = pair.get("name", "")
                h_value = pair.get("value", "")
                if isinstance(h_name, str) and h_name.strip() and isinstance(h_value, str):
                    headers[h_name.strip()] = h_value
        return headers

    if auth_kind == "cookie" and isinstance(secret, str) and secret:
        headers["Cookie"] = secret
        return headers

    if not isinstance(secret, str) or not secret:
        return headers

    if auth_kind == "bearer":
        headers["Authorization"] = f"Bearer {secret}"
    elif auth_kind == "basic_auth":
        import base64
        headers["Authorization"] = f"Basic {base64.b64encode(secret.encode()).decode()}"
    elif auth_kind in {"api_key_header", "custom_header"} and isinstance(header_name, str) and header_name:
        headers[header_name] = secret

    return headers


def build_url(endpoint_url: str, target: dict[str, Any]) -> str:
    credential = as_dict(target.get("credential"))
    auth_kind = credential.get("auth_kind") or "none"
    if auth_kind != "query_param":
        return endpoint_url

    secret = credential.get("secret")
    metadata = as_dict(credential.get("metadata_json"))
    param_name = metadata.get("param_name")
    if not isinstance(param_name, str) or not param_name or not isinstance(secret, str) or not secret:
        return endpoint_url

    parsed = urlparse(endpoint_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [secret]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def append_query_params(endpoint_url: str, params: dict[str, Any]) -> str:
    parsed = urlparse(endpoint_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, str):
            serialized = value
        elif isinstance(value, bool):
            serialized = json.dumps(value)
        elif isinstance(value, (int, float)):
            serialized = str(value)
        else:
            serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        query[key] = [serialized]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _merge_headers(base_headers: dict[str, str], extra_headers: Any) -> dict[str, str]:
    headers = dict(base_headers)
    if not isinstance(extra_headers, dict):
        return headers
    for key, value in extra_headers.items():
        if isinstance(key, str) and key.strip() and isinstance(value, str):
            headers[key.strip()] = value
    return headers


def _serialize_replacement_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _lifecycle_manifest_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _parse_response_payload(raw_text: str, content_type: str) -> Any:
    if "json" not in content_type:
        return raw_text
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text


def _coerce_int(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        coerced = default
    return min(max(coerced, minimum), maximum)


def _coerce_float(value: Any, default: float, *, minimum: float, maximum: float) -> float:
    try:
        coerced = float(value)
    except (TypeError, ValueError):
        coerced = default
    return min(max(coerced, minimum), maximum)


def _values_match(actual: Any, expected: Any) -> bool:
    if actual == expected:
        return True
    return _serialize_replacement_value(actual) == _serialize_replacement_value(expected)


def _contains_value(actual: Any, expected: Any) -> bool:
    if isinstance(actual, list):
        return any(_values_match(item, expected) for item in actual)
    return _serialize_replacement_value(expected) in _serialize_replacement_value(actual)


@dataclass
class ConversationExchange:
    request_method: str
    status_code: int | None
    latency_ms: float
    prompt: str
    response_excerpt: str = ""
    error: str | None = None
    input_chars: int = 0
    output_chars: int = 0
    response_metadata: dict[str, Any] | None = None

    def to_transcript(self, probe: dict[str, str]) -> dict[str, Any]:
        transcript = {
            "probe_id": probe["id"],
            "probe_family": probe["family"],
            "request_method": self.request_method,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "prompt": self.prompt,
        }
        if self.error is not None:
            transcript["error"] = self.error
            if self.response_metadata:
                transcript["response_metadata"] = self.response_metadata
            return transcript
        transcript["response_excerpt"] = self.response_excerpt[:2000]
        transcript["tokens_estimated"] = {
            "input": max(self.input_chars // CHARS_PER_TOKEN_ESTIMATE, 1),
            "output": max(self.output_chars // CHARS_PER_TOKEN_ESTIMATE, 1),
        }
        if self.response_metadata:
            transcript["response_metadata"] = self.response_metadata
        return transcript


class RestJsonConversationTarget:
    def __init__(self, target_url: str, target: dict[str, Any]) -> None:
        self.target = target
        self.method = str(target.get("method") or "POST").upper()
        raw_url = str(target.get("endpoint_url") or target_url).strip()
        if self.method not in {"GET", "POST", "PUT", "PATCH"}:
            raise ValueError(f"Unsupported AI target method: {self.method}")
        if not raw_url:
            raise ValueError("AI target endpoint_url is required")

        self.endpoint_url = build_url(raw_url, target)
        raw_request_template = target.get("request_template")
        if raw_request_template is None:
            raw_request_template = {}
        if not isinstance(raw_request_template, dict):
            raise ValueError("AI target request_template must be a JSON object")
        self.request_template = as_dict(raw_request_template)
        if self.method != "GET" and not self.request_template:
            raise ValueError("AI target request_template must be a JSON object")

        self.response_path = (
            target.get("response_path") if isinstance(target.get("response_path"), str) else None
        )
        self.headers = build_headers(target)
        self.streaming_mode = "sse" if target.get("streaming_mode") == "sse" else "json"
        if self.streaming_mode == "sse":
            self.headers.setdefault("Accept", "text/event-stream")
        metadata = as_dict(target.get("metadata_json"))
        self.setup_requests = self._read_lifecycle_requests(
            metadata,
            "setup_requests",
            "rag_setup_requests",
        )
        self.cleanup_requests = self._read_lifecycle_requests(
            metadata,
            "cleanup_requests",
            "rag_cleanup_requests",
        )
        configured_preflight = metadata.get("preflight_requests")
        if isinstance(configured_preflight, list):
            self.preflight_requests = tuple(
                item for item in configured_preflight if isinstance(item, dict)
            )
        elif metadata.get("preset_slug") == "mcp_server":
            self.preflight_requests = (
                {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "clientInfo": {"name": "Shaker AI Gate", "version": "0.1"},
                        "capabilities": {},
                    },
                    "id": "{{session_id}}-initialize",
                },
            )
        else:
            self.preflight_requests = ()
        self._preflight_completed_session_ids: set[str] = set()
        self._setup_completed_session_ids: set[str] = set()
        self._setup_failed_session_errors: dict[str, str] = {}
        self._cleanup_eligible_session_ids: set[str] = set()
        self._cleanup_completed_session_ids: set[str] = set()
        self._session_replacements: dict[str, dict[str, str]] = {}
        self._lifecycle_events: list[dict[str, Any]] = []
        self._lifecycle_captured_keys: set[str] = set()

    def get_session_canary_tokens(self, session_id: str) -> list[str]:
        replacements = self._session_replacements.get(session_id)
        if not replacements:
            return []

        canary_tokens: list[str] = []
        canary_key_fragments = (
            "canary",
            "document_id",
            "indexed_document_id",
            "source_id",
            "citation_id",
        )
        for key, value in replacements.items():
            normalized_key = key.strip().lower()
            if not any(fragment in normalized_key for fragment in canary_key_fragments):
                continue
            token = value.strip()
            if 6 <= len(token) <= 200:
                canary_tokens.append(token)

        return list(dict.fromkeys(canary_tokens))

    def _read_lifecycle_requests(
        self,
        metadata: dict[str, Any],
        *keys: str,
    ) -> tuple[dict[str, Any], ...]:
        for key in keys:
            configured = metadata.get(key)
            if isinstance(configured, list):
                return tuple(item for item in configured if isinstance(item, dict))
        return ()

    async def _send_lifecycle_request(
        self,
        session: Any,
        request_config: dict[str, Any],
        replacements: dict[str, str],
        *,
        phase: str,
    ) -> tuple[int, str, Any]:
        method = str(request_config.get("method") or self.method).upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"{phase} request method must be GET, POST, PUT, PATCH, or DELETE")

        configured_url = (
            request_config.get("url")
            or request_config.get("endpoint_url")
            or request_config.get("target_url")
            or self.endpoint_url
        )
        if not isinstance(configured_url, str) or not configured_url.strip():
            raise ValueError(f"{phase} request url is required")
        request_url = replace_placeholders(configured_url.strip(), replacements)

        query_template = request_config.get("query")
        if isinstance(query_template, dict):
            request_url = append_query_params(
                request_url,
                replace_placeholders(query_template, replacements),
            )

        body_template = (
            request_config["json"]
            if "json" in request_config
            else request_config.get("body", request_config.get("request_template", {}))
        )
        body = replace_placeholders(body_template, replacements)
        headers = _merge_headers(
            self.headers,
            replace_placeholders(request_config.get("headers"), replacements),
        )
        request_kwargs: dict[str, Any] = {"headers": headers}
        if method not in {"GET", "DELETE"}:
            request_kwargs["json"] = body if isinstance(body, (dict, list)) else {}

        async with session.request(method, request_url, **request_kwargs) as response:
            raw_text = await response.text()
            content_type = response.headers.get("Content-Type", "")
            return response.status, raw_text, _parse_response_payload(raw_text, content_type)

    def _capture_lifecycle_values(
        self,
        request_config: dict[str, Any],
        payload: Any,
        replacements: dict[str, str],
    ) -> dict[str, str]:
        capture_config = request_config.get("capture") or request_config.get("captures")
        if not isinstance(capture_config, dict):
            return {}

        captured: dict[str, str] = {}
        for key, path in capture_config.items():
            if not isinstance(key, str) or not key.strip() or not isinstance(path, str):
                continue
            value = _extract_path_value(payload, path)
            serialized = _serialize_replacement_value(value)
            if serialized:
                captured[key.strip()] = serialized

        replacements.update(captured)
        self._lifecycle_captured_keys.update(captured.keys())
        return captured

    def _read_wait_config(self, request_config: dict[str, Any]) -> dict[str, Any] | None:
        configured = (
            request_config.get("wait_for")
            or request_config.get("wait_until")
            or request_config.get("wait_request")
        )
        return configured if isinstance(configured, dict) else None

    def _evaluate_wait_condition(
        self,
        wait_config: dict[str, Any],
        *,
        status: int,
        payload: Any,
    ) -> tuple[bool, Any]:
        expected_status = wait_config.get("status_code", wait_config.get("status"))
        if expected_status is not None:
            allowed_statuses = (
                expected_status if isinstance(expected_status, list) else [expected_status]
            )
            normalized_statuses = {
                int(item)
                for item in allowed_statuses
                if isinstance(item, (int, str)) and str(item).isdigit()
            }
            if status not in normalized_statuses:
                return False, None
        elif status < 200 or status >= 400:
            return False, None

        response_path = wait_config.get("response_path") or wait_config.get("path")
        response_path = response_path if isinstance(response_path, str) else None
        actual = _extract_path_value(payload, response_path)

        if "exists" in wait_config:
            exists = actual is not None
            expected_exists = wait_config.get("exists")
            if isinstance(expected_exists, str):
                expected_exists = expected_exists.strip().lower() not in {"0", "false", "no"}
            else:
                expected_exists = bool(expected_exists)
            return exists is expected_exists, actual

        expected_values: list[Any] | None = None
        if "equals" in wait_config:
            expected_values = [wait_config["equals"]]
        elif "value" in wait_config:
            expected_values = [wait_config["value"]]
        elif "expected" in wait_config:
            expected_values = [wait_config["expected"]]
        elif isinstance(wait_config.get("in"), list):
            expected_values = wait_config["in"]

        if expected_values is not None:
            return any(_values_match(actual, expected) for expected in expected_values), actual

        if "not_equals" in wait_config:
            return not _values_match(actual, wait_config["not_equals"]), actual

        if "contains" in wait_config:
            return _contains_value(actual, wait_config["contains"]), actual

        return True, actual

    async def _wait_for_lifecycle_condition(
        self,
        session: Any,
        wait_config: dict[str, Any],
        replacements: dict[str, str],
        *,
        setup_index: int,
    ) -> str | None:
        max_attempts = _coerce_int(
            wait_config.get("max_attempts", wait_config.get("attempts")),
            5,
            minimum=1,
            maximum=20,
        )
        interval_seconds = _coerce_float(
            wait_config.get("interval_seconds", wait_config.get("poll_interval_seconds")),
            0.5,
            minimum=0.0,
            maximum=5.0,
        )

        last_status: int | None = None
        last_value: Any = None
        last_error: str | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                status, raw_text, payload = await self._send_lifecycle_request(
                    session,
                    wait_config,
                    replacements,
                    phase="setup wait",
                )
                last_status = status
                matched, actual = self._evaluate_wait_condition(
                    wait_config,
                    status=status,
                    payload=payload,
                )
                last_value = actual
                event: dict[str, Any] = {
                    "phase": "setup_wait",
                    "index": setup_index,
                    "attempt": attempt,
                    "status_code": status,
                    "matched": matched,
                }
                if actual is not None:
                    event["value"] = _serialize_replacement_value(actual)[:200]
                if status < 200 or status >= 400:
                    event["error"] = raw_text[:400]
                captured = self._capture_lifecycle_values(wait_config, payload, replacements)
                if captured:
                    event["captured"] = sorted(captured.keys())
                self._lifecycle_events.append(event)
                if matched:
                    return None
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                self._lifecycle_events.append(
                    {
                        "phase": "setup_wait",
                        "index": setup_index,
                        "attempt": attempt,
                        "error": last_error,
                        "matched": False,
                    }
                )

            if attempt < max_attempts and interval_seconds > 0:
                await asyncio.sleep(interval_seconds)

        if last_error:
            return f"Setup wait failed after {max_attempts} attempts: {last_error}"

        value = _serialize_replacement_value(last_value)
        status_detail = f"last status {last_status}" if last_status is not None else "no response"
        value_detail = f", last value {value[:200]}" if value else ""
        return (
            f"Setup wait condition was not satisfied after {max_attempts} attempts "
            f"({status_detail}{value_detail})"
        )

    async def _ensure_lifecycle_setup(
        self,
        session: Any,
        *,
        session_id: str,
        replacements: dict[str, str],
    ) -> str | None:
        if not self.setup_requests or session_id in self._setup_completed_session_ids:
            return None
        if session_id in self._setup_failed_session_errors:
            return self._setup_failed_session_errors[session_id]

        session_replacements = self._session_replacements.setdefault(session_id, {})
        replacements.update(session_replacements)
        for index, setup_request in enumerate(self.setup_requests):
            try:
                status, raw_text, payload = await self._send_lifecycle_request(
                    session,
                    setup_request,
                    replacements,
                    phase="setup",
                )
                event = {"phase": "setup", "index": index, "status_code": status}
                if status < 200 or status >= 400:
                    event["error"] = raw_text[:400]
                    self._lifecycle_events.append(event)
                    error = f"Setup request failed with {status}: {raw_text[:400]}"
                    self._setup_failed_session_errors[session_id] = error
                    return error
                captured = self._capture_lifecycle_values(setup_request, payload, replacements)
                if captured:
                    session_replacements.update(captured)
                    event["captured"] = sorted(captured.keys())
                self._lifecycle_events.append(event)
                self._cleanup_eligible_session_ids.add(session_id)
                wait_config = self._read_wait_config(setup_request)
                if wait_config is not None:
                    wait_error = await self._wait_for_lifecycle_condition(
                        session,
                        wait_config,
                        replacements,
                        setup_index=index,
                    )
                    session_replacements.update(
                        {
                            key: value
                            for key, value in replacements.items()
                            if key not in {"prompt", "probe_id", "session_id"}
                        }
                    )
                    if wait_error is not None:
                        self._setup_failed_session_errors[session_id] = wait_error
                        return wait_error
            except Exception as exc:  # noqa: BLE001
                self._lifecycle_events.append(
                    {"phase": "setup", "index": index, "error": str(exc)}
                )
                error = f"Setup request failed: {exc}"
                self._setup_failed_session_errors[session_id] = error
                return error

        self._setup_completed_session_ids.add(session_id)
        return None

    async def finalize_session(self, session: Any, session_id: str) -> None:
        if (
            not self.cleanup_requests
            or session_id in self._cleanup_completed_session_ids
            or session_id not in self._cleanup_eligible_session_ids
        ):
            return

        replacements = {
            "session_id": session_id,
            **self._session_replacements.get(session_id, {}),
        }
        for index, cleanup_request in enumerate(self.cleanup_requests):
            try:
                status, raw_text, _payload = await self._send_lifecycle_request(
                    session,
                    cleanup_request,
                    replacements,
                    phase="cleanup",
                )
                event = {"phase": "cleanup", "index": index, "status_code": status}
                if status < 200 or status >= 400:
                    event["error"] = raw_text[:400]
                self._lifecycle_events.append(event)
            except Exception as exc:  # noqa: BLE001
                self._lifecycle_events.append(
                    {"phase": "cleanup", "index": index, "error": str(exc)}
                )

        self._cleanup_completed_session_ids.add(session_id)

    def describe_lifecycle_summary(self) -> dict[str, Any] | None:
        if not self.setup_requests and not self.cleanup_requests:
            return None
        manifest = {
            "setup_requests": self.setup_requests,
            "cleanup_requests": self.cleanup_requests,
        }
        canary_token_count = 0
        for session_id in self._session_replacements:
            canary_token_count += len(self.get_session_canary_tokens(session_id))
        return {
            "manifest_hash": "sha256:"
            + _lifecycle_manifest_hash(manifest),
            "setup_request_count": len(self.setup_requests),
            "cleanup_request_count": len(self.cleanup_requests),
            "setup_completed_session_count": len(self._setup_completed_session_ids),
            "cleanup_completed_session_count": len(self._cleanup_completed_session_ids),
            "wait_event_count": sum(
                1 for event in self._lifecycle_events if event.get("phase") == "setup_wait"
            ),
            "captured_keys": sorted(self._lifecycle_captured_keys),
            "canary_token_count": canary_token_count,
            "events": self._lifecycle_events,
        }

    async def _ensure_preflight(
        self,
        session: Any,
        *,
        session_id: str,
        replacements: dict[str, str],
    ) -> str | None:
        if not self.preflight_requests or session_id in self._preflight_completed_session_ids:
            return None

        for preflight_request in self.preflight_requests:
            body = replace_placeholders(preflight_request, replacements)
            request_url = (
                append_query_params(self.endpoint_url, body)
                if self.method == "GET"
                else self.endpoint_url
            )
            try:
                async with session.request(
                    self.method,
                    request_url,
                    **({} if self.method == "GET" else {"json": body}),
                    headers=self.headers,
                ) as response:
                    raw_text = await response.text()
                    if response.status < 200 or response.status >= 400:
                        return (
                            f"Preflight request failed with {response.status}: "
                            f"{raw_text[:400]}"
                        )
            except Exception as exc:  # noqa: BLE001
                return f"Preflight request failed: {exc}"

        self._preflight_completed_session_ids.add(session_id)
        return None

    async def send_message(
        self,
        session: Any,
        *,
        prompt: str,
        probe_id: str,
        session_id: str,
        replacements: dict[str, str] | None = None,
    ) -> ConversationExchange:
        runtime_replacements = {
            "prompt": prompt,
            "probe_id": probe_id,
            "session_id": session_id,
        }
        if replacements:
            runtime_replacements.update(replacements)
        runtime_replacements.update(self._session_replacements.get(session_id, {}))

        setup_error = await self._ensure_lifecycle_setup(
            session,
            session_id=session_id,
            replacements=runtime_replacements,
        )
        if setup_error is not None:
            return ConversationExchange(
                request_method=self.method,
                status_code=None,
                latency_ms=0.0,
                prompt=prompt,
                error=setup_error,
            )
        runtime_replacements.update(self._session_replacements.get(session_id, {}))

        preflight_error = await self._ensure_preflight(
            session,
            session_id=session_id,
            replacements=runtime_replacements,
        )
        if preflight_error is not None:
            return ConversationExchange(
                request_method=self.method,
                status_code=None,
                latency_ms=0.0,
                prompt=prompt,
                error=preflight_error,
            )

        body = replace_placeholders(
            self.request_template,
            runtime_replacements,
        )
        request_url = append_query_params(self.endpoint_url, body) if self.method == "GET" else self.endpoint_url

        input_chars = len(json.dumps(body, ensure_ascii=False))
        started = time.perf_counter()
        try:
            async with session.request(
                self.method,
                request_url,
                **({} if self.method == "GET" else {"json": body}),
                headers=self.headers,
            ) as response:
                raw_text = await response.text()
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
                content_type = response.headers.get("Content-Type", "")
                response_text = extract_response_text(raw_text, content_type, self.response_path)
                stream_event_count = (
                    sum(1 for line in raw_text.splitlines() if line.startswith("data:"))
                    if "text/event-stream" in content_type or self.streaming_mode == "sse"
                    else 0
                )
                response_metadata: dict[str, Any] = {
                    "streaming_mode": self.streaming_mode,
                    "content_type": content_type,
                }
                if stream_event_count:
                    response_metadata["stream_event_count"] = stream_event_count
                return ConversationExchange(
                    request_method=self.method,
                    status_code=response.status,
                    latency_ms=elapsed_ms,
                    prompt=prompt,
                    response_excerpt=response_text,
                    input_chars=input_chars,
                    output_chars=len(raw_text),
                    response_metadata=response_metadata,
                )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            return ConversationExchange(
                request_method=self.method,
                status_code=None,
                latency_ms=elapsed_ms,
                prompt=prompt,
                error=str(exc),
                input_chars=input_chars,
                response_metadata={"streaming_mode": self.streaming_mode},
            )

    async def send_probe(self, session: Any, probe: dict[str, str], session_id: str) -> ConversationExchange:
        return await self.send_message(
            session,
            prompt=probe["prompt"],
            probe_id=probe["id"],
            session_id=session_id,
        )


class SseConversationTarget(RestJsonConversationTarget):
    def __init__(self, target_url: str, target: dict[str, Any]) -> None:
        sse_target = dict(target)
        sse_target["streaming_mode"] = "sse"
        super().__init__(target_url, sse_target)
