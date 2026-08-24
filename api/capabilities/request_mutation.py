"""Worker-private, target-bound verification of saved JSON and form requests."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
import re
import time
from typing import Any, Mapping, Sequence
import urllib.parse

try:
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from runtime.capability_registry import CapabilitySpec
    from runtime.models import TargetBinding
    from runtime.request_replay_executor import ReplayTransport, ReplayTransportResult
except ModuleNotFoundError:  # package imports in host-side tests
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..runtime.capability_registry import CapabilitySpec
    from ..runtime.models import TargetBinding
    from ..runtime.request_replay_executor import ReplayTransport, ReplayTransportResult

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:  # package imports in host-side tests
    from scanner.scanner_tools.request_replay import ReplayRequest


REQUEST_MUTATION_PARSER_VERSION = "request-mutation-differential/v1"
MAX_MUTATION_FIELDS = 128
MAX_JSON_DEPTH = 8
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_XSS_FIELD_HINTS = frozenset({
    "comment", "description", "html", "message", "name", "q", "query",
    "search", "text", "title", "url",
})
_SQLI_FIELD_HINTS = frozenset({
    "account", "category", "customer", "filter", "id", "item", "order",
    "product", "record", "search", "sort", "user", "username",
})
_SQL_ERROR_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"you have an error in your sql syntax",
    r"warning.{0,40}mysql",
    r"unclosed quotation mark after the character string",
    r"postgresql.{0,40}(error|exception)",
    r"pg_query\(\)",
    r"sqlite(?:3)?(?:error|_exception)",
    r"ora-\d{4,5}",
    r"sqlstate\[[0-9a-z]+\]",
    r"syntax error.{0,80}(sql|query|database)",
))


class RequestMutationVerificationError(ValueError):
    """An exact private request cannot be safely verified."""


def _content_type(request: ReplayRequest) -> str:
    for name, value in request.headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    mode = str(request.body_mode or "").strip().lower()
    if "json" in mode:
        return "application/json"
    if "urlencoded" in mode or "form" in mode:
        return "application/x-www-form-urlencoded"
    stripped = request.body.lstrip()
    if stripped.startswith((b"{", b"[")):
        return "application/json"
    return ""


def _content_free_origin(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        scheme = parsed.scheme.lower()
        host = str(parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise RequestMutationVerificationError(
            "request verifier URL authority is invalid"
        ) from exc
    if scheme not in {"http", "https"} or not host:
        raise RequestMutationVerificationError(
            "request verifier URL authority is invalid"
        )
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = display_host if port in {None, default_port} else f"{display_host}:{port}"
    return urllib.parse.urlunsplit((scheme, authority, "", "", ""))


def _json_paths(
    value: Any,
    *,
    prefix: tuple[str | int, ...] = (),
    depth: int = 0,
) -> list[tuple[tuple[str | int, ...], Any]]:
    if depth > MAX_JSON_DEPTH:
        return []
    rows: list[tuple[tuple[str | int, ...], Any]] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item)):
            rows.extend(_json_paths(
                value[key], prefix=(*prefix, str(key)), depth=depth + 1,
            ))
            if len(rows) >= MAX_MUTATION_FIELDS:
                break
    elif isinstance(value, list):
        for index, item in enumerate(value[:MAX_MUTATION_FIELDS]):
            rows.extend(_json_paths(
                item, prefix=(*prefix, index), depth=depth + 1,
            ))
            if len(rows) >= MAX_MUTATION_FIELDS:
                break
    elif prefix and isinstance(value, (str, int, float)) and not isinstance(value, bool):
        rows.append((prefix, value))
    return rows[:MAX_MUTATION_FIELDS]


def _field_rank(path: Sequence[str | int], *, family: str) -> tuple[int, str]:
    name = str(path[-1]).lower().replace("-", "_")
    hints = _XSS_FIELD_HINTS if family == "xss" else _SQLI_FIELD_HINTS
    semantic = name in hints or (family == "sqli" and name.endswith("_id"))
    return (0 if semantic else 1, ".".join(str(item) for item in path))


def _set_json_path(value: Any, path: Sequence[str | int], replacement: str) -> None:
    cursor = value
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = replacement


def _mutation_value(*, family: str, original: Any, candidate_id: str) -> tuple[str, str]:
    marker = f"shakerscan_{family}_{candidate_id[:16]}"
    if family == "xss":
        return marker, marker
    original_text = str(original)
    return f"{original_text}'", marker


def mutate_private_request(
    request: ReplayRequest,
    *,
    family: str,
    candidate_id: str,
) -> tuple[ReplayRequest, str, str, str]:
    """Return one deterministic mutation while keeping exact wire values private."""
    if family not in {"xss", "sqli"}:
        raise RequestMutationVerificationError("request mutation family is unsupported")
    if request.method in _SAFE_METHODS:
        raise RequestMutationVerificationError(
            "request mutation requires a state-changing method"
        )
    if not request.body:
        raise RequestMutationVerificationError("private request has no body")
    content_type = _content_type(request)
    if content_type == "application/json" or content_type.endswith("+json"):
        try:
            document = json.loads(request.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestMutationVerificationError(
                "private JSON request body is invalid"
            ) from exc
        fields = sorted(
            _json_paths(document), key=lambda item: _field_rank(item[0], family=family),
        )
        if not fields:
            raise RequestMutationVerificationError(
                "private JSON request has no scalar mutation field"
            )
        path, original = fields[0]
        replacement, marker = _mutation_value(
            family=family, original=original, candidate_id=candidate_id,
        )
        _set_json_path(document, path, replacement)
        body = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        field_path = ".".join(str(item) for item in path)
        encoding = "json"
    elif content_type == "application/x-www-form-urlencoded":
        try:
            pairs = urllib.parse.parse_qsl(
                request.body.decode("utf-8"), keep_blank_values=True,
                strict_parsing=False, max_num_fields=MAX_MUTATION_FIELDS,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise RequestMutationVerificationError(
                "private form request body is invalid"
            ) from exc
        if not pairs:
            raise RequestMutationVerificationError(
                "private form request has no mutation field"
            )
        index = min(
            range(len(pairs)),
            key=lambda item: _field_rank((pairs[item][0],), family=family),
        )
        name, original = pairs[index]
        replacement, marker = _mutation_value(
            family=family, original=original, candidate_id=candidate_id,
        )
        pairs[index] = (name, replacement)
        body = urllib.parse.urlencode(pairs, doseq=True).encode("utf-8")
        field_path = name
        encoding = "form"
    else:
        raise RequestMutationVerificationError(
            "private request body is not JSON or URL-encoded form data"
        )
    return replace(request, body=body), field_path[:300], marker, encoding


def _body_sha256(result: ReplayTransportResult) -> str:
    return hashlib.sha256(result.response_body).hexdigest()


def _sql_errors(body: bytes) -> tuple[str, ...]:
    text = body[:2_000_000].decode("utf-8", errors="replace")
    return tuple(
        pattern.pattern for pattern in _SQL_ERROR_PATTERNS if pattern.search(text)
    )


class RequestMutationVerificationAdapter:
    """Compare an exact control request with one bounded worker-private mutation."""

    manages_cancellation = True

    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        target: TargetBinding,
        request: ReplayRequest,
        candidate: Mapping[str, Any],
        transport: ReplayTransport,
        requested_budget: Mapping[str, int],
    ) -> None:
        family = "xss" if specification.name == "xss.request_verify" else "sqli"
        if specification.name not in {"xss.request_verify", "sqli.request_verify"}:
            raise RequestMutationVerificationError(
                "request mutation capability is unsupported"
            )
        if str(candidate.get("request_ref_id") or "") != request.request_id:
            raise RequestMutationVerificationError(
                "private request differs from candidate reference"
            )
        if str(candidate.get("method") or "").upper() != request.method:
            raise RequestMutationVerificationError(
                "private request method differs from candidate manifest"
            )
        if family not in tuple(candidate.get("family_hints") or ()):
            raise RequestMutationVerificationError(
                "request candidate does not authorize this family"
            )
        if int(requested_budget.get("http_requests") or 0) < 2 or int(
            requested_budget.get("state_changing_requests") or 0
        ) < 2:
            raise RequestMutationVerificationError(
                "request verifier requires two HTTP and mutation reservations"
            )
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version
        self.family = family
        self.target = target
        self.request = request
        self.candidate = dict(candidate)
        self.transport = transport
        self.requested_budget = {
            str(name): int(amount) for name, amount in requested_budget.items()
        }

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        if cancelled():
            return CapabilityAdapterResult(
                status="cancelled",
                errors=("cancelled_before_execution",),
                parser_version=REQUEST_MUTATION_PARSER_VERSION,
            )
        candidate_id = str(self.candidate["candidate_id"])
        try:
            mutated, field_path, marker, encoding = mutate_private_request(
                self.request, family=self.family, candidate_id=candidate_id,
            )
        except RequestMutationVerificationError as exc:
            return CapabilityAdapterResult(
                status="blocked",
                errors=(str(exc),),
                parser_version=REQUEST_MUTATION_PARSER_VERSION,
                redacted_execution={
                    "candidate_id": candidate_id,
                    "request_ref_id": self.request.request_id,
                    "secret_values_visible": False,
                },
            )
        wall = max(2, int(self.requested_budget.get("tool_wall_seconds") or 2))
        timeout = max(0.5, min(30.0, wall / 2))
        started = time.monotonic()
        control = await self.transport.send(
            self.request,
            target=self.target,
            timeout_seconds=timeout,
            follow_redirects=False,
        )
        attempted = 1
        await heartbeat()
        if cancelled():
            return CapabilityAdapterResult(
                status="cancelled",
                errors=("cancelled_after_control",),
                actual_budget={
                    "http_requests": 1,
                    "state_changing_requests": 1,
                    "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started)),
                },
                partial=True,
                execution_started=True,
                parser_version=REQUEST_MUTATION_PARSER_VERSION,
            )
        changed = await self.transport.send(
            mutated,
            target=self.target,
            timeout_seconds=timeout,
            follow_redirects=False,
        )
        attempted = 2
        await heartbeat()
        partial = bool(control.error_code or changed.error_code)
        proof_status = "not_proven"
        proof_contract = (
            "xss_reflection_differential/v1"
            if self.family == "xss" else "sqli_error_differential/v1"
        )
        if not partial and self.family == "xss":
            marker_bytes = marker.encode("utf-8")
            if marker_bytes in changed.response_body and marker_bytes not in control.response_body:
                proof_status = "reflected_candidate_only"
        elif not partial:
            control_errors = set(_sql_errors(control.response_body))
            candidate_errors = set(_sql_errors(changed.response_body))
            if candidate_errors - control_errors:
                proof_status = "db_error_candidate_only"
        observation = {
            "kind": "request_body_verification",
            "origin": _content_free_origin(self.request.url),
            "resolved_ips": list(dict.fromkeys(
                address for address in (
                    control.connected_address, changed.connected_address,
                ) if address
            )),
            "family": self.family,
            "candidate_id": candidate_id,
            "request_ref_id": self.request.request_id,
            "method": self.request.method,
            "body_encoding": encoding,
            "field_path": field_path,
            "control_status": control.status_code,
            "candidate_status": changed.status_code,
            "control_response_sha256": _body_sha256(control),
            "candidate_response_sha256": _body_sha256(changed),
            "control_response_size": len(control.response_body),
            "candidate_response_size": len(changed.response_body),
            "proof_contract": proof_contract,
            "proof_status": proof_status,
            "finding_verdict": (
                "suspected" if proof_status != "not_proven" else "not_proven"
            ),
            "secret_values_visible": False,
        }
        errors = tuple(
            item for item in (control.error_code, changed.error_code) if item
        )
        return CapabilityAdapterResult(
            status="partial" if partial else "success",
            observations=(observation,),
            errors=errors,
            actual_budget={
                "http_requests": attempted,
                "state_changing_requests": attempted,
                "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started)),
            },
            partial=partial,
            timed_out=bool(control.timed_out or changed.timed_out),
            execution_started=True,
            parser_version=REQUEST_MUTATION_PARSER_VERSION,
            redacted_execution={
                "candidate_id": candidate_id,
                "request_ref_id": self.request.request_id,
                "method": self.request.method,
                "body_encoding": encoding,
                "field_path": field_path,
                "follow_redirects": False,
                "secret_values_visible": False,
            },
        )


__all__ = [
    "REQUEST_MUTATION_PARSER_VERSION",
    "RequestMutationVerificationAdapter",
    "RequestMutationVerificationError",
    "mutate_private_request",
]
