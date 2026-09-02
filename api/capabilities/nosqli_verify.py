"""Deterministic NoSQL-operator injection verification over exact requests.

The contract is a sentinel differential: a value that matches nothing is sent
both literally and wrapped in a NoSQL operator (``$ne`` / ``$gt`` / ``$regex``).
If the operator form returns a materially different, repeatable response — or,
in an authentication lane, a session where the literal failed — the operator
was interpreted by a document store, which is NoSQL injection. Nothing is
promoted from a single request or from normal dynamic variation, and a store
that treats the operator as a literal key produces no differential.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
import time
from typing import Any, Mapping
import urllib.parse

try:
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from runtime.capability_registry import CapabilitySpec
    from runtime.models import TargetBinding
    from runtime.request_replay_executor import ReplayTransport, ReplayTransportResult
except ModuleNotFoundError:
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..runtime.capability_registry import CapabilitySpec
    from ..runtime.models import TargetBinding
    from ..runtime.request_replay_executor import ReplayTransport, ReplayTransportResult

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest


NOSQLI_VERIFY_PARSER_VERSION = "nosqli-verify/v1"


class NoSQLiVerifyError(ValueError):
    """A NoSQLi verification request does not match immutable candidate authority."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _content_type(request: ReplayRequest) -> str:
    for name, value in request.headers:
        if str(name).lower() == "content-type":
            return str(value).lower()
    return ""


def _query_field_value(request: ReplayRequest, field: str) -> str | None:
    parsed = urllib.parse.urlsplit(request.url)
    values = [
        value for name, value in urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True,
        ) if name == field
    ]
    return values[0] if len(values) == 1 else None


def _query_literal(request: ReplayRequest, field: str, value: str) -> ReplayRequest:
    parsed = urllib.parse.urlsplit(request.url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    matches = [index for index, (name, _v) in enumerate(pairs) if name == field]
    if len(matches) != 1:
        raise NoSQLiVerifyError("query candidate field authority is ambiguous")
    pairs[matches[0]] = (field, value)
    return replace(request, url=_rebuild(parsed, pairs))


def _query_operator(
    request: ReplayRequest, field: str, operator: str, value: str,
) -> ReplayRequest:
    parsed = urllib.parse.urlsplit(request.url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    matches = [index for index, (name, _v) in enumerate(pairs) if name == field]
    if len(matches) != 1:
        raise NoSQLiVerifyError("query candidate field authority is ambiguous")
    # ``field[$ne]=value`` — PHP/Express body parsers turn this into a nested
    # operator object; a literal store keeps it as the key ``field[$ne]``.
    pairs[matches[0]] = (f"{field}[{operator}]", value)
    return replace(request, url=_rebuild(parsed, pairs))


def _rebuild(parsed: Any, pairs: list[tuple[str, str]]) -> str:
    return urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path,
        urllib.parse.urlencode(pairs, doseq=True), "",
    ))


def _form_pairs(request: ReplayRequest) -> list[tuple[str, str]]:
    try:
        text = (request.body or b"").decode("utf-8")
    except (UnicodeDecodeError, AttributeError) as exc:
        raise NoSQLiVerifyError("private form request body is invalid") from exc
    return urllib.parse.parse_qsl(text, keep_blank_values=True)


def _form_field_index(pairs: list[tuple[str, str]], field: str) -> int:
    matches = [index for index, (name, _v) in enumerate(pairs) if name == field]
    if len(matches) != 1:
        raise NoSQLiVerifyError("form candidate field authority is ambiguous")
    return matches[0]


def _form_literal(request: ReplayRequest, field: str, value: str) -> ReplayRequest:
    pairs = _form_pairs(request)
    pairs[_form_field_index(pairs, field)] = (field, value)
    return replace(request, body=urllib.parse.urlencode(pairs).encode("utf-8"))


def _form_operator(
    request: ReplayRequest, field: str, operator: str, value: str,
) -> ReplayRequest:
    # ``field[$ne]=value`` in a form body is what PHP/Express body parsers turn
    # into a nested operator object, mirroring the query-string bracket form.
    pairs = _form_pairs(request)
    pairs[_form_field_index(pairs, field)] = (f"{field}[{operator}]", value)
    return replace(request, body=urllib.parse.urlencode(pairs).encode("utf-8"))


def _json_document(request: ReplayRequest) -> Any:
    try:
        return json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NoSQLiVerifyError("private JSON request body is invalid") from exc


def _set_json_path(document: Any, field_path: str, value: Any) -> Any:
    parts: list[Any] = []
    for token in field_path.split("."):
        parts.append(int(token) if token.lstrip("-").isdigit() else token)
    cursor = document
    for component in parts[:-1]:
        # An array of objects is flattened to a dotted name (items, items.id), so a
        # string segment landing on a list descends into its first element. Any
        # other mismatch (a missing node, or a scalar where an object is required)
        # is a malformed body shape, not proof -- fail closed rather than raise an
        # uncaught TypeError/KeyError that would settle the whole batch as failed.
        try:
            if isinstance(cursor, list) and not isinstance(component, int):
                cursor = cursor[0]
            cursor = cursor[component]
        except (KeyError, IndexError, TypeError) as exc:
            raise NoSQLiVerifyError(
                "private JSON body shape does not match the candidate field path"
            ) from exc
    try:
        if isinstance(cursor, list) and not isinstance(parts[-1], int):
            cursor = cursor[0]
        cursor[parts[-1]] = value
    except (IndexError, TypeError) as exc:
        raise NoSQLiVerifyError(
            "private JSON body shape does not match the candidate field path"
        ) from exc
    return document


def _json_body(request: ReplayRequest, field_path: str, value: Any) -> ReplayRequest:
    document = _set_json_path(_json_document(request), field_path, value)
    body = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return replace(request, body=body)


def _identity_signal(result: ReplayTransportResult) -> bool:
    for name, value in result.response_headers.items():
        if str(name).lower() in {"set-cookie", "authorization", "x-auth-token"}:
            return True
    content_type = next((
        str(value).lower() for name, value in result.response_headers.items()
        if str(name).lower() == "content-type"
    ), "")
    if "json" in content_type and result.response_body:
        try:
            document = json.loads(result.response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False

        def walk(value: Any) -> bool:
            if isinstance(value, Mapping):
                for raw_name, child in value.items():
                    name = str(raw_name).lower()
                    if name in {"token", "access_token", "id_token", "jwt", "authentication"} \
                            and isinstance(child, str) and child.strip():
                        return True
                    if walk(child):
                        return True
            elif isinstance(value, list):
                return any(walk(child) for child in value[:20])
            return False

        return walk(document)
    return False


def _succeeded(result: ReplayTransportResult) -> bool:
    """True when the target answered normally rather than failing the request."""
    status = result.status_code
    return isinstance(status, int) and 200 <= status < 300


def _fingerprint(result: ReplayTransportResult) -> tuple[int | None, int, str]:
    return (
        result.status_code, len(result.response_body), _sha256(result.response_body),
    )


class NoSQLiVerifyAdapter:
    """Prove NoSQL-operator injection with a repeated sentinel differential."""

    # CapabilityExecutor checks these against the registry before it runs an
    # adapter. Without them every execution raised AttributeError and settled
    # as a bare "adapter_failed", so this family never ran a single attempt.
    capability_name = "nosqli.verify_batch"
    adapter_name = "nosqli.verify_batch"
    adapter_version = "1"
    manages_cancellation = True

    def __init__(
        self, *, specification: CapabilitySpec, target: TargetBinding,
        request: ReplayRequest, candidate: Mapping[str, Any],
        transport: ReplayTransport, requested_budget: Mapping[str, int],
    ) -> None:
        if specification.name != "nosqli.verify_batch":
            raise NoSQLiVerifyError("NoSQLi verify capability is invalid")
        if int(requested_budget.get("http_requests") or 0) < 4:
            raise NoSQLiVerifyError("NoSQLi verification requires at least four HTTP requests")
        if str(candidate.get("method") or "").upper() != request.method:
            raise NoSQLiVerifyError("NoSQLi request method differs from candidate")
        request_ref = str(candidate.get("request_ref_id") or "")
        if request_ref and request_ref != request.request_id:
            raise NoSQLiVerifyError("NoSQLi private request reference differs")
        field = str(candidate.get("field_path") or candidate.get("parameter_name") or "")
        if not field:
            raise NoSQLiVerifyError("NoSQLi candidate has no exact field")
        declared_fields = [
            str(item) for item in candidate.get("body_field_names") or ()
            if str(item)
        ]
        if declared_fields and field not in declared_fields:
            raise NoSQLiVerifyError(
                "NoSQLi candidate anchor is absent from its declared body fields"
            )
        self.specification = specification
        self.target = target
        self.request = request
        self.candidate = dict(candidate)
        self.transport = transport
        self.requested_budget = {str(k): int(v) for k, v in requested_budget.items()}
        # An endpoint-body candidate represents the whole declared body. Its
        # anchor only supplies stable identity and ranking; try it first, then
        # its siblings while another bounded four-request differential fits.
        self.fields = tuple(dict.fromkeys([field, *declared_fields]))
        self.request_mode = bool(request_ref) or request.method not in {"GET", "HEAD"}
        # A form-encoded body carries bracket-style operators (field[$ne]=x), not a
        # JSON document, so routing it through the JSON mutator raised "private JSON
        # request body is invalid" and no form NoSQL candidate could execute.
        self.body_is_form = (
            self.request_mode
            and "x-www-form-urlencoded" in _content_type(request)
        )

    def _literal(self, field: str, value: str) -> ReplayRequest:
        if self.body_is_form:
            return _form_literal(self.request, field, value)
        if self.request_mode:
            return _json_body(self.request, field, value)
        return _query_literal(self.request, field, value)

    def _operator(self, field: str, operator: str, value: str) -> ReplayRequest:
        if self.body_is_form:
            return _form_operator(self.request, field, operator, value)
        if self.request_mode:
            return _json_body(self.request, field, {operator: value})
        return _query_operator(self.request, field, operator, value)

    async def execute(self, *, heartbeat: Heartbeat, cancelled: Cancelled) -> CapabilityAdapterResult:
        started = time.monotonic()
        attempted = 0
        results: list[ReplayTransportResult] = []

        async def send(request: ReplayRequest) -> ReplayTransportResult:
            nonlocal attempted
            if cancelled():
                raise NoSQLiVerifyError("cancelled")
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

        candidate_id = str(self.candidate.get("candidate_id") or "")
        request_class = str(self.candidate.get("request_class") or "safe_read")
        observations: list[Mapping[str, Any]] = []
        attempted_fields: list[str] = []
        verified = False
        try:
            for field in self.fields:
                if self.requested_budget["http_requests"] - attempted < 4:
                    break
                attempted_fields.append(field)
                field_digest = hashlib.sha256(field.encode("utf-8")).hexdigest()[:8]
                sentinel = f"shakerscan_nosqli_{candidate_id[:8]}_{field_digest}"
                technique = None
                if request_class == "safe_authentication":
                    # Auth bypass: the sentinel password never matches; ``$ne``
                    # matches every stored password, so a resulting authenticated
                    # session is proof -- but only when the operator response itself
                    # succeeded, so a stray cookie on an error page cannot forge one.
                    pairs = [
                        (
                            await send(self._literal(field, sentinel)),
                            await send(self._operator(field, "$ne", sentinel)),
                        )
                        for _ in range(2)
                    ]
                    if all(
                        not literal.error_code and not payload.error_code
                        and _succeeded(payload)
                        and not _identity_signal(literal) and _identity_signal(payload)
                        for literal, payload in pairs
                    ):
                        verified = True
                        technique = "operator_auth_bypass_repeated"
                else:
                    # Semantic oracle. In a document store ``{field: {$eq: X}}`` is
                    # identical to ``{field: X}`` while ``{field: {$ne: X}}`` is its
                    # complement. An endpoint that merely echoes the value, stringifies
                    # the operator object, or rejects every operator shape with one
                    # constant response cannot satisfy BOTH "eq collapses onto the
                    # literal" AND "ne diverges from it", so reflection can no longer
                    # masquerade as an interpreted operator.
                    r_literal = await send(self._literal(field, sentinel))
                    r_ne = await send(self._operator(field, "$ne", sentinel))
                    r_eq = await send(self._operator(field, "$eq", sentinel))
                    r_ne_again = await send(self._operator(field, "$ne", sentinel))
                    samples = (r_literal, r_ne, r_eq, r_ne_again)
                    fp_literal = _fingerprint(r_literal)
                    fp_ne = _fingerprint(r_ne)
                    fp_eq = _fingerprint(r_eq)
                    fp_ne_again = _fingerprint(r_ne_again)
                    pairs = [(r_literal, r_ne), (r_literal, r_ne_again)]
                    if (
                        all(not item.error_code and _succeeded(item) for item in samples)
                        and fp_ne == fp_ne_again      # the operator answer is stable
                        and fp_eq == fp_literal        # {$eq:X} collapses onto literal X
                        and fp_ne != fp_literal        # {$ne:X} is the complement, not X
                    ):
                        verified = True
                        technique = "operator_equality_complement_differential"

                observations.append({
                    "kind": "nosqli_proof",
                    # The route is already value-free immutable manifest content,
                    # and a verified injection that cannot say where it is is not
                    # actionable.
                    "canonical_path": self.candidate.get("canonical_path"),
                    "candidate_id": self.candidate.get("candidate_id"),
                    "request_ref_id": self.candidate.get("request_ref_id"),
                    "method": self.request.method,
                    "field_path": field,
                    "request_class": request_class,
                    "proof_state": "verified" if verified else "not_proven",
                    "finding_verdict": "verified" if verified else "not_proven",
                    "proof_contract": (
                        "nosqli_operator_differential/v1" if verified else None
                    ),
                    "technique": technique,
                    "operator": "$ne",
                    "repetitions": 2,
                    "response_pairs": [{
                        "literal_status": literal.status_code,
                        "operator_status": payload.status_code,
                        "literal_response_sha256": _sha256(literal.response_body),
                        "operator_response_sha256": _sha256(payload.response_body),
                    } for literal, payload in pairs],
                    "session_state_discarded": request_class == "safe_authentication",
                    "secret_values_visible": False,
                })
                if verified:
                    break
        except NoSQLiVerifyError as exc:
            status = "cancelled" if str(exc) == "cancelled" else "blocked"
            return CapabilityAdapterResult(
                status=status, errors=(str(exc),), execution_started=bool(attempted),
                actual_budget={
                    "http_requests": attempted,
                    "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started)),
                },
                partial=bool(attempted), parser_version=NOSQLI_VERIFY_PARSER_VERSION,
            )

        errors = tuple(item.error_code for item in results if item.error_code)
        fields_exhausted = not verified and len(attempted_fields) < len(self.fields)
        return CapabilityAdapterResult(
            status="partial" if errors or fields_exhausted else "success",
            observations=tuple(observations), errors=errors,
            actual_budget={
                "http_requests": attempted,
                "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started)),
            },
            partial=bool(errors or fields_exhausted),
            timed_out=any(item.timed_out for item in results),
            execution_started=True, parser_version=NOSQLI_VERIFY_PARSER_VERSION,
            redacted_execution={
                "candidate_id": self.candidate.get("candidate_id"),
                "request_ref_id": self.candidate.get("request_ref_id"),
                "method": self.request.method,
                "field_path": attempted_fields[0] if attempted_fields else None,
                "field_paths": attempted_fields,
                "proof_contract": (
                    "nosqli_operator_differential/v1" if verified else None
                ),
                "secret_values_visible": False,
            },
        )


__all__ = ["NOSQLI_VERIFY_PARSER_VERSION", "NoSQLiVerifyAdapter", "NoSQLiVerifyError"]
