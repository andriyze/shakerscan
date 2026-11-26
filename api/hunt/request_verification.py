"""``request.verify``: a Hunt proves one vulnerability class on one exact request.

The planner names the request the way it names an ``http.request`` (method, path, query, body,
headers, and the identity it is sent as) plus the ``check`` to run and, for an input check, the
``parameter`` to test. The worker resolves the identity exactly as for ``artifact.inspect``
(a principal, a session, or a session cookie this Hunt's login captured), then runs a
deterministic differential with a repeat and a negative control:

* ``command_injection``, ``path_traversal``, ``template_injection``, ``xxe``, ``ssrf``: the Scan's
  server-side injection verifier (``capabilities/injection_verify.py``);
* ``nosql_injection``: the Scan's NoSQL operator verifier (``capabilities/nosqli_verify.py``);
* ``sql_injection``: the Scan's SQL injection proof (``capabilities/sqli_proof.py``): a repeated
  database-error, boolean (quoted and numeric) or delay differential in a few requests, never an
  OR pair, and never at a sign-in (``sqli.verify`` runs the full tool);
* the request-level checks of ``capabilities/request_verify.py``.

A verified observation becomes a finding through ``deterministic_findings``, as ``sqli.verify`` and
``xss.verify`` do; anything else stays an observation. Authority: every check needs active testing;
a request that writes (any method but GET/HEAD/OPTIONS, and every upload) needs the Hunt's
state-changing permission and is held as verifier writes, beside the planner's own write ceiling.
The safety limits of the Scan verifiers hold here too: traversal only through a request that
reads, SSRF only in-band to the application's own loopback address with GET, no SQL OR pair, and
nothing sent to a sign-in endpoint except the checks that are about signing in.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Any, Mapping
import urllib.parse

try:
    from capabilities.injection_verify import INJECTION_CLASSES, InjectionVerifyAdapter
    from capabilities.nosqli_verify import NoSQLiVerifyAdapter
    from capabilities.sqli_proof import SQLiProofAdapter
    from capabilities.request_verify import (
        FIELD_CHECKS, REQUEST_CHECKS, RequestVerifyAdapter, RequestVerifyError,
    )
    from capabilities.replay import RecordedHuntReplayTransport
    from runtime.auth_refusal import is_authentication_path
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from runtime.request_verify_contract import CHECKS, HOLD as REQUEST_VERIFY_HOLD
except ModuleNotFoundError:  # package import layout
    from ..capabilities.injection_verify import INJECTION_CLASSES, InjectionVerifyAdapter
    from ..capabilities.nosqli_verify import NoSQLiVerifyAdapter
    from ..capabilities.sqli_proof import SQLiProofAdapter
    from ..capabilities.request_verify import (
        FIELD_CHECKS, REQUEST_CHECKS, RequestVerifyAdapter, RequestVerifyError,
    )
    from ..capabilities.replay import RecordedHuntReplayTransport
    from ..runtime.auth_refusal import is_authentication_path
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from ..runtime.request_verify_contract import CHECKS, HOLD as REQUEST_VERIFY_HOLD

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest

CAPABILITY = "request.verify"
NOSQL_CHECK = "nosql_injection"
SQL_CHECK = "sql_injection"
# The registry's contract names the checks (CHECKS); the verifiers implement exactly these
# (tests/test_hunt_request_verify.py). Checks about signing in are the only ones a sign-in
# endpoint is sent: the Scan never sends its injection probes to the credential profile's own
# login, and neither does a Hunt.
SIGN_IN_CHECKS = frozenset({"rate_limit", "ldap_injection", "nosql_injection", "csrf", "open_redirect",
                            "cors", "security_headers", "host_header_injection"})
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_XML_TYPES = ("application/xml", "text/xml")


class RequestVerificationRefused(ValueError):
    """The call cannot run as given; nothing was sent."""


def writes(values: Mapping[str, Any]) -> bool:
    """Whether the call sends a state-changing request (an upload always does)."""
    return str(values.get("method") or "GET").upper() in WRITE_METHODS or values.get("check") == "file_upload"


def admission_refusal(values: Mapping[str, Any], policy: Mapping[str, Any]) -> str | None:
    """Why this call cannot run, decided from its input and the Hunt's policy alone."""
    check = str(values.get("check") or "")
    method = str(values.get("method") or "GET").upper()
    if check not in CHECKS:
        return f"check must be one of {', '.join(CHECKS)}"
    if policy.get("active_testing") is not True:
        return "request.verify needs this Hunt's active_testing permission"
    if writes(values) and policy.get("allow_state_changing_http") is not True:
        return (f"{check} with {method} sends state-changing requests and needs this Hunt's "
                "allow_state_changing_http permission")
    needs_field = check in FIELD_CHECKS or check in INJECTION_CLASSES or check in {NOSQL_CHECK, SQL_CHECK}
    if needs_field and check != "xxe" and not values.get("parameter"):
        return f"{check} tests one input: name it in parameter (a query name, form field or JSON field path)"
    bodies = [key for key in ("json_body", "form_body", "xml_body") if key in values]
    if len(bodies) > 1:
        return "send one of json_body, form_body or xml_body"
    if bodies and method in READ_METHODS:
        return "a request body needs POST, PUT, PATCH or DELETE"
    if check == "xxe" and "xml_body" not in values:
        return "xxe needs the XML document the endpoint accepts in xml_body (with one text element)"
    if check == "path_traversal" and method not in READ_METHODS:
        return "path_traversal is tried only through a request that reads (GET)"
    if check == "ssrf" and method != "GET":
        return "ssrf is proved in-band through a GET parameter only"
    if check == "csrf" and method not in WRITE_METHODS:
        return "csrf needs the state-changing request (POST, PUT, PATCH or DELETE) it is about"
    if check == "file_upload":
        retrieve = str(values.get("retrieve_path") or "")
        if method not in {"POST", "PUT"} or "{filename}" not in retrieve or not retrieve.startswith("/"):
            return "file_upload needs POST or PUT and retrieve_path, a same-origin path with {filename}"
        if "json_body" in values or "xml_body" in values:
            return "file_upload sends a multipart form; give other form fields in form_body"
    if check == "jwt" and not (values.get("as_principal") or values.get("session_ref")):
        return "jwt tests the token a principal signs in with: send as_principal or session_ref"
    if check in {"unauthenticated_api", "exposure"} and (method != "GET" or values.get("as_principal") or values.get("session_ref")):
        return f"{check} tests an anonymous GET: send no as_principal or session_ref"
    if check in {"rate_limit", "ldap_injection"} and method not in WRITE_METHODS:
        return f"{check} tests a sign-in request (POST)"
    if is_authentication_path(values.get("path")) and check not in SIGN_IN_CHECKS:
        return f"{check} probes are not sent to a sign-in endpoint"
    try:
        from agent_tools import classify_request_headers
    except ModuleNotFoundError:  # package import layout
        from ..agent_tools import classify_request_headers
    _accepted, rejected = classify_request_headers(
        dict(values.get("headers") or {}), allow_identity_headers=policy.get("allow_identity_headers") is True,
    )
    if rejected:
        return "headers refused: " + ", ".join(f"{name} ({reason})" for name, reason in sorted(rejected.items()))
    return None


def _encode_body(values: Mapping[str, Any]) -> tuple[bytes, str | None]:
    if "json_body" in values:
        return json.dumps(values["json_body"], separators=(",", ":"), ensure_ascii=False).encode(), "application/json"
    if "form_body" in values and values.get("check") != "file_upload":
        pairs = []
        for name, value in dict(values["form_body"]).items():
            for item in value if isinstance(value, list) else [value]:
                pairs.append((str(name), "" if item is None else str(item).lower() if isinstance(item, bool) else str(item)))
        return urllib.parse.urlencode(pairs).encode(), "application/x-www-form-urlencoded"
    if "xml_body" in values:
        return str(values["xml_body"]).encode("utf-8"), "application/xml"
    return b"", None


def build_request(
    values: Mapping[str, Any], *, base_url: str, headers: Mapping[str, str], action_id: Any,
    allow_identity_headers: bool = False,
) -> ReplayRequest:
    """The exact request to verify, with the worker-resolved identity headers."""
    try:
        from agent_tools import classify_request_headers
    except ModuleNotFoundError:  # package import layout
        from ..agent_tools import classify_request_headers
    accepted, rejected = classify_request_headers(
        dict(values.get("headers") or {}), allow_identity_headers=allow_identity_headers,
    )
    if rejected:
        raise RequestVerificationRefused(
            "headers refused: " + ", ".join(f"{name} ({reason})" for name, reason in sorted(rejected.items())))
    path = str(values.get("path") or "/")
    if not path.startswith("/") or path.startswith("//"):
        raise RequestVerificationRefused("path must be a same-origin path starting with /")
    url = urllib.parse.urljoin(str(values.get("origin") or base_url), path)
    query = values.get("query")
    if isinstance(query, Mapping) and query:
        parsed = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in query.items():
            for item in value if isinstance(value, list) else [value]:
                pairs.append((str(name), "" if item is None else str(item)))
        url = urllib.parse.urlunsplit((*parsed[:3], urllib.parse.urlencode(pairs), ""))
    body, content_type = _encode_body(values)
    items = [(str(k), str(v)) for k, v in accepted.items() if str(k).lower() != "content-type"]
    items += [(str(k), str(v)) for k, v in headers.items()]
    if content_type:
        items.append(("Content-Type", content_type))
    method = str(values.get("method") or "GET").upper()
    return ReplayRequest(
        request_id=f"hunt-request-verify:{action_id}", ordinal=0, name="Hunt request.verify",
        folder="", method=method, url=url, headers=tuple(items), body=body,
        body_mode="raw" if body else "none", auth_type="broker_session" if headers else "none",
        has_sensitive_material=bool(headers),
    )


def _request_class(request: ReplayRequest, check: str) -> str:
    if request.method in READ_METHODS:
        return "safe_read"
    path = urllib.parse.urlsplit(request.url).path
    if check in {"rate_limit", "ldap_injection"} or is_authentication_path(path):
        return "safe_authentication"
    return "confirmed_mutation"


def _candidate(request: ReplayRequest, values: Mapping[str, Any], seed: str, request_class: str) -> dict[str, Any]:
    field = str(values.get("parameter") or "")
    if values.get("check") == "xxe" and not field:
        field = "xml_body"
    candidate = {
        "candidate_id": seed, "method": request.method, "field_path": field,
        "parameter_name": field, "canonical_path": urllib.parse.urlsplit(request.url).path or "/",
        "request_class": request_class,
    }
    if values.get("check") == NOSQL_CHECK and "form_body" in values:
        candidate["body_field_names"] = [str(name) for name in dict(values["form_body"])]
    if values.get("check") == NOSQL_CHECK and isinstance(values.get("json_body"), Mapping):
        candidate["body_field_names"] = [str(name) for name in dict(values["json_body"])]
    return candidate


def verifier_adapter(
    values: Mapping[str, Any], *, target: Any, request: ReplayRequest, recorder: Any,
    principal_slot: str, requested_budget: Mapping[str, int], seed: str,
    allow_identity_headers: bool = False, transport: Any = None,
) -> Any:
    """The adapter that runs this call's check against ``request``."""
    check = str(values["check"])
    # A short body (a server that overstates Content-Length, as some directory index middleware
    # does) is kept and marked incomplete_read, as the Scan's exposure probe keeps it.
    transport = transport or RecordedHuntReplayTransport(
        PinnedAiohttpReplayTransport(tolerate_incomplete_body=True), recorder, principal_slot=principal_slot,
    )
    request_class = _request_class(request, check)
    budget = {key: int(value) for key, value in requested_budget.items()
              if key in {"http_requests", "tool_wall_seconds", "state_changing_requests"}}
    if request.method not in READ_METHODS:
        # The Scan verifiers' own mutation guard: every body request is a possible write.
        budget["state_changing_requests"] = budget["http_requests"]
    if check in INJECTION_CLASSES:
        if check == "xxe" and not any(
            str(name).lower() == "content-type" and str(value).startswith(_XML_TYPES)
            for name, value in request.headers
        ):
            raise RequestVerifyError("xxe needs an XML request body")
        return InjectionVerifyAdapter(
            specification=CAPABILITY_REGISTRY.require("injection.verify_batch"), target=target,
            request=request, candidate=_candidate(request, values, seed, request_class),
            transport=transport, requested_budget=budget, classes=(check,),
        )
    if check == SQL_CHECK:
        # Never the sign-in bypass pair (admission keeps it off sign-in endpoints): a write is
        # proved with the AND pairs only, as the Scan proves it.
        return SQLiProofAdapter(
            specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"), target=target,
            request=request, candidate=_candidate(request, values, seed, request_class),
            transport=transport, requested_budget=budget, extended=True,
        )
    if check == NOSQL_CHECK:
        return NoSQLiVerifyAdapter(
            specification=CAPABILITY_REGISTRY.require("nosqli.verify_batch"), target=target,
            request=request, candidate=_candidate(request, values, seed, request_class),
            transport=transport, requested_budget=budget,
        )
    options = {
        "retrieve_path": values.get("retrieve_path"), "token_field": values.get("token_field"),
        "allow_identity_headers": allow_identity_headers,
        "form_fields": [
            (str(name), str(value)) for name, value in dict(values.get("form_body") or {}).items()
            if not isinstance(value, (list, dict))
        ],
    }
    if check == "file_upload":
        # The multipart body is built per upload; the request carries no body of its own.
        request = replace(request, body=b"", body_mode="none",
                          headers=tuple(item for item in request.headers if str(item[0]).lower() != "content-type"))
    return RequestVerifyAdapter(
        check=check, target=target, request=request, field=str(values.get("parameter") or "") or None,
        transport=transport, requested_budget=budget, seed=seed, request_class=request_class,
        options=options,
    )


class RequestVerificationExecutionAdapter:
    """The worker adapter for ``request.verify``: runs the check's adapter, cancellable."""

    capability_name = CAPABILITY
    adapter_name = CAPABILITY
    adapter_version = "1"
    manages_cancellation = True

    def __init__(self, *, specification: Any, operation: Any, requested_budget: Mapping[str, int],
                 redacted_execution: Mapping[str, Any]) -> None:
        self._specification = specification
        self._operation = operation
        self._requested_budget = dict(requested_budget)
        self._redacted_execution = dict(redacted_execution)

    async def execute(self, *, heartbeat: Any, cancelled: Any) -> Any:
        adapter = await self._operation()
        result = await adapter.execute(heartbeat=heartbeat, cancelled=cancelled)
        actual = dict(result.actual_budget)
        if "verifier_write_requests" in self._requested_budget:
            # Every request of a writing check is a verifier write, settled to what was sent.
            actual["verifier_write_requests"] = int(actual.get("http_requests") or 0)
        actual.pop("state_changing_requests", None)
        actual = {key: min(int(value), int(self._requested_budget.get(key, value)))
                  for key, value in actual.items() if key in self._requested_budget}
        return replace(
            result, actual_budget=actual, parser_version=self._specification.output_schema,
            redacted_execution={**self._redacted_execution, **dict(result.redacted_execution or {})},
        )


def redacted_input(values: Mapping[str, Any]) -> dict[str, Any]:
    """The receipt's view of the call: names and shapes, no values."""
    return {
        "check": values.get("check"), "method": str(values.get("method") or "GET").upper(),
        "path": str(values.get("path") or "")[:300].split("?", 1)[0],
        "parameter": values.get("parameter"),
        "query_names": sorted(str(name) for name in dict(values.get("query") or {}))[:32],
        "body_kind": next((key for key in ("json_body", "form_body", "xml_body") if key in values), None),
        "header_names": sorted(str(name) for name in dict(values.get("headers") or {}))[:32],
        **({"origin": str(values["origin"])[:200]} if values.get("origin") else {}),
        **({"as_principal": values["as_principal"]} if values.get("as_principal") else {}),
        **({"session_ref": values["session_ref"]} if values.get("session_ref") else {}),
        "secret_values_visible": False,
    }


async def run_check(
    check: str, *, url: str, target: Any, transport: Any, policy: Mapping[str, Any], seed: str,
    method: str = "GET", parameter: str | None = None, json_body: Mapping[str, Any] | None = None,
    form_body: Mapping[str, Any] | None = None, xml_body: str | None = None,
    identity_headers: Mapping[str, str] | None = None, retrieve_path: str | None = None,
    token_field: str | None = None, requested_budget: Mapping[str, int] | None = None,
    heartbeat: Any = None, cancelled: Any = None,
) -> Any:
    """Run one check on one endpoint, outside a planner: a server-side sweep calls this with an
    endpoint, its parameter and the class to prove, under the Hunt or Scan ``policy`` it runs for.

    The same admission rules and safety limits as a planner's call apply (the refusal is raised as
    ``RequestVerificationRefused`` before anything is sent); ``transport`` sends and archives.
    Returns the adapter's result; ``finding_records`` turns its verified observations into findings.
    """
    parsed = urllib.parse.urlsplit(url)
    values: dict[str, Any] = {
        "check": check, "method": method.upper(),
        "path": urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
        **({"parameter": parameter} if parameter else {}),
        **({"json_body": dict(json_body)} if json_body is not None else {}),
        **({"form_body": dict(form_body)} if form_body is not None else {}),
        **({"xml_body": xml_body} if xml_body is not None else {}),
        **({"retrieve_path": retrieve_path} if retrieve_path else {}),
        **({"token_field": token_field} if token_field else {}),
    }
    refused = admission_refusal(values, policy)
    if refused:
        raise RequestVerificationRefused(refused)
    allow_identity = policy.get("allow_identity_headers") is True
    request = build_request(values, base_url=f"{parsed.scheme}://{parsed.netloc}/",
                            headers=dict(identity_headers or {}), action_id=seed,
                            allow_identity_headers=allow_identity)
    adapter = verifier_adapter(
        values, target=target, request=request, recorder=None, principal_slot="anonymous",
        requested_budget=dict(requested_budget or REQUEST_VERIFY_HOLD), seed=seed,
        allow_identity_headers=allow_identity, transport=transport,
    )

    async def beat() -> None:
        if heartbeat is not None:
            await heartbeat()

    return await adapter.execute(heartbeat=beat, cancelled=cancelled or (lambda: False))


async def prepare_operation(
    *, pool: Any, run: Mapping[str, Any], hunt_id: Any, action_id: Any, context: Any, target: Any,
    policy: Any, hunt_policy: Mapping[str, Any], target_url: str, values: Mapping[str, Any],
    stack: Any, session_store: Any, recorder: Any, requested_budget: Mapping[str, int],
) -> tuple[Any, dict[str, Any], str]:
    """``(operation, redacted execution, principal slot)`` for the worker's HTTP path."""
    from .artifact_identity import resolve_artifact_identity
    refused = admission_refusal(values, hunt_policy)
    if refused:
        raise RequestVerificationRefused(refused)
    headers, bound, principal_slot = await resolve_artifact_identity(
        pool=pool, run=run, hunt_id=hunt_id, context=context, target=target, policy=policy,
        hunt_policy=hunt_policy, target_url=target_url, values=values, stack=stack,
        session_store=session_store, capability=CAPABILITY,
    )
    allow_identity = hunt_policy.get("allow_identity_headers") is True
    request = build_request(values, base_url=target_url, headers=headers, action_id=action_id,
                            allow_identity_headers=allow_identity)
    seed = hashlib.sha256(f"{action_id}:{values.get('check')}".encode()).hexdigest()[:32]

    async def operation() -> Any:
        from runtime.archive_body_masking import active_withheld_values
        if bound and (collector := active_withheld_values()) is not None:
            collector.bind_known(bound)
        return verifier_adapter(
            values, target=target, request=request, recorder=recorder, principal_slot=principal_slot,
            requested_budget=requested_budget, seed=seed,
            allow_identity_headers=allow_identity,
        )

    return operation, {**redacted_input(values), "as_principal": principal_slot,
                       "credential_headers_injected": bool(headers)}, principal_slot


# -- findings -------------------------------------------------------------------------------

def _injection_findings() -> Mapping[str, tuple[str, str, str, str]]:
    try:
        from scan.finalizer import _INJECTION_FINDINGS
    except ModuleNotFoundError:  # package import layout
        from ..scan.finalizer import _INJECTION_FINDINGS
    return _INJECTION_FINDINGS


# (title, severity, CWE, why) per proof class of capabilities/request_verify.py.
REQUEST_FINDINGS: Mapping[str, tuple[str, str, str, str]] = {
    "open_redirect": ("Verified open redirect", "medium", "CWE-601",
                      "A redirect parameter sent the browser to two random outside hosts; the "
                      "application's own path in it did not"),
    "crlf_injection": ("Verified CRLF injection in a response header", "medium", "CWE-113",
                       "A line break in a parameter started a response header the application does "
                       "not send, twice; the same text with spaces did not"),
    "host_header_injection": ("Verified host header injection", "medium", "CWE-644",
                              "A random host sent in a host header was written into the response "
                              "twice; the same host in an unrelated header was not"),
    "cors_reflected_origin": ("CORS policy reflects any origin", "medium", "CWE-942",
                              "Two random origins were each granted in Access-Control-Allow-Origin"),
    "cors_null_origin": ("CORS policy trusts the null origin", "medium", "CWE-942",
                         "The null origin was granted twice while a random origin was not"),
    "cors_wildcard_credentials": ("CORS wildcard combined with credentials", "low", "CWE-942",
                                  "Access-Control-Allow-Origin: * was sent with "
                                  "Access-Control-Allow-Credentials: true twice"),
    "missing_content_security_policy": ("Content-Security-Policy missing on an HTML page", "low", "CWE-693",
                                        "The page was served twice without a Content-Security-Policy"),
    "clickjacking": ("Page can be framed by any site (clickjacking)", "low", "CWE-1021",
                     "The page was served twice without X-Frame-Options or frame-ancestors"),
    "weak_security_header": ("Weak security header values", "low", "CWE-693",
                             "The same weak security header values were served twice"),
    "directory_listing": ("Verified directory listing", "medium", "CWE-548",
                          "A server-generated index was served twice; a sibling directory that does "
                          "not exist was not listed"),
    "graphql_introspection": ("GraphQL introspection enabled", "low", "CWE-200",
                              "A validating GraphQL server answered the schema meta field"),
    "field_suggestions": ("GraphQL field suggestions enabled", "low", "CWE-200",
                          "A misspelt field was answered with the real field's name"),
    "alias_limit_absent": ("GraphQL alias limit absent (100 aliases in one query)", "low", "CWE-770",
                           "100 aliases of one field were answered in one request"),
    "duplicate_field_limit_absent": ("GraphQL duplicate field limit absent (100 duplicates in one query)",
                                     "low", "CWE-770", "100 duplicate fields were answered in one request"),
    "batch_limit_absent": ("GraphQL batching not limited", "low", "CWE-770",
                           "A batch of operations in one request was answered in full; the same batch "
                           "of an undefined field was rejected"),
    "file_upload": ("Verified unrestricted file upload (HTML served from the application origin)", "high",
                    "CWE-434", "Two uploaded HTML files were served back as HTML from the "
                    "application's origin; a file name never uploaded was not"),
    "rate_limit": ("Sign-in not rate limited or locked out", "medium", "CWE-307",
                   "A run of wrong passwords was refused each time with no lockout, rate-limit "
                   "status or Retry-After"),
    "csrf": ("Verified cross-site request forgery", "medium", "CWE-352",
             "The state-changing request, sent as another site would send it, was accepted twice; "
             "the same request without the session was refused"),
    "ldap_injection": ("Verified LDAP injection in sign-in", "critical", "CWE-90",
                       "A wildcard signed in twice; a random value and the escaped wildcard did not"),
    "unauthenticated_api": ("Management API answers without authentication", "high", "CWE-306",
                            "An anonymous request to a self-hosted product's management route was "
                            "answered with that product's data twice; a sibling route that does not "
                            "exist was not"),
    "jwt": ("JSON Web Token accepted without a valid signature", "critical", "CWE-347",
            "The principal's token was accepted forged (altered signature, alg none or a well-known "
            "secret), twice"),
}
def _exposure_finding(exposure_class: str, severity: Any) -> tuple[str, str, str, str] | None:
    """(title, severity, CWE, why) for a proved Scan exposure class."""
    if not exposure_class:
        return None
    cwe = {"directory_listing": "CWE-548", "verbose_error_disclosure": "CWE-209",
           "debug_interface_exposure": "CWE-489", "phpinfo_disclosure": "CWE-200",
           "metrics_endpoint": "CWE-200", "version_control_exposure": "CWE-527",
           "backup_or_source_artifact": "CWE-530"}.get(exposure_class, "CWE-200")
    label = exposure_class.replace("_", " ")
    return (f"Exposed {label}", str(severity or "medium"), cwe,
            f"An anonymous read was classified as {label} twice; a sibling path that does not exist was not")


_SQL_FINDING = ("Verified SQL injection", "critical", "CWE-89",
                "A database error, a true/false pair or a delay followed the injected SQL syntax twice; "
                "the unchanged request did not")
_NOSQL_FINDING = ("Verified NoSQL injection", "high", "CWE-943",
                  "An operator-wrapped value answered differently from the same value sent literally, twice")


def finding_records(
    hunt_id: Any, action_id: Any, target_url: str, receipt_id: Any, capability_input: Mapping[str, Any],
    observations: Any, *, allowed_origins: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Verified findings from this call's proof observations, on the Hunt's own services."""
    try:
        from findings import templated_finding_identity
    except ModuleNotFoundError:
        from scanner.findings import templated_finding_identity

    def origin_of(value: Any) -> str:
        parts = urllib.parse.urlsplit(str(value or ""))
        return f"{parts.scheme.lower()}://{parts.netloc.rpartition('@')[2].lower()}"

    admitted = {origin_of(value) for value in (target_url, *allowed_origins) if value}
    records: list[dict[str, Any]] = []
    for raw in observations if isinstance(observations, (list, tuple)) else ():
        if not (isinstance(raw, Mapping) and raw.get("proof_state") == "verified"
                and raw.get("finding_verdict") == "verified" and raw.get("proof_contract")):
            continue
        kind = raw.get("kind")
        if kind == "injection_proof" and int(raw.get("repetitions") or 0) >= 2:
            known = _injection_findings().get(str(raw.get("injection_class")))
            proof_class = str(raw.get("injection_class"))
        elif kind == "sqli_proof" and int(raw.get("repetitions") or 0) >= 2:
            known, proof_class = _SQL_FINDING, "sql_injection"
        elif kind == "nosqli_proof" and int(raw.get("repetitions") or 0) >= 2:
            known, proof_class = _NOSQL_FINDING, "nosql_injection"
        elif kind == "request_proof" and raw.get("check") == "exposure" and int(raw.get("repetitions") or 0) >= 2:
            proof_class = str(raw.get("exposure_class") or "")
            known = _exposure_finding(proof_class, raw.get("exposure_severity"))
        elif kind == "request_proof" and int(raw.get("repetitions") or 0) >= 2:
            proof_class = str(raw.get("proof_class") or raw.get("check"))
            known = REQUEST_FINDINGS.get(proof_class)
        else:
            continue
        origin = origin_of(raw.get("origin"))
        if known is None or origin not in admitted:
            continue
        title, severity, cwe, reason = known
        if proof_class in {"cors_reflected_origin", "cors_null_origin"} and raw.get("credentials"):
            severity = "high"
        path = str(raw.get("canonical_path") or "/")
        method = str(raw.get("method") or capability_input.get("method") or "GET").upper()
        field = str(raw.get("field_path") or raw.get("header_name") or "")[:200]
        url = origin + path
        identity = templated_finding_identity({
            "cwe": cwe, "tool": f"shakerscan_request_verify:{proof_class}", "url": url,
            "evidence": {"method": method, "param": field},
        }) or f"request_verify|{proof_class}|{method}|{url}|{field}"
        evidence = {
            "schema_version": "hunt-deterministic-finding/v1", "authoritative": True,
            "proof_state": "verified", "finding_verdict": "verified",
            "canonical_capability": CAPABILITY, "proof_contract": str(raw["proof_contract"]),
            "hunt_id": str(hunt_id), "source_action_id": str(action_id),
            "tool_receipt_id": str(receipt_id), "origin": origin, "url": url, "path": path,
            "method": method, "check": capability_input.get("check"), "proof_class": proof_class,
            **({"param": field, "field_path": field} if field else {}),
            **{key: raw.get(key) for key in (
                "technique", "repetitions", "response_pairs", "payload_shape", "file_signature",
                "timing_ms", "operator", "header_name", "credentials", "header_issues", "attempts",
                "refusal_status", "batch_size", "alias_count", "duplicate_count", "suggested_fields",
                "served_content_type", "token_field_removed", "algorithm", "none_spelling",
                "secret_in_common_list", "forged_token_accepted", "listed_links", "root_type", "product",
                "exposure_class", "matched_pattern", "secret_keys",
            ) if raw.get(key) is not None},
            "proof_producer": "shakerscan", "evidence_type": "deterministic_differential",
            "secret_values_visible": False,
        }
        records.append({
            "fingerprint": "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
            "url": url, "evidence": evidence, "title": title,
            "description": f"{reason}. Proved on {method} {path}" + (f" ({field})." if field else "."),
            "tool": "shakerscan_request_verify", "cwe": cwe, "finding_type": proof_class,
            "verdict_reason": reason, "contract_id": str(raw["proof_contract"]).split("/", 1)[0],
            "severity": severity,
        })
    return records


__all__ = [
    "CAPABILITY", "CHECKS", "REQUEST_FINDINGS", "REQUEST_VERIFY_HOLD",
    "RequestVerificationExecutionAdapter", "RequestVerificationRefused", "admission_refusal",
    "build_request", "finding_records", "prepare_operation", "run_check", "redacted_input", "verifier_adapter", "writes",
]
