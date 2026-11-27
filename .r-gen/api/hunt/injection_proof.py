"""Deterministic proof for an injection candidate a Hunt recorded.

A planner that sees a parameter evaluate a template, read a file, run a command, fetch a URL or
change a database query records a candidate of that family with the route and the parameter.
``candidate.verify`` on it runs the Scan's own proofs here, inside the verification action and
under the Hunt's authority: the differential verifier (``capabilities.injection_verify``) for
template injection, path traversal, command injection and request forgery, the SQL injection
proof (``capabilities.sqli_proof``, every stage) and the NoSQL operator differential
(``capabilities.nosqli_verify``).

The family the planner wrote picks the proof: a specific name (``ssti``, ``path_traversal``,
``command_injection``, ``ssrf``, ``sqli``, ``nosqli``) runs that one, the plain ``injection``
runs them all. The proof is the server's: the planner's evidence locates the request, and only a
repeated differential the server observed itself verifies it. XSS is proven in a browser by
``xss.verify``, not here.

The request is a GET of the candidate's route with its one parameter, sent as the anonymous
client. Every request is archived as this action's HTTP evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any
import urllib.parse
import uuid

FAMILY = "injection"
PROOF_REQUESTS = 96
PROOF_WALL_SECONDS = 150
# What the planner called the candidate -> the proofs that run, in order.
_SERVER_CLASSES = ("template_injection", "path_traversal", "command_injection", "ssrf")
_PROOFS_BY_FAMILY: Mapping[str, tuple[str, ...]] = {
    "injection": (*_SERVER_CLASSES, "sqli", "nosqli"),
    "server_injection": _SERVER_CLASSES,
    "ssti": ("template_injection",), "template_injection": ("template_injection",),
    "server_side_template_injection": ("template_injection",),
    "path_traversal": ("path_traversal",), "directory_traversal": ("path_traversal",),
    "lfi": ("path_traversal",), "local_file_inclusion": ("path_traversal",),
    "command_injection": ("command_injection",), "os_command_injection": ("command_injection",),
    "cmdi": ("command_injection",), "rce": ("command_injection", "template_injection"),
    "remote_code_execution": ("command_injection", "template_injection"),
    "ssrf": ("ssrf",), "server_side_request_forgery": ("ssrf",),
    "sqli": ("sqli",), "sql_injection": ("sqli",),
    "nosqli": ("nosqli",), "nosql_injection": ("nosqli",),
}
_BROWSER_FAMILIES = frozenset({"xss", "cross_site_scripting", "dom_xss", "stored_xss", "reflected_xss"})
_FINDINGS: Mapping[str, tuple[str, str, str]] = {
    "template_injection": ("Verified server-side template injection", "critical", "CWE-1336"),
    "command_injection": ("Verified command injection", "critical", "CWE-78"),
    "path_traversal": ("Verified path traversal", "high", "CWE-22"),
    "ssrf": ("Verified server-side request forgery", "high", "CWE-918"),
    "sqli": ("Verified SQL injection", "critical", "CWE-89"),
    "nosqli": ("Verified NoSQL injection", "high", "CWE-943"),
}


class InjectionProofRefused(Exception):
    """The proof cannot run; nothing was sent. ``reason`` is machine-readable."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def _name(family: Any) -> str:
    return str(family or "").strip().lower().replace("-", "_").replace(" ", "_")


def is_injection_family(family: Any) -> bool:
    name = _name(family)
    return name in _PROOFS_BY_FAMILY or name in _BROWSER_FAMILIES


def proofs_for(family: Any) -> tuple[str, ...]:
    """The proofs a candidate of ``family`` runs; refused for a family proven in a browser."""
    name = _name(family)
    if name in _BROWSER_FAMILIES:
        raise InjectionProofRefused(
            "injection_proof_browser_family",
            "Cross-site scripting is proven in a browser: call xss.verify on the route.",
        )
    try:
        return _PROOFS_BY_FAMILY[name]
    except KeyError:
        raise InjectionProofRefused(
            "injection_proof_family_unknown",
            f"No injection proof for family '{name}'. Use one of: " + ", ".join(sorted(_PROOFS_BY_FAMILY)),
        ) from None


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def proof_request(candidate: Mapping[str, Any], *, origin: str) -> tuple[str, str, str]:
    """``(url, route, parameter)`` of the GET the proofs mutate, from the candidate's locus."""
    locus = _mapping(candidate.get("canonical_locus"))
    context = _mapping(candidate.get("verification_context"))
    method = str(locus.get("method") or context.get("method") or "GET").strip().upper()
    if method != "GET":
        raise InjectionProofRefused(
            "injection_proof_get_only",
            "This proof mutates one query parameter of a GET. For a request body call sqli.verify "
            "or xss.verify with the body fields.",
        )
    parameter = str(locus.get("parameter") or context.get("parameter") or "").strip()
    if not parameter or len(parameter) > 200 or any(ord(ch) < 33 for ch in parameter):
        raise InjectionProofRefused(
            "injection_proof_parameter_missing",
            "Name the parameter in the candidate's locus (parameter: <query parameter name>).",
        )
    raw = next((str(locus.get(key)).strip() for key in ("route", "url", "path") if locus.get(key)),
               str(context.get("route") or "").strip())
    parsed = urllib.parse.urlsplit(raw)
    route = parsed.path if parsed.scheme else raw.split("?", 1)[0].split("#", 1)[0]
    if not route.startswith("/") or any(ord(ch) < 33 for ch in route) or ".." in route.split("/"):
        raise InjectionProofRefused(
            "injection_proof_route_missing",
            "Name the request's path in the candidate's locus (route: /path).",
        )
    # The other parameters the planner's request carried stay as written; the tested one starts
    # from the value it had, or a plain one.
    pairs = [(name, value) for name, value in urllib.parse.parse_qsl(
        parsed.query if parsed.scheme else (raw.split("?", 1)[1].split("#", 1)[0] if "?" in raw else ""),
        keep_blank_values=True,
    ) if name != parameter][:32]
    original = next((value for name, value in urllib.parse.parse_qsl(
        parsed.query if parsed.scheme else (raw.split("?", 1)[1].split("#", 1)[0] if "?" in raw else ""),
        keep_blank_values=True,
    ) if name == parameter), "1")
    query = urllib.parse.urlencode([*pairs, (parameter, original)])
    return f"{origin}{route}?{query}", route, parameter


_FIELD_NAME = re.compile(r"^[A-Za-z0-9_\-\[\]]{1,64}$")
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def verifier_call(candidate: Mapping[str, Any]) -> dict[str, Any] | None:
    """The ready-to-send sqli.verify / xss.verify call for an injection candidate this proof cannot
    run (XSS, a request body), or None when the locus does not name a route and a parameter.

    2026-11: agents read "no deterministic verifier" and dropped injection leads; a refusal now
    carries the call that proves the claim. Only what the candidate's own locus names is used.
    """
    name = _name(candidate.get("family"))
    capability = "xss.verify" if name in _BROWSER_FAMILIES else (
        "sqli.verify" if name in _PROOFS_BY_FAMILY else None)
    if capability is None:
        return None
    locus = _mapping(candidate.get("canonical_locus"))
    context = _mapping(candidate.get("verification_context"))
    method = str(locus.get("method") or context.get("method") or "GET").strip().upper()
    parameter = str(locus.get("parameter") or context.get("parameter") or "").strip()
    raw = next((str(locus.get(key)).strip() for key in ("route", "url", "path") if locus.get(key)),
               str(context.get("route") or "").strip())
    parsed = urllib.parse.urlsplit(raw)
    route = parsed.path if parsed.scheme else raw.split("?", 1)[0].split("#", 1)[0]
    query = parsed.query if parsed.scheme else (raw.split("?", 1)[1].split("#", 1)[0] if "?" in raw else "")
    if (not route.startswith("/") or route.startswith("//") or any(ord(ch) < 33 for ch in route)
            or not _FIELD_NAME.match(parameter)):
        return None
    call: dict[str, Any] = {"capability": capability}
    if method in _BODY_METHODS:
        fields = [str(item) for item in (locus.get("body_field_names") or context.get("body_field_names") or [])
                  if _FIELD_NAME.match(str(item))][:32]
        if parameter not in fields:
            fields.append(parameter)
        call["input"] = {"path": route, "method": method, "body_field_names": fields, "injection_field": parameter}
        content_type = str(locus.get("content_type") or context.get("content_type") or "")
        if content_type in {"application/json", "application/x-www-form-urlencoded"}:
            call["input"]["content_type"] = content_type
        call["note"] = ("A body test sends writes: it needs the Hunt's state-changing permission. List every "
                        "field the endpoint expects in body_field_names.")
    elif method == "GET":
        pairs = [(key, value) for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True)
                 if key != parameter][:32]
        original = next((value for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True)
                         if key == parameter), "1")
        call["input"] = {"path": f"{route}?{urllib.parse.urlencode([*pairs, (parameter, original)])}"}
    else:
        return None
    slot = str(locus.get("as_principal") or context.get("as_principal") or "").strip()
    if slot and slot.lower() not in {"anonymous", "anon", "none"} and _FIELD_NAME.match(slot):
        call["input"]["as_principal"] = slot
    if capability == "sqli.verify" and name not in {"sqli", "sql_injection", "injection"}:
        call["note"] = ((call.get("note", "") + " ").lstrip()
                        + "sqli.verify proves SQL injection only; this proof covers the other classes "
                          "for a GET query parameter.")
    return call


def finding_record(
    proof: Mapping[str, Any], *, kind: str, hunt_id: Any, action_id: Any, url: str,
) -> dict[str, Any]:
    """The verified finding a proven injection candidate becomes (no response body in it)."""
    try:
        from findings import templated_finding_identity
    except ModuleNotFoundError:  # package import layout
        from scanner.findings import templated_finding_identity
    title, severity, cwe = _FINDINGS[kind]
    tool = {"sqli": "shakerscan_sqli_proof", "nosqli": "shakerscan_nosqli_verify"}.get(
        kind, "shakerscan_injection_verify")
    field = str(proof.get("field_path") or "")[:200]
    identity = templated_finding_identity({
        "cwe": cwe, "tool": tool, "url": url, "evidence": {"method": "GET", "param": field},
    }) or f"{kind}|{url}|{field}"
    evidence = {
        "schema_version": "hunt-deterministic-finding/v1", "authoritative": True,
        "proof_state": "verified", "finding_verdict": "verified",
        "canonical_capability": "candidate.verify",
        "proof_contract": proof.get("proof_contract"), "technique": proof.get("technique"),
        "hunt_id": str(hunt_id), "verification_action_id": str(action_id),
        "url": url, "origin": proof.get("origin"), "method": "GET", "field_path": field,
        "request_class": "safe_read", "candidate_id": proof.get("candidate_id"),
        **({"injection_class": kind} if tool == "shakerscan_injection_verify" else {}),
        **{key: proof[key] for key in ("payload_shape", "file_signature", "timing_ms", "operator",
                                       "database_error_signatures") if proof.get(key)},
        "repetitions": proof.get("repetitions"),
        "response_pairs": list(proof.get("response_pairs") or ())[:6],
        "proof_producer": "shakerscan", "evidence_type": "deterministic_differential",
        "secret_values_visible": False,
    }
    return {
        "fingerprint": "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
        "url": url, "evidence": evidence, "title": title,
        "description": ("The server sent the request itself: a probe changed the answer twice, "
                        "with different random values, and a control that carries the same "
                        "characters without the syntax did not."),
        "tool": tool, "cwe": cwe, "finding_type": kind,
        "verdict_reason": "Repeated deterministic differential satisfied; control silent",
        "contract_id": "injection", "severity": severity,
    }


async def run_proof(
    *, run: Mapping[str, Any], context: Mapping[str, Any], policy: Mapping[str, Any],
    candidate: Mapping[str, Any], action_id: Any, transport: Any = None,
    cancelled: Any = None, heartbeat: Any = None, service_origin: Any = None,
) -> dict[str, Any]:
    """Run every proof the candidate's family names; the first that verifies is the result.

    ``service_origin(candidate, target_url)`` names the HTTP service a candidate on a network
    target is proved on (``candidate_verification_preflight.verification_service_origin``, passed
    in by the caller: that module admits these candidates, so this one does not import it).
    """
    try:
        from capabilities.injection_verify import InjectionVerifyAdapter
        from capabilities.nosqli_verify import NoSQLiVerifyAdapter
        from capabilities.sqli_proof import SQLiProofAdapter
        from runtime.capability_registry import CAPABILITY_REGISTRY
        from scanner_tools.request_replay import ReplayRequest
        from hunt.target_binding import web_hunt_target
    except ModuleNotFoundError:  # package import layout
        from ..capabilities.injection_verify import InjectionVerifyAdapter
        from ..capabilities.nosqli_verify import NoSQLiVerifyAdapter
        from ..capabilities.sqli_proof import SQLiProofAdapter
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
        from scanner.scanner_tools.request_replay import ReplayRequest
        from .target_binding import web_hunt_target
    proofs = proofs_for(candidate.get("family"))
    target, target_url = web_hunt_target(run, context, policy)
    named = service_origin(
        candidate, str(_mapping(context.get("target")).get("url") or target_url),
    ) if service_origin is not None else None
    parsed = urllib.parse.urlsplit(named or target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    url, route, parameter = proof_request(candidate, origin=origin)
    request = ReplayRequest(
        request_id=f"candidate:{candidate['id']}", ordinal=0, name="injection proof", folder="",
        method="GET", url=url, headers=(), body=b"", body_mode="none", auth_type="none",
        has_sensitive_material=False,
    )
    proof_candidate = {
        "candidate_id": hashlib.sha256(f"{candidate['id']}".encode()).hexdigest(),
        "method": "GET", "field_path": parameter, "parameter_name": parameter,
        "canonical_path": route, "request_class": "safe_read", "request_ref_id": None,
        "body_field_names": [],
    }
    server = tuple(name for name in proofs if name not in {"sqli", "nosqli"})
    stages: list[tuple[str, Any]] = []
    if server:
        stages.append(("injection.verify_batch", lambda budget: InjectionVerifyAdapter(
            specification=CAPABILITY_REGISTRY.require("injection.verify_batch"), target=target,
            request=request, candidate=proof_candidate, transport=transport,
            requested_budget=budget, classes=server)))
    if "sqli" in proofs:
        stages.append(("sqli.prove_batch", lambda budget: SQLiProofAdapter(
            specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"), target=target,
            request=request, candidate=proof_candidate, transport=transport,
            requested_budget=budget, extended=True)))
    if "nosqli" in proofs:
        stages.append(("nosqli.verify_batch", lambda budget: NoSQLiVerifyAdapter(
            specification=CAPABILITY_REGISTRY.require("nosqli.verify_batch"), target=target,
            request=request, candidate=proof_candidate, transport=transport,
            requested_budget=budget)))

    async def beat() -> None:
        # Between requests: lets the caller re-read whether the Hunt was cancelled.
        if heartbeat is not None:
            await heartbeat()

    sent = 0
    observations: list[dict[str, Any]] = []
    errors: list[str] = []
    verified: dict[str, Any] | None = None
    for position, (_capability, build) in enumerate(stages):
        left = PROOF_REQUESTS - sent
        share = left // (len(stages) - position)
        if share < 8:
            break
        try:
            adapter = build({"http_requests": share, "tool_wall_seconds": PROOF_WALL_SECONDS // len(stages)})
            result = await adapter.execute(heartbeat=beat, cancelled=cancelled or (lambda: False))
        except ValueError as exc:  # the request does not fit this proof: try the next
            errors.append(f"proof_unconstructable:{exc}"[:200])
            continue
        sent += int(result.actual_budget.get("http_requests") or 0)
        errors.extend(str(item)[:200] for item in result.errors)
        for item in result.observations:
            item = dict(item)
            observations.append(item)
            if verified is None and item.get("proof_state") == "verified":
                kind = str(item.get("injection_class") or (
                    "sqli" if str(item.get("proof_contract") or "").startswith("sqli_") else "nosqli"))
                verified = {**item, "kind": kind}
        if verified is not None:
            break
    refused = next((str(item.get("inconclusive_reason")) for item in observations
                    if item.get("finding_verdict") == "inconclusive"), None)
    return {
        "verdict": "verified" if verified else "inconclusive" if refused or errors else "not_reproduced",
        "promotable": verified is not None, "verified": verified, "url": url.split("?", 1)[0],
        "route": route, "parameter": parameter, "proofs": list(proofs),
        "tried": [
            {"proof": str(item.get("injection_class") or item.get("kind")),
             "proof_state": item.get("proof_state"),
             **({"reason": item["inconclusive_reason"]} if item.get("inconclusive_reason") else {})}
            for item in observations
        ][:16],
        "errors": errors[:5],
        "traffic": {"http_requests": sent, "state_changing_requests": 0},
    }


async def verify_candidate(
    pool: Any, *, run: Mapping[str, Any], context: Mapping[str, Any], policy: Mapping[str, Any],
    candidate_uuid: Any, action_id: Any, transport: Any = None, cancelled: Any = None,
    heartbeat: Any = None, service_origin: Any = None,
) -> dict[str, Any]:
    """candidate.verify for an injection candidate: run the proofs, then record the result."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT id, target_id, hunt_run_id, family, canonical_locus, verification_context, status
               FROM investigation_candidates WHERE id=$1""", uuid.UUID(str(candidate_uuid)))
    if row is None or str(row["target_id"]) != str(run.get("target_id")):
        raise InjectionProofRefused("injection_proof_candidate_missing",
                                    "Candidate not found on this Hunt's target.")
    candidate = dict(row)
    archived = None
    if transport is None:
        try:
            from capabilities.replay import RecordedHuntReplayTransport
            from runtime import http_archive
            from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
            from hunt.target_binding import web_hunt_target
        except ModuleNotFoundError:  # package import layout
            from ..capabilities.replay import RecordedHuntReplayTransport
            from ..runtime import http_archive
            from ..runtime.pinned_http_replay import PinnedAiohttpReplayTransport
            from .target_binding import web_hunt_target
        _target, target_url = web_hunt_target(run, context, policy)
        archived, recorder = http_archive.hunt_run_call_recorder(
            run, action_id=action_id, capability_name="candidate.verify",
            adapter="hunt.injection.proof", target_url=target_url)
        transport = RecordedHuntReplayTransport(
            PinnedAiohttpReplayTransport(), recorder, principal_slot="anonymous")
    try:
        proof = await run_proof(run=run, context=context, policy=policy, candidate=candidate,
                                action_id=action_id, transport=transport, cancelled=cancelled,
                                heartbeat=heartbeat, service_origin=service_origin)
    finally:
        if archived:
            async with pool.acquire() as conn:
                await http_archive.archive_hunt_capture(
                    conn, archived, run["id"], run["id"],
                    Path(os.environ.get("RESULTS_DIR", "/results")))
    status = "verified" if proof["promotable"] else "inconclusive"
    finding_ids: list[str] = []
    public = {key: proof[key] for key in ("verdict", "route", "parameter", "proofs", "tried", "errors")}
    async with pool.acquire() as conn:
        async with conn.transaction():
            if proof["promotable"]:
                try:
                    from hunt.deterministic_findings import persist_verified_records
                except ModuleNotFoundError:  # package import layout
                    from .deterministic_findings import persist_verified_records
                verified = proof["verified"]
                public["proof_contract"] = verified.get("proof_contract")
                finding_ids = await persist_verified_records(
                    conn, [finding_record(verified, kind=verified["kind"], hunt_id=run["id"],
                                          action_id=action_id, url=proof["url"])],
                    hunt_id=uuid.UUID(str(run["id"])), action_id=uuid.UUID(str(action_id)),
                    target_id=uuid.UUID(str(candidate["target_id"])))
            await conn.execute(
                """UPDATE investigation_candidates SET status=$2,
                       verification_context=verification_context || jsonb_build_object(
                           'finding_id',$3::text,'verdict',$4::text,'proof',$5::jsonb),
                       updated_at=NOW()
                   WHERE id=$1""",
                candidate["id"], status, finding_ids[0] if finding_ids else None,
                str(proof["verdict"]), json.dumps(public))
    return {
        "candidate_id": str(candidate["id"]), "verified": bool(finding_ids),
        "verified_finding_id": finding_ids[0] if finding_ids else None,
        "proof_state": status,
        "family_proof": {"verdict": proof["verdict"], "promotable": proof["promotable"]},
        "injection_proof": public, "traffic": proof["traffic"],
    }


__all__ = [
    "FAMILY", "InjectionProofRefused", "PROOF_REQUESTS", "finding_record", "is_injection_family",
    "proof_request", "proofs_for", "run_proof", "verify_candidate",
]
