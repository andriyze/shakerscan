"""Deterministic proof for a default-credential candidate: the accepted pair again, and a control.

A Hunt records an accepted default-credential attempt as a candidate of family
``default_credentials`` citing the attempt's action (hunt/default_credentials.py). ``candidate.verify``
on that candidate runs this proof, inside the verification action, under the Hunt's authority:

1. It finds the cited attempt in this Hunt's attempts ledger: accepted, with the login request's
   recorded shape (login URL, body kind, literal body fields and the two field pointers).
2. It sends that login twice on the same login URL, by the server's own values: the accepted pair
   again, then a control with the pair's user name and a fresh random password no list holds.
   Both are ordinary default-credential attempts: admitted by the same bounds (attempts per
   login, the cross-Hunt window, pacing, the lockout and rate-limit stop), recorded in the ledger
   and archived as this action's HTTP evidence; redirects are not followed.
3. Each answer is judged by the same classifier as every attempt, from the private response.

Proven only when the pair is accepted again AND the control is refused. A lockout or rate-limit
sign at either step stops the check on that login (as for any attempt) and leaves the candidate
inconclusive; so does a control that is not clearly refused, a request whose shape cannot be
replayed (it carried values captured from a page), or a login the bounds no longer admit. A
control that is accepted refutes the candidate (the login accepts any password, not this pair).
The proof's evidence names the pair by reference and user name only; no password is stored.
"""
from __future__ import annotations

from collections.abc import Mapping
import asyncio
import copy
import json
import os
from pathlib import Path
import secrets
from typing import Any
import urllib.parse
import uuid

from . import default_credentials as dc

FAMILY = "default_credentials"
FAMILY_ALIASES = ("default_credential", "weak_credentials", "weak_credential", "weak_password",
                  "default_password")
CONTROL_PAIR = "dc-00"
PROOF_CONTRACT = "default_credentials/v1"
_TERMINAL_VERDICTS = frozenset({"accepted", "rejected", "unclear", "rate_limited", "locked", "not_sent"})


class DefaultCredentialProofRefused(Exception):
    """The proof cannot run; nothing was sent. ``reason`` is machine-readable."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def is_default_credential_family(family: Any) -> bool:
    text = str(family or "").strip().lower().replace("-", "_").replace(" ", "_")
    return text == FAMILY or text in FAMILY_ALIASES


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


async def accepted_attempt(conn: Any, *, hunt_id: Any, evidence_refs: Any) -> dict[str, Any]:
    """The accepted attempt the candidate cites (one of its evidence actions), with its shape."""
    refs = [ref for ref in (_uuid(item) for item in (evidence_refs or [])[:50]) if ref is not None]
    if not refs:
        raise DefaultCredentialProofRefused(
            "default_credentials_evidence_missing",
            "The candidate cites no action of this Hunt; cite the accepted default-credential attempt.")
    row = await conn.fetchrow(
        """SELECT action_id, login_key, login_host, pair_id, verdict, request_shape
           FROM hunt_default_credential_attempts
           WHERE hunt_run_id=$1 AND action_id = ANY($2::uuid[]) AND verdict='accepted'
             AND pair_id <> $3
           ORDER BY attempted_at DESC LIMIT 1""",
        uuid.UUID(str(hunt_id)), refs, CONTROL_PAIR,
    )
    if row is None:
        raise DefaultCredentialProofRefused(
            "default_credentials_evidence_missing",
            "None of the candidate's evidence actions is an accepted default-credential attempt of "
            "this Hunt.")
    attempt = dict(row)
    shape = _json(attempt.get("request_shape"), {})
    if not isinstance(shape, Mapping) or not shape.get("replayable") or not shape.get("login_url"):
        raise DefaultCredentialProofRefused(
            "default_credentials_not_replayable",
            "The accepted attempt carried values captured from a page (a CSRF token) or has no "
            "recorded shape, so it cannot be replayed deterministically.")
    attempt["request_shape"] = dict(shape)
    return attempt


def build_request(shape: Mapping[str, Any], *, username: str | None, secret: str) -> dict[str, Any]:
    """The login request for one proof step, from the recorded shape and the server's values."""
    url = urllib.parse.urlsplit(str(shape["login_url"]))
    origin = f"{url.scheme}://{url.netloc}"
    if shape.get("body_kind") == dc.BASIC_FIELD:
        import base64
        token = base64.b64encode(f"{username or ''}:{secret}".encode()).decode("ascii")
        # ``trusted_headers`` never reaches the wire input: the sender passes it beside the request.
        return {"method": "GET", "origin": origin, "path": url.path or "/", "follow_redirects": False,
                "trusted_headers": {"Authorization": f"Basic {token}"}}
    body_kind = "json_body" if shape.get("body_kind") == "json" else "form_body"
    body = copy.deepcopy(dict(shape.get("body") or {}))
    try:
        from runtime.hunt_http_exchange_contract import pointer_set
    except ModuleNotFoundError:  # package import layout
        from ..runtime.hunt_http_exchange_contract import pointer_set
    if shape.get("user_pointer") and username is not None:
        pointer_set(body, str(shape["user_pointer"]), username)
    pointer_set(body, str(shape["secret_pointer"]), secret)
    return {"method": "POST", "origin": origin, "path": url.path or "/", body_kind: body,
            "follow_redirects": False}


async def _admit(conn: Any, *, run: Mapping[str, Any], login_key: str, pair_id: str, reserve: int) -> None:
    """The same bounds as an attempt, for ``reserve`` more attempts on this login."""
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 7243))", login_key)
    hunt_id = uuid.UUID(str(run["id"]))
    rows = await conn.fetch(
        """SELECT pair_id, verdict, EXTRACT(EPOCH FROM (NOW() - attempted_at)) AS age
           FROM hunt_default_credential_attempts WHERE hunt_run_id=$1 AND login_key=$2
           ORDER BY attempted_at DESC""", hunt_id, login_key)
    if any(row["verdict"] in dc.STOP_VERDICTS for row in rows) or await conn.fetchval(
            """SELECT 1 FROM hunt_default_credential_attempts
               WHERE login_key=$1 AND verdict = ANY($2::text[]) AND attempted_at > NOW() - $3::interval
               LIMIT 1""", login_key, sorted(dc.STOP_VERDICTS), dc.WINDOW):
        raise DefaultCredentialProofRefused(
            "default_credentials_stopped",
            "This login answered with a lockout or rate-limit sign; the proof sends nothing more to it.")
    if len(rows) + reserve > dc.MAX_ATTEMPTS_PER_LOGIN:
        raise DefaultCredentialProofRefused(
            "default_credentials_exhausted",
            f"The proof needs {reserve} more attempts on this login and the Hunt has "
            f"{max(0, dc.MAX_ATTEMPTS_PER_LOGIN - len(rows))} left of {dc.MAX_ATTEMPTS_PER_LOGIN}.")
    window = int(await conn.fetchval(
        """SELECT count(*) FROM hunt_default_credential_attempts
           WHERE login_key=$1 AND attempted_at > NOW() - $2::interval""", login_key, dc.WINDOW) or 0)
    if window + reserve > dc.WINDOW_MAX:
        raise DefaultCredentialProofRefused(
            "default_credentials_paced",
            f"This login received {window} default-credential attempts in the last hour; the proof "
            "would exceed the cross-Hunt limit. Try again later.")


async def run_proof(
    pool: Any, *, run: Mapping[str, Any], context: Mapping[str, Any], policy: Mapping[str, Any],
    candidate: Mapping[str, Any], action_id: Any, send: Any = None, sleep: Any = None,
) -> dict[str, Any]:
    """The proof for one candidate. ``send(request) -> (verdict, public_response)`` sends one step
    (the worker HTTP path by default); ``sleep`` paces the two steps."""
    if not dc.enabled():
        raise DefaultCredentialProofRefused(
            "default_credentials_disabled", "The operator switched the default-credential check off.")
    if policy.get("active_testing") is not True:
        raise DefaultCredentialProofRefused(
            "default_credentials_invalid", "The proof needs this Hunt's active_testing permission.")
    async with pool.acquire() as conn:
        attempt = await accepted_attempt(conn, hunt_id=run["id"],
                                         evidence_refs=_json(candidate.get("evidence_refs"), []))
    shape = attempt["request_shape"]
    pair = dc.pair(attempt["pair_id"])
    if pair is None:
        raise DefaultCredentialProofRefused("default_credentials_evidence_missing", "Unknown pair reference.")
    username = pair[0] if shape.get("user_pointer") or shape.get("body_kind") == dc.BASIC_FIELD else None
    control_secret = "shakerscan-control-" + secrets.token_urlsafe(18)
    steps = (("pair", attempt["pair_id"], pair[1]), ("control", CONTROL_PAIR, control_secret))
    send = send or _worker_sender(pool, run=run, context=context, policy=policy, action_id=action_id)
    sleep = sleep or asyncio.sleep
    outcome: dict[str, str] = {}
    for index, (label, pair_id, secret) in enumerate(steps):
        async with pool.acquire() as conn:
            async with conn.transaction():
                try:
                    await _admit(conn, run=run, login_key=attempt["login_key"], pair_id=pair_id,
                                 reserve=len(steps) - index)
                except DefaultCredentialProofRefused:
                    if not index:
                        raise  # nothing was sent: a refusal, not a verdict
                    break  # the pair was sent: the proof ends inconclusive, the control unsent
                await conn.execute(
                    """INSERT INTO hunt_default_credential_attempts
                           (hunt_run_id, action_id, login_key, login_host, pair_id, request_shape)
                       VALUES ($1,$2,$3,$4,$5,$6::jsonb)""",
                    uuid.UUID(str(run["id"])), uuid.UUID(str(action_id)), attempt["login_key"],
                    attempt["login_host"], pair_id, json.dumps({"proof_step": label}))
        if index:
            await sleep(dc.PACE_SECONDS)
        verdict = await send(build_request(shape, username=username, secret=secret))
        verdict = verdict if verdict in _TERMINAL_VERDICTS else "unclear"
        outcome[label] = verdict
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE hunt_default_credential_attempts SET verdict=$4, settled_at=NOW()
                   WHERE hunt_run_id=$1 AND action_id=$2 AND pair_id=$3 AND verdict='pending'""",
                uuid.UUID(str(run["id"])), uuid.UUID(str(action_id)), pair_id, verdict)
        if verdict in dc.STOP_VERDICTS or (label == "pair" and verdict != "accepted"):
            break
    return evaluate(outcome, attempt=attempt, username=pair[0])


def evaluate(outcome: Mapping[str, str], *, attempt: Mapping[str, Any], username: str) -> dict[str, Any]:
    """The family-proof verdict from the two steps' verdicts."""
    try:
        from family_proof import evaluate_family_proof
    except ModuleNotFoundError:  # package import layout
        from ..family_proof import evaluate_family_proof
    pair, control = outcome.get("pair"), outcome.get("control")
    evidence = {
        "pair_authenticated": pair == "accepted",
        "control_rejected": control == "rejected",
        "same_login": True,
        "control_authenticated": control == "accepted",
        "reexecuted_at_handoff": pair is not None,
    }
    proof = evaluate_family_proof(FAMILY, evidence)
    stopped = any(value in dc.STOP_VERDICTS for value in outcome.values())
    return {
        "proof_contract": PROOF_CONTRACT,
        "verdict": proof.get("verdict"),
        "promotable": bool(proof.get("promotable")) and not stopped,
        "steps": {"pair": pair or "not_sent", "control": control or "not_sent"},
        "stopped": stopped,
        "pair": str(attempt["pair_id"]), "username": username,
        "login_url": str(attempt["request_shape"].get("login_url")),
        "source_action_id": str(attempt["action_id"]),
        "traffic": {"http_requests": sum(1 for value in outcome.values() if value != "not_sent"),
                    "state_changing_requests": 0},
    }


def finding_record(proof: Mapping[str, Any], *, hunt_id: Any, action_id: Any) -> dict[str, Any]:
    """The verified finding a proven default-credential candidate becomes (no password in it)."""
    try:
        from findings import templated_finding_identity
    except ModuleNotFoundError:  # package import layout
        from scanner.findings import templated_finding_identity
    import hashlib
    url = str(proof["login_url"])
    identity = templated_finding_identity({
        "cwe": "CWE-1392", "tool": "shakerscan_default_credentials", "url": url,
        "evidence": {"method": "POST", "param": str(proof.get("username") or "")[:80]},
    }) or f"default_credentials|{url}|{proof.get('username')}"
    evidence = {
        "schema_version": "hunt-deterministic-finding/v1", "authoritative": True,
        "proof_state": "verified", "finding_verdict": "verified",
        "canonical_capability": "candidate.verify", "proof_contract": PROOF_CONTRACT,
        "hunt_id": str(hunt_id), "source_action_id": str(proof.get("source_action_id")),
        "verification_action_id": str(action_id), "url": url, "method": "POST",
        "default_credential": {"pair": proof.get("pair"), "username": proof.get("username")},
        "steps": dict(proof.get("steps") or {}),
        "proof_producer": "shakerscan", "evidence_type": "deterministic_differential",
        "secret_values_visible": False,
    }
    return {
        "fingerprint": "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
        "url": url, "evidence": evidence,
        "title": f"Verified default credentials accepted for user {str(proof.get('username'))[:60]}",
        "description": ("The login accepted a well-known default or common credential pair, sent "
                        "again by the server, while a random-password control for the same user was "
                        "refused."),
        "tool": "shakerscan_default_credentials", "cwe": "CWE-1392",
        "finding_type": "default_credentials",
        "verdict_reason": "Accepted pair re-authenticated; random-password control refused",
        "contract_id": "default_credentials", "severity": "high",
    }


async def verify_candidate(
    pool: Any, *, run: Mapping[str, Any], context: Mapping[str, Any], policy: Mapping[str, Any],
    candidate_uuid: Any, action_id: Any, send: Any = None, sleep: Any = None,
) -> dict[str, Any]:
    """candidate.verify for a default-credential candidate: run the proof, then record it."""
    async with pool.acquire() as conn:
        candidate = await conn.fetchrow(
            """SELECT id, target_id, hunt_run_id, family, evidence_refs, status
               FROM investigation_candidates WHERE id=$1""", uuid.UUID(str(candidate_uuid)))
    if candidate is None or str(candidate["target_id"]) != str(run.get("target_id")):
        raise DefaultCredentialProofRefused("default_credentials_evidence_missing",
                                            "Candidate not found on this Hunt's target.")
    candidate = dict(candidate)
    proof = await run_proof(pool, run=run, context=context, policy=policy, candidate=candidate,
                            action_id=action_id, send=send, sleep=sleep)
    status = ("verified" if proof["promotable"] else
              "refuted" if proof["verdict"] == "refuted" else "inconclusive")
    finding_ids: list[str] = []
    async with pool.acquire() as conn:
        async with conn.transaction():
            if proof["promotable"]:
                try:
                    from hunt.deterministic_findings import persist_verified_records
                except ModuleNotFoundError:  # package import layout
                    from .deterministic_findings import persist_verified_records
                finding_ids = await persist_verified_records(
                    conn, [finding_record(proof, hunt_id=run["id"], action_id=action_id)],
                    hunt_id=uuid.UUID(str(run["id"])), action_id=uuid.UUID(str(action_id)),
                    target_id=uuid.UUID(str(candidate["target_id"])))
            public = {key: proof[key] for key in ("proof_contract", "verdict", "steps", "stopped", "pair",
                                                  "username", "login_url", "source_action_id")}
            await conn.execute(
                """UPDATE investigation_candidates SET status=$2,
                       verification_context=verification_context || jsonb_build_object(
                           'finding_id',$3::text,'verdict',$4::text,'proof',$5::jsonb),
                       updated_at=NOW()
                   WHERE id=$1""",
                candidate["id"], status, finding_ids[0] if finding_ids else None,
                str(proof["verdict"] or status), json.dumps(public))
    return {
        "candidate_id": str(candidate["id"]), "verified": bool(finding_ids),
        "verified_finding_id": finding_ids[0] if finding_ids else None,
        "proof_state": status, "family_proof": {"verdict": proof["verdict"], "promotable": proof["promotable"]},
        "default_credentials_proof": public, "traffic": proof["traffic"],
    }


def _worker_sender(pool: Any, *, run: Mapping[str, Any], context: Mapping[str, Any],
                   policy: Mapping[str, Any], action_id: Any) -> Any:
    """Send one proof step through the worker HTTP path and archive it as this action's evidence."""
    try:
        from capabilities.http import execute_bound_http_request
        from runtime import http_archive
        from hunt.target_binding import web_hunt_target
    except ModuleNotFoundError:  # package import layout
        from ..capabilities.http import execute_bound_http_request
        from ..runtime import http_archive
        from .target_binding import web_hunt_target
    target, target_url = web_hunt_target(run, context, policy)

    async def send(request: Mapping[str, Any]) -> str:
        request = dict(request)
        trusted = request.pop("trusted_headers", None)
        login_url = str(request["origin"]) + str(request["path"])
        archived, record = http_archive.hunt_run_call_recorder(
            run, action_id=action_id, capability_name="candidate.verify",
            adapter="hunt.default_credentials.proof", target_url=target_url)
        verdicts: list[str] = []

        def sink(private: Any) -> None:
            try:
                verdicts.append(dc.classify_response(
                    status=private.status_code, headers=private.headers(),
                    cookie_names=sorted(private.cookies()), body=private.body(),
                    location=private.headers().get("location"), login_path=str(request["path"]),
                    basic=trusted is not None))
            except Exception:  # noqa: BLE001 - target content never fails the proof step
                verdicts.append("unclear")

        await execute_bound_http_request(
            login_url, dict(request), target=target, allow_write=trusted is None,
            **({"trusted_headers": trusted} if trusted is not None else {}),
            transaction_recorder=lambda captured: record({**captured, "workflow_values_private": True}),
            principal_slot="workflow_binding", timeout_seconds=30,
            allow_bound_origin_redirects=False, private_response_sink=sink,
            private_response_headers=("retry-after",),
        )
        async with pool.acquire() as conn:
            await http_archive.archive_hunt_capture(
                conn, archived, run["id"], run["id"], Path(os.environ.get("RESULTS_DIR", "/results")))
        return verdicts[0] if verdicts else "not_sent"

    return send


__all__ = [
    "CONTROL_PAIR", "DefaultCredentialProofRefused", "FAMILY", "PROOF_CONTRACT", "accepted_attempt",
    "build_request", "evaluate", "finding_record", "is_default_credential_family", "run_proof",
    "verify_candidate",
]
