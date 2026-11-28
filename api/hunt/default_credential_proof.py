"""Deterministic proof for a default-credential candidate: the accepted pair again, and a control.

A Hunt records an accepted default-credential attempt as a candidate of family
``default_credentials`` citing the attempt's action (hunt/default_credentials.py). ``candidate.verify``
on that candidate runs this proof, inside the verification action, under the Hunt's authority:

1. It finds the cited attempt in this Hunt's attempts ledger: accepted, with the login request's
   recorded shape (login URL, body kind, literal body fields and the two field pointers).
2. It sends that login twice on the same login URL, by the server's own values: the accepted pair
   again, then a control with the pair's user name and a fresh random password no list holds. The
   control has the pair's password's length and character classes, so only the value differs (a
   login that checks a password's form before authenticating cannot refuse it for its form).
   Both are ordinary default-credential attempts: admitted by the same bounds (attempts per
   login, the cross-Hunt window, pacing, the lockout and rate-limit stop), recorded in the ledger
   and archived as this action's HTTP evidence; redirects are not followed.
3. Each answer is judged by the same classifier as every attempt, from the private response.

Proven only when the pair is accepted again AND the control is refused. A lockout or rate-limit
sign at either step stops the check on that login (as for any attempt) and leaves the candidate
inconclusive; so does a control that is not clearly refused, a request whose shape cannot be
replayed (it carried values captured from a page), or a login the bounds no longer admit. A
control that is accepted refutes the candidate (the login accepts any password, not this pair).
The proof's evidence names the pair by reference and user name only; no password is stored. When
the planner bound only the pair's password and wrote its own user name into the body, the proof
names no user: the pair's user name was never sent.

Authority and accounting are the attempt's own (runtime/hunt_http_contract.py): a login needs
active_testing, not the state-changing permission, and is not charged as a state-changing
request. The proof's ``traffic`` counts every request it sends, the form page's GET included, and
names its login POSTs separately.
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
    """An evidence reference's action id: the bare id, or the ``action:<id>`` form candidates use
    elsewhere (the engine's own sweep cites its attempts that way)."""
    try:
        return uuid.UUID(str(value).strip().removeprefix("action:"))
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
    request = {"method": "POST", "origin": origin, "path": url.path or "/", body_kind: body,
               "follow_redirects": False}
    if shape.get("form_prefetch") is True and body_kind == "form_body":
        request["form_prefetch"] = True
        if shape.get("form_page"):
            request["form_page"] = str(shape["form_page"])
    return request


def control_secret(password: str, *, avoid: Any = ()) -> str:
    """A random password of the same length and character classes as ``password``: a lower-case
    letter for each lower-case letter, a digit for each digit, and so on (any other character is
    kept). Never ``password`` itself, a listed password or a value in ``avoid``."""
    import string
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
    taken = {password, *(listed for _id, _user, listed, _source in dc.PAIRS), *(str(v) for v in avoid)}
    for _ in range(64):
        value = "".join(
            next((secrets.choice(alphabet) for alphabet in classes if char in alphabet), char)
            for char in password)
        if value not in taken:
            return value
    # No such value exists (a password of other characters only): a longer one of the same alphabet.
    return password + secrets.choice(string.ascii_lowercase) + secrets.token_hex(4)


def step_requests(shape: Mapping[str, Any]) -> int:
    """The requests one proof step sends: the login, and the form's page first when it is read."""
    return 2 if shape.get("form_prefetch") is True and shape.get("body_kind") == "form" else 1


async def _admit(conn: Any, *, run: Mapping[str, Any], login_key: str, pair_id: str, reserve: int,
                 first: bool = False) -> None:
    """The same bounds as an attempt, for ``reserve`` more attempts on this login. The first step
    is also paced against the Hunt's last attempt there and waits for an attempt that has no
    answer yet; the proof paces its own second step."""
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 7243))", login_key)
    hunt_id = uuid.UUID(str(run["id"]))
    rows = await conn.fetch(
        """SELECT pair_id, verdict, EXTRACT(EPOCH FROM (NOW() - attempted_at)) AS age
           FROM hunt_default_credential_attempts WHERE hunt_run_id=$1 AND login_key=$2
           ORDER BY attempted_at DESC""", hunt_id, login_key)
    if any(row["verdict"] in dc.STOP_VERDICTS for row in rows) or await dc.stop_recorded(
            conn, hunt_id=hunt_id, key=login_key):
        raise DefaultCredentialProofRefused(
            "default_credentials_stopped",
            "This login answered with a lockout or rate-limit sign; the proof sends nothing more to it.")
    if first and rows and rows[0]["age"] is not None and float(rows[0]["age"]) < dc.PACE_SECONDS:
        raise DefaultCredentialProofRefused(
            "default_credentials_paced",
            f"Default-credential attempts on one login are at least {dc.PACE_SECONDS:g} seconds apart; "
            "verify again in a moment. Nothing was sent.")
    if await dc.answer_awaited(conn, key=login_key):
        raise DefaultCredentialProofRefused(
            "default_credentials_paced",
            "An earlier default-credential attempt on this login has no answer yet; verify again once "
            "it has. Nothing was sent.")
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
    # The pair's user name is named only when the proof sends it (the planner may have bound the
    # password alone and written another user name into the body).
    username = pair[0] if shape.get("user_pointer") or shape.get("body_kind") == dc.BASIC_FIELD else None
    steps = (("pair", attempt["pair_id"], pair[1]),
             ("control", CONTROL_PAIR, control_secret(pair[1], avoid=(pair[0],))))
    send = send or _worker_sender(pool, run=run, context=context, policy=policy, action_id=action_id)
    sleep = sleep or asyncio.sleep
    outcome: dict[str, str] = {}
    for index, (label, pair_id, secret) in enumerate(steps):
        async with pool.acquire() as conn:
            async with conn.transaction():
                try:
                    await _admit(conn, run=run, login_key=attempt["login_key"], pair_id=pair_id,
                                 reserve=len(steps) - index, first=not index)
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
    return evaluate(outcome, attempt=attempt, username=username, requests_per_step=step_requests(shape))


def evaluate(outcome: Mapping[str, str], *, attempt: Mapping[str, Any], username: str | None,
             requests_per_step: int = 1) -> dict[str, Any]:
    """The family-proof verdict from the two steps' verdicts. ``username`` is the user name the
    proof sent, or None when the login's user name was the planner's own."""
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
        "traffic": _traffic(outcome, attempt=attempt, requests_per_step=requests_per_step),
    }


def _traffic(outcome: Mapping[str, str], *, attempt: Mapping[str, Any], requests_per_step: int) -> dict[str, int]:
    """What the proof sent. ``http_requests`` is every request (each step's login and the form
    page read before it); ``login_posts`` the logins sent with a body. ``state_changing_requests``
    is the Hunt's budget dimension and stays 0, as for the attempt this proof repeats: a login is
    admitted on active_testing and not charged as a state-changing request
    (runtime/hunt_http_contract.require_http_request_authority)."""
    sent = sum(1 for value in outcome.values() if value != "not_sent")
    basic = (attempt.get("request_shape") or {}).get("body_kind") == dc.BASIC_FIELD
    return {"http_requests": sent * max(1, int(requests_per_step)),
            "login_posts": 0 if basic else sent, "state_changing_requests": 0}



def finding_record(proof: Mapping[str, Any], *, hunt_id: Any, action_id: Any) -> dict[str, Any]:
    """The verified finding a proven default-credential candidate becomes (no password in it)."""
    try:
        from findings import templated_finding_identity
    except ModuleNotFoundError:  # package import layout
        from scanner.findings import templated_finding_identity
    import hashlib
    url = str(proof["login_url"])
    username = str(proof["username"]) if proof.get("username") else ""
    identity = templated_finding_identity({
        "cwe": "CWE-1392", "tool": "shakerscan_default_credentials", "url": url,
        "evidence": {"method": "POST", "param": username[:80]},
    }) or f"default_credentials|{url}|{username}"
    evidence = {
        "schema_version": "hunt-deterministic-finding/v1", "authoritative": True,
        "proof_state": "verified", "finding_verdict": "verified",
        "canonical_capability": "candidate.verify", "proof_contract": PROOF_CONTRACT,
        "hunt_id": str(hunt_id), "source_action_id": str(proof.get("source_action_id")),
        "verification_action_id": str(action_id), "url": url, "method": "POST",
        "default_credential": {"pair": proof.get("pair"), **({"username": username} if username else {})},
        "steps": dict(proof.get("steps") or {}),
        "proof_producer": "shakerscan", "evidence_type": "deterministic_differential",
        "secret_values_visible": False,
    }
    return {
        "fingerprint": "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
        "url": url, "evidence": evidence,
        "title": (f"Verified default credentials accepted for user {username[:60]}" if username
                  else "Verified default password accepted on a login"),
        "description": ("The login accepted a well-known default or common credential pair, sent "
                        "again by the server, while a random-password control for the same user was "
                        "refused." if username else
                        "The login accepted a well-known default or common password for the user name "
                        "the Hunt supplied, sent again by the server, while a random-password control "
                        "for the same user name was refused."),
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
