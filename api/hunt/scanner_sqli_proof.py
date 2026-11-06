"""A Hunt ``sqli.verify`` signal is proved with the Scan's deterministic SQLi proof.

sqlmap's "parameter ... is vulnerable" line is a candidate in a Scan until the repeated
payload/control differential of ``sqli.prove_batch`` (``capabilities/sqli_proof.py``) holds; only
that proof makes a verified finding. A Hunt holds the same standard: when its ``sqli.verify`` run
reports a vulnerable parameter it named (a query parameter of the tested URL or one of the body
fields it was given), the same worker job runs ``SQLiProofAdapter`` against the same request,
signed in as the run was, inside what is left of the action's own reservation. The proof's
``sqli_proof`` observation joins the action's observations; ``deterministic_findings`` turns a
verified one into a finding exactly as the Scan finalizer does.

Value-free: the request carries the inert placeholder the tool's body template used, the proof
publishes digests and the field name, and every request goes to the Hunt's call archive.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import math
import time
from typing import Any, Awaitable, Callable, Mapping, Sequence
import urllib.parse

try:
    from capabilities.sqli_proof import SQLiProofAdapter, SQLiProofError
    from capabilities.replay import RecordedHuntReplayTransport
    from runtime.auth_refusal import is_authentication_candidate
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from runtime import http_archive
except ModuleNotFoundError:
    from ..capabilities.sqli_proof import SQLiProofAdapter, SQLiProofError
    from ..capabilities.replay import RecordedHuntReplayTransport
    from ..runtime.auth_refusal import is_authentication_candidate
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.pinned_http_replay import PinnedAiohttpReplayTransport
    from ..runtime import http_archive

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest

# The proof's stages: an error pair (4), then a boolean pair (4) or an authentication-bypass pair
# (4), then three timing pairs (6). It needs at least the error pair.
PROOF_REQUESTS = 14
PROOF_MINIMUM_REQUESTS = 4
PROOF_WALL_SECONDS = 60
PROOF_MINIMUM_WALL_SECONDS = 4
# The value every body field carries (agent_tools._BODY_PLACEHOLDER_VALUE): the request the proof
# sends is the request sqlmap was given.
_PLACEHOLDER = "shakerscan"


def _signalled_parameters(observations: Sequence[Mapping[str, Any]]) -> list[str]:
    """Parameter names sqlmap called vulnerable, in report order ("JSON user" names ``user``)."""
    names: list[str] = []
    for item in observations:
        if not isinstance(item, Mapping) or item.get("kind") != "sqli_finding":
            continue
        raw = str(item.get("param") or "").strip()
        name = raw.split()[-1] if raw else ""
        if name and name not in names:
            names.append(name)
    return names


def proof_request(
    execution_target: str, values: Mapping[str, Any], parameter: str, *,
    headers: Mapping[str, str], action_id: Any,
) -> tuple[ReplayRequest, dict[str, Any]] | None:
    """The exact request and proof candidate for one signalled parameter, or None."""
    parsed = urllib.parse.urlsplit(execution_target)
    fields = [str(item) for item in values.get("body_field_names") or ()]
    header_items = tuple((str(k), str(v)) for k, v in headers.items() if str(k).lower() != "content-type")
    if fields:
        if parameter not in fields:
            return None
        method = str(values.get("method") or "POST").upper()
        if "json" in str(values.get("content_type") or ""):
            body = json.dumps({name: _PLACEHOLDER for name in fields}, sort_keys=True, separators=(",", ":"))
            media_type = "application/json"
        else:
            body = "&".join(f"{urllib.parse.quote(name, safe='')}={_PLACEHOLDER}" for name in fields)
            media_type = "application/x-www-form-urlencoded"
        request_class = (
            "safe_authentication"
            if is_authentication_candidate({"body_field_names": fields, "path": parsed.path})
            else "confirmed_mutation"
        )
        header_items += (("Content-Type", media_type),)
        payload = body.encode("utf-8")
    else:
        names = [name for name, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
        if names.count(parameter) != 1:
            return None
        method, payload, request_class = "GET", b"", "safe_read"
    candidate_id = hashlib.sha256(f"{action_id}:sqli:{parameter}".encode()).hexdigest()[:32]
    request = ReplayRequest(
        request_id=f"hunt-sqli:{candidate_id}", ordinal=0, name="Hunt sqli.verify proof", folder="",
        method=method, url=urllib.parse.urlunsplit((*parsed[:4], "")), headers=header_items,
        body=payload, body_mode="raw" if payload else "none",
        auth_type="broker_session" if headers else "none", has_sensitive_material=bool(headers),
    )
    candidate = {
        "candidate_id": candidate_id, "method": method, "field_path": parameter,
        "canonical_path": parsed.path or "/", "request_class": request_class,
    }
    return request, candidate


# How long past its deadline a proof that ignored it is waited for before it is cut off; its whole
# allowance is then charged, since what it sent is unknown.
PROOF_DEADLINE_GRACE_SECONDS = 2


@dataclass(frozen=True)
class ProofPhase:
    """What the proof phase of a ``sqli.verify`` action did, for the action's one outcome."""

    observations: tuple[dict[str, Any], ...] = ()
    used: Mapping[str, int] = field(default_factory=dict)
    # "success" (or nothing to prove), "partial", "cancelled"
    status: str = "success"
    timed_out: bool = False
    errors: tuple[str, ...] = ()
    ran: bool = False


def _not_proven(parameter: str | None, reason: str) -> dict[str, Any]:
    return {
        "kind": "sqli_proof", "field_path": parameter, "proof_state": "not_proven",
        "finding_verdict": "not_proven", "not_proven_reason": reason, "secret_values_visible": False,
    }


async def prove_hunt_sqli_signal(
    *, pool: Any, results_dir: Any, run: Mapping[str, Any], action_id: Any, target: Any,
    execution_target: str, values: Mapping[str, Any], observations: Sequence[Mapping[str, Any]],
    reserved: Mapping[str, Any], actual: Mapping[str, Any], headers: Mapping[str, str],
    principal_slot: str, heartbeat: Callable[[], Awaitable[None]], cancelled: Callable[[], bool],
    deadline: float,
) -> ProofPhase:
    """Prove the first signalled parameter, as the second phase of the action's one execution.

    The phase runs under the action's contract, not beside it: ``deadline`` (``time.monotonic()``)
    is the action's, set when its scanner was dispatched, and no proof request starts after it;
    the budget is what is left of the action's own reservation after sqlmap (requests and wall),
    so the action settles inside the hold it was admitted with; a cancellation or a timeout is
    reported (``status``, ``timed_out``) for the action's outcome. A body proof's requests are
    verifier writes, settled in the action's ``verifier_write_requests`` hold.
    """
    parameters = _signalled_parameters(observations)
    if not parameters:
        return ProofPhase()
    prepared = None
    for parameter in parameters:
        prepared = proof_request(execution_target, values, parameter, headers=headers, action_id=action_id)
        if prepared is not None:
            break
    if prepared is None:
        # A path segment, a header or a parameter the call did not name: nothing to replay exactly.
        return ProofPhase(observations=(_not_proven(parameters[0], "signalled_input_not_replayable"),))
    request, candidate = prepared
    if cancelled():
        return ProofPhase(observations=(_not_proven(candidate["field_path"], "cancelled"),),
                          status="cancelled", errors=("cancelled",))
    left = math.floor(deadline - time.monotonic())
    requests = min(PROOF_REQUESTS, int(reserved.get("http_requests") or 0) - int(actual.get("http_requests") or 0))
    wall = min(PROOF_WALL_SECONDS, left,
               int(reserved.get("tool_wall_seconds") or 0) - int(actual.get("tool_wall_seconds") or 0))
    if requests < PROOF_MINIMUM_REQUESTS or wall < PROOF_MINIMUM_WALL_SECONDS:
        return ProofPhase(observations=(_not_proven(candidate["field_path"], "proof_unfunded"),))
    body = request.method not in {"GET", "HEAD", "OPTIONS"}
    budget = {"http_requests": requests, "tool_wall_seconds": wall}
    if body:
        # The adapter's own mutation guard: every body request is a possible write.
        budget["state_changing_requests"] = requests
    archived, recorder = http_archive.hunt_run_call_recorder(
        run, action_id=action_id, capability_name="sqli.verify", adapter="sqli.proof_batch",
        target_url=execution_target,
    )
    phase_deadline = min(deadline, time.monotonic() + wall)
    try:
        adapter = SQLiProofAdapter(
            specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"), target=target,
            request=request, candidate=candidate, requested_budget=budget,
            transport=RecordedHuntReplayTransport(
                PinnedAiohttpReplayTransport(), recorder, principal_slot=principal_slot,
            ),
            deadline=phase_deadline,
        )
        try:
            async with asyncio.timeout(max(0.0, phase_deadline - time.monotonic()) + PROOF_DEADLINE_GRACE_SECONDS):
                result = await adapter.execute(heartbeat=heartbeat, cancelled=cancelled)
        except TimeoutError:
            # The adapter outlived its deadline: what it sent is unknown, so its allowance is spent.
            return ProofPhase(
                observations=(_not_proven(candidate["field_path"], "proof_deadline"),),
                used=_writes(budget, body), status="partial", timed_out=True,
                errors=("proof_deadline",), ran=True,
            )
    except SQLiProofError as exc:
        return ProofPhase(observations=(_not_proven(candidate["field_path"], f"proof_unconstructable:{exc}"[:200]),))
    finally:
        if archived:
            async with pool.acquire() as conn:
                await http_archive.archive_hunt_capture(conn, archived, run["id"], run["id"], results_dir)
    # Settled inside what was granted: a wall rounded up past it was cut at it.
    used = {
        "http_requests": min(requests, int(result.actual_budget.get("http_requests") or 0)),
        "tool_wall_seconds": min(wall, int(result.actual_budget.get("tool_wall_seconds") or 0)),
    }
    proofs = [
        {**dict(item), **({"proof_errors": list(result.errors)[:5]} if result.errors else {})}
        for item in result.observations
    ]
    status = "cancelled" if result.status == "cancelled" else "partial" if (
        result.timed_out or result.status in {"partial", "blocked", "failed"} and not proofs) else "success"
    if not proofs:
        reason = "proof_deadline" if result.timed_out else (
            "cancelled" if result.status == "cancelled" else (result.errors or ("proof_failed",))[0])
        proofs = [_not_proven(candidate["field_path"], str(reason)[:200])]
    return ProofPhase(
        observations=tuple(proofs), used=_writes(used, body), status=status,
        timed_out=bool(result.timed_out), errors=tuple(result.errors)[:5], ran=True,
    )


def _writes(used: Mapping[str, int], body: bool) -> dict[str, int]:
    """The budget a proof phase used; a body proof's requests are verifier writes too."""
    settled = {key: int(used.get(key) or 0) for key in ("http_requests", "tool_wall_seconds")}
    if body:
        settled["verifier_write_requests"] = settled["http_requests"]
    return {key: value for key, value in settled.items() if value}


__all__ = ["PROOF_REQUESTS", "ProofPhase", "proof_request", "prove_hunt_sqli_signal"]
