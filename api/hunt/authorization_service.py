"""One integrated captured-request -> approval -> canonical action -> resume path.

No network calls are made by propose/read/skip. Approval dispatches authz.verify
through the existing Hunt lifecycle. Durable attempt links are written first;
outcomes are read back from canonical actions, never accepted from the client.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import urlsplit
import hashlib
import uuid

from .authorization_evidence import (
    AuthorizationWorkflowError, attributed_outcome, canonical_action_id,
    digest, mapping, request_identity, supported_capture,
)
from .authorization_repository import (
    ATTEMPT_TYPE, DECISION_TYPE, MAX_ATTEMPTS, PROPOSAL_TYPE,
    PostgresAuthorizationRepository, uid,
)
from .authorization_workflow import CapturedRequest, investigate
from .investigation_memory import Experiment, InMemoryGraphStore, InvestigationMemory


Executor = Callable[[str, str, Mapping[str, Any]], Awaitable[Mapping[str, Any]]]
ProofURL = Callable[..., str]
TERMINAL_ACTION_STATES = frozenset({"completed", "partial", "failed", "blocked", "cancelled"})


def _active(run: Mapping[str, Any]) -> None:
    if run.get("status") not in {"active", "awaiting_planner"}:
        raise AuthorizationWorkflowError("This Hunt is not active; existing investigations remain readable")


def _target_context(run: Mapping[str, Any]) -> dict[str, Any]:
    context = mapping(run.get("context_pack"))
    target = mapping(context.get("target"))
    if not isinstance(target.get("origins"), list) or not target["origins"]:
        raise AuthorizationWorkflowError("This Hunt has no frozen HTTP origins")
    return {"target": target, "addresses": context.get("authorized_target_addresses", [])}


class AuthorizationInvestigationService:
    def __init__(self, pool: Any, execute: Executor, public_proof_url: ProofURL,
                 repository: PostgresAuthorizationRepository | None = None) -> None:
        self.pool = pool
        self.execute = execute
        self.public_proof_url = public_proof_url
        self.repo = repository or PostgresAuthorizationRepository()

    async def _bindings(self, conn: Any, run: Mapping[str, Any], values: Mapping[str, Any]) -> tuple[dict, dict, dict, dict]:
        primary = await self.repo.session(conn, run, values["primary_session_ref"], "primary")
        secondary = await self.repo.session(conn, run, values["secondary_session_ref"], "secondary")
        if (primary["profile_id"] == secondary["profile_id"]
                or primary["target_binding_digest"] != secondary["target_binding_digest"]):
            raise AuthorizationWorkflowError("The sessions must use distinct profiles on the same frozen target")
        capture = await self.repo.capture(conn, run, values["capture_id"])
        baseline = await self.repo.capture(conn, run, values["baseline_capture_id"])
        origins = _target_context(run)["target"]["origins"]
        path = supported_capture(capture, origins)
        baseline_path = supported_capture(baseline, origins)
        if capture.get("principal_slot") != "primary" or baseline.get("principal_slot") != "secondary":
            raise AuthorizationWorkflowError("Select the primary object request and the secondary principal's baseline capture", 422)
        # authz.verify reuses session headers, not arbitrary headers/body options
        # from a captured request. Do not silently claim faithful replay of a
        # tenant/version/custom-header request that this capability cannot preserve.
        for captured, session in ((capture, primary), (baseline, secondary)):
            source = await self.repo.action(conn, run, captured.get("hunt_action_id"))
            source_input = mapping(mapping(source.get("input_summary")).get("input")) if source else {}
            if (not source or source.get("capability_name") != "http.request"
                    or str(source_input.get("session_ref")) != str(session["id"])
                    or set(source_input) - {"method", "path", "session_ref", "headers", "body", "timeout_seconds", "max_response_bytes"}
                    or source_input.get("headers")
                    or any(source_input.get(key) for key in ("body", "json_body", "request_collection_id", "collection_id", "request_collection_ref"))):
                raise AuthorizationWorkflowError(
                    "Use captures from this Hunt's http.request capability with the selected session_ref and no custom headers/body/collection options", 422,
                )
        request = CapturedRequest("GET", path, "primary")
        if not request.addresses_an_object:
            raise AuthorizationWorkflowError("The selected capture is not a supported identifier-addressed GET", 422)
        if (baseline_path.rstrip("/") != f"/{request.collection}"
                or urlsplit(capture["url"]).netloc != urlsplit(baseline["url"]).netloc
                or urlsplit(capture["url"]).scheme != urlsplit(baseline["url"]).scheme):
            raise AuthorizationWorkflowError("The baseline must address the same origin and resource collection as the selected object", 422)
        return primary, secondary, capture, baseline

    async def propose(self, hunt_id: Any, *, capture_id: Any, baseline_capture_id: Any,
                      primary_session_ref: Any, secondary_session_ref: Any) -> dict[str, Any]:
        refs = {"capture_id": str(uid(capture_id)), "baseline_capture_id": str(uid(baseline_capture_id)),
                "primary_session_ref": str(uid(primary_session_ref)), "secondary_session_ref": str(uid(secondary_session_ref))}
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await self.repo.run(conn, hunt_id)
                _active(run)
                primary, secondary, capture, baseline = await self._bindings(conn, run, refs)
                request = CapturedRequest("GET", urlsplit(capture["url"]).path, "primary")
                # Reuse the proposal semantics. No ownership is inferred from the capture.
                proposal = investigate(request, available_principals=["primary", "secondary"],
                                       memory=InvestigationMemory(InMemoryGraphStore(), target_id=run["target_id"]))["proposals"][0]
                origin = _target_context(run)["target"]["origins"][0]
                binding = {
                    "schema_version": "hunt-authorization/v1", "hunt_id": str(run["id"]),
                    "target_id": str(run["target_id"]), **refs,
                    "target_context_sha256": digest(_target_context(run)),
                    "sessions_sha256": digest([primary, secondary]),
                    "capture_sha256": request_identity(capture), "baseline_sha256": request_identity(baseline),
                    "resource_id_sha256": hashlib.sha256(request.identifier.encode()).hexdigest(),
                    "public_consumer_url": self.public_proof_url(capture["url"], base_origin=origin, object_id=request.identifier),
                    "public_baseline_url": self.public_proof_url(baseline["url"], base_origin=origin),
                    "evidence_needed": list(proposal.evidence_needed),
                    "capability_input_sha256": digest({"primary_session_ref": refs["primary_session_ref"],
                                                       "secondary_session_ref": refs["secondary_session_ref"],
                                                       "routes": [baseline["url"], capture["url"]]}),
                }
                proposal_digest = digest(binding)
                proposal_id = uuid.uuid5(uid(run["id"]), "authorization:" + proposal_digest)
                document = {**binding, "proposal_id": str(proposal_id), "proposal_digest": proposal_digest}
                await self.repo.insert_node(conn, run, proposal_id, PROPOSAL_TYPE,
                                            f"authz:{proposal_id}", document)
        return await self.read(hunt_id, proposal_id)

    async def _attempt_views(self, conn: Any, run: Mapping[str, Any], proposal: Mapping[str, Any]) -> list[dict[str, Any]]:
        views = []
        for attempt in await self.repo.attempts(conn, run, proposal["proposal_id"]):
            if attempt["input_digest"] != proposal["capability_input_sha256"]:
                raise AuthorizationWorkflowError("The attempt does not match the proposal's bound input")
            action = await self.repo.action(conn, run, attempt["action_id"])
            transactions = await self.repo.transactions(conn, run, attempt["action_id"])
            outcome = attributed_outcome(proposal, attempt, action, transactions)
            views.append({"attempt": attempt["attempt"], **outcome})
        return views

    async def read(self, hunt_id: Any, proposal_id: Any) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            run = await self.repo.run(conn, hunt_id)
            proposal = await self.repo.proposal(conn, run, proposal_id)
            attempts = await self._attempt_views(conn, run, proposal)
            deferred = await self.repo.skipped(conn, run, proposal_id)
        # A request-scoped memory projection, reconstructed from PostgreSQL after
        # every restart. The graph stores references; canonical actions own outcomes.
        memory = InvestigationMemory(InMemoryGraphStore(), target_id=run["target_id"])
        template = urlsplit(proposal["public_consumer_url"]).path
        collection = urlsplit(proposal["public_baseline_url"]).path
        for attempt in attempts:
            if attempt["execution_status"] not in TERMINAL_ACTION_STATES:
                continue
            memory.record_experiment(Experiment(
                hypothesis="Cross-principal access to the selected captured object",
                method="GET", route_template=template, collection=collection,
                identifier=proposal["resource_id_sha256"], actor_principal="secondary", subject_principal="primary",
                conditions={"proposal_digest": proposal["proposal_digest"]},
                outcome=attempt["outcome"], detail=attempt["reason"],
                attempt_id=attempt["action_id"],
                evidence_refs=tuple([attempt["action_id"]] + ([attempt["receipt_id"]] if attempt["receipt_id"] else [])),
                **({"at": attempt["completed_at"]} if attempt.get("completed_at") else {}),
            ))
        latest = attempts[-1] if attempts else None
        return {
            "schema_version": "hunt-authorization/v1", "hunt_id": str(run["id"]),
            "proposal_id": proposal["proposal_id"], "proposal_digest": proposal["proposal_digest"],
            "capture_id": proposal["capture_id"], "baseline_capture_id": proposal["baseline_capture_id"],
            "route": template, "resource_id_sha256": proposal["resource_id_sha256"],
            "evidence_needed": proposal["evidence_needed"], "attempts": attempts,
            "deferred": deferred and not attempts, "deferral_recorded": deferred,
            "settled": bool(latest and latest["outcome"] in {"supported", "refuted"}),
            "next_attempt": len(attempts) + 1 if len(attempts) < MAX_ATTEMPTS else None,
            "resume": memory.resume_briefing(),
            "selected_request_examined": any(a.get("selected_request_examined") for a in attempts),
            "explanation": latest["reason"] if latest else "A proposal only; no authorization test has run",
            "reproduction": [
                {"as": "secondary", "method": "GET", "capture_id": proposal["baseline_capture_id"], "establishes": "same-collection baseline"},
                {"as": "primary", "method": "GET", "capture_id": proposal["capture_id"], "establishes": "primary view of selected object"},
                {"as": "secondary", "method": "GET", "capture_id": proposal["capture_id"], "establishes": "cross-principal replay"},
            ],
            "reproduction_is_plan": True,
            "limitations": ["GET-only, same-Hunt http.request captures using the selected session_ref; no custom headers/body/query/fragment support",
                            "Requires a baseline for the same collection; listing completeness/entitlement is not inferred from capture status",
                            "The collection-based verifier may not exercise every supplied object; another object's result never settles the selection",
                            "Skipping records a deferral and does not cancel an already admitted action",
                            "Canonical evidence is reported; this workflow never promotes findings or replaces proof validation"],
        }

    async def approve(self, hunt_id: Any, proposal_id: Any, *, proposal_digest: str,
                      confirm: bool, attempt: int = 1, retry_settled: bool = False) -> dict[str, Any]:
        if confirm is not True or type(attempt) is not int or not 1 <= attempt <= MAX_ATTEMPTS:
            raise AuthorizationWorkflowError("Explicit confirmation and a bounded attempt number are required", 422)
        replay_finished = False
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await self.repo.run(conn, hunt_id)
                proposal = await self.repo.proposal(conn, run, proposal_id, lock=True)
                if proposal_digest != proposal["proposal_digest"]:
                    raise AuthorizationWorkflowError("The approved proposal digest does not match")
                history = await self.repo.attempts(conn, run, proposal_id)
                existing = next((r for r in history if r["attempt"] == attempt), None)
                if existing:
                    action = await self.repo.action(conn, run, existing["action_id"])
                    replay_finished = bool(action and action.get("status") in TERMINAL_ACTION_STATES)
                if not replay_finished:
                    _active(run)
                    if not existing:
                        if attempt != len(history) + 1:
                            raise AuthorizationWorkflowError("Attempts must be consecutive; reuse an existing number to recover its execution")
                        if history:
                            previous = await self.repo.action(conn, run, history[-1]["action_id"])
                            if not previous or previous.get("status") not in TERMINAL_ACTION_STATES:
                                raise AuthorizationWorkflowError("Recover the preceding attempt before starting another")
                            previous_outcome = (await self._attempt_views(conn, run, proposal))[-1]
                            if previous_outcome["outcome"] in {"supported", "refuted"} and retry_settled is not True:
                                raise AuthorizationWorkflowError("This experiment is settled; explicitly request a retest")
                    primary, secondary, capture, baseline = await self._bindings(conn, run, proposal)
                    if (digest(_target_context(run)) != proposal["target_context_sha256"]
                            or digest([primary, secondary]) != proposal["sessions_sha256"]
                            or request_identity(capture) != proposal["capture_sha256"]
                            or request_identity(baseline) != proposal["baseline_sha256"]):
                        raise AuthorizationWorkflowError("The captures, sessions or target changed; create and approve a fresh proposal")
                    capability_input = {"primary_session_ref": proposal["primary_session_ref"],
                                        "secondary_session_ref": proposal["secondary_session_ref"],
                                        "routes": [baseline["url"], capture["url"]]}
                    idempotency_key = f"authz-investigation:{proposal_id}:{attempt}"
                    link = {"hunt_id": str(run["id"]), "proposal_id": str(proposal_id), "attempt": attempt,
                            "idempotency_key": idempotency_key, "input_digest": digest(capability_input),
                            "action_id": str(canonical_action_id(run["id"], idempotency_key))}
                    if existing and existing != link:
                        raise AuthorizationWorkflowError("The persisted attempt binding changed")
                    await self.repo.insert_node(conn, run, uuid.uuid5(uid(proposal_id), f"attempt:{attempt}"),
                                                ATTEMPT_TYPE, f"authz:{proposal_id}:attempt:{attempt:03}", link)
        # No database lock is held across a worker call. Canonical idempotency,
        # approvals, session checks, cancellation and budgets stay authoritative.
        if not replay_finished:
            await self.execute(str(hunt_id), idempotency_key, capability_input)
        return await self.read(hunt_id, proposal_id)

    async def skip(self, hunt_id: Any, proposal_id: Any) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await self.repo.run(conn, hunt_id)
                await self.repo.proposal(conn, run, proposal_id, lock=True)
                await self.repo.insert_node(conn, run, uuid.uuid5(uid(proposal_id), "skip"), DECISION_TYPE,
                                            f"authz:{proposal_id}:skip", {"hunt_id": str(run["id"]), "decision": "deferred"})
        return await self.read(hunt_id, proposal_id)
