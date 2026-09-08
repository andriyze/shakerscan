"""The assisted authorization workflow: propose, explain, resume, reproduce.

What this is
------------
The thin layer that turns "here is a request I captured" into an investigation a pentester can
drive. It answers five things and nothing else:

    investigate  -> hypotheses worth testing and the evidence each one needs
    approve/skip -> the exact experiment to run, or a different direction
    explain      -> what actually differed between the principals, and how sure we are
    resume       -> the facts, settled results and open questions from before the interruption
    reproduce    -> the minimal ordered sequence that re-establishes a result

What this deliberately is not
-----------------------------
It does not execute, and it does not decide. Execution goes through the existing capability path,
and whether something is proven is settled by the deterministic differential and its validator --
never here. A proposal is a suggestion with its reasoning attached, which the human approves,
modifies or rejects. Nothing in this module may promote a finding.

It also does not re-propose work the investigation has already done: proposals are filtered against
the durable memory, so a resumed session spends its budget on what is still open.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from .investigation_memory import (
    INCONCLUSIVE,
    REFUTED,
    SUPPORTED,
    UNKNOWN,
    Experiment,
    InvestigationMemory,
)

# A trailing segment that identifies an object rather than naming a route.
_IDENTIFIER = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})$")


@dataclass(frozen=True)
class CapturedRequest:
    """The request a pentester hands to Hunt to start an investigation."""

    method: str
    path: str
    principal: str
    auth_context: str = "bearer"

    @property
    def collection(self) -> str | None:
        parts = [segment for segment in self.path.split("/") if segment]
        return "/".join(parts[:-1]) if len(parts) >= 2 else None

    @property
    def identifier(self) -> str | None:
        parts = [segment for segment in self.path.split("/") if segment]
        return parts[-1] if len(parts) >= 2 else None

    @property
    def addresses_an_object(self) -> bool:
        """Whether this request names a specific object, which is what makes it testable."""
        return bool(self.identifier and _IDENTIFIER.match(self.identifier))

    @property
    def route_template(self) -> str:
        if not self.addresses_an_object:
            return self.path
        return "/" + "/".join(
            [segment for segment in self.path.split("/") if segment][:-1] + ["{id}"]
        )


@dataclass(frozen=True)
class ProposedExperiment:
    """A suggestion with its reasoning, for the human to approve, modify or skip."""

    hypothesis: str
    why: str
    method: str
    route_template: str
    collection: str
    identifier: str
    actor_principal: str
    subject_principal: str
    evidence_needed: tuple[str, ...]
    conditions: Mapping[str, Any] = field(default_factory=dict)
    risk: str = "read-only cross-principal replay (GET only)"

    def as_experiment(self, outcome: str) -> Experiment:
        return Experiment(
            hypothesis=self.hypothesis,
            route_template=self.route_template,
            method=self.method,
            collection=self.collection,
            identifier=self.identifier,
            actor_principal=self.actor_principal,
            subject_principal=self.subject_principal,
            outcome=outcome,
            conditions=dict(self.conditions),
        )

    def as_row(self) -> dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "why": self.why,
            "method": self.method,
            "route_template": self.route_template,
            "object": f"{self.collection}/{self.identifier}",
            "actor_principal": self.actor_principal,
            "subject_principal": self.subject_principal,
            "evidence_needed": list(self.evidence_needed),
            "conditions": dict(self.conditions),
            "risk": self.risk,
        }


def investigate(
    request: CapturedRequest,
    *,
    available_principals: Sequence[str],
    memory: InvestigationMemory,
    retry_settled: bool = False,
) -> dict[str, Any]:
    """Propose what is worth testing about this request, and what each test would need.

    Returns proposals plus the reason any were withheld, so a pentester can see that the absence
    of a suggestion is a stated limitation rather than silence.
    """
    # A cross-principal replay of a mutating verb is not a read-only test: it needs separate
    # mutation authorization and faithful body preservation, neither of which this workflow has.
    # Proposing one and labelling it read-only would be misleading even though nothing here
    # executes, and `reproduction` would emit the mutating request verbatim.
    if request.method.upper() != "GET":
        return {
            "proposals": [],
            "not_proposed": [
                (
                    f"{request.method.upper()} is not supported by this workflow. A cross-principal "
                    "replay of a mutating request requires separate mutation authorization and exact "
                    "request-body preservation; capture the corresponding GET, or drive the mutation "
                    "through an explicitly authorized path."
                )
            ],
        }
    if not request.addresses_an_object:
        return {
            "proposals": [],
            "not_proposed": [
                (
                    "This request does not address a specific object, so there is no ownership "
                    "boundary to cross. Capture a request that names one."
                )
            ],
        }

    others = [p for p in available_principals if p != request.principal]
    if not others:
        return {
            "proposals": [],
            "not_proposed": [
                (
                    "A cross-principal test needs a second principal; only "
                    f"{request.principal!r} is available."
                )
            ],
        }

    ownership = memory.ownership_of(request.collection, request.identifier)
    proposals, withheld = [], []
    for other in others:
        proposal = ProposedExperiment(
            hypothesis=(
                f"{other} can read {request.collection}/{request.identifier}, "
                f"which {request.principal} reached"
            ),
            why=(
                "The request names a specific object and a second principal exists, so "
                "authorization can be tested by replaying it as that principal. Ownership is "
                f"currently {ownership.get('certainty', UNKNOWN)}, so the replay also has to "
                "establish whose object it is."
            ),
            method=request.method,
            route_template=request.route_template,
            collection=request.collection,
            identifier=request.identifier,
            actor_principal=other,
            subject_principal=request.principal,
            evidence_needed=(
                f"the collection listing as {other}, to establish their own baseline",
                f"the object read as {request.principal}, the owner's view",
                f"the same object read as {other}",
            ),
            conditions={"auth_context": request.auth_context},
        )
        prior = memory.already_tried(proposal.as_experiment(INCONCLUSIVE))
        if prior is not None and prior.get("settled") and not retry_settled:
            withheld.append(
                f"already tested as {other}: {prior.get('outcome')} "
                f"({prior.get('hypothesis')})"
            )
            continue
        if prior is not None and not prior.get("settled"):
            # Inconclusive is an open question, not a closed one: re-propose it, and say why it
            # is coming back so the pentester can fix the prerequisite instead of repeating it
            # blindly.
            proposal = replace(
                proposal,
                why=(
                    f"{proposal.why} A previous attempt was inconclusive after "
                    f"{prior.get('attempt_count')} try/tries; retry once the missing evidence "
                    "(baseline listing, or a live session for both principals) is available."
                ),
            )
        proposals.append(proposal)
    return {"proposals": proposals, "not_proposed": withheld}


def outcome_from_result(
    proposal: ProposedExperiment,
    result: Mapping[str, Any],
) -> tuple[str, str]:
    """Derive this proposal's outcome from the proof evidence, not from an aggregate flag.

    A collection-wide differential reports that *something* under the collection was readable
    across principals. Recording that as the proposal's result would attribute another object's
    finding to the object the pentester selected. So a supported outcome requires a finding whose
    evidence names this proposal's object; anything else is refuted or inconclusive.
    """
    findings = [f for f in (result.get("findings") or []) if isinstance(f, Mapping)]
    for finding in findings:
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, Mapping):
            continue
        if str(evidence.get("proof_type") or "") != "cross_principal_replay":
            continue
        if str(evidence.get("requested_object_id") or "") != str(proposal.identifier):
            continue
        if evidence.get("method") != proposal.method or evidence.get(
            "producer_endpoint"
        ) != (f"{proposal.method} /{proposal.collection.lstrip('/')}"):
            continue
        if evidence.get("consumer_endpoint") != (
            f"{proposal.method} /{proposal.collection.lstrip('/')}/{proposal.identifier}"
        ):
            continue
        return SUPPORTED, (
            f"evidence names object {proposal.identifier}: owner "
            f"{evidence.get('owner_status')} / actor {evidence.get('attacker_status')}, "
            "absent from the actor's own listing"
        )
    if findings:
        others = sorted(
            {
                str(f["evidence"].get("requested_object_id") or "?")
                for f in findings
                if isinstance(f.get("evidence"), Mapping)
            }
        )
        return INCONCLUSIVE, (
            f"the run produced findings for {', '.join(others)}, none of which is "
            f"{proposal.identifier}; this proposal is unproven and another object's finding "
            "cannot stand in for it"
        )
    for attempt in result.get("endpoint_attempts") or []:
        if not isinstance(attempt, Mapping):
            continue
        if (
            str(attempt.get("requested_object_id") or "") == str(proposal.identifier)
            and attempt.get("method") == proposal.method
            and attempt.get("producer_endpoint")
            == f"{proposal.method} /{proposal.collection.lstrip('/')}"
            and attempt.get("consumer_endpoint")
            == f"{proposal.method} /{proposal.collection.lstrip('/')}/{proposal.identifier}"
            and attempt.get("status") == "completed"
            and attempt.get("owner_status") == 200
            and type(attempt.get("attacker_status")) is int
            and attempt.get("attacker_status") in {403, 404}
        ):
            return REFUTED, (
                "the selected object's replay was explicitly denied; no cross-principal evidence "
                f"for object {proposal.identifier} in this attempt"
            )
    return (
        INCONCLUSIVE,
        "no bound denial or proof for the selected object was established",
    )


def explain(
    *,
    owner_status: int,
    attacker_status: int,
    owner_fields: Iterable[str],
    attacker_fields: Iterable[str],
    object_absent_from_attacker_listing: bool | None,
    proven: bool,
) -> dict[str, Any]:
    """Say what differed between the two principals, and how much it is worth.

    ``proven`` comes from the deterministic validator. This function reports; it never decides.
    """
    owner_set, attacker_set = set(owner_fields), set(attacker_fields)
    shared = sorted(owner_set & attacker_set)
    if object_absent_from_attacker_listing is None:
        certainty = UNKNOWN
        reading = (
            "The attacker's own baseline was not established, so it is not possible to say "
            "whether this object was theirs to begin with."
        )
    elif proven:
        certainty = "confirmed"
        reading = (
            "The second principal received an object that is absent from their own listing, so "
            "they read data belonging to another principal."
        )
    elif attacker_status == owner_status and not object_absent_from_attacker_listing:
        certainty = UNKNOWN
        reading = (
            "Both principals see the same response, but the object also appears in the second "
            "principal's own listing, so this is shared access rather than a boundary crossing."
        )
    elif owner_status == attacker_status:
        # Identical answers with no proof settle nothing. Reading this as enforcement would turn
        # "we failed to demonstrate a crossing" into "the boundary held", which the evidence does
        # not support.
        certainty = UNKNOWN
        reading = (
            "Both principals were answered identically, but the crossing was not established. "
            "This is inconclusive, not evidence of enforcement. Missing: confirmation that the "
            "object is absent from the actor's own listing, and that the body returned to the "
            "actor is the owner's object rather than their own."
        )
    else:
        certainty = "observed"
        reading = (
            "The two principals were answered differently, which is consistent with the boundary "
            "being enforced. That is not proof the route is safe elsewhere."
        )
    return {
        "owner_status": owner_status,
        "attacker_status": attacker_status,
        "status_differs": owner_status != attacker_status,
        "fields_visible_to_both": shared,
        "object_absent_from_attacker_listing": object_absent_from_attacker_listing,
        "certainty": certainty,
        "reading": reading,
        # Stated on every explanation: one result describes one pair under one set of conditions.
        "scope": "this pair of principals, this object, these conditions",
    }


def reproduction(
    proposal: ProposedExperiment, *, origin: str = ""
) -> list[dict[str, str]]:
    """The minimal ordered sequence that re-establishes the result, and nothing more."""
    base = origin.rstrip("/")
    collection_path = f"{base}/{proposal.collection}"
    object_path = f"{collection_path}/{proposal.identifier}"
    return [
        {
            "step": "1",
            "as": proposal.actor_principal,
            "request": f"GET {collection_path}",
            "establishes": "the actor's own baseline for this collection",
        },
        {
            "step": "2",
            "as": proposal.subject_principal,
            "request": f"{proposal.method.upper()} {object_path}",
            "establishes": "the owner's view of the object",
        },
        {
            "step": "3",
            "as": proposal.actor_principal,
            "request": f"{proposal.method.upper()} {object_path}",
            "establishes": "whether the actor receives an object absent from their baseline",
        },
    ]


def resume(memory: InvestigationMemory) -> dict[str, Any]:
    """What a fresh context needs to carry on: facts, settled results, open questions."""
    briefing = memory.resume_briefing()
    briefing["next_step_hint"] = (
        "Open questions first; an inconclusive result usually means the baseline or the "
        "principal context was missing, not that the idea was wrong."
        if briefing.get("open_questions")
        else "No open questions recorded; propose a new object or principal pair."
    )
    return briefing
