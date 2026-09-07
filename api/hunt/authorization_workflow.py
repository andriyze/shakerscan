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
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .investigation_memory import (
    INCONCLUSIVE,
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
    risk: str = "read-only cross-principal replay"

    def as_experiment(self, outcome: str) -> Experiment:
        return Experiment(
            hypothesis=self.hypothesis, route_template=self.route_template, method=self.method,
            collection=self.collection, identifier=self.identifier,
            actor_principal=self.actor_principal, subject_principal=self.subject_principal,
            outcome=outcome, conditions=dict(self.conditions),
        )

    def as_row(self) -> dict[str, Any]:
        return {
            "hypothesis": self.hypothesis, "why": self.why, "method": self.method,
            "route_template": self.route_template, "object": f"{self.collection}/{self.identifier}",
            "actor_principal": self.actor_principal, "subject_principal": self.subject_principal,
            "evidence_needed": list(self.evidence_needed), "conditions": dict(self.conditions),
            "risk": self.risk,
        }


def investigate(
    request: CapturedRequest,
    *,
    available_principals: Sequence[str],
    memory: InvestigationMemory,
) -> dict[str, Any]:
    """Propose what is worth testing about this request, and what each test would need.

    Returns proposals plus the reason any were withheld, so a pentester can see that the absence
    of a suggestion is a stated limitation rather than silence.
    """
    if not request.addresses_an_object:
        return {
            "proposals": [],
            "not_proposed": [
                "This request does not address a specific object, so there is no ownership "
                "boundary to cross. Capture a request that names one."
            ],
        }

    others = [p for p in available_principals if p != request.principal]
    if not others:
        return {
            "proposals": [],
            "not_proposed": [
                "A cross-principal test needs a second principal; only "
                f"{request.principal!r} is available."
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
            method=request.method, route_template=request.route_template,
            collection=request.collection, identifier=request.identifier,
            actor_principal=other, subject_principal=request.principal,
            evidence_needed=(
                f"the collection listing as {other}, to establish their own baseline",
                f"the object read as {request.principal}, the owner's view",
                f"the same object read as {other}",
            ),
            conditions={"auth_context": request.auth_context},
        )
        prior = memory.already_tried(proposal.as_experiment(INCONCLUSIVE))
        if prior is not None:
            withheld.append(
                f"already tested as {other}: {prior.get('outcome')} "
                f"({prior.get('hypothesis')})"
            )
            continue
        proposals.append(proposal)
    return {"proposals": proposals, "not_proposed": withheld}


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


def reproduction(proposal: ProposedExperiment, *, origin: str = "") -> list[dict[str, str]]:
    """The minimal ordered sequence that re-establishes the result, and nothing more."""
    base = origin.rstrip("/")
    collection_path = f"{base}/{proposal.collection}"
    object_path = f"{collection_path}/{proposal.identifier}"
    return [
        {"step": "1", "as": proposal.actor_principal, "request": f"GET {collection_path}",
         "establishes": "the actor's own baseline for this collection"},
        {"step": "2", "as": proposal.subject_principal,
         "request": f"{proposal.method.upper()} {object_path}",
         "establishes": "the owner's view of the object"},
        {"step": "3", "as": proposal.actor_principal,
         "request": f"{proposal.method.upper()} {object_path}",
         "establishes": "whether the actor receives an object absent from their baseline"},
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
