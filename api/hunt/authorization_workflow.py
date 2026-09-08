"""GET-only authorization proposals and explanations, never an execution authority.

Production uses captured-request references and the canonical Hunt action lifecycle.
This module also supports the local fixture workflow. Neither a proposed outcome nor
an aggregate scanner flag is proof about the particular object being investigated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import unquote, urlsplit

from .investigation_memory import (
    INCONCLUSIVE, REFUTED, SUPPORTED, UNKNOWN, Experiment, InvestigationMemory,
)

_IDENTIFIER = re.compile(r"^(?:[0-9]+|[0-9a-fA-F]{24,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")


def _path_parts(path: str) -> list[str]:
    """Only a literal, query-free path is supported; never silently rewrite it."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return []
    if any(ord(c) < 33 or ord(c) == 127 for c in path) or "\\" in path:
        return []
    parsed = urlsplit(path)
    if parsed.query or parsed.fragment or "?" in path or "#" in path:
        return []
    parts = path[1:].rstrip("/").split("/")
    if any(not p or unquote(p) in {".", ".."} for p in parts):
        return []
    return parts


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    path: str
    principal: str
    auth_context: str = "bearer"

    @property
    def collection(self) -> str | None:
        parts = _path_parts(self.path)
        return "/".join(parts[:-1]) if len(parts) >= 2 else None

    @property
    def identifier(self) -> str | None:
        parts = _path_parts(self.path)
        return parts[-1] if len(parts) >= 2 else None

    @property
    def addresses_an_object(self) -> bool:
        return bool(self.identifier and _IDENTIFIER.fullmatch(self.identifier))

    @property
    def route_template(self) -> str:
        if not self.addresses_an_object:
            return self.path
        suffix = "/" if self.path.endswith("/") else ""
        return f"/{self.collection}/{{id}}{suffix}"


@dataclass(frozen=True)
class ProposedExperiment:
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
    request_path: str | None = None

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
    request: CapturedRequest, *, available_principals: Sequence[str],
    memory: InvestigationMemory, retry_settled: bool = False,
) -> dict[str, Any]:
    if request.method.upper() != "GET":
        return {"proposals": [], "not_proposed": [
            f"{request.method.upper()} is not supported by this workflow. A cross-principal "
            "replay of a mutating request requires separate mutation authorization and exact "
            "request-body preservation."
        ]}
    if not request.addresses_an_object:
        return {"proposals": [], "not_proposed": [
            "This request does not address a specific object recognizable by this workflow. "
            "Query, body, fragment and non-identifier object references need explicit support; "
            "this limitation does not establish that no authorization boundary exists."
        ]}
    principals = list(dict.fromkeys(available_principals))
    if request.principal not in principals:
        return {"proposals": [], "not_proposed": ["The captured request's principal is unavailable."]}
    others = [p for p in principals if p != request.principal]
    if not others:
        return {"proposals": [], "not_proposed": [
            f"A cross-principal test needs a second principal; only {request.principal!r} is available."
        ]}
    ownership = memory.ownership_of(request.collection, request.identifier)
    proposals, withheld = [], []
    for other in others:
        proposal = ProposedExperiment(
            hypothesis=f"{other} can read {request.collection}/{request.identifier}, which {request.principal} reached",
            why=("The captured request identifies an object and a second principal is available. "
                 f"Ownership is {ownership.get('certainty', UNKNOWN)}; the experiment must establish "
                 "the baseline and ownership/access evidence, not assume them."),
            method="GET", route_template=request.route_template,
            collection=request.collection, identifier=request.identifier,
            actor_principal=other, subject_principal=request.principal,
            evidence_needed=(f"the collection listing as {other}, to establish their own baseline",
                             f"the object read as {request.principal}, the owner's view to be tested",
                             f"the same object read as {other}"),
            conditions={"auth_context": request.auth_context}, request_path=request.path,
        )
        prior = memory.already_tried(proposal.as_experiment(INCONCLUSIVE))
        # The latest attempt, not a historical success, determines whether prerequisites
        # still leave this experiment open. Historical results remain in memory.
        settled = bool(prior and prior.get("outcome") in {SUPPORTED, REFUTED})
        if settled and not retry_settled:
            withheld.append(f"already tested as {other}: {prior.get('outcome')} ({prior.get('hypothesis')})")
            continue
        if prior and not settled:
            proposal = replace(proposal, why=(
                f"{proposal.why} A previous attempt was inconclusive after {prior.get('attempt_count')} "
                f"try/tries: {prior.get('detail') or 'baseline or principal evidence was missing'}. "
                "Retry only after addressing the missing evidence or on explicit instruction."
            ))
        proposals.append(proposal)
    return {"proposals": proposals, "not_proposed": withheld}


def _object_url_matches(proposal: ProposedExperiment, value: Any) -> bool:
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        return False
    try:
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        expected = proposal.request_path or f"/{proposal.collection.strip('/')}/{proposal.identifier}"
        if parsed.path != expected:
            return False
        origin = proposal.conditions.get("origin")
        if origin:
            other = urlsplit(str(origin))
            port = lambda p: p.port or (443 if p.scheme.lower() == "https" else 80)
            if (parsed.scheme.lower(), parsed.hostname, port(parsed)) != (other.scheme.lower(), other.hostname, port(other)):
                return False
        return True
    except ValueError:
        return False


def outcome_from_result(
    proposal: ProposedExperiment, result: Mapping[str, Any], *,
    validator: Callable[[dict[str, Any]], Any] | None = None,
) -> tuple[str, str]:
    """Attribute a trusted internal differential result to this exact request.

    Public routes never accept this result or a proof boolean from the caller.
    Production instead reads its canonical, target-bound Hunt action receipt.
    An aggregate negative count does not prove this object was even tested.
    """
    if proposal.method.upper() != "GET":
        return INCONCLUSIVE, "this workflow supports GET only"
    for finding in result.get("findings") or []:
        if not isinstance(finding, Mapping) or not isinstance(finding.get("evidence"), Mapping):
            continue
        evidence = finding["evidence"]
        if (evidence.get("proof_type") != "cross_principal_replay"
                or str(evidence.get("requested_object_id") or "") != proposal.identifier
                or str(evidence.get("method") or "GET").upper() != "GET"
                or not _object_url_matches(proposal, evidence.get("url") or evidence.get("consumer_endpoint") or finding.get("url"))):
            continue
        if validator is None:
            try:
                from scanner_tools.finding_validator import validate_object_authorization
            except ModuleNotFoundError:
                from scanner.scanner_tools.finding_validator import validate_object_authorization
            validator = validate_object_authorization
        validation = validator(dict(finding))
        if getattr(validation, "verified", False) is not True:
            continue
        return SUPPORTED, f"validated cross-principal evidence names object {proposal.identifier} at the selected request"
    return INCONCLUSIVE, (
        f"no validated cross-principal evidence was attributed to the selected request for object {proposal.identifier}; "
        "another object's finding or a completed collection replay cannot settle this object"
    )


def explain(
    *, owner_status: int, attacker_status: int, owner_fields: Iterable[str],
    attacker_fields: Iterable[str], object_absent_from_attacker_listing: bool | None,
    proven: bool,
) -> dict[str, Any]:
    shared = sorted(set(owner_fields) & set(attacker_fields))
    owner_ok = 200 <= owner_status < 300
    actor_ok = 200 <= attacker_status < 300
    certainty = UNKNOWN
    if proven is True and owner_ok and actor_ok and object_absent_from_attacker_listing is True:
        certainty = "confirmed"
        reading = "The deterministic validator confirmed a cross-principal read of data belonging to another principal."
    elif object_absent_from_attacker_listing is None:
        reading = ("The actor's baseline was not established, so it is not possible to say whether "
                   "this object was theirs or shared. The outcome is inconclusive.")
    elif owner_ok and actor_ok and object_absent_from_attacker_listing is False:
        reading = ("The object appears in the second principal's own listing. This is consistent "
                   "with shared access rather than a boundary crossing; equal statuses do not prove equal bodies.")
    elif owner_ok and attacker_status == 403 and proven is not True:
        certainty = "observed"
        reading = ("The actor was denied this request while the first principal succeeded. "
                   "That is not proof the route is safe elsewhere.")
    else:
        reading = ("This result is inconclusive, not evidence of enforcement. Missing: validated "
                   "ownership/baseline and response evidence for this exact object and principal pair. "
                   "Errors, expired authentication and equal status codes do not settle authorization.")
    return {
        "owner_status": owner_status, "attacker_status": attacker_status,
        "status_differs": owner_status != attacker_status, "fields_visible_to_both": shared,
        "object_absent_from_attacker_listing": object_absent_from_attacker_listing,
        "certainty": certainty, "reading": reading,
        "scope": "this pair of principals, this object, these conditions",
    }


def reproduction(proposal: ProposedExperiment, *, origin: str = "") -> list[dict[str, str]]:
    if proposal.method.upper() != "GET":
        raise ValueError("authorization reproduction is GET-only; mutations require separate authority")
    path = proposal.request_path or f"/{proposal.collection.strip('/')}/{proposal.identifier}"
    if not _path_parts(path):
        raise ValueError("reproduction requires an exact supported request path")
    if origin:
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username
                or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(ord(c) < 33 for c in origin)):
            raise ValueError("reproduction origin is invalid")
    base = origin.rstrip("/")
    return [
        {"step": "1", "as": proposal.actor_principal, "request": f"GET {base}/{proposal.collection.strip('/')}",
         "establishes": "the actor's own baseline for this collection"},
        {"step": "2", "as": proposal.subject_principal, "request": f"GET {base}{path}",
         "establishes": "the first principal's view of the selected object"},
        {"step": "3", "as": proposal.actor_principal, "request": f"GET {base}{path}",
         "establishes": "whether the actor receives the selected object"},
    ]


def resume(memory: InvestigationMemory) -> dict[str, Any]:
    briefing = memory.resume_briefing()
    briefing["next_step_hint"] = (
        "Open questions first; fix missing baseline/principal evidence before retrying."
        if briefing.get("open_questions") else "No open questions recorded; propose a new object or principal pair."
    )
    return briefing
