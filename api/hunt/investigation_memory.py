"""Durable memory for one authorization investigation.

Scope
-----
Only what an investigation actually needs, held as a chain a pentester can audit:

    request -> principal -> object -> ownership/access evidence -> hypothesis -> experiment -> outcome

This is deliberately not a general application graph. It reuses the existing
``application_graph_nodes`` / ``application_graph_edges`` tables rather than introducing another
store, and it exists to answer three questions after an interruption: what object are we looking at,
what do we actually know about who may reach it, and which experiments have already been run so we
do not pay for them twice.

Two rules it enforces, because both have produced false conclusions before
--------------------------------------------------------------------------
**Access is not authorization.** "User A received this object" is an observation. "Only user A may
reach it" is an inference that needs its own evidence and carries its own uncertainty. They are
separate edge types here and one never silently becomes the other: ownership must be asserted with
a basis, and its certainty is recorded, never assumed.

**An experiment settles what it tested, and nothing wider.** An outcome is scoped to the exact
object, actor, subject and conditions it ran under. A route is never marked safe because one object
under it behaved: that is how a single passing check hides every case it did not try. Rejected and
inconclusive results are retained for the same reason -- knowing an idea was tried and failed is
what stops a resumed session from repeating it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .experiment_conditions import freeze, thaw

# How much weight a recorded relationship carries. `observed` is something we saw happen;
# `inferred` is reasoning that may be wrong; `confirmed` requires deterministic proof; `unknown`
# is the honest answer whenever the evidence does not decide.
OBSERVED = "observed"
INFERRED = "inferred"
CONFIRMED = "confirmed"
UNKNOWN = "unknown"
CERTAINTIES = frozenset({OBSERVED, INFERRED, CONFIRMED, UNKNOWN})

# What an experiment concluded about the exact thing it tried.
SUPPORTED = "supported"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"
OUTCOMES = frozenset({SUPPORTED, REFUTED, INCONCLUSIVE})

NODE_PRINCIPAL = "principal"
NODE_OBJECT = "object"
NODE_ROUTE = "route"

EDGE_ACCESSED = "accessed"        # observation: this principal received this object
EDGE_OWNS = "owns"                # inference: this principal appears to own this object

# An experiment is an ENTITY, not a relationship. Edge identity is
# (target, src, dst, edge_type) -- in the live schema too -- so storing experiments as edges
# meant a second test of the same route and object silently overwrote the first, discarding
# exactly the rejected and inconclusive results that stop a resumed session repeating work.
NODE_EXPERIMENT = "experiment"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def principal_key(label: str) -> str:
    return f"principal:{label}"


def object_key(collection: str, identifier: str) -> str:
    return f"object:{collection}/{identifier}"


def route_key(method: str, template: str) -> str:
    return f"route:{method.upper()} {template}"


@dataclass(frozen=True)
class AccessObservation:
    """A principal received (or was refused) an object. A fact, not a judgement."""

    principal: str
    collection: str
    identifier: str
    status: int
    auth_context: str
    disclosed_fields: tuple[str, ...] = ()
    at: str = field(default_factory=_now)

    @property
    def succeeded(self) -> bool:
        return 200 <= int(self.status) < 300


@dataclass(frozen=True)
class OwnershipClaim:
    """Who appears to own an object, with the basis and how much that is worth."""

    collection: str
    identifier: str
    principal: str
    basis: str
    certainty: str = INFERRED

    def __post_init__(self) -> None:
        if self.certainty not in CERTAINTIES:
            raise ValueError(f"unknown certainty: {self.certainty}")
        if not str(self.basis).strip():
            # An ownership claim with no stated basis is exactly the silent inference this
            # module exists to prevent.
            raise ValueError("an ownership claim requires an explicit basis")


@dataclass(frozen=True)
class Experiment:
    """One test, the conditions it ran under, and what it settled -- and only that."""

    hypothesis: str
    route_template: str
    method: str
    collection: str
    identifier: str
    actor_principal: str
    subject_principal: str
    outcome: str
    conditions: Mapping[str, Any] = field(default_factory=dict)
    detail: str = ""
    at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome: {self.outcome}")
        if not isinstance(self.conditions, Mapping):
            raise TypeError("experiment conditions must be an object")
        object.__setattr__(self, "conditions", freeze(self.conditions))

    @property
    def key(self) -> str:
        """Identity of the exact experiment, so a resumed session recognises it.

        Conditions are part of the identity: the same replay under a different auth context or a
        different subject is a different experiment and must not be skipped as already done.
        """
        payload = json.dumps({
            "route": f"{self.method.upper()} {self.route_template}",
            "object": object_key(self.collection, self.identifier),
            "actor": self.actor_principal,
            "subject": self.subject_principal,
            "conditions": thaw(self.conditions),
            "hypothesis": self.hypothesis,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:32]


class InvestigationMemory:
    """The investigation's durable state, over a node/edge store.

    ``store`` is any object exposing ``upsert_node`` and ``upsert_edge``; the Postgres-backed
    implementation writes the existing application-graph tables. Reads come from the same store so
    a resumed session sees exactly what a live one does.
    """

    def __init__(self, store: Any, *, target_id: Any) -> None:
        self._store = store
        self._target_id = target_id

    # -- recording ---------------------------------------------------------------------
    def record_access(self, observation: AccessObservation) -> dict[str, Any]:
        """Record that a principal did or did not receive an object. No inference."""
        subject = object_key(observation.collection, observation.identifier)
        actor = principal_key(observation.principal)
        self._store.upsert_node(self._target_id, NODE_PRINCIPAL, actor, {})
        self._store.upsert_node(self._target_id, NODE_OBJECT, subject, {
            "collection": observation.collection, "identifier": observation.identifier,
        })
        attributes = {
            "status": int(observation.status),
            "succeeded": observation.succeeded,
            "auth_context": observation.auth_context,
            "disclosed_fields": list(observation.disclosed_fields),
            "certainty": OBSERVED,
            "at": observation.at,
            # Stated so no reader can mistake reach for entitlement.
            "means": "this principal reached this object; it does NOT establish who is authorised",
        }
        self._store.upsert_edge(self._target_id, actor, subject, EDGE_ACCESSED, attributes)
        return attributes

    def claim_ownership(self, claim: OwnershipClaim) -> dict[str, Any]:
        """Record who appears to own an object, with its basis and certainty."""
        subject = object_key(claim.collection, claim.identifier)
        owner = principal_key(claim.principal)
        self._store.upsert_node(self._target_id, NODE_PRINCIPAL, owner, {})
        self._store.upsert_node(self._target_id, NODE_OBJECT, subject, {
            "collection": claim.collection, "identifier": claim.identifier,
        })
        attributes = {"basis": claim.basis, "certainty": claim.certainty, "at": _now()}
        self._store.upsert_edge(self._target_id, owner, subject, EDGE_OWNS, attributes)
        return attributes

    def record_experiment(self, experiment: Experiment) -> dict[str, Any]:
        """Append an attempt for this experiment, scoped to exactly what it tried.

        Identity and history are different things. Re-running an experiment used to overwrite its
        record, so an inconclusive first attempt vanished the moment it was retried and the reason
        for the retry was lost with it. Attempts accumulate: the same identity can legitimately be
        run again after a failed prerequisite, a refreshed session, changed application state, or
        because the pentester asked for it, and the history is what makes that judgeable.
        """
        subject = object_key(experiment.collection, experiment.identifier)
        route = route_key(experiment.method, experiment.route_template)
        self._store.upsert_node(self._target_id, NODE_ROUTE, route, {})
        self._store.upsert_node(self._target_id, NODE_OBJECT, subject, {
            "collection": experiment.collection, "identifier": experiment.identifier,
        })
        prior = self._experiment_record(experiment.key)
        attempts = list(prior.get("attempts") or [])
        attempts.append({
            "outcome": experiment.outcome, "at": experiment.at, "detail": experiment.detail,
        })
        self._store.upsert_node(self._target_id, NODE_EXPERIMENT, f"experiment:{experiment.key}", {
            "experiment_key": experiment.key,
            "attempts": attempts,
            "attempt_count": len(attempts),
            # Historical proof remains in attempts, but cannot settle a later
            # inconclusive retry or replace its recorded outcome.
            "settled": experiment.outcome in {SUPPORTED, REFUTED},
            "hypothesis": experiment.hypothesis,
            "actor_principal": experiment.actor_principal,
            "subject_principal": experiment.subject_principal,
            "conditions": thaw(experiment.conditions),
            "outcome": experiment.outcome,
            "detail": experiment.detail,
            "at": experiment.at,
            # The scope guard, recorded with the row so it survives into any export.
            "settles": (
                f"only object {subject} for actor {experiment.actor_principal} under these "
                "conditions; it does not describe the route as a whole"
            ),
            "route": route,
            "object": subject,
        })
        return self._experiment_record(experiment.key)

    def _experiments(self) -> list[dict[str, Any]]:
        records = [
            dict(node.get("attributes") or {})
            for node in self._store.nodes(self._target_id)
            if node.get("node_type") == NODE_EXPERIMENT
        ]
        for record in records:
            attempts = record.get("attempts") or []
            latest = attempts[-1].get("outcome", INCONCLUSIVE) if attempts else INCONCLUSIVE
            # Derive this on reads too: older stored rows used strongest-ever
            # settlement. Do not mutate or discard their retained history.
            record["outcome"] = latest
            record["settled"] = latest in {SUPPORTED, REFUTED}
        return records

    def _experiment_record(self, key: str) -> dict[str, Any]:
        for record in self._experiments():
            if record.get("experiment_key") == key:
                return record
        return {}

    # -- reading -----------------------------------------------------------------------
    def already_tried(self, experiment: Experiment) -> dict[str, Any] | None:
        """The prior result for this exact experiment, or None. Resume relies on this."""
        return self._experiment_record(experiment.key) or None

    def ownership_of(self, collection: str, identifier: str) -> dict[str, Any]:
        """What is known about who owns an object. Absent evidence yields `unknown`."""
        subject = object_key(collection, identifier)
        claims = []
        for edge in self._store.edges(self._target_id, EDGE_OWNS):
            if edge.get("dst_key") == subject:
                attributes = dict(edge.get("attributes") or {})
                attributes["principal"] = str(edge.get("src_key", "")).removeprefix("principal:")
                claims.append(attributes)
        if len({claim["principal"] for claim in claims}) > 1:
            return {
                "principal": None,
                "certainty": UNKNOWN,
                "basis": "multiple ownership claims require reconciliation; shared access is possible",
                "claims": sorted(claims, key=lambda claim: claim["principal"]),
            }
        if claims:
            return claims[0]
        return {"principal": None, "certainty": UNKNOWN, "basis": "no ownership evidence recorded"}

    def route_conclusion(self, method: str, template: str) -> dict[str, Any]:
        """What the experiments so far permit saying about a route.

        Never "safe". A route is only ever as tested as the objects and principals actually tried,
        so this reports the tested pairs and states the untested remainder explicitly.
        """
        route = route_key(method, template)
        experiments = [r for r in self._experiments() if r.get("route") == route]
        outcomes = {name: 0 for name in sorted(OUTCOMES)}
        for item in experiments:
            # This is the latest recorded attempt for each exact context, not a
            # strongest-ever verdict or a claim about the live deployment.
            attempts = item.get("attempts") or []
            latest = attempts[-1].get("outcome", INCONCLUSIVE) if attempts else INCONCLUSIVE
            outcomes[latest] = outcomes.get(latest, 0) + 1
        demonstrated = bool(outcomes.get(SUPPORTED))
        return {
            "route": route,
            "experiments": len(experiments),
            "outcomes": outcomes,
            # Read this, not the prose. The two verdict strings differ only by a leading "no",
            # so a consumer matching on substrings gets the answer exactly backwards.
            "weakness_demonstrated": demonstrated,
            "historical_weakness_demonstrated": any(
                attempt.get("outcome") == SUPPORTED
                for item in experiments for attempt in item.get("attempts") or []
            ),
            "outcome_basis": "latest recorded attempt per experiment context; not live verification",
            "examined": bool(experiments),
            "tested_pairs": sorted({
                f"{item.get('actor_principal')}->{item.get('subject_principal')}"
                for item in experiments
            }),
            # The wording matters: a completed check is coverage, never a clean bill of health.
            "verdict": (
                "no authorization weakness demonstrated on the pairs tested; untested pairs and "
                "objects remain unexamined"
                if experiments and not outcomes.get(SUPPORTED)
                else "authorization weakness demonstrated on at least one tested pair"
                if outcomes.get(SUPPORTED) else "not examined"
            ),
        }

    def resume_briefing(self) -> dict[str, Any]:
        """Everything a fresh context needs to continue without redoing work."""
        objects, principals = [], []
        for node in self._store.nodes(self._target_id):
            if node.get("node_type") == NODE_EXPERIMENT:
                continue
            if node.get("node_type") == NODE_OBJECT:
                objects.append(node.get("node_key"))
            elif node.get("node_type") == NODE_PRINCIPAL:
                principals.append(node.get("node_key"))
        experiments = self._experiments()
        open_questions = [
            f"{item.get('hypothesis')} — inconclusive after {item.get('attempt_count')} attempt(s)"
            for item in experiments if not item.get("settled")
        ]
        return {
            "objects": sorted(objects),
            "principals": sorted(principals),
            "experiments_run": len(experiments),
            "experiment_keys": sorted(
                item.get("experiment_key", "") for item in experiments
            ),
            "settled": [
                f"{item.get('hypothesis')} — {item.get('outcome')}"
                for item in experiments if item.get("settled")
            ],
            "open_questions": open_questions,
        }


class InMemoryGraphStore:
    """A store for tests and for driving an investigation before it is persisted."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[Any, str, str], dict[str, Any]] = {}
        self._edges: dict[tuple[Any, str, str, str], dict[str, Any]] = {}

    def upsert_node(self, target_id: Any, node_type: str, node_key: str,
                    attributes: Mapping[str, Any]) -> None:
        self._nodes[(target_id, node_type, node_key)] = {
            "node_type": node_type, "node_key": node_key, "attributes": dict(attributes),
        }

    def upsert_edge(self, target_id: Any, src_key: str, dst_key: str, edge_type: str,
                    attributes: Mapping[str, Any]) -> None:
        self._edges[(target_id, src_key, dst_key, edge_type)] = {
            "src_key": src_key, "dst_key": dst_key, "edge_type": edge_type,
            "attributes": dict(attributes),
        }

    def nodes(self, target_id: Any) -> Iterable[dict[str, Any]]:
        return [v for k, v in self._nodes.items() if k[0] == target_id]

    def edges(self, target_id: Any, edge_type: str | None = None) -> Iterable[dict[str, Any]]:
        return [
            v for k, v in self._edges.items()
            if k[0] == target_id and (edge_type is None or k[3] == edge_type)
        ]
