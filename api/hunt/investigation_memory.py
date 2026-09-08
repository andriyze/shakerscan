"""Evidence-scoped authorization memory over a caller-owned node/edge store.

Access is not entitlement. An experiment covers one object, principal pair and
set of conditions, never an entire route. The integrated workflow reconstructs
this projection from PostgreSQL proposal/attempt links and canonical Hunt actions.
A mutable backing store must serialize read-modify-write operations externally.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .experiment_conditions import freeze, thaw

OBSERVED, INFERRED, CONFIRMED, UNKNOWN = "observed", "inferred", "confirmed", "unknown"
CERTAINTIES = frozenset({OBSERVED, INFERRED, CONFIRMED, UNKNOWN})
SUPPORTED, REFUTED, INCONCLUSIVE = "supported", "refuted", "inconclusive"
OUTCOMES = frozenset({SUPPORTED, REFUTED, INCONCLUSIVE})
NODE_PRINCIPAL, NODE_OBJECT, NODE_ROUTE, NODE_EXPERIMENT = "principal", "object", "route", "experiment"
EDGE_ACCESSED, EDGE_OWNS = "accessed", "owns"


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
    collection: str
    identifier: str
    principal: str
    basis: str
    certainty: str = INFERRED

    def __post_init__(self) -> None:
        if self.certainty not in CERTAINTIES:
            raise ValueError(f"unknown certainty: {self.certainty}")
        if not str(self.basis).strip():
            raise ValueError("an ownership claim requires an explicit basis")


@dataclass(frozen=True)
class Experiment:
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
    attempt_id: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome: {self.outcome}")
        if not isinstance(self.conditions, Mapping):
            raise TypeError("experiment conditions must be an object")
        # Snapshot to an immutable JSON value so a later mutation of the caller's dict cannot
        # change this experiment's identity, and reject non-JSON conditions up front.
        object.__setattr__(self, "conditions", freeze(self.conditions))

    @property
    def key(self) -> str:
        payload = json.dumps({
            "route": f"{self.method.upper()} {self.route_template}",
            "object": object_key(self.collection, self.identifier),
            "actor": self.actor_principal, "subject": self.subject_principal,
            "conditions": thaw(self.conditions), "hypothesis": self.hypothesis,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:32]


class InvestigationMemory:
    def __init__(self, store: Any, *, target_id: Any) -> None:
        self._store, self._target_id = store, target_id

    def record_access(self, observation: AccessObservation) -> dict[str, Any]:
        subject = object_key(observation.collection, observation.identifier)
        actor = principal_key(observation.principal)
        self._store.upsert_node(self._target_id, NODE_PRINCIPAL, actor, {})
        self._store.upsert_node(self._target_id, NODE_OBJECT, subject, {
            "collection": observation.collection, "identifier": observation.identifier,
        })
        attributes = {
            "status": int(observation.status), "succeeded": observation.succeeded,
            "auth_context": observation.auth_context, "disclosed_fields": list(observation.disclosed_fields),
            "certainty": OBSERVED, "at": observation.at,
            "means": "this principal was observed accessing or being refused this object; it does NOT establish who is authorised",
        }
        self._store.upsert_edge(self._target_id, actor, subject, EDGE_ACCESSED, attributes)
        return attributes

    def claim_ownership(self, claim: OwnershipClaim) -> dict[str, Any]:
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
        subject = object_key(experiment.collection, experiment.identifier)
        route = route_key(experiment.method, experiment.route_template)
        self._store.upsert_node(self._target_id, NODE_ROUTE, route, {})
        self._store.upsert_node(self._target_id, NODE_OBJECT, subject, {
            "collection": experiment.collection, "identifier": experiment.identifier,
        })
        for principal in (experiment.actor_principal, experiment.subject_principal):
            self._store.upsert_node(self._target_id, NODE_PRINCIPAL, principal_key(principal), {})
        prior = self._experiment_record(experiment.key)
        attempts = list(prior.get("attempts") or [])
        attempt = {"outcome": experiment.outcome, "at": experiment.at, "detail": experiment.detail,
                   "attempt_id": experiment.attempt_id, "evidence_refs": list(experiment.evidence_refs)}
        if experiment.attempt_id:
            previous = next((a for a in attempts if a.get("attempt_id") == experiment.attempt_id), None)
            if previous is not None:
                # A retry of a read must not append another execution. A changed
                # outcome for one canonical action identity is a conflict, not history.
                if any(previous.get(k) != attempt[k] for k in ("outcome", "detail", "evidence_refs")):
                    raise ValueError("attempt identity already has different evidence or outcome")
                return prior
        attempts.append(attempt)
        self._store.upsert_node(self._target_id, NODE_EXPERIMENT, f"experiment:{experiment.key}", {
            "experiment_key": experiment.key, "attempts": attempts, "attempt_count": len(attempts),
            "settled": experiment.outcome in {SUPPORTED, REFUTED},
            "ever_supported": any(a["outcome"] == SUPPORTED for a in attempts),
            "hypothesis": experiment.hypothesis, "actor_principal": experiment.actor_principal,
            "subject_principal": experiment.subject_principal, "conditions": thaw(experiment.conditions),
            "outcome": experiment.outcome, "detail": experiment.detail, "at": experiment.at,
            "settles": f"only object {subject} for actor {experiment.actor_principal} under these conditions; it does not describe the route as a whole",
            "route": route, "object": subject,
        })
        return self._experiment_record(experiment.key)

    def _experiments(self) -> list[dict[str, Any]]:
        records = [dict(n.get("attributes") or {}) for n in self._store.nodes(self._target_id)
                   if n.get("node_type") == NODE_EXPERIMENT]
        for record in records:
            # Older rows persisted a strongest-ever outcome/settlement. Re-derive both from the
            # latest attempt on every read, without mutating or discarding retained attempt history.
            attempts = record.get("attempts") or []
            latest = attempts[-1].get("outcome", INCONCLUSIVE) if attempts else INCONCLUSIVE
            record["outcome"] = latest
            record["settled"] = latest in {SUPPORTED, REFUTED}
        return records

    def _experiment_record(self, key: str) -> dict[str, Any]:
        return next((r for r in self._experiments() if r.get("experiment_key") == key), {})

    def already_tried(self, experiment: Experiment) -> dict[str, Any] | None:
        return self._experiment_record(experiment.key) or None

    def ownership_of(self, collection: str, identifier: str) -> dict[str, Any]:
        claims = []
        for edge in self._store.edges(self._target_id, EDGE_OWNS):
            if edge.get("dst_key") == object_key(collection, identifier):
                attributes = dict(edge.get("attributes") or {})
                attributes["principal"] = str(edge.get("src_key", "")).removeprefix("principal:")
                claims.append(attributes)
        if len({claim["principal"] for claim in claims}) > 1:
            # Conflicting owners stay explicit and unresolved; never silently pick the first row.
            return {"principal": None, "certainty": UNKNOWN,
                    "basis": "multiple ownership claims require reconciliation; shared access is possible",
                    "claims": sorted(claims, key=lambda claim: claim["principal"])}
        if claims:
            return claims[0]
        return {"principal": None, "certainty": UNKNOWN, "basis": "no ownership evidence recorded"}

    def route_conclusion(self, method: str, template: str) -> dict[str, Any]:
        route = route_key(method, template)
        experiments = [r for r in self._experiments() if r.get("route") == route]
        outcomes = {name: 0 for name in sorted(OUTCOMES)}
        for item in experiments:
            # Count the latest recorded attempt per exact context, not a strongest-ever verdict and
            # not a claim about the live deployment.
            attempts = item.get("attempts") or []
            latest = attempts[-1].get("outcome", INCONCLUSIVE) if attempts else INCONCLUSIVE
            outcomes[latest] += 1
        demonstrated = bool(outcomes[SUPPORTED])
        historical = any(a.get("outcome") == SUPPORTED
                         for item in experiments for a in item.get("attempts") or [])
        return {
            "route": route, "experiments": len(experiments), "outcomes": outcomes,
            "weakness_demonstrated": demonstrated,
            "historical_weakness_demonstrated": historical,
            "outcome_basis": "latest recorded attempt per experiment context; not live verification",
            "examined": bool(experiments),
            "tested_pairs": sorted({f"{r.get('actor_principal')}->{r.get('subject_principal')}" for r in experiments}),
            "verdict": ("authorization weakness demonstrated on at least one tested pair"
                        if demonstrated else "no authorization weakness demonstrated on the pairs tested; untested pairs and objects remain unexamined"
                        if experiments else "not examined"),
        }

    def resume_briefing(self) -> dict[str, Any]:
        nodes = list(self._store.nodes(self._target_id))
        experiments = self._experiments()
        return {
            "objects": sorted(n.get("node_key") for n in nodes if n.get("node_type") == NODE_OBJECT),
            "principals": sorted(n.get("node_key") for n in nodes if n.get("node_type") == NODE_PRINCIPAL),
            "experiments_run": len(experiments),
            "attempts_run": sum(r.get("attempt_count", 0) for r in experiments),
            "experiment_keys": sorted(r.get("experiment_key", "") for r in experiments),
            "settled": [f"{r.get('hypothesis')} — {r.get('outcome')}" for r in experiments if r.get("settled")],
            "open_questions": [f"{r.get('hypothesis')} — inconclusive after {r.get('attempt_count')} attempt(s): {r.get('detail') or 'missing evidence'}"
                               for r in experiments if not r.get("settled")],
        }


class InMemoryGraphStore:
    """Request-scoped projection/test store. This is not durable by itself."""
    def __init__(self) -> None:
        self._nodes: dict[tuple[Any, str, str], dict[str, Any]] = {}
        self._edges: dict[tuple[Any, str, str, str], dict[str, Any]] = {}

    def upsert_node(self, target_id: Any, node_type: str, node_key: str, attributes: Mapping[str, Any]) -> None:
        self._nodes[(target_id, node_type, node_key)] = {"node_type": node_type, "node_key": node_key, "attributes": dict(attributes)}

    def upsert_edge(self, target_id: Any, src_key: str, dst_key: str, edge_type: str, attributes: Mapping[str, Any]) -> None:
        self._edges[(target_id, src_key, dst_key, edge_type)] = {"src_key": src_key, "dst_key": dst_key, "edge_type": edge_type, "attributes": dict(attributes)}

    def nodes(self, target_id: Any) -> Iterable[dict[str, Any]]:
        return [v for k, v in self._nodes.items() if k[0] == target_id]

    def edges(self, target_id: Any, edge_type: str | None = None) -> Iterable[dict[str, Any]]:
        return [v for k, v in self._edges.items() if k[0] == target_id and (edge_type is None or k[3] == edge_type)]
