"""Compile discovered agent-authorization facts into deterministic boundary proposals.

This module is deliberately secret-free and side-effect free. Hunt (or another
authorized investigator) may discover facts and propose a hypothesis; this
compiler decides whether enough *declared/observed* information exists to hand
that hypothesis to the existing AI Boundary verifier.

It never infers a customer's business authorization policy.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from .contract import ContractError, relative_path

HypothesisKind = Literal[
    "cross_tenant_read",
    "cross_tenant_action",
    "approval_bypass",
    "tool_principal",
]

_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_FIELD_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\Z")
_ALLOWED_KINDS = {
    "cross_tenant_read",
    "cross_tenant_action",
    "approval_bypass",
    "tool_principal",
}


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ContractError(f"invalid_boundary_hypothesis_{field}")
    return value


def _field(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _FIELD_RE.fullmatch(value):
        raise ContractError(f"invalid_boundary_hypothesis_{field}")
    return value


def _optional_path(value: Any, field: str) -> str | None:
    if value is None:
        return None
    try:
        return relative_path(value)
    except ContractError as exc:
        raise ContractError(f"invalid_boundary_hypothesis_{field}") from exc


def _bounded_text(value: Any, field: str, *, limit: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ContractError(f"invalid_boundary_hypothesis_{field}")
    return value.strip()


def _provenance(value: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise ContractError("boundary_hypothesis_requires_provenance")
    out: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {"kind", "id", "evidence_sha256"}:
            raise ContractError("invalid_boundary_hypothesis_provenance")
        kind = _identifier(item.get("kind"), "provenance_kind")
        item_id = _identifier(item.get("id"), "provenance_id")
        evidence = item.get("evidence_sha256")
        if evidence is not None and (
            not isinstance(evidence, str)
            or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", evidence)
        ):
            raise ContractError("invalid_boundary_hypothesis_evidence_digest")
        normalized = {"kind": kind, "id": item_id}
        if evidence:
            normalized["evidence_sha256"] = (
                evidence if evidence.startswith("sha256:") else f"sha256:{evidence}"
            )
        out.append(normalized)
    return tuple(out)


@dataclass(frozen=True)
class BoundaryHypothesis:
    version: int
    hypothesis_id: str
    kind: HypothesisKind
    owner_role: str
    attacker_role: str
    owner_subject: str
    attacker_subject: str
    owner_tenant: str
    attacker_tenant: str
    owner_resource_id: str
    attacker_resource_id: str
    expected_rule: str | None
    expected_rule_source: str | None
    verifier_path: str | None
    state_path: str | None
    initial_value: Any
    forbidden_value: Any
    approval_path: str | None
    approval_state_path: str | None
    required_approval_value: Any
    tool_name: str | None
    expected_principal: str | None
    prompt: str | None
    provenance: tuple[dict[str, str], ...]
    source: dict[str, Any]

    @property
    def digest(self) -> str:
        return _digest(self.source)

    @classmethod
    def parse(cls, raw: Any) -> "BoundaryHypothesis":
        allowed = {
            "version", "hypothesis_id", "kind", "owner", "attacker",
            "expected_rule", "expected_rule_source", "verifier_path", "state_path",
            "initial_value", "forbidden_value", "approval_path",
            "approval_state_path", "required_approval_value", "tool_name",
            "expected_principal", "prompt", "provenance",
        }
        required = {"version", "hypothesis_id", "kind", "owner", "attacker", "provenance"}
        if not isinstance(raw, dict) or set(raw) - allowed or required - set(raw):
            raise ContractError("missing_or_unknown_boundary_hypothesis_fields")
        if raw["version"] != 1 or type(raw["version"]) is not int:
            raise ContractError("unsupported_boundary_hypothesis_version")
        kind = raw["kind"]
        if kind not in _ALLOWED_KINDS:
            raise ContractError("unsupported_boundary_hypothesis_kind")

        identities = []
        for slot in ("owner", "attacker"):
            value = raw[slot]
            if not isinstance(value, dict) or set(value) != {"role", "subject", "tenant", "resource_id"}:
                raise ContractError("invalid_boundary_hypothesis_identity")
            identities.append(tuple(_identifier(value[k], f"{slot}_{k}") for k in (
                "role", "subject", "tenant", "resource_id"
            )))
        owner, attacker = identities
        if any(a == b for a, b in zip(owner, attacker)):
            raise ContractError("boundary_hypothesis_requires_distinct_control_principals")

        expected_rule = raw.get("expected_rule")
        expected_rule_source = raw.get("expected_rule_source")
        if expected_rule is not None:
            expected_rule = _bounded_text(expected_rule, "expected_rule", limit=1000)
            if expected_rule_source not in {"operator", "application_contract", "policy_evidence"}:
                raise ContractError("boundary_hypothesis_expected_rule_requires_authoritative_source")
        elif expected_rule_source is not None:
            raise ContractError("boundary_hypothesis_rule_source_without_rule")

        return cls(
            version=1,
            hypothesis_id=_identifier(raw["hypothesis_id"], "id"),
            kind=kind,
            owner_role=owner[0], attacker_role=attacker[0],
            owner_subject=owner[1], attacker_subject=attacker[1],
            owner_tenant=owner[2], attacker_tenant=attacker[2],
            owner_resource_id=owner[3], attacker_resource_id=attacker[3],
            expected_rule=expected_rule,
            expected_rule_source=expected_rule_source,
            verifier_path=_optional_path(raw.get("verifier_path"), "verifier_path"),
            state_path=_field(raw["state_path"], "state_path") if raw.get("state_path") is not None else None,
            initial_value=copy.deepcopy(raw.get("initial_value")),
            forbidden_value=copy.deepcopy(raw.get("forbidden_value")),
            approval_path=_optional_path(raw.get("approval_path"), "approval_path"),
            approval_state_path=_field(raw["approval_state_path"], "approval_state_path")
                if raw.get("approval_state_path") is not None else None,
            required_approval_value=copy.deepcopy(raw.get("required_approval_value")),
            tool_name=_identifier(raw["tool_name"], "tool_name") if raw.get("tool_name") is not None else None,
            expected_principal=_identifier(raw["expected_principal"], "expected_principal")
                if raw.get("expected_principal") is not None else None,
            prompt=_bounded_text(raw["prompt"], "prompt") if raw.get("prompt") is not None else None,
            provenance=_provenance(raw["provenance"]),
            source=copy.deepcopy(raw),
        )


@dataclass(frozen=True)
class BoundaryProposal:
    status: Literal["ready", "needs_context"]
    hypothesis_id: str
    hypothesis_sha256: str
    kind: HypothesisKind
    missing_facts: tuple[str, ...]
    contract_fragment: dict[str, Any] | None
    provenance: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "boundary-proposal/v1",
            "status": self.status,
            "hypothesis_id": self.hypothesis_id,
            "hypothesis_sha256": self.hypothesis_sha256,
            "kind": self.kind,
            "missing_facts": list(self.missing_facts),
            "contract_fragment": copy.deepcopy(self.contract_fragment),
            "provenance": [dict(item) for item in self.provenance],
        }


def compile_boundary_hypothesis(raw: Any) -> dict[str, Any]:
    """Return a deterministic verifier proposal or exact missing business facts.

    The compiler never manufactures an expected authorization rule. Read isolation
    is structurally testable from two distinct controlled tenants/resources.
    State-changing hypotheses require an authoritative expected rule plus the
    postcondition fields needed by the existing boundary executors.
    """
    h = BoundaryHypothesis.parse(raw)
    missing: list[str] = []

    if h.kind != "cross_tenant_read" and h.expected_rule is None:
        missing.extend(["expected_rule", "expected_rule_source"])

    fragment: dict[str, Any] | None = None

    if h.kind == "cross_tenant_read":
        # The enclosing BoundaryContract owns identity/resource paths and can compile
        # this hypothesis directly into its existing cross-customer read scenario.
        fragment = {
            "kind": h.kind,
            "owner_role": h.owner_role,
            "attacker_role": h.attacker_role,
            "owner_resource_id": h.owner_resource_id,
            "attacker_resource_id": h.attacker_resource_id,
        }

    elif h.kind == "cross_tenant_action":
        for name, value in (
            ("verifier_path", h.verifier_path),
            ("state_path", h.state_path),
            ("initial_value", h.initial_value),
            ("forbidden_value", h.forbidden_value),
            ("prompt", h.prompt),
        ):
            if value is None:
                missing.append(name)
        if not missing:
            if h.initial_value == h.forbidden_value:
                raise ContractError("boundary_hypothesis_action_state_values_must_differ")
            fragment = {
                "action": {
                    "name": h.hypothesis_id,
                    "prompt": h.prompt,
                    "verifier_path": h.verifier_path,
                    "state_path": h.state_path,
                    "initial_value": h.initial_value,
                    "forbidden_value": h.forbidden_value,
                }
            }

    elif h.kind == "approval_bypass":
        for name, value in (
            ("verifier_path", h.verifier_path),
            ("state_path", h.state_path),
            ("initial_value", h.initial_value),
            ("forbidden_value", h.forbidden_value),
            ("approval_path", h.approval_path),
            ("approval_state_path", h.approval_state_path),
            ("required_approval_value", h.required_approval_value),
            ("prompt", h.prompt),
        ):
            if value is None:
                missing.append(name)
        if not missing:
            if h.initial_value == h.forbidden_value:
                raise ContractError("boundary_hypothesis_action_state_values_must_differ")
            fragment = {
                "approval": {
                    "name": h.hypothesis_id,
                    "prompt": h.prompt,
                    "verifier_path": h.verifier_path,
                    "state_path": h.state_path,
                    "initial_value": h.initial_value,
                    "forbidden_value": h.forbidden_value,
                    "approval_path": h.approval_path,
                    "approval_state_path": h.approval_state_path,
                    "required_approval_value": h.required_approval_value,
                }
            }

    elif h.kind == "tool_principal":
        for name, value in (
            ("tool_name", h.tool_name),
            ("expected_principal", h.expected_principal),
            ("prompt", h.prompt),
        ):
            if value is None:
                missing.append(name)
        if not missing:
            fragment = {
                "tool": {
                    "name": h.hypothesis_id,
                    "prompt": h.prompt,
                    "tool_name": h.tool_name,
                    "expected_principal": h.expected_principal,
                }
            }
            if h.verifier_path is not None:
                for name, value in (
                    ("state_path", h.state_path),
                    ("forbidden_value", h.forbidden_value),
                ):
                    if value is None:
                        missing.append(name)
                if not missing:
                    fragment["tool"].update({
                        "verifier_path": h.verifier_path,
                        "state_path": h.state_path,
                        "forbidden_value": h.forbidden_value,
                    })

    if missing:
        fragment = None

    return BoundaryProposal(
        status="needs_context" if missing else "ready",
        hypothesis_id=h.hypothesis_id,
        hypothesis_sha256=h.digest,
        kind=h.kind,
        missing_facts=tuple(dict.fromkeys(missing)),
        contract_fragment=fragment,
        provenance=h.provenance,
    ).to_dict()
