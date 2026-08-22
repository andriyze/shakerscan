"""Fail-closed, secret-free Hunt V2 start authority.

The coding agent owns investigation strategy. This contract owns everything the model must never
infer or smuggle through prose: target kind, active/network/mutation authority, authorization
attestation, bounded budgets, capability allowlists, credential references, and imported request
collections.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping, Sequence

from .contracts import HUNT_BUDGET_PROFILES


HUNT_START_SCHEMA = "hunt-start/v2"
MAX_HUNT_BODY_BYTES = 1_048_576
MAX_GOAL_CHARS = 20_000
MAX_CAPABILITIES = 128
MAX_COLLECTIONS = 32
MAX_CREDENTIAL_REFS = 16
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_CAPABILITY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_ALLOWED_TARGET_KINDS = frozenset({"web", "api", "device", "network"})
_ALLOWED_TOP_LEVEL_KEYS = frozenset({
    "target_id", "target_kind", "goal", "objective", "budget_profile", "policy_profile",
    "budgets", "policy", "credential_refs", "capabilities", "request_collection_ids",
    "approval_receipt_id", "scope_receipt_id", "schema_version",
})
_ALLOWED_BUDGET_KEYS = frozenset({
    "max_duration_seconds",
    "max_capability_calls",
    "max_http_requests",
    "max_active_actions",
    "max_candidates",
    "max_verifications",
    "max_tcp_ports",
    "max_browser_actions",
    "max_state_changing_requests",
    "max_device_fragility_points",
    "max_hosts",
    "max_udp_ports",
    "max_oob_interactions",
})
_ALLOWED_CREDENTIAL_REF_KEYS = frozenset({
    "web_credential_profile_id",
    "ssh_credential_profile_id",
    "primary_credential_profile_id",
    "secondary_credential_profile_id",
    "authorization_header_credential_id",
    "cookie_credential_id",
    "oauth_credential_profile_id",
})
_ALLOWED_POLICY_KEYS = frozenset({
    "active_testing",
    "allow_state_changing_http",
    "network_discovery",
    "authorization_confirmed",
    "approval_receipt_id",
    "scope_receipt_id",
})


class HuntStartContractError(ValueError):
    """The submitted Hunt request is outside the V2 authority contract."""


def _object(value: Any, name: str, *, required: bool = False) -> dict[str, Any]:
    if value is None:
        if required:
            raise HuntStartContractError(f"{name} is required")
        return {}
    if not isinstance(value, Mapping):
        raise HuntStartContractError(f"{name} must be an object")
    return dict(value)


def _identifier(value: Any, name: str, *, required: bool = False) -> str | None:
    normalized = str(value or "").strip()
    if not normalized:
        if required:
            raise HuntStartContractError(f"{name} is required")
        return None
    if not _ID_RE.fullmatch(normalized):
        raise HuntStartContractError(f"{name} is invalid")
    return normalized


def _boolean(value: Any, name: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise HuntStartContractError(f"{name} must be a boolean")
    return value


def _string_list(
    value: Any,
    name: str,
    *,
    maximum: int,
    pattern: re.Pattern[str] = _ID_RE,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise HuntStartContractError(f"{name} must be an array of at most {maximum} items")
    result: list[str] = []
    for raw in value:
        item = str(raw or "").strip()
        if not item or not pattern.fullmatch(item):
            raise HuntStartContractError(f"{name} contains an invalid item")
        if item in result:
            raise HuntStartContractError(f"{name} contains duplicate items")
        result.append(item)
    return tuple(result)


def _budget_overrides(value: Any, profile: str) -> dict[str, int]:
    raw = _object(value, "budgets")
    unknown = sorted(set(raw) - _ALLOWED_BUDGET_KEYS)
    if unknown:
        raise HuntStartContractError(f"unsupported budget fields: {', '.join(unknown)}")
    defaults = asdict(HUNT_BUDGET_PROFILES[profile])
    result: dict[str, int] = {}
    for key, raw_amount in raw.items():
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
            raise HuntStartContractError(f"{key} must be a positive integer")
        amount = int(raw_amount)
        if amount < 1:
            raise HuntStartContractError(f"{key} must be a positive integer")
        if amount > int(defaults[key]):
            raise HuntStartContractError(
                f"{key} exceeds the {profile} Hunt profile ceiling ({defaults[key]})"
            )
        result[key] = amount
    return result


def _credential_refs(value: Any) -> dict[str, str]:
    raw = _object(value, "credential_refs")
    if len(raw) > MAX_CREDENTIAL_REFS:
        raise HuntStartContractError("too many credential references")
    unknown = sorted(set(raw) - _ALLOWED_CREDENTIAL_REF_KEYS)
    if unknown:
        raise HuntStartContractError(
            f"unsupported credential reference fields: {', '.join(unknown)}"
        )
    result: dict[str, str] = {}
    for key, value in raw.items():
        item = _identifier(value, key)
        if item:
            result[key] = item
    return result


@dataclass(frozen=True)
class HuntStartPolicy:
    active_testing: bool = False
    allow_state_changing_http: bool = False
    network_discovery: bool = False
    authorization_confirmed: bool = False
    approval_receipt_id: str | None = None
    scope_receipt_id: str | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.authorization_confirmed and self.approval_receipt_id)

    def validate(self, *, credentials_requested: bool) -> None:
        if self.allow_state_changing_http and not self.active_testing:
            raise HuntStartContractError("state-changing HTTP requires active_testing")
        if self.network_discovery and not self.active_testing:
            raise HuntStartContractError("network discovery requires active_testing")
        privileged = bool(
            self.active_testing
            or self.allow_state_changing_http
            or self.network_discovery
            or credentials_requested
        )
        if privileged and not self.authorization_confirmed:
            raise HuntStartContractError(
                "active, network, mutation, and credential use require authorization_confirmed=true"
            )
        if privileged and not self.approval_receipt_id:
            raise HuntStartContractError(
                "active, network, mutation, and credential use require a target-bound approval receipt"
            )

    def public_dict(self) -> dict[str, Any]:
        return {
            "active_testing": self.active_testing,
            "allow_state_changing_http": self.allow_state_changing_http,
            "network_discovery": self.network_discovery,
            "authorization_confirmed": self.authorization_confirmed,
            "approval_receipt_id": self.approval_receipt_id,
            "scope_receipt_id": self.scope_receipt_id,
        }


@dataclass(frozen=True)
class HuntStartContract:
    target_id: str
    target_kind: str
    goal: str
    budget_profile: str
    budgets: Mapping[str, int]
    policy: HuntStartPolicy
    credential_refs: Mapping[str, str]
    capabilities: Sequence[str]
    request_collection_ids: Sequence[str]
    schema_version: str = HUNT_START_SCHEMA

    @property
    def resolved_budget(self) -> dict[str, int]:
        result = asdict(HUNT_BUDGET_PROFILES[self.budget_profile])
        result.update({key: int(value) for key, value in self.budgets.items()})
        return result

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "goal": self.goal,
            "budget_profile": self.budget_profile,
            "budgets": dict(self.budgets),
            "resolved_budget": self.resolved_budget,
            "policy": self.policy.public_dict(),
            "credential_refs": dict(self.credential_refs),
            "capabilities": list(self.capabilities),
            "request_collection_ids": list(self.request_collection_ids),
            "secret_values_visible": False,
        }

    def legacy_payload(self, _original: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return only fields accepted by the old route.

        This method exists for emergency downgrade tooling. It deliberately refuses contracts whose
        authority cannot be represented by the old request model; normal V2 traffic must use the
        native V2 handler in ``api_v2.py``.
        """
        unsupported_credentials = set(self.credential_refs) - {"ssh_credential_profile_id"}
        if (
            self.budgets
            or self.capabilities
            or unsupported_credentials
            or self.policy.network_discovery
            or self.policy.allow_state_changing_http
            or self.policy.scope_receipt_id
        ):
            raise HuntStartContractError(
                "this Hunt V2 contract cannot be represented by the legacy start route"
            )
        return {
            "target_id": self.target_id,
            "objective": self.goal,
            "budget_profile": self.budget_profile,
            "approval_receipt_id": self.policy.approval_receipt_id,
            "request_collection_ids": list(self.request_collection_ids),
            "ssh_credential_profile_id": self.credential_refs.get(
                "ssh_credential_profile_id"
            ),
        }


def normalize_hunt_start_payload(value: Mapping[str, Any]) -> HuntStartContract:
    if not isinstance(value, Mapping):
        raise HuntStartContractError("Hunt request body must be an object")
    payload = dict(value)
    unknown = sorted(set(payload) - _ALLOWED_TOP_LEVEL_KEYS)
    if unknown:
        raise HuntStartContractError(f"unsupported Hunt start fields: {', '.join(unknown)}")
    schema = str(payload.get("schema_version") or HUNT_START_SCHEMA).strip()
    if schema != HUNT_START_SCHEMA:
        raise HuntStartContractError(f"schema_version must be {HUNT_START_SCHEMA}")

    target_id = _identifier(payload.get("target_id"), "target_id", required=True)
    target_kind = str(payload.get("target_kind") or "").strip().lower()
    if target_kind not in _ALLOWED_TARGET_KINDS:
        raise HuntStartContractError("target_kind must be web, api, device, or network")

    raw_goal = payload.get("goal")
    raw_objective = payload.get("objective")
    if raw_goal not in (None, "") and raw_objective not in (None, ""):
        if str(raw_goal).strip() != str(raw_objective).strip():
            raise HuntStartContractError("goal and objective conflict")
    goal = str(raw_goal or raw_objective or "Find exploitable vulnerabilities.").strip()
    if not goal or len(goal) > MAX_GOAL_CHARS:
        raise HuntStartContractError(f"goal must contain 1 to {MAX_GOAL_CHARS} characters")

    requested_profile = str(
        payload.get("budget_profile") or payload.get("policy_profile") or "balanced"
    ).strip().lower()
    if requested_profile not in HUNT_BUDGET_PROFILES:
        raise HuntStartContractError("budget profile must be fast, balanced, or thorough")

    policy_raw = _object(payload.get("policy"), "policy", required=True)
    unknown_policy = sorted(set(policy_raw) - _ALLOWED_POLICY_KEYS)
    if unknown_policy:
        raise HuntStartContractError(
            f"unsupported Hunt policy fields: {', '.join(unknown_policy)}"
        )
    policy = HuntStartPolicy(
        active_testing=_boolean(policy_raw.get("active_testing"), "active_testing"),
        allow_state_changing_http=_boolean(
            policy_raw.get("allow_state_changing_http"), "allow_state_changing_http"
        ),
        network_discovery=_boolean(
            policy_raw.get("network_discovery"), "network_discovery"
        ),
        authorization_confirmed=_boolean(
            policy_raw.get("authorization_confirmed"), "authorization_confirmed"
        ),
        approval_receipt_id=_identifier(
            policy_raw.get("approval_receipt_id") or payload.get("approval_receipt_id"),
            "approval_receipt_id",
        ),
        scope_receipt_id=_identifier(
            policy_raw.get("scope_receipt_id") or payload.get("scope_receipt_id"),
            "scope_receipt_id",
        ),
    )
    credential_refs = _credential_refs(payload.get("credential_refs"))
    policy.validate(credentials_requested=bool(credential_refs))

    return HuntStartContract(
        target_id=target_id or "",
        target_kind=target_kind,
        goal=goal,
        budget_profile=requested_profile,
        budgets=_budget_overrides(payload.get("budgets"), requested_profile),
        policy=policy,
        credential_refs=credential_refs,
        capabilities=_string_list(
            payload.get("capabilities"),
            "capabilities",
            maximum=MAX_CAPABILITIES,
            pattern=_CAPABILITY_RE,
        ),
        request_collection_ids=_string_list(
            payload.get("request_collection_ids"),
            "request_collection_ids",
            maximum=MAX_COLLECTIONS,
        ),
    )
