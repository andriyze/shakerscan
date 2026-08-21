"""Explicit, secret-free Hunt start contract for the V2 API boundary.

The existing Hunt endpoint remains the persistence/orchestration implementation while the
migration is completed.  This module owns the request authority that must not be hidden inside
model prose: active testing, mutation/network permission, authorization attestation, budgets,
credential references, capabilities, and imported request collections.
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


def _object(value: Any, name: str) -> dict[str, Any]:
    if value is None:
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
        # A request may lower a profile ceiling but cannot silently raise server authority.
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
        return bool(self.authorization_confirmed or self.approval_receipt_id)

    def validate(self, *, credentials_requested: bool) -> None:
        if self.allow_state_changing_http and not self.active_testing:
            raise HuntStartContractError("state-changing HTTP requires active_testing")
        if self.network_discovery and not self.active_testing:
            raise HuntStartContractError("network discovery requires active_testing")
        if (self.active_testing or self.allow_state_changing_http or self.network_discovery):
            if not self.authorized:
                raise HuntStartContractError(
                    "active Hunt actions require authorization confirmation or an approval receipt"
                )
        if credentials_requested and not self.authorized:
            raise HuntStartContractError(
                "credential use requires authorization confirmation or an approval receipt"
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

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "goal": self.goal,
            "budget_profile": self.budget_profile,
            "budgets": dict(self.budgets),
            "policy": self.policy.public_dict(),
            "credential_refs": dict(self.credential_refs),
            "capabilities": list(self.capabilities),
            "request_collection_ids": list(self.request_collection_ids),
            "secret_values_visible": False,
        }

    def legacy_payload(self, original: Mapping[str, Any]) -> dict[str, Any]:
        """Return the old route payload after V2 authority has been validated.

        Structured policy is deliberately removed because the current route model predates it.
        Existing fields remain byte-for-byte compatible while the middleware enforces policy.
        """
        payload = dict(original)
        payload.pop("policy", None)
        payload["target_id"] = self.target_id
        payload["target_kind"] = self.target_kind
        payload["goal"] = self.goal
        payload["policy_profile"] = self.budget_profile
        payload["budgets"] = dict(self.budgets)
        payload["credential_refs"] = dict(self.credential_refs)
        payload["capabilities"] = list(self.capabilities)
        payload["request_collection_ids"] = list(self.request_collection_ids)
        if self.policy.approval_receipt_id and "approval_receipt_id" in payload:
            payload["approval_receipt_id"] = self.policy.approval_receipt_id
        return payload


def normalize_hunt_start_payload(value: Mapping[str, Any]) -> HuntStartContract:
    if not isinstance(value, Mapping):
        raise HuntStartContractError("Hunt request body must be an object")
    payload = dict(value)
    target_id = _identifier(payload.get("target_id"), "target_id", required=True)
    target_kind = str(payload.get("target_kind") or "web").strip().lower()
    if target_kind not in _ALLOWED_TARGET_KINDS:
        raise HuntStartContractError("target_kind must be web, api, device, or network")
    goal = str(payload.get("goal") or "Find exploitable vulnerabilities.").strip()
    if not goal or len(goal) > MAX_GOAL_CHARS:
        raise HuntStartContractError(f"goal must contain 1 to {MAX_GOAL_CHARS} characters")
    requested_profile = str(
        payload.get("budget_profile") or payload.get("policy_profile") or "balanced"
    ).strip().lower()
    # Older UI versions used target kind as policy_profile. Preserve them without expanding authority.
    profile = "balanced" if requested_profile in _ALLOWED_TARGET_KINDS else requested_profile
    if profile not in HUNT_BUDGET_PROFILES:
        raise HuntStartContractError("budget profile must be fast, balanced, or thorough")

    policy_raw = _object(payload.get("policy"), "policy")
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
        budget_profile=profile,
        budgets=_budget_overrides(payload.get("budgets"), profile),
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
