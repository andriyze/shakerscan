"""Fail-closed, secret-free Hunt V2 start authority.

The coding agent owns investigation strategy. This contract owns everything the model must never
infer or smuggle through prose: target kind, active/network/mutation authority, authorization
attestation, bounded budgets, capability allowlists, credential references, and imported request
collections.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import re
from typing import Any, Mapping, Sequence


HUNT_START_SCHEMA = "hunt-start/v2"
HUNT_BUDGET_SCHEMA = "hunt-budget/v3"
MAX_HUNT_BODY_BYTES = 1_048_576
MAX_GOAL_CHARS = 20_000
MAX_CAPABILITIES = 128
MAX_COLLECTIONS = 32
# Kept equal to MAX_SKILLS_PER_HUNT in hunt/skills.py; asserted by the skill tests so the
# request boundary and the library cannot drift into disagreeing about the same limit.
MAX_SKILLS = 4
# Enough to cover an origin's IPv4 and IPv6 addresses plus a small failover pool. A larger
# list stops being an operator confirming specific hosts and becomes a scan range.
MAX_DIRECT_ORIGIN_ADDRESSES = 8
MAX_CREDENTIAL_REFS = 16
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_CAPABILITY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_SKILL_RE = re.compile(r"^skill\.[a-z0-9][a-z0-9_.-]{0,127}$")
_ALLOWED_TARGET_KINDS = frozenset({"web", "api", "device", "network"})
_ALLOWED_TOP_LEVEL_KEYS = frozenset({
    "target_id", "target_kind", "goal", "objective", "budget_profile", "policy_profile",
    "budgets", "policy", "credential_refs", "capabilities", "request_collection_ids",
    "approval_receipt_id", "scope_receipt_id", "schema_version", "skill_ids",
    "direct_origin_addresses",
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
    "service_credential_profile_id",
    "authorization_header_credential_id",
    "cookie_credential_id",
    "oauth_credential_profile_id",
})
_ALLOWED_POLICY_KEYS = frozenset({
    "active_testing",
    "allow_state_changing_http",
    "network_discovery",
    "allow_oob_interactions",
    "allow_identity_headers",
    "allow_direct_origin",
    "authorization_confirmed",
    "approval_receipt_id",
    "scope_receipt_id",
})


@dataclass(frozen=True)
class HuntBudget:
    max_duration_seconds: int
    max_capability_calls: int
    max_http_requests: int
    max_active_actions: int
    max_candidates: int
    max_verifications: int
    max_tcp_ports: int
    max_browser_actions: int
    max_state_changing_requests: int
    max_device_fragility_points: int
    max_hosts: int
    max_udp_ports: int
    max_oob_interactions: int

    def ledger_limits(self) -> dict[str, int]:
        return {
            "agent_actions": self.max_capability_calls,
            "active_actions": self.max_active_actions,
            "http_requests": self.max_http_requests,
            "tcp_ports_attempted": self.max_tcp_ports,
            "browser_actions": self.max_browser_actions,
            "state_changing_requests": self.max_state_changing_requests,
            "tool_wall_seconds": self.max_duration_seconds,
            "device_fragility_points": self.max_device_fragility_points,
            "hosts_attempted": self.max_hosts,
            "udp_ports_attempted": self.max_udp_ports,
            "oob_interactions": self.max_oob_interactions,
        }


HUNT_BUDGET_PROFILES: Mapping[str, HuntBudget] = {
    "fast": HuntBudget(900, 20, 500, 4, 20, 4, 100, 20, 4, 20, 50, 100, 10),
    "balanced": HuntBudget(
        3_600, 80, 5_000, 20, 100, 20, 1_200, 200, 20, 100, 500, 1_000, 50,
    ),
    "thorough": HuntBudget(
        14_400, 300, 20_000, 80, 500, 100, 10_000, 1_000, 80, 500, 5_000,
        5_000, 200,
    ),
}

ZEROABLE_HUNT_BUDGET_DIMENSIONS = frozenset({
    "max_active_actions",
    "max_browser_actions",
    "max_device_fragility_points",
    "max_hosts",
    "max_oob_interactions",
    "max_state_changing_requests",
    "max_tcp_ports",
    "max_udp_ports",
})
MANDATORY_HUNT_BUDGET_DIMENSIONS = _ALLOWED_BUDGET_KEYS - ZEROABLE_HUNT_BUDGET_DIMENSIONS
HUNT_BUDGET_DIMENSION_LABELS: Mapping[str, str] = {
    "max_duration_seconds": "Maximum duration (seconds)",
    "max_capability_calls": "Maximum capability calls",
    "max_http_requests": "Maximum HTTP requests",
    "max_active_actions": "Maximum approval-gated actions",
    "max_candidates": "Maximum candidates",
    "max_verifications": "Maximum deterministic verifications",
    "max_tcp_ports": "Maximum TCP ports",
    "max_browser_actions": "Maximum browser actions",
    "max_state_changing_requests": "Maximum state-changing requests",
    "max_device_fragility_points": "Maximum device fragility points",
    "max_hosts": "Maximum hosts",
    "max_udp_ports": "Maximum UDP ports",
    "max_oob_interactions": "Maximum out-of-band interactions",
}


class HuntStartContractError(ValueError):
    """The submitted Hunt request is outside the V2 authority contract."""


def hunt_start_public_contract() -> dict[str, Any]:
    """Return the API/UI contract generated from the server's authority constants."""
    return {
        "schema_version": HUNT_START_SCHEMA,
        "budget_schema_version": HUNT_BUDGET_SCHEMA,
        "target_kinds": sorted(_ALLOWED_TARGET_KINDS),
        "policy_fields": sorted(_ALLOWED_POLICY_KEYS),
        "credential_ref_fields": sorted(_ALLOWED_CREDENTIAL_REF_KEYS),
        "limits": {
            "goal_chars": MAX_GOAL_CHARS,
            "capabilities": MAX_CAPABILITIES,
            "request_collections": MAX_COLLECTIONS,
            "credential_refs": MAX_CREDENTIAL_REFS,
            "skill_ids": MAX_SKILLS,
            "direct_origin_addresses": MAX_DIRECT_ORIGIN_ADDRESSES,
        },
        "patterns": {
            "identifier": _ID_RE.pattern,
            "capability": _CAPABILITY_RE.pattern,
            "skill_id": _SKILL_RE.pattern,
        },
        "skill_catalog": "/hunt/skills",
        "budget_profiles": {
            name: asdict(value) for name, value in HUNT_BUDGET_PROFILES.items()
        },
        "budget_dimensions": [
            {
                "name": name,
                "label": HUNT_BUDGET_DIMENSION_LABELS[name],
                "minimum": 0 if name in ZEROABLE_HUNT_BUDGET_DIMENSIONS else 1,
                "zeroable": name in ZEROABLE_HUNT_BUDGET_DIMENSIONS,
            }
            for name in sorted(_ALLOWED_BUDGET_KEYS)
        ],
        "policy_derived_zeros": {
            "mutation_disabled": ["max_state_changing_requests"],
            "network_disabled": ["max_hosts", "max_tcp_ports", "max_udp_ports"],
            "oob_disabled": ["max_oob_interactions"],
            "non_device_target": ["max_device_fragility_points"],
            "passive_without_credentials": ["max_active_actions"],
        },
    }


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
            qualifier = "a non-negative" if key in ZEROABLE_HUNT_BUDGET_DIMENSIONS else "a positive"
            raise HuntStartContractError(f"{key} must be {qualifier} integer")
        amount = int(raw_amount)
        minimum = 0 if key in ZEROABLE_HUNT_BUDGET_DIMENSIONS else 1
        if amount < minimum:
            qualifier = "a non-negative" if minimum == 0 else "a positive"
            raise HuntStartContractError(f"{key} must be {qualifier} integer")
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
    if len(result.values()) != len(set(result.values())):
        raise HuntStartContractError(
            "credential references must use distinct profile IDs"
        )
    return result


@dataclass(frozen=True)
class HuntStartPolicy:
    active_testing: bool = False
    allow_state_changing_http: bool = False
    network_discovery: bool = False
    allow_oob_interactions: bool = False
    # The operator's explicit decision that forging a client-address header against this
    # target is in scope. Needed to test whether an origin trusts a client-suppliable
    # address, which is exploitable wherever that origin is reachable outside its edge.
    allow_identity_headers: bool = False
    # The operator's explicit decision that this hunt may connect to specific addresses it
    # names, rather than only the target's resolved address. This is the difference between
    # suspecting an origin is exposed behind a CDN and demonstrating it.
    allow_direct_origin: bool = False
    authorization_confirmed: bool = False
    approval_receipt_id: str | None = None
    scope_receipt_id: str | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.authorization_confirmed and self.approval_receipt_id)

    def is_privileged(self, *, credentials_requested: bool) -> bool:
        """Whether this policy needs confirmed authorization and an approval receipt.

        One definition, because the same rule was previously restated at the start handler
        and had to be edited in both places whenever a new authority was added.
        """
        return bool(
            credentials_requested
            or self.active_testing
            or self.allow_state_changing_http
            or self.network_discovery
            or self.allow_oob_interactions
            or self.allow_identity_headers
            or self.allow_direct_origin
        )

    def validate(self, *, credentials_requested: bool) -> None:
        if self.scope_receipt_id and not self.approval_receipt_id:
            raise HuntStartContractError(
                "scope_receipt_id must come from a validated approval receipt"
            )
        if self.allow_state_changing_http and not self.active_testing:
            raise HuntStartContractError("state-changing HTTP requires active_testing")
        if self.network_discovery and not self.active_testing:
            raise HuntStartContractError("network discovery requires active_testing")
        if self.allow_oob_interactions and not self.active_testing:
            raise HuntStartContractError("OOB interactions require active_testing")
        if self.allow_identity_headers and not self.active_testing:
            raise HuntStartContractError(
                "identity-header forgery requires active_testing"
            )
        if self.allow_direct_origin and not self.active_testing:
            raise HuntStartContractError(
                "direct-origin requests require active_testing"
            )
        privileged = self.is_privileged(credentials_requested=credentials_requested)
        if privileged and not self.authorization_confirmed:
            raise HuntStartContractError(
                "active, network, mutation, OOB, and credential use require authorization_confirmed=true"
            )
        if privileged and not self.approval_receipt_id:
            raise HuntStartContractError(
                "active, network, mutation, OOB, and credential use require a target-bound approval receipt"
            )

    def forbidden_budget_dimensions(
        self, *, target_kind: str, credentials_requested: bool,
    ) -> frozenset[str]:
        forbidden: set[str] = set()
        if not self.allow_state_changing_http:
            forbidden.add("max_state_changing_requests")
        if not self.network_discovery:
            forbidden.update({"max_tcp_ports", "max_udp_ports", "max_hosts"})
        if not self.allow_oob_interactions:
            forbidden.add("max_oob_interactions")
        if target_kind != "device":
            forbidden.add("max_device_fragility_points")
        if not self.active_testing and not credentials_requested:
            forbidden.add("max_active_actions")
        return frozenset(forbidden)

    def public_dict(self) -> dict[str, Any]:
        return {
            "active_testing": self.active_testing,
            "allow_state_changing_http": self.allow_state_changing_http,
            "network_discovery": self.network_discovery,
            "allow_oob_interactions": self.allow_oob_interactions,
            "allow_identity_headers": self.allow_identity_headers,
            "allow_direct_origin": self.allow_direct_origin,
            "authorization_confirmed": self.authorization_confirmed,
            "approval_receipt_id": self.approval_receipt_id,
            "scope_receipt_id": self.scope_receipt_id,
        }


def bind_validated_receipts(
    policy: HuntStartPolicy,
    approval_context: Mapping[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Bind submitted receipt references to the server-validated approval result."""
    if not policy.approval_receipt_id:
        if approval_context:
            raise HuntStartContractError(
                "approval validation returned authority that was not requested"
            )
        return None, None
    if not isinstance(approval_context, Mapping):
        raise HuntStartContractError("approval receipt was not validated")
    approval_id = str(approval_context.get("approval_receipt_id") or "").strip()
    scope_id = str(approval_context.get("scope_receipt_id") or "").strip()
    if not approval_id or approval_id != str(policy.approval_receipt_id):
        raise HuntStartContractError(
            "validated approval receipt does not match the Hunt contract"
        )
    if not scope_id:
        raise HuntStartContractError(
            "validated approval receipt has no target-bound scope receipt"
        )
    if policy.scope_receipt_id and scope_id != str(policy.scope_receipt_id):
        raise HuntStartContractError(
            "scope_receipt_id does not match the validated approval scope"
        )
    return approval_id, scope_id


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
    skill_ids: Sequence[str] = ()
    direct_origin_addresses: Sequence[str] = ()
    schema_version: str = HUNT_START_SCHEMA

    @property
    def resolved_budget(self) -> dict[str, int]:
        result = asdict(HUNT_BUDGET_PROFILES[self.budget_profile])
        result.update({key: int(value) for key, value in self.budgets.items()})
        for key in self.policy.forbidden_budget_dimensions(
            target_kind=self.target_kind,
            credentials_requested=bool(self.credential_refs),
        ):
            result[key] = 0
        return result

    @property
    def resolved_budget_object(self) -> HuntBudget:
        return HuntBudget(**self.resolved_budget)

    def persisted_policy(
        self,
        *,
        approval_validated: bool,
        credential_access: bool,
        approval_receipt_id: str | None,
        scope_receipt_id: str | None,
        budget: Any,
        allowed_capabilities: Sequence[str],
    ) -> dict[str, Any]:
        """Project the requested policy into the row a run is actually governed by.

        Every privileged authority is ANDed with ``approval_validated`` here rather than at
        each reader, so a request that asked for authority it did not earn is stored as not
        having it. Workers read this row, not the request.
        """
        earned = bool(approval_validated)
        return {
            "schema_version": "hunt-policy/v2",
            "target_kind": self.target_kind,
            "active_testing": bool(self.policy.active_testing and earned),
            "credential_access": credential_access,
            "mutation_allowed": bool(self.policy.allow_state_changing_http and earned),
            "allow_state_changing_http": bool(
                self.policy.allow_state_changing_http and earned
            ),
            "network_discovery": bool(self.policy.network_discovery and earned),
            "allow_oob_interactions": bool(self.policy.allow_oob_interactions and earned),
            "allow_identity_headers": bool(self.policy.allow_identity_headers and earned),
            "allow_direct_origin": bool(self.policy.allow_direct_origin and earned),
            "direct_origin_addresses": (
                list(self.direct_origin_addresses) if earned else []
            ),
            "authorization_confirmed": self.policy.authorization_confirmed,
            "approval_receipt_id": approval_receipt_id,
            "scope_receipt_id": scope_receipt_id,
            "device_fragility_profile": (
                "authenticated_active"
                if self.target_kind == "device" and credential_access
                else "safe_remote" if self.target_kind == "device" else None
            ),
            "budget_profile": self.budget_profile,
            "budget_schema_version": HUNT_BUDGET_SCHEMA,
            "budget": asdict(budget),
            "allowed_capabilities": list(allowed_capabilities),
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "goal": self.goal,
            "budget_profile": self.budget_profile,
            "budget_schema_version": HUNT_BUDGET_SCHEMA,
            "budgets": dict(self.budgets),
            "resolved_budget": self.resolved_budget,
            "policy": self.policy.public_dict(),
            "credential_refs": dict(self.credential_refs),
            "capabilities": list(self.capabilities),
            "request_collection_ids": list(self.request_collection_ids),
            "skill_ids": list(self.skill_ids),
            "direct_origin_addresses": list(self.direct_origin_addresses),
            "secret_values_visible": False,
        }


def _ip_addresses(value: Any, field: str) -> tuple[str, ...]:
    """Operator-confirmed literal addresses. Hostnames are refused on purpose.

    A hostname would be resolved at connect time, which is exactly the indirection this
    field exists to remove: the operator is naming the machine, not another name for it.
    """
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or len(value) > MAX_DIRECT_ORIGIN_ADDRESSES:
        raise HuntStartContractError(
            f"{field} must be an array of at most "
            f"{MAX_DIRECT_ORIGIN_ADDRESSES} IP addresses"
        )
    addresses: list[str] = []
    forbidden_networks = tuple(ipaddress.ip_network(network) for network in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
        "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7",
        "fe80::/10", "ff00::/8",
    ))
    for item in value:
        try:
            parsed = ipaddress.ip_address(str(item).strip())
        except ValueError as exc:
            raise HuntStartContractError(
                f"{field} must contain literal IP addresses"
            ) from exc
        comparable = getattr(parsed, "ipv4_mapped", None) or parsed
        if any(
            comparable.version == network.version and comparable in network
            for network in forbidden_networks
        ):
            raise HuntStartContractError(
                f"{field} cannot contain private, local, or non-routable addresses"
            )
        address = str(parsed)
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


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
        allow_oob_interactions=_boolean(
            policy_raw.get("allow_oob_interactions"), "allow_oob_interactions"
        ),
        allow_identity_headers=_boolean(
            policy_raw.get("allow_identity_headers"), "allow_identity_headers"
        ),
        allow_direct_origin=_boolean(
            policy_raw.get("allow_direct_origin"), "allow_direct_origin"
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
    budget_overrides = _budget_overrides(payload.get("budgets"), requested_profile)
    contradictions = sorted(
        key
        for key in policy.forbidden_budget_dimensions(
            target_kind=target_kind,
            credentials_requested=bool(credential_refs),
        )
        if int(budget_overrides.get(key, 0)) > 0
    )
    if contradictions:
        raise HuntStartContractError(
            "budget fields contradict disabled Hunt authority: "
            + ", ".join(contradictions)
        )

    direct_origin_addresses = _ip_addresses(
        payload.get("direct_origin_addresses"), "direct_origin_addresses",
    )
    # The two halves have to agree. An address list without the authority would be silently
    # ignored, and the authority without addresses grants something with nothing to use it
    # on -- both read as "this was configured" while doing nothing.
    if direct_origin_addresses and not policy.allow_direct_origin:
        raise HuntStartContractError(
            "direct_origin_addresses requires policy.allow_direct_origin"
        )
    if policy.allow_direct_origin and not direct_origin_addresses:
        raise HuntStartContractError(
            "policy.allow_direct_origin requires at least one direct origin address"
        )

    return HuntStartContract(
        target_id=target_id or "",
        target_kind=target_kind,
        goal=goal,
        budget_profile=requested_profile,
        budgets=budget_overrides,
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
        skill_ids=_string_list(
            payload.get("skill_ids"),
            "skill_ids",
            maximum=MAX_SKILLS,
            pattern=_SKILL_RE,
        ),
        direct_origin_addresses=direct_origin_addresses,
    )
