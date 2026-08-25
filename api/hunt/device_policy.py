"""Typed safety state for device targets in the native Hunt runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


DEVICE_HUNT_POLICY_SCHEMA = "hunt-device-policy/v2"


class DeviceHuntPolicyError(ValueError):
    """Persisted device policy state is missing or malformed."""


@dataclass(frozen=True)
class DeviceHuntPolicyState:
    """Durable pacing and circuit-breaker state, separate from planner memory."""

    schema_version: str = DEVICE_HUNT_POLICY_SCHEMA
    safety_profile: str = "safe_remote"
    fragility_limit: int = 40
    fragility_used: int = 0
    request_limit: int = 40
    requests_used: int = 0
    scan_limit: int = 3
    scans_queued: int = 0
    minimum_request_interval_ms: int = 1_000
    consecutive_health_failures: int = 0
    circuit_breaker_threshold: int = 2
    traffic_frozen: bool = False
    last_request_at: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != DEVICE_HUNT_POLICY_SCHEMA:
            raise DeviceHuntPolicyError("unknown native device Hunt policy schema")
        if self.safety_profile not in {"safe_remote", "authenticated_active"}:
            raise DeviceHuntPolicyError("invalid native device Hunt safety profile")
        numeric = (
            self.fragility_limit,
            self.fragility_used,
            self.request_limit,
            self.requests_used,
            self.scan_limit,
            self.scans_queued,
            self.minimum_request_interval_ms,
            self.consecutive_health_failures,
            self.circuit_breaker_threshold,
        )
        if any(isinstance(value, bool) or int(value) < 0 for value in numeric):
            raise DeviceHuntPolicyError("native device Hunt policy counters are invalid")
        if self.fragility_used > self.fragility_limit:
            raise DeviceHuntPolicyError("native device Hunt fragility state exceeds its limit")
        if self.requests_used > self.request_limit:
            raise DeviceHuntPolicyError("native device Hunt request state exceeds its limit")
        if self.scans_queued > self.scan_limit:
            raise DeviceHuntPolicyError("native device Hunt scan state exceeds its limit")

    @classmethod
    def initial(
        cls,
        *,
        safety_profile: str,
        fragility_limit: int,
        request_limit: int = 40,
        scan_limit: int = 3,
        minimum_request_interval_ms: int = 1_000,
        circuit_breaker_threshold: int = 2,
    ) -> "DeviceHuntPolicyState":
        return cls(
            safety_profile=safety_profile,
            fragility_limit=max(0, int(fragility_limit)),
            request_limit=max(0, int(request_limit)),
            scan_limit=max(0, int(scan_limit)),
            minimum_request_interval_ms=max(0, int(minimum_request_interval_ms)),
            circuit_breaker_threshold=max(1, int(circuit_breaker_threshold)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DeviceHuntPolicyState":
        if not isinstance(value, Mapping):
            raise DeviceHuntPolicyError("native device Hunt policy state is required")
        fields = {
            name: value[name]
            for name in cls.__dataclass_fields__
            if name in value
        }
        try:
            return cls(**fields)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, DeviceHuntPolicyError):
                raise
            raise DeviceHuntPolicyError(
                "native device Hunt policy state is malformed"
            ) from exc

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)

    def require_admission(
        self,
        *,
        request_attempts: int = 0,
        scan_attempts: int = 0,
        fragility_cost: int = 0,
        now: datetime | None = None,
    ) -> None:
        """Fail closed before any device traffic or downstream queue handoff."""
        if self.traffic_frozen:
            raise DeviceHuntPolicyError(
                "device traffic is frozen by the health circuit breaker"
            )
        if self.requests_used + max(0, int(request_attempts)) > self.request_limit:
            raise DeviceHuntPolicyError("native device Hunt request limit is exhausted")
        if self.scans_queued + max(0, int(scan_attempts)) > self.scan_limit:
            raise DeviceHuntPolicyError("native device Hunt scan limit is exhausted")
        if self.fragility_used + max(0, int(fragility_cost)) > self.fragility_limit:
            raise DeviceHuntPolicyError("native device Hunt fragility limit is exhausted")
        if request_attempts and self.last_request_at:
            try:
                previous = datetime.fromisoformat(
                    self.last_request_at.replace("Z", "+00:00")
                )
                if previous.tzinfo is None:
                    previous = previous.replace(tzinfo=timezone.utc)
            except ValueError as exc:
                raise DeviceHuntPolicyError(
                    "native device Hunt pacing state is invalid"
                ) from exc
            current = now or datetime.now(timezone.utc)
            elapsed_ms = (current - previous).total_seconds() * 1_000
            if elapsed_ms < self.minimum_request_interval_ms:
                raise DeviceHuntPolicyError(
                    "native device Hunt request pacing interval has not elapsed"
                )

    def adapter_state(
        self,
        *,
        credential_refs: list[Mapping[str, Any]],
        collection_refs: list[Mapping[str, Any]],
        runtime: Mapping[str, Any] | None = None,
        allow_state_changing_requests: bool = False,
    ) -> dict[str, Any]:
        """Build transient compatibility input for registered device adapters."""
        runtime = dict(runtime or {})
        return {
            "schema_version": "hunt-device-adapter-state/v2",
            "safety_profile": self.safety_profile,
            "scans_queued": self.scans_queued,
            "device_http_requests_used": self.requests_used,
            "fragility_budget": self.fragility_limit,
            "fragility_used": self.fragility_used,
            "traffic_frozen": self.traffic_frozen,
            "last_device_http_request_monotonic": 0.0,
            "next_evidence_ref": int(runtime.get("next_evidence_ref") or 1),
            "evidence": dict(runtime.get("evidence") or {}),
            "shell_plans": list(runtime.get("shell_plans") or []),
            "device_credential_profiles": [dict(item) for item in credential_refs],
            "device_request_collections": [dict(item) for item in collection_refs],
            "allow_state_changing_requests": bool(allow_state_changing_requests),
        }

    def reconcile_adapter_state(
        self,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        *,
        actual_fragility: int = 0,
        health_failed: bool = False,
    ) -> "DeviceHuntPolicyState":
        request_delta = max(
            0,
            int(after.get("device_http_requests_used") or 0)
            - int(before.get("device_http_requests_used") or 0),
        )
        scan_delta = max(
            0,
            int(after.get("scans_queued") or 0)
            - int(before.get("scans_queued") or 0),
        )
        health_observed = bool(after.get("health_observed"))
        failures = (
            self.consecutive_health_failures + 1
            if health_observed and health_failed
            else 0
            if health_observed
            else self.consecutive_health_failures
        )
        frozen = self.traffic_frozen or bool(after.get("traffic_frozen")) or (
            failures >= self.circuit_breaker_threshold
        )
        return DeviceHuntPolicyState(
            safety_profile=self.safety_profile,
            fragility_limit=self.fragility_limit,
            fragility_used=min(
                self.fragility_limit,
                self.fragility_used + max(0, int(actual_fragility)),
            ),
            request_limit=self.request_limit,
            requests_used=min(self.request_limit, self.requests_used + request_delta),
            scan_limit=self.scan_limit,
            scans_queued=min(self.scan_limit, self.scans_queued + scan_delta),
            minimum_request_interval_ms=self.minimum_request_interval_ms,
            consecutive_health_failures=failures,
            circuit_breaker_threshold=self.circuit_breaker_threshold,
            traffic_frozen=frozen,
            last_request_at=(
                datetime.now(timezone.utc).isoformat()
                if request_delta
                else self.last_request_at
            ),
        )
