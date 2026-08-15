"""Safety contracts and health monitoring for connected-device assessments.

Coverage depth and operational safety are deliberately independent.  A scan
can inventory every TCP port without receiving permission to mutate device
state, while a future lab workflow may use a narrow target surface with more
invasive actions.  This module is kept separate from Web DAST so device safety
decisions cannot change ordinary DAST behavior.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import asdict, dataclass
from typing import Any


DEVICE_SAFETY_PROFILES = {
    "observe_only",
    "safe_remote",
    "authenticated_active",
    "lab_invasive",
}
ACTION_SAFETY_CLASSES = {
    "readonly",
    "ephemeral_state",
    "persistent_state",
    "resource_intensive",
    "destructive",
}


@dataclass(frozen=True)
class DeviceSafetyProfile:
    name: str
    label: str
    allowed_action_classes: tuple[str, ...]
    max_concurrency: int
    max_requests_per_second: float
    health_monitor_required: bool
    credentials_allowed: bool
    explicit_lab_confirmation_required: bool
    available: bool
    unavailable_reason: str | None = None


SAFETY_PROFILES: dict[str, DeviceSafetyProfile] = {
    "observe_only": DeviceSafetyProfile(
        name="observe_only",
        label="Observe only",
        allowed_action_classes=("readonly",),
        max_concurrency=4,
        max_requests_per_second=5.0,
        health_monitor_required=False,
        credentials_allowed=False,
        explicit_lab_confirmation_required=False,
        available=True,
    ),
    "safe_remote": DeviceSafetyProfile(
        name="safe_remote",
        label="Safe remote",
        allowed_action_classes=("readonly", "ephemeral_state"),
        max_concurrency=8,
        max_requests_per_second=10.0,
        health_monitor_required=True,
        credentials_allowed=False,
        explicit_lab_confirmation_required=False,
        available=True,
    ),
    "authenticated_active": DeviceSafetyProfile(
        name="authenticated_active",
        label="Authenticated active",
        allowed_action_classes=("readonly", "ephemeral_state"),
        max_concurrency=6,
        max_requests_per_second=8.0,
        health_monitor_required=True,
        credentials_allowed=True,
        explicit_lab_confirmation_required=False,
        available=True,
    ),
    "lab_invasive": DeviceSafetyProfile(
        name="lab_invasive",
        label="Lab invasive",
        allowed_action_classes=(
            "readonly",
            "ephemeral_state",
            "persistent_state",
            "resource_intensive",
            "destructive",
        ),
        max_concurrency=2,
        max_requests_per_second=3.0,
        health_monitor_required=True,
        credentials_allowed=True,
        explicit_lab_confirmation_required=True,
        available=False,
        unavailable_reason="lab_invasive_runner_not_ready",
    ),
}


def safety_profile_catalog() -> list[dict[str, Any]]:
    """Return a stable, non-secret readiness catalog for API and UI clients."""
    return [asdict(SAFETY_PROFILES[name]) for name in sorted(SAFETY_PROFILES)]


def resolve_safety_profile(value: Any) -> DeviceSafetyProfile:
    name = str(value or "safe_remote").strip().lower().replace("-", "_")
    profile = SAFETY_PROFILES.get(name)
    if not profile:
        raise ValueError(
            "device safety_profile must be one of: "
            + ", ".join(sorted(DEVICE_SAFETY_PROFILES))
        )
    return profile


def validate_safety_request(options: dict[str, Any]) -> DeviceSafetyProfile:
    profile = resolve_safety_profile(options.get("safety_profile"))
    if not profile.available:
        raise ValueError(
            f"device safety profile {profile.name} is not ready: "
            f"{profile.unavailable_reason or 'capability_unavailable'}"
        )
    if profile.explicit_lab_confirmation_required and not options.get("confirm_lab_invasive"):
        raise ValueError("lab-invasive device testing requires confirm_lab_invasive=true")
    if profile.name == "observe_only" and options.get("include_web_dast"):
        raise ValueError("observe_only permits web-origin discovery but not Web DAST children")
    return profile


class DeviceSafetyGovernor:
    """Authorize device actions and retain health/safety receipts for one run."""

    def __init__(self, profile: DeviceSafetyProfile):
        self.profile = profile
        self.actions: list[dict[str, Any]] = []
        self.limit_enforcements: list[dict[str, Any]] = []
        self.health_checkpoints: list[dict[str, Any]] = []
        self.halted = False
        self.halt_reason: str | None = None

    def authorize(self, action_id: str, safety_class: str, *, side_effects: str = "none") -> dict[str, Any]:
        normalized = str(safety_class or "").strip().lower()
        if normalized not in ACTION_SAFETY_CLASSES:
            raise ValueError(f"unknown device action safety class: {safety_class}")
        allowed = normalized in self.profile.allowed_action_classes and not self.halted
        receipt = {
            "action_id": str(action_id),
            "safety_class": normalized,
            "side_effects": str(side_effects or "none"),
            "profile": self.profile.name,
            "allowed": allowed,
            "reason": self.halt_reason if self.halted else None,
        }
        self.actions.append(receipt)
        if not allowed:
            reason = self.halt_reason or f"{normalized} is forbidden by {self.profile.name}"
            raise PermissionError(f"device action {action_id} blocked: {reason}")
        return receipt

    def record_limit_enforcement(
        self,
        component: str,
        *,
        max_concurrency: int | None = None,
        max_requests_per_second: float | None = None,
    ) -> None:
        """Record the concrete limiter used by one scanner component."""
        self.limit_enforcements.append({
            "component": str(component),
            "max_concurrency": int(max_concurrency) if max_concurrency is not None else None,
            "max_requests_per_second": (
                float(max_requests_per_second)
                if max_requests_per_second is not None
                else None
            ),
        })

    def record_health(self, checkpoint: dict[str, Any]) -> None:
        current = dict(checkpoint)
        self.health_checkpoints.append(current)
        if current.get("status") != "degraded":
            return
        prior = self.health_checkpoints[:-1]
        attempted_tcp_ports = bool(current.get("attempted_tcp_ports"))
        if any(item.get("status") == "healthy" for item in prior) or (
            attempted_tcp_ports and any(item.get("status") == "indeterminate" for item in prior)
        ):
            self.halted = True
            self.halt_reason = f"device health degraded at {current.get('stage') or 'unknown stage'}"

    def receipt(self) -> dict[str, Any]:
        return {
            "schema_version": "device-safety/v1",
            "profile": asdict(self.profile),
            "actions": list(self.actions),
            "limit_enforcements": list(self.limit_enforcements),
            "health_checkpoints": list(self.health_checkpoints),
            "halted": self.halted,
            "halt_reason": self.halt_reason,
        }


async def check_device_health(
    locator: str,
    *,
    stage: str,
    tcp_ports: list[int] | tuple[int, ...] = (),
    timeout: float = 1.5,
) -> dict[str, Any]:
    """Perform a bounded, read-only liveness checkpoint.

    Name/address resolution is always checked.  When confirmed TCP listeners
    are known, up to three are used as a stronger signal.  Failure to connect
    is reported as degraded evidence, never reinterpreted as proof that the
    device or a service is absent.
    """
    started = time.monotonic()
    loop = asyncio.get_running_loop()
    addresses: list[str] = []
    resolution_error: str | None = None
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(locator, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
        addresses = sorted({str(info[4][0]) for info in infos if info and info[4]})
    except (TimeoutError, OSError, socket.gaierror) as exc:
        resolution_error = type(exc).__name__

    attempted_ports: list[int] = []
    responsive_ports: list[int] = []
    for raw_port in list(tcp_ports)[:3]:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        attempted_ports.append(port)
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(locator, port),
                timeout=timeout,
            )
            responsive_ports.append(port)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            break
        except (TimeoutError, OSError):
            continue

    if not addresses:
        status = "degraded"
    elif responsive_ports:
        status = "healthy"
    elif attempted_ports:
        status = "degraded"
    else:
        status = "indeterminate"
    return {
        "stage": str(stage),
        "status": status,
        "resolution_succeeded": bool(addresses),
        "addresses": addresses[:8],
        "resolution_error": resolution_error,
        "attempted_tcp_ports": attempted_ports,
        "responsive_tcp_ports": responsive_ports,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
    }
