"""Worker-private exact inputs for one canonical broker Scan lease."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

try:
    from scanner_tools.request_replay import (
        ReplayAuthorization,
        ReplayPlan,
        ReplayRequest,
        RequestReplayError,
        build_replay_plan,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import (
        ReplayAuthorization,
        ReplayPlan,
        ReplayRequest,
        RequestReplayError,
        build_replay_plan,
    )


BROKER_PRIVATE_SCAN_INPUT_SCHEMA = "broker-private-scan-input/v1"
PRIVATE_REPLAY_PLAN_SCHEMA = "request-replay-plan-private/v1"
MAX_PRIVATE_REPLAY_PLANS = 32
MAX_PRIVATE_OPTIONS_BYTES = 2 * 1024 * 1024
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


class BrokerPrivateScanInputError(ValueError):
    """A decrypted broker input differs from its immutable lease authority."""


def _body_b64(value: bytes) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _decode_body(value: Any) -> bytes:
    try:
        return base64.b64decode(str(value or ""), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise BrokerPrivateScanInputError("private replay body is invalid") from exc


def private_replay_plan_payload(plan: ReplayPlan) -> dict[str, Any]:
    """Serialize exact wire requests for encryption, never for public storage."""
    if (
        str(getattr(plan, "schema_version", "")) != "request-replay-plan/v1"
        or not tuple(getattr(plan, "requests", ()) or ())
        or not _HEX_64_RE.fullmatch(str(getattr(plan, "input_digest", "")))
    ):
        raise BrokerPrivateScanInputError("private replay plan is invalid")
    return {
        "schema_version": PRIVATE_REPLAY_PLAN_SCHEMA,
        "input_digest": plan.input_digest,
        "allowed_origins": list(plan.allowed_origins),
        "default_origin": plan.default_origin,
        "authorization": {
            "active_testing": plan.authorization.active_testing,
            "allow_state_changing_http": (
                plan.authorization.allow_state_changing_http
            ),
            "approval_receipt_id": plan.authorization.approval_receipt_id,
        },
        "requests": [
            {
                "request_id": request.request_id,
                "ordinal": request.ordinal,
                "name": request.name,
                "folder": request.folder,
                "method": request.method,
                "url": request.url,
                "headers": [[name, value] for name, value in request.headers],
                "body_b64": _body_b64(request.body),
                "body_mode": request.body_mode,
                "auth_type": request.auth_type,
                "has_sensitive_material": request.has_sensitive_material,
            }
            for request in plan.requests
        ],
    }


def replay_plan_from_private_payload(value: Mapping[str, Any]) -> ReplayPlan:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "input_digest", "allowed_origins", "default_origin",
        "authorization", "requests",
    }:
        raise BrokerPrivateScanInputError("private replay plan shape is invalid")
    if value.get("schema_version") != PRIVATE_REPLAY_PLAN_SCHEMA:
        raise BrokerPrivateScanInputError("private replay plan schema is invalid")
    expected_digest = str(value.get("input_digest") or "").lower()
    if not _HEX_64_RE.fullmatch(expected_digest):
        raise BrokerPrivateScanInputError("private replay digest is invalid")
    raw_authorization = value.get("authorization")
    if not isinstance(raw_authorization, Mapping) or set(raw_authorization) != {
        "active_testing", "allow_state_changing_http", "approval_receipt_id",
    }:
        raise BrokerPrivateScanInputError("private replay authorization is invalid")
    if not isinstance(raw_authorization.get("active_testing"), bool) or not isinstance(
        raw_authorization.get("allow_state_changing_http"), bool,
    ):
        raise BrokerPrivateScanInputError("private replay authorization is invalid")
    rows = value.get("requests")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 2_000:
        raise BrokerPrivateScanInputError("private replay request list is invalid")
    requests: list[dict[str, Any]] = []
    expected_public: list[tuple[int, str, str, bool]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping) or set(raw) != {
            "request_id", "ordinal", "name", "folder", "method", "url",
            "headers", "body_b64", "body_mode", "auth_type",
            "has_sensitive_material",
        }:
            raise BrokerPrivateScanInputError("private replay request is invalid")
        if raw.get("ordinal") != index or not isinstance(
            raw.get("has_sensitive_material"), bool,
        ):
            raise BrokerPrivateScanInputError("private replay request is invalid")
        headers = raw.get("headers")
        if not isinstance(headers, list) or any(
            not isinstance(item, list) or len(item) != 2 for item in headers
        ):
            raise BrokerPrivateScanInputError("private replay headers are invalid")
        header_map: dict[str, str] = {}
        for name, item in headers:
            normalized_name = str(name)
            if normalized_name in header_map:
                raise BrokerPrivateScanInputError(
                    "private replay headers contain duplicate names"
                )
            header_map[normalized_name] = str(item)
        request_id = str(raw.get("request_id") or "")
        requests.append({
            "id": request_id,
            "name": str(raw.get("name") or ""),
            "folder": str(raw.get("folder") or ""),
            "method": str(raw.get("method") or ""),
            "url": str(raw.get("url") or ""),
            "headers": header_map,
            "body": _decode_body(raw.get("body_b64")),
            "body_mode": str(raw.get("body_mode") or "none"),
            "auth_type": str(raw.get("auth_type") or "none"),
            "has_sensitive_material": bool(raw.get("has_sensitive_material")),
        })
        expected_public.append((
            index,
            request_id,
            str(raw.get("auth_type") or "none"),
            bool(raw.get("has_sensitive_material")),
        ))
    try:
        plan = build_replay_plan(
            requests,
            allowed_origins=value.get("allowed_origins") or (),
            default_origin=value.get("default_origin"),
            authorization=ReplayAuthorization(
                active_testing=raw_authorization["active_testing"],
                allow_state_changing_http=raw_authorization[
                    "allow_state_changing_http"
                ],
                approval_receipt_id=(
                    str(raw_authorization.get("approval_receipt_id") or "")
                    or None
                ),
            ),
            limit=len(requests),
        )
    except RequestReplayError as exc:
        raise BrokerPrivateScanInputError(str(exc)) from exc
    actual_public = [
        (
            request.ordinal, request.request_id, request.auth_type,
            request.has_sensitive_material,
        )
        for request in plan.requests
    ]
    if actual_public != expected_public or plan.input_digest != expected_digest:
        raise BrokerPrivateScanInputError(
            "private replay plan differs from its sealed digest"
        )
    return plan


@dataclass(frozen=True)
class BrokerPrivateScanInputs:
    lease_id: str
    worker_id: str
    plan_digest: str
    target_binding_digest: str
    expires_at: str
    options: Mapping[str, Any]
    replay_plans: Mapping[str, ReplayPlan]

    @classmethod
    def from_payload(
        cls,
        value: Mapping[str, Any],
        *,
        lease_id: str,
        worker_id: str,
        plan_digest: str,
        target_binding_digest: str,
        now: datetime | None = None,
    ) -> "BrokerPrivateScanInputs":
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version", "lease_id", "worker_id", "plan_digest",
            "target_binding_digest", "expires_at", "options", "replay_plans",
        }:
            raise BrokerPrivateScanInputError("private Scan input shape is invalid")
        if value.get("schema_version") != BROKER_PRIVATE_SCAN_INPUT_SCHEMA:
            raise BrokerPrivateScanInputError("private Scan input schema is invalid")
        if (
            str(value.get("lease_id") or "") != str(lease_id)
            or str(value.get("worker_id") or "") != str(worker_id)
            or str(value.get("plan_digest") or "") != str(plan_digest)
            or str(value.get("target_binding_digest") or "")
            != str(target_binding_digest)
        ):
            raise BrokerPrivateScanInputError(
                "private Scan input authority does not match the lease"
            )
        try:
            expires_at = datetime.fromisoformat(
                str(value.get("expires_at") or "").replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise BrokerPrivateScanInputError(
                "private Scan input expiry is invalid"
            ) from exc
        if expires_at.tzinfo is None or expires_at.astimezone(timezone.utc) <= (
            now or datetime.now(timezone.utc)
        ).astimezone(timezone.utc):
            raise BrokerPrivateScanInputError("private Scan input is expired")
        options = value.get("options")
        if not isinstance(options, Mapping):
            raise BrokerPrivateScanInputError("private Scan options are invalid")
        try:
            option_size = len(json.dumps(
                dict(options), sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise BrokerPrivateScanInputError(
                "private Scan options are invalid"
            ) from exc
        if option_size > MAX_PRIVATE_OPTIONS_BYTES:
            raise BrokerPrivateScanInputError("private Scan options are too large")
        raw_plans = value.get("replay_plans")
        if not isinstance(raw_plans, Mapping) or len(raw_plans) > MAX_PRIVATE_REPLAY_PLANS:
            raise BrokerPrivateScanInputError("private replay plan map is invalid")
        plans: dict[str, ReplayPlan] = {}
        for raw_action_id, raw_plan in raw_plans.items():
            action_id = str(raw_action_id or "")
            if not _ACTION_ID_RE.fullmatch(action_id) or not isinstance(
                raw_plan, Mapping,
            ):
                raise BrokerPrivateScanInputError(
                    "private replay plan identity is invalid"
                )
            plans[action_id] = replay_plan_from_private_payload(raw_plan)
        return cls(
            lease_id=str(lease_id),
            worker_id=str(worker_id),
            plan_digest=str(plan_digest),
            target_binding_digest=str(target_binding_digest),
            expires_at=expires_at.astimezone(timezone.utc).isoformat(),
            options=MappingProxyType(dict(options)),
            replay_plans=MappingProxyType(plans),
        )

    def request_map(self) -> Mapping[str, ReplayRequest]:
        result: dict[str, ReplayRequest] = {}
        for plan in self.replay_plans.values():
            for request in plan.requests:
                previous = result.get(request.request_id)
                if previous is not None and previous.digest_dict() != request.digest_dict():
                    raise BrokerPrivateScanInputError(
                        "private replay request identity is ambiguous"
                    )
                result[request.request_id] = request
        return MappingProxyType(result)


__all__ = [
    "BROKER_PRIVATE_SCAN_INPUT_SCHEMA",
    "PRIVATE_REPLAY_PLAN_SCHEMA",
    "BrokerPrivateScanInputError",
    "BrokerPrivateScanInputs",
    "private_replay_plan_payload",
    "replay_plan_from_private_payload",
]
