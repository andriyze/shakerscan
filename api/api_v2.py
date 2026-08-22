#!/usr/bin/env python3
"""Native Hunt V2 API boundary layered over the existing control-plane services.

The large compatibility module still owns shared persistence helpers, fleet placement, evidence,
and non-Hunt routes. The canonical ``POST /hunts`` route is replaced here so a validated V2
contract is persisted without translating authority back into the legacy request model.
"""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from typing import Any, Mapping
import uuid

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

import api as _legacy_api
from hunt.contracts import HuntBudget
from hunt.start_contract import (
    MAX_HUNT_BODY_BYTES,
    HUNT_START_SCHEMA,
    HuntStartContract,
    HuntStartContractError,
    bind_validated_receipts,
    normalize_hunt_start_payload,
)
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilitySpec


_LEGACY_START_HUNT = _legacy_api.start_hunt
_LEGACY_HUNT_PUBLIC = _legacy_api._hunt_public
_NETWORK_CAPABILITIES = frozenset({"ports.discover", "service.fingerprint"})
_DEVICE_CREDENTIAL_KEYS = frozenset({
    "ssh_credential_profile_id", "web_credential_profile_id",
})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def _legacy_hunt_starts_enabled() -> bool:
    return str(os.environ.get("SHAKERSCAN_ALLOW_LEGACY_HUNT_STARTS") or "").strip().lower() in _TRUE_VALUES


def _capability_public(spec: CapabilitySpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "risk_tier": spec.risk_tier,
        "input_schema": dict(spec.input_schema),
        "output_schema": spec.output_schema,
        "budget_cost": dict(spec.budget_cost),
        "required_approval": spec.required_approval,
        "evidence_contract": list(spec.evidence_contract),
    }


def _capability_is_allowed(
    spec: CapabilitySpec,
    contract: HuntStartContract,
    *,
    credential_access: bool,
) -> bool:
    if contract.target_kind not in spec.target_kinds:
        return False
    if spec.name in _NETWORK_CAPABILITIES and not contract.policy.network_discovery:
        return False
    if spec.risk_tier == "credential" and not credential_access:
        return False
    if spec.risk_tier == "mutation" and not contract.policy.allow_state_changing_http:
        return False
    if spec.required_approval == "network_discovery" and not contract.policy.network_discovery:
        return False
    if spec.risk_tier == "active" and not contract.policy.active_testing:
        return False
    if spec.required_approval == "active_testing" and not contract.policy.active_testing:
        return False
    return True


def _resolve_allowed_capabilities(
    contract: HuntStartContract,
    *,
    credential_access: bool,
) -> tuple[str, ...]:
    available = {
        spec.name: spec
        for spec in CAPABILITY_REGISTRY.list(target_kind=contract.target_kind, include_active=True)
        if _capability_is_allowed(spec, contract, credential_access=credential_access)
    }
    if not contract.capabilities:
        return tuple(available)
    result: list[str] = []
    for name in contract.capabilities:
        try:
            spec = CAPABILITY_REGISTRY.require(name)
        except KeyError as exc:
            raise HuntStartContractError(str(exc)) from exc
        if name not in available:
            raise HuntStartContractError(
                f"capability {name} is outside this target or Hunt policy"
            )
        if spec.name not in result:
            result.append(spec.name)
    return tuple(result)


def _hunt_public_v2(row: Any, *, include_context: bool = True) -> dict[str, Any]:
    result = _LEGACY_HUNT_PUBLIC(row, include_context=include_context)
    item = (
        _legacy_api.row_to_dict(row)
        if row is not None and not isinstance(row, dict)
        else dict(row or {})
    )
    policy = _legacy_api._hunt_json(item.get("policy_json"), {})
    allowed = policy.get("allowed_capabilities")
    if isinstance(allowed, list):
        capabilities: list[dict[str, Any]] = []
        for raw_name in allowed:
            try:
                capabilities.append(_capability_public(CAPABILITY_REGISTRY.require(str(raw_name))))
            except KeyError:
                continue
        result["capabilities"] = capabilities
        result["policy"] = policy
    return result


# Existing get/list/execute routes resolve this global at request time. Filtering the public
# manifest here also makes their capability authorization check honor the persisted V2 allowlist.
_legacy_api._hunt_public = _hunt_public_v2


async def _validate_device_credentials(
    conn: Any,
    contract: HuntStartContract,
    device_id: uuid.UUID,
) -> list[dict[str, Any]]:
    unsupported = sorted(set(contract.credential_refs) - _DEVICE_CREDENTIAL_KEYS)
    if unsupported:
        raise HTTPException(
            status_code=422,
            detail=(
                "device Hunt currently supports only ssh_credential_profile_id and "
                f"web_credential_profile_id; unsupported: {', '.join(unsupported)}"
            ),
        )
    return await _legacy_api._validate_device_credential_refs(
        conn,
        device_id,
        ssh_profile_id=contract.credential_refs.get("ssh_credential_profile_id"),
        web_profile_id=contract.credential_refs.get("web_credential_profile_id"),
    )


def _reject_unmigrated_web_credentials(contract: HuntStartContract) -> None:
    if contract.credential_refs:
        raise HTTPException(
            status_code=422,
            detail=(
                "generic web/API credential-profile binding is not yet available in the native "
                "Hunt worker; refusing to discard or broaden the submitted credential references"
            ),
        )


async def _start_hunt_v2(contract: HuntStartContract) -> dict[str, Any]:
    target_uuid = _legacy_api._uuid_or_400(contract.target_id, "target id")
    approval_validated = False
    approval_context: Mapping[str, Any] | None = None
    budget = HuntBudget(**contract.resolved_budget)

    async with _legacy_api.db_pool.acquire() as conn:
        web = await conn.fetchrow(
            "SELECT id, url, name, root_domain, metadata_json, is_active FROM targets WHERE id=$1",
            target_uuid,
        )
        device = await conn.fetchrow(
            "SELECT id, name, primary_locator, device_class, is_active FROM device_targets WHERE id=$1",
            target_uuid,
        )

        if contract.target_kind in {"web", "api", "network"}:
            if not web or not web["is_active"]:
                raise HTTPException(status_code=404, detail="Active web/API/network target not found")
            _reject_unmigrated_web_credentials(contract)
            target_url = str(web["url"])
            db_target_id, device_target_id = target_uuid, None
            credential_rows: list[dict[str, Any]] = []
            origins = await _legacy_api._target_web_origins(conn, target_uuid, target_url)
            collection_refs, _collection_endpoints = await _legacy_api._generic_collection_refs(
                conn,
                target_id=target_uuid,
                bindings=[{"id": value} for value in contract.request_collection_ids],
            )
            context_pack: dict[str, Any] = {
                "schema_version": "hunt-context/v2",
                "target": {
                    "id": str(target_uuid),
                    "kind": contract.target_kind,
                    "url": target_url,
                    "origins": origins,
                    "root_domain": web["root_domain"],
                    "environment": str(
                        _legacy_api._hunt_json(web["metadata_json"], {}).get("environment")
                        or "unknown"
                    ),
                },
                "principal_refs_available": False,
                "credential_refs": [],
                "secret_values_visible_to_planner": False,
                "request_collections": collection_refs,
                "authorized_target_addresses": await _legacy_api._resolve_agent_target_addresses(
                    target_url
                ),
            }
        elif contract.target_kind == "device":
            if not device or not device["is_active"]:
                raise HTTPException(status_code=404, detail="Active device target not found")
            target_url = str(device["primary_locator"])
            db_target_id, device_target_id = None, target_uuid
            credential_rows = await _validate_device_credentials(conn, contract, target_uuid)
            collection_refs, _collection_endpoints = await _legacy_api._generic_collection_refs(
                conn,
                device_target_id=target_uuid,
                bindings=[{"id": value} for value in contract.request_collection_ids],
            )
            device_state = _legacy_api.device_agent.seed_state(
                objective=contract.goal,
                safety_profile=(
                    "authenticated_active"
                    if contract.policy.active_testing and contract.policy.approval_receipt_id
                    else "safe_remote"
                ),
                max_turns=30,
            )
            device_state["device_request_collections"] = collection_refs
            device_state["device_credential_profiles"] = credential_rows
            context_pack = {
                "schema_version": "hunt-context/v2",
                "target": {
                    "id": str(target_uuid),
                    "kind": "device",
                    "name": device["name"],
                    "locator": target_url,
                    "device_class": device["device_class"],
                },
                "principal_refs_available": bool(credential_rows),
                "credential_refs": credential_rows,
                "secret_values_visible_to_planner": False,
                "request_collections": collection_refs,
                "device_state": device_state,
            }
        else:
            raise HTTPException(status_code=422, detail="unsupported target kind")

        privileged = bool(
            contract.policy.active_testing
            or contract.policy.network_discovery
            or contract.policy.allow_state_changing_http
            or credential_rows
        )
        if contract.policy.approval_receipt_id:
            approval_context = await _legacy_api._validate_approval_receipt_for_action(
                conn,
                contract.policy.approval_receipt_id,
                target_url=target_url,
                target_id=target_uuid,
                action_name="hunt.start.v2",
                command="hunt.start.v2",
                risk_tier=("credential" if credential_rows else "active" if privileged else "read_only"),
                always_require_receipt=privileged,
                require_target_binding=True,
                require_expiry=True,
                created_by="hunt_v2_native",
            )
            approval_validated = True
        else:
            await _legacy_api._require_approval_receipt_if_policy_enabled(
                conn,
                None,
                action_name="hunt.start.v2",
                risk_tier="passive",
                created_by="hunt_v2_native",
            )

        validated_approval_id, validated_scope_id = bind_validated_receipts(
            contract.policy, approval_context,
        )

        if privileged and not approval_validated:
            raise HTTPException(
                status_code=403,
                detail="privileged Hunt policy requires a validated target-bound approval receipt",
            )

        credential_access = bool(credential_rows and approval_validated)
        allowed_capabilities = _resolve_allowed_capabilities(
            contract,
            credential_access=credential_access,
        )
        policy = {
            "schema_version": "hunt-policy/v2",
            "target_kind": contract.target_kind,
            "active_testing": bool(contract.policy.active_testing and approval_validated),
            "credential_access": credential_access,
            "mutation_allowed": bool(
                contract.policy.allow_state_changing_http and approval_validated
            ),
            "allow_state_changing_http": bool(
                contract.policy.allow_state_changing_http and approval_validated
            ),
            "network_discovery": bool(
                contract.policy.network_discovery and approval_validated
            ),
            "authorization_confirmed": contract.policy.authorization_confirmed,
            "approval_receipt_id": validated_approval_id,
            "scope_receipt_id": validated_scope_id,
            "device_fragility_profile": (
                "authenticated_active"
                if contract.target_kind == "device" and credential_access
                else "safe_remote" if contract.target_kind == "device" else None
            ),
            "budget_profile": contract.budget_profile,
            "budget": asdict(budget),
            "allowed_capabilities": list(allowed_capabilities),
        }
        normalized_contract = contract.public_dict()
        normalized_contract["policy"]["approval_receipt_id"] = validated_approval_id
        normalized_contract["policy"]["scope_receipt_id"] = validated_scope_id
        context_pack["hunt_start_contract"] = normalized_contract
        if approval_context:
            context_pack["runtime_scope_guard"] = dict(
                approval_context.get("runtime_scope_guard") or {}
            )
        context_pack["allowed_capabilities"] = list(allowed_capabilities)

        row = await conn.fetchrow(
            """INSERT INTO hunt_runs (
                   target_kind, target_id, device_target_id, objective, status, budget_profile,
                   policy_json, budget_json, budget_used_json, context_pack,
                   approval_receipt_id, created_by
               ) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,'hunt_v2_native')
               RETURNING *""",
            contract.target_kind,
            db_target_id,
            device_target_id,
            contract.goal,
            contract.budget_profile,
            json.dumps(policy),
            json.dumps(asdict(budget)),
            json.dumps({
                **{key: 0 for key in budget.ledger_limits()},
                "candidates": 0,
                "verifications": 0,
            }),
            json.dumps(context_pack, default=str),
            _legacy_api._optional_uuid(validated_approval_id)
            if validated_approval_id
            else None,
        )
    return _hunt_public_v2(row)


async def start_hunt_v2_http(request: Request) -> JSONResponse:
    raw_body = await request.body()
    if len(raw_body) > MAX_HUNT_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Hunt request body is too large")
    try:
        decoded = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Hunt request body must be valid JSON") from exc
    if not isinstance(decoded, Mapping):
        raise HTTPException(status_code=422, detail="Hunt request body must be an object")

    if "policy" not in decoded and _legacy_hunt_starts_enabled():
        try:
            legacy_request = _legacy_api.HuntStartRequest.model_validate(decoded)
        except _legacy_api.ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc
        result = await _LEGACY_START_HUNT(legacy_request)
        return JSONResponse(
            content=_legacy_api._json_safe_row(result),
            headers={"x-shakerscan-hunt-contract": "legacy-compatible"},
        )
    if "policy" not in decoded:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "explicit_v2_policy_required",
                "message": "Hunt starts must include the hunt-start/v2 policy object",
                "schema_version": HUNT_START_SCHEMA,
            },
        )

    try:
        contract = normalize_hunt_start_payload(decoded)
        result = await _start_hunt_v2(contract)
    except HuntStartContractError as exc:
        raise HTTPException(
            status_code=422,
            detail={"message": str(exc), "schema_version": HUNT_START_SCHEMA},
        ) from exc
    return JSONResponse(
        content=_legacy_api._json_safe_row(result),
        headers={"x-shakerscan-hunt-contract": "v2"},
    )


def _install_native_hunt_route() -> None:
    routes = list(_legacy_api.app.router.routes)
    _legacy_api.app.router.routes[:] = [
        route
        for route in routes
        if not (
            getattr(route, "path", None) == "/hunts"
            and "POST" in set(getattr(route, "methods", set()) or set())
        )
    ]
    _legacy_api.app.add_api_route(
        "/hunts",
        start_hunt_v2_http,
        methods=["POST"],
        name="start_hunt_v2",
        tags=["Hunt"],
        response_class=JSONResponse,
    )


_install_native_hunt_route()
app = _legacy_api.app


def main() -> None:
    import uvicorn

    host = str(os.environ.get("SHAKERSCAN_API_HOST") or "0.0.0.0")
    try:
        port = int(os.environ.get("SHAKERSCAN_API_PORT") or "8080")
    except ValueError as exc:
        raise SystemExit("SHAKERSCAN_API_PORT must be an integer") from exc
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
