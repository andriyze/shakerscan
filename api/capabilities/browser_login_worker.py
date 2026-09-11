"""Worker/queue composition for the shared saved browser login QA action.

Existing navigate/interact behavior is unchanged. New login execution reloads
owner, target, approval and credential-version authority before every request.
"""
from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
import json
from typing import Any, Mapping
import uuid

from .browser import browser_capability_adapter
from .browser_login_action import BrowserLoginAdapter, BrowserLoginMaterial
from .browser_login import BrowserLoginValues
try:
    from hunt.browser_credentials import browser_session_headers
    from runtime.browser_login_contract import BROWSER_LOGIN_CAPABILITY, require_browser_login_policy
    from runtime.credential_refs import select_hunt_principal_reference
    from runtime.credential_resolver import WorkerCredentialResolver, validate_worker_credential_authority
    from runtime.credential_store import PostgresCredentialProfileStore
    from runtime.models import ScanPolicy
    from scan.authorization import revalidate_scan_action_authority, ActionAuthorityDecision
except ModuleNotFoundError:
    from ..hunt.browser_credentials import browser_session_headers
    from ..runtime.browser_login_contract import BROWSER_LOGIN_CAPABILITY, require_browser_login_policy
    from ..runtime.credential_refs import select_hunt_principal_reference
    from ..runtime.credential_resolver import WorkerCredentialResolver, validate_worker_credential_authority
    from ..runtime.credential_store import PostgresCredentialProfileStore
    from ..runtime.models import ScanPolicy
    from ..scan.authorization import revalidate_scan_action_authority, ActionAuthorityDecision


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    return dict(value) if isinstance(value, Mapping) else {}


def prepare_hunt_browser_action(name, *, target, base_url, args, context, policy):
    adapter = browser_capability_adapter(name)
    if name != BROWSER_LOGIN_CAPABILITY:
        return adapter.prepare(target=target, base_url=base_url, args=args)
    require_browser_login_policy(policy)
    # Use the persisted run's principal selection, never a planner-supplied ID.
    if set(args) != {"as_principal"}:
        raise ValueError("browser login accepts only a managed principal selection")
    reference = select_hunt_principal_reference(
        context, args.get("as_principal"), capability=BROWSER_LOGIN_CAPABILITY,
    )
    return adapter.prepare(target=target, base_url=base_url, args=args, profile_ref=reference)


def browser_worker_policy(name: str, *, policy, target) -> ScanPolicy:
    result = ScanPolicy(
        active_testing=bool(policy.get("active_testing")),
        allow_state_changing_http=(name == BROWSER_LOGIN_CAPABILITY
                                  and policy.get("allow_state_changing_http") is True),
        scope_receipt_id=target.scope_receipt_id,
        approval_receipt_id=policy.get("approval_receipt_id"),
    )
    if name == BROWSER_LOGIN_CAPABILITY:
        require_browser_login_policy(result)
    return result


@asynccontextmanager
async def browser_login_material(pool, *, prepared, owner_kind, owner_id, policy):
    """Decrypt only after lease admission; release the connection during browsing."""
    require_browser_login_policy(policy)
    reference = prepared.profile_ref
    profile_id = reference["profile_id"]
    owner_uuid = uuid.UUID(str(owner_id))
    target_uuid = uuid.UUID(str(prepared.target.target_id))
    store = PostgresCredentialProfileStore()
    action_name = "scan.submit" if owner_kind == "scan" else f"hunt.capability:{BROWSER_LOGIN_CAPABILITY}"

    async def authority(conn):
        # This helper is only constructed after the canonical worker owns its
        # durable action lease. Heartbeat in the adapter maintains that lease.
        if owner_kind == "hunt":
            row = await conn.fetchrow(
                "SELECT status, policy_json, context_pack FROM hunt_runs WHERE id=$1 AND target_id=$2",
                owner_uuid, target_uuid,
            )
            if not row or row["status"] not in {"active", "awaiting_planner", "budget_exhausted"}:
                raise ValueError("browser login owner is not executable")
            current = _mapping(row["policy_json"])
            require_browser_login_policy(current)
            if (BROWSER_LOGIN_CAPABILITY not in current.get("allowed_capabilities", ())
                    or str(current.get("approval_receipt_id")) != str(policy.approval_receipt_id)
                    or str(current.get("scope_receipt_id")) != str(policy.scope_receipt_id)
                    or select_hunt_principal_reference(
                        _mapping(row["context_pack"]), reference["principal_slot"],
                        capability=BROWSER_LOGIN_CAPABILITY) != dict(reference)):
                raise ValueError("browser login owner authority changed")
        elif owner_kind == "scan":
            row = await conn.fetchrow(
                "SELECT status FROM scans WHERE id=$1 AND target_id=$2", owner_uuid, target_uuid,
            )
            if not row or row["status"] != "running":
                raise ValueError("browser login owner is not executable")
        else:
            raise ValueError("browser login owner kind is invalid")
        current_target = await conn.fetchrow("SELECT url, is_active FROM targets WHERE id=$1", target_uuid)
        if (not current_target or not current_target["is_active"]
                or str(current_target["url"]).rstrip("/") != prepared.target_url.rstrip("/")):
            raise ValueError("browser login target changed")
        decision = await revalidate_scan_action_authority(
            conn, action={"capability_name": BROWSER_LOGIN_CAPABILITY},
            target_binding=prepared.target, scope_receipt_id=policy.scope_receipt_id,
            approval_receipt_id=policy.approval_receipt_id,
        )
        if decision is not ActionAuthorityDecision.ALLOWED:
            raise ValueError("browser login authority is no longer valid")
        return await validate_worker_credential_authority(
            conn, owner_kind=owner_kind, owner_id=str(owner_uuid), target=prepared.target,
            approval_receipt_id=policy.approval_receipt_id,
            scope_receipt_id=policy.scope_receipt_id, action_name=action_name,
        )

    def check_profile(metadata):
        if (metadata.current_version != reference["profile_version"]
                or metadata.principal_slot != reference["principal_slot"]
                or metadata.auth_kind not in {"form_login", "json_login"}
                or BROWSER_LOGIN_CAPABILITY not in metadata.allowed_capabilities
                or not metadata.configuration.get("browser_login_configured")):
            raise ValueError("browser login profile changed or is not configured")

    async def revalidate():
        async with pool.acquire() as conn:
            await authority(conn)
            stored = await store.load_for_worker(
                conn, profile_id=profile_id, target_kind=prepared.target.target_kind,
                target_id=prepared.target.target_id, capability=BROWSER_LOGIN_CAPABILITY,
            )
            check_profile(stored.metadata)

    async with AsyncExitStack() as stack:
        async with pool.acquire() as conn:
            approved = await authority(conn)
            resolved = await stack.enter_async_context(WorkerCredentialResolver().resolve(
                conn, profile_id=profile_id, target=prepared.target,
                capability=BROWSER_LOGIN_CAPABILITY, authority=approved,
                expected_version=reference["profile_version"],
                expected_principal_slot=reference["principal_slot"],
            ))
            check_profile(resolved.profile)
        credential = resolved.interactive_http()
        config = resolved.browser_login_configuration()
        try:
            yield BrowserLoginMaterial(
                config, BrowserLoginValues(credential.username or "", credential.secret), revalidate,
            )
        finally:
            config.clear()


def build_hunt_browser_adapter(pool, *, prepared, hunt_id, policy):
    if prepared.capability_name == BROWSER_LOGIN_CAPABILITY:
        return BrowserLoginAdapter(
            prepared, policy=policy,
            credential_loader=lambda: browser_login_material(
                pool, prepared=prepared, owner_kind="hunt", owner_id=hunt_id, policy=policy,
            ),
        )
    return browser_capability_adapter(prepared.capability_name)(
        prepared, session_loader=lambda: browser_session_headers(
            pool, prepared=prepared, hunt_id=hunt_id, policy=policy,
        ),
    )


def build_scan_browser_login_adapter(pool, *, action, dispatcher):
    prepared = BrowserLoginAdapter.prepare(
        target=dispatcher.target, base_url=dispatcher.target_url,
        args=action.capability_args,
    )
    if any(action.requested_budget.get(k, 0) < v for k, v in prepared.estimated_budget.items()):
        raise ValueError("browser login action is missing its reservation")
    return BrowserLoginAdapter(
        prepared, policy=dispatcher.policy,
        credential_loader=lambda: browser_login_material(
            pool, prepared=prepared, owner_kind="scan", owner_id=dispatcher.scan_id,
            policy=dispatcher.policy,
        ),
    )
