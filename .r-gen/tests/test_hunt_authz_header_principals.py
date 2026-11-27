"""Header principals reach authorization proof without interactive sessions."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from types import SimpleNamespace

import pytest

from api.hunt.authz_credentials import resolve_hunt_authz_principals
from api.hunt.interaction_router import HuntCapabilityRequest
from api.hunt.run_service import public_hunt_run
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from runtime.credential_refs import CredentialReferenceError
from runtime.credential_resolver import CredentialResolutionError


PRIMARY = "00000000-0000-4000-8000-00000000000b"
SECONDARY = "00000000-0000-4000-8000-00000000000c"
HUNT = "00000000-0000-4000-8000-00000000000d"


def _context(kind: str = "authorization_header") -> dict:
    return {"credential_refs": [
        {"source": "credential_profiles", "profile_id": PRIMARY,
         "principal_slot": "primary", "profile_version": 3, "auth_kind": kind,
         "allowed_capabilities": ["authz.verify"]},
        {"source": "credential_profiles", "profile_id": SECONDARY,
         "principal_slot": "secondary", "profile_version": 4,
         "auth_kind": "bearer_token", "allowed_capabilities": ["authz.verify"]},
    ]}


def test_authz_planner_accepts_exactly_one_credential_mode():
    registry = CAPABILITY_REGISTRY
    principal_input = {"routes": ["/api/objects"],
                       "primary_principal": "primary", "secondary_principal": "secondary"}
    session_input = {"routes": ["/api/objects"],
                     "primary_session_ref": PRIMARY, "secondary_session_ref": SECONDARY}
    assert registry.validate_hunt_input("authz.verify", principal_input) == principal_input
    assert registry.validate_hunt_input("authz.verify", session_input) == session_input
    for invalid in (
        {"routes": ["/api/objects"]},
        {"routes": ["/api/objects"], "primary_principal": "primary"},
        {**principal_input, "primary_session_ref": PRIMARY},
        {**principal_input, "secondary_principal": "primary"},
        {**principal_input, "token": "secret"},
    ):
        with pytest.raises(CapabilityInputContractError):
            registry.validate_hunt_input("authz.verify", invalid)


class _Resolver:
    def __init__(self, *, changed_version: bool = False):
        self.calls = []
        self.changed_version = changed_version
        self.closed = []

    @asynccontextmanager
    async def resolve(self, conn, *, profile_id, target, capability, authority):
        assert conn is CONNECTION and target is TARGET and authority is AUTHORITY
        assert capability == "authz.verify"
        self.calls.append(profile_id)
        slot = "primary" if profile_id == PRIMARY else "secondary"
        version = 3 if slot == "primary" else 4
        if self.changed_version and slot == "secondary":
            version += 1
        resolved = SimpleNamespace(
            profile=SimpleNamespace(profile_id=profile_id, principal_slot=slot,
                                    current_version=version,
                                    auth_kind=("authorization_header" if slot == "primary" else "bearer_token")),
            http_headers=lambda: SimpleNamespace(as_dict=lambda: {
                "Authorization": f"Bearer {slot}-secret",
            }),
        )
        try:
            yield resolved
        finally:
            self.closed.append(profile_id)


CONNECTION, TARGET, AUTHORITY = object(), object(), object()


def test_worker_resolves_two_selected_profiles_and_closes_both():
    async def scenario():
        resolver = _Resolver()
        async with AsyncExitStack() as stack:
            result = await resolve_hunt_authz_principals(
                CONNECTION, context=_context(), target=TARGET,
                authority=AUTHORITY, credential_stack=stack, resolver=resolver,
            )
            assert result.primary_headers == {"Authorization": "Bearer primary-secret"}
            assert result.secondary_headers == {"Authorization": "Bearer secondary-secret"}
            assert (result.primary_profile_id, result.secondary_profile_id) == (PRIMARY, SECONDARY)
            assert "secret" not in repr(result)
        assert resolver.calls == [PRIMARY, SECONDARY]
        assert resolver.closed == [SECONDARY, PRIMARY]
    asyncio.run(scenario())


def test_worker_rejects_changed_profile_version_before_using_headers():
    async def scenario():
        resolver = _Resolver(changed_version=True)
        async with AsyncExitStack() as stack:
            with pytest.raises(CredentialResolutionError, match="changed after admission"):
                await resolve_hunt_authz_principals(
                    CONNECTION, context=_context(), target=TARGET,
                    authority=AUTHORITY, credential_stack=stack, resolver=resolver,
                )
        assert resolver.closed == [SECONDARY, PRIMARY]
    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["form_login", "oauth_password", "query_parameter"])
def test_non_header_profiles_are_rejected_before_decryption(kind):
    async def scenario():
        resolver = _Resolver()
        async with AsyncExitStack() as stack:
            with pytest.raises(CredentialReferenceError, match="immediate HTTP header"):
                await resolve_hunt_authz_principals(
                    CONNECTION, context=_context(kind), target=TARGET,
                    authority=AUTHORITY, credential_stack=stack, resolver=resolver,
                )
        assert resolver.calls == []
    asyncio.run(scenario())


def test_hunt_manifest_shows_required_call_envelope_and_candidate_surfaces():
    row = {"id": HUNT, "target_kind": "web", "target_id": PRIMARY,
           "policy_json": {"allowed_capabilities": ["authz.verify"]},
           "budget_json": {}, "budget_used_json": {}, "context_pack": {}}
    manifest = public_hunt_run(row)
    authz = manifest["capabilities"][0]
    assert authz["call"]["url"] == f"/hunts/{HUNT}/capabilities/authz.verify"
    assert authz["call"]["method"] == "POST"
    assert authz["call"]["request_schema"]["required"] == ["idempotency_key", "input"]
    assert authz["call"]["request_schema"]["properties"]["input"] == authz["input_schema"]
    api_key = HuntCapabilityRequest.model_json_schema()["properties"]["idempotency_key"]
    advertised_key = authz["call"]["request_schema"]["properties"]["idempotency_key"]
    assert {key: api_key[key] for key in ("minLength", "maxLength", "pattern")} == {
        key: advertised_key[key] for key in ("minLength", "maxLength", "pattern")
    }
    assert manifest["candidate_review"]["findings_url"] == (
        f"/findings?hunt_id={HUNT}&include_candidates=true"
    )
    assert manifest["candidate_review"]["investigation_candidates_url"] == (
        f"/investigation/candidates?target_id={PRIMARY}"
    )
