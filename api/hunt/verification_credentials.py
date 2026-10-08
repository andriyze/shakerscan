"""Hunt verification resolves principals from the Hunt target's attached credential list.

Outside a Hunt, a server-owned workflow proof uses the target's registered principals
(``workflow_principals.resolve_target_principal_contexts``). Inside a Hunt the same proof uses
the attached list (``hunt/credential_uses.py``): the target's own principals and profiles plus
profiles shared to it by an active grant. For each workflow slot (``user1`` is the primary
principal, ``user2`` the secondary):

1. a credential selected at Hunt start for that principal slot is used, and nothing else;
2. otherwise the target's own registered principal for the slot (today's behaviour);
3. otherwise the one attached profile whose principal slot fits. Several fitting profiles
   are refused as ambiguous: select one at Hunt start.

Every choice is checked (attached, active, unexpired, current version, an immediate HTTP kind,
``authz.verify`` granted) before anything is decrypted, and decryption goes through the
target-bound worker store query, so an unattached profile is never decrypted. Each credential
used is recorded in ``hunt_credential_uses`` against the Hunt action.

The Hunt binds this scope around its verifier call (``hunt_credential_scope``); the verifier
code path is shared with non-Hunt callers and consults the scope, so only Hunts change.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid

try:
    from workflow_experiment import WorkflowContractError
    from workflow_principals import workflow_cookie_map, workflow_identity_fingerprint
except ModuleNotFoundError:  # package import in host-side tests
    from ..workflow_experiment import WorkflowContractError
    from ..workflow_principals import workflow_cookie_map, workflow_identity_fingerprint

try:
    from runtime.credential_store import (
        CredentialProfileMetadata,
        CredentialStoreError,
        PostgresCredentialProfileStore,
    )
    from runtime.credentials import (
        CredentialContractError,
        immediate_http_headers,
        parse_credential_secret,
    )
    from secret_store import decrypt_secret
    from serialization import _decode_json_value, row_to_dict
except ModuleNotFoundError:
    from ..runtime.credential_store import (
        CredentialProfileMetadata,
        CredentialStoreError,
        PostgresCredentialProfileStore,
    )
    from ..runtime.credentials import (
        CredentialContractError,
        immediate_http_headers,
        parse_credential_secret,
    )
    from ..secret_store import decrypt_secret
    from ..serialization import _decode_json_value, row_to_dict

try:
    from redaction import is_sensitive_key
except ModuleNotFoundError as exc:
    if exc.name != "redaction":
        raise
    from scanner.redaction import is_sensitive_key

from .credential_uses import (
    CREDENTIAL_AMBIGUOUS_FOR_SLOT,
    CREDENTIAL_CAPABILITY_NOT_GRANTED,
    CREDENTIAL_KIND_UNSUPPORTED,
    CREDENTIAL_MISSING_FOR_SLOT,
    CREDENTIAL_NOT_ATTACHED,
    CREDENTIAL_SECRET_UNAVAILABLE,
    CREDENTIAL_TARGET_MISMATCH,
    CREDENTIAL_VERSION_CHANGED,
    CREDENTIALS_NOT_DISTINCT,
    SOURCE_SELECTED,
    SOURCE_TARGET_OWN,
    CredentialUse,
    HuntCredentialRefusal,
    attached_source,
    record_credential_uses,
)


# Workflow slots and the credential-profile principal slot each one is filled from.
WORKFLOW_PROFILE_SLOTS = {"user1": "primary", "user2": "secondary"}
VERIFIER_CAPABILITY = "authz.verify"
# Kinds that become an Authorization header or a cookie jar without a login exchange: the
# two forms the workflow runtime (and its browser steps) applies to a principal.
VERIFIER_AUTH_KINDS = frozenset({"authorization_header", "bearer_token", "basic_auth", "cookie"})


class HuntVerificationCredentialRefused(HuntCredentialRefusal, WorkflowContractError):
    """A Hunt verification credential refusal that existing workflow guards also understand."""

    status_code = 422


@dataclass(frozen=True)
class HuntCredentialScope:
    hunt_id: uuid.UUID
    action_id: uuid.UUID
    target_kind: str
    target_id: uuid.UUID | None
    credential_refs: tuple[Mapping[str, Any], ...] = field(default=())

    @classmethod
    def for_action(
        cls, run: Mapping[str, Any], context: Mapping[str, Any], action_id: Any,
    ) -> "HuntCredentialScope":
        target = run.get("target_id") or run.get("device_target_id")
        return cls(
            hunt_id=uuid.UUID(str(run["id"])),
            action_id=uuid.UUID(str(action_id)),
            target_kind=str(run.get("target_kind") or "web"),
            target_id=uuid.UUID(str(target)) if target else None,
            credential_refs=tuple(
                dict(item) for item in context.get("credential_refs") or ()
                if isinstance(item, Mapping)
            ),
        )


_SCOPE: ContextVar[HuntCredentialScope | None] = ContextVar("hunt_credential_scope", default=None)


@contextmanager
def hunt_credential_scope(scope: HuntCredentialScope) -> Iterator[HuntCredentialScope]:
    token = _SCOPE.set(scope)
    try:
        yield scope
    finally:
        _SCOPE.reset(token)


def current_hunt_credential_scope() -> HuntCredentialScope | None:
    return _SCOPE.get()


@dataclass(frozen=True)
class _Selection:
    slot: str
    profile: CredentialProfileMetadata
    source: str
    principal: Mapping[str, Any] | None


def _refuse(code: str, message: str, *, slot: str | None = None, profile_id: str | None = None):
    return HuntVerificationCredentialRefused(code, message, slot=slot, profile_id=profile_id)


def _principal_slots(row: Mapping[str, Any]) -> set[str]:
    slots = {str(row.get("auth_state") or "").strip().lower()}
    if str(row.get("role") or "").strip().lower() == "admin":
        slots.add("admin")
    tenant = str(row.get("tenant_id") or "").strip().lower()
    if tenant:
        slots.add(f"tenant:{tenant}")
    return slots


def _unexpired(profile: CredentialProfileMetadata, now: datetime) -> bool:
    expires_at = profile.expires_at
    if expires_at is None:
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at > now


def _use_slot(slot: str) -> str:
    return WORKFLOW_PROFILE_SLOTS.get(slot, slot)


def _check_usable(selection: _Selection) -> None:
    profile = selection.profile
    if profile.auth_kind not in VERIFIER_AUTH_KINDS:
        raise _refuse(
            CREDENTIAL_KIND_UNSUPPORTED,
            f"A {profile.auth_kind} credential needs a login exchange; verification needs a "
            "header, bearer, basic or cookie credential for this slot.",
            slot=selection.slot, profile_id=profile.profile_id,
        )
    if VERIFIER_CAPABILITY not in profile.allowed_capabilities:
        raise _refuse(
            CREDENTIAL_CAPABILITY_NOT_GRANTED,
            f"The credential for this slot does not allow {VERIFIER_CAPABILITY}.",
            slot=selection.slot, profile_id=profile.profile_id,
        )


async def _select(
    conn: Any,
    scope: HuntCredentialScope,
    slots: Sequence[str],
    store: PostgresCredentialProfileStore,
) -> list[_Selection]:
    now = datetime.now(timezone.utc)
    attached = {
        profile.profile_id: profile
        for profile in await store.list_profiles(
            conn, target_kind=scope.target_kind, target_id=scope.target_id,
        )
        if profile.is_active and _unexpired(profile, now)
    }
    principal_rows = [
        row_to_dict(row) for row in await conn.fetch(
            """SELECT p.id AS principal_id, p.role, p.tenant_id, p.auth_state,
                      p.metadata_json AS principal_metadata, cp.id AS profile_id,
                      cp.metadata_json AS profile_metadata
               FROM target_principals p
               JOIN target_credential_profiles cp
                 ON cp.target_id = p.target_id
                AND lower(cp.name) = lower(p.credential_profile)
               WHERE p.target_id = $1 AND p.is_active = true
               ORDER BY p.updated_at DESC""",
            scope.target_id,
        )
    ]
    # A principal counts only while its credential is attached (active, unexpired, bound),
    # the same filter the registered-principal resolver applies.
    own_principals = [row for row in principal_rows if str(row["profile_id"]) in attached]
    selected: dict[str, list[Mapping[str, Any]]] = {}
    for ref in scope.credential_refs:
        if ref.get("source") == "credential_profiles" and ref.get("principal_slot") in {"primary", "secondary"}:
            selected.setdefault(str(ref["principal_slot"]), []).append(ref)
    selections: list[_Selection] = []
    for slot in slots:
        profile_slot = WORKFLOW_PROFILE_SLOTS.get(slot)
        picks = selected.get(profile_slot or "", [])
        if picks:
            if len(picks) > 1:
                raise _refuse(
                    CREDENTIAL_AMBIGUOUS_FOR_SLOT,
                    f"Several credentials were selected for the {profile_slot} principal.",
                    slot=slot,
                )
            profile_id = str(picks[0].get("profile_id") or "")
            profile = attached.get(profile_id)
            if profile is None:
                raise _refuse(
                    CREDENTIAL_NOT_ATTACHED,
                    f"The credential selected for the {profile_slot} principal is not attached "
                    "to this target (deactivated, expired, or its grant was revoked).",
                    slot=slot, profile_id=profile_id or None,
                )
            if profile.current_version != int(picks[0].get("profile_version") or 0):
                raise _refuse(
                    CREDENTIAL_VERSION_CHANGED,
                    "The credential selected at Hunt start was rotated; start a Hunt with the "
                    "current version.",
                    slot=slot, profile_id=profile_id,
                )
            principal = next(
                (row for row in own_principals if str(row["profile_id"]) == profile_id), None,
            )
            selection = _Selection(slot, profile, SOURCE_SELECTED, principal)
        else:
            own = [row for row in own_principals if slot in _principal_slots(row)]
            if len(own) > 1:
                raise _refuse(
                    CREDENTIAL_AMBIGUOUS_FOR_SLOT,
                    f"Several registered principals of this target fill {slot}.",
                    slot=slot,
                )
            if own:
                selection = _Selection(
                    slot, attached[str(own[0]["profile_id"])], SOURCE_TARGET_OWN, own[0],
                )
            else:
                fitting = [
                    profile for profile in attached.values()
                    if profile_slot and profile.principal_slot == profile_slot
                    and profile.auth_kind in VERIFIER_AUTH_KINDS
                    and VERIFIER_CAPABILITY in profile.allowed_capabilities
                ]
                if not fitting:
                    raise _refuse(
                        CREDENTIAL_MISSING_FOR_SLOT,
                        f"No credential attached to this target fills {slot}"
                        + (f" (a {profile_slot} principal)" if profile_slot else "") + ".",
                        slot=slot,
                    )
                if len(fitting) > 1:
                    raise _refuse(
                        CREDENTIAL_AMBIGUOUS_FOR_SLOT,
                        f"Several attached credentials fill the {profile_slot} principal; select "
                        f"one with {profile_slot}_credential_profile_id when starting the Hunt.",
                        slot=slot,
                    )
                profile = fitting[0]
                selection = _Selection(
                    slot, profile,
                    attached_source(home_target_id=profile.target_id, hunt_target_id=scope.target_id),
                    None,
                )
        _check_usable(selection)
        selections.append(selection)
    if len(selections) > 1:
        seen: dict[str, str] = {}
        for selection in selections:
            if selection.profile.profile_id in seen:
                raise _refuse(
                    CREDENTIALS_NOT_DISTINCT,
                    f"{seen[selection.profile.profile_id]} and {selection.slot} resolve to the same "
                    "credential; a cross-principal proof needs two distinct attached credentials.",
                    slot=selection.slot, profile_id=selection.profile.profile_id,
                )
            seen[selection.profile.profile_id] = selection.slot
    return selections


def _context(selection: _Selection, material: Mapping[str, Any] | None) -> dict[str, Any]:
    principal = selection.principal or {}
    principal_metadata = _decode_json_value(principal.get("principal_metadata")) or {}
    raw_refs = (
        principal_metadata.get("captured_refs")
        if isinstance(principal_metadata, dict) and isinstance(principal_metadata.get("captured_refs"), dict)
        else {}
    )
    context: dict[str, Any] = {
        "principal_id": str(principal["principal_id"]) if principal.get("principal_id") else None,
        "profile_id": selection.profile.profile_id,
        "profile_version": selection.profile.current_version,
        "credential_source": selection.source,
        "role": principal.get("role"),
        "tenant_id": principal.get("tenant_id"),
        "captured_refs": {
            str(key): str(value)
            for key, value in raw_refs.items()
            if not is_sensitive_key(str(key)) and value not in (None, "")
        },
        "headers": {},
        "cookies": {},
        "identity_fingerprint": None,
    }
    if material is None:
        return context
    if selection.profile.auth_kind == "cookie":
        secret = str(material.get("secret") or "")
        context["cookies"] = workflow_cookie_map(secret)
        identity_value, identity_kind = secret, "cookie"
    else:
        authorization = immediate_http_headers(material).get("Authorization") or ""
        context["headers"] = {"Authorization": authorization}
        identity_value, identity_kind = authorization, "authorization_header"
    if not context["headers"].get("Authorization") and not context["cookies"]:
        raise _refuse(
            CREDENTIAL_SECRET_UNAVAILABLE,
            "The credential for this slot holds no usable header or cookie.",
            slot=selection.slot, profile_id=selection.profile.profile_id,
        )
    context["identity_fingerprint"] = workflow_identity_fingerprint(
        principal.get("principal_metadata"), principal.get("profile_metadata"),
        identity_value, identity_kind,
    )
    return context


async def resolve_hunt_workflow_principal_contexts(
    conn: Any,
    scope: HuntCredentialScope,
    target_uuid: Any,
    used_slots: set[str],
    *,
    select_only: bool = False,
    store: PostgresCredentialProfileStore | None = None,
    decryptor: Callable[[Any], Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Resolve each used workflow slot from the attached list, and record what was used.

    ``select_only`` returns the chosen principals without decrypting or recording anything:
    the proof builder needs only their owned object references, before approval is checked.
    """
    if scope.target_id is None or str(target_uuid) != str(scope.target_id):
        raise _refuse(
            CREDENTIAL_TARGET_MISMATCH,
            "Hunt verification credentials resolve only for the Hunt's own target.",
        )
    slots = sorted(set(used_slots) - {"anonymous"})
    if not slots:
        return {}
    repository = store or PostgresCredentialProfileStore()
    selections = await _select(conn, scope, slots, repository)
    if select_only:
        return {selection.slot: _context(selection, None) for selection in selections}
    decrypt = decryptor or decrypt_secret
    contexts: dict[str, dict[str, Any]] = {}
    for selection in selections:
        try:
            # Target-bound: the store returns ciphertext only for a profile attached to this
            # target (own or an active grant) that allows the verifier capability.
            stored = await repository.load_for_worker(
                conn, profile_id=selection.profile.profile_id,
                target_kind=scope.target_kind, target_id=scope.target_id,
                capability=VERIFIER_CAPABILITY,
            )
        except CredentialStoreError as exc:
            raise _refuse(
                CREDENTIAL_NOT_ATTACHED,
                "The credential for this slot is no longer attached to this target.",
                slot=selection.slot, profile_id=selection.profile.profile_id,
            ) from exc
        if stored.metadata.current_version != selection.profile.current_version:
            raise _refuse(
                CREDENTIAL_VERSION_CHANGED,
                "The credential for this slot was rotated during resolution.",
                slot=selection.slot, profile_id=selection.profile.profile_id,
            )
        try:
            envelope = str(decrypt(stored.encrypted_secret) or "")
            if not envelope or envelope.startswith("enc:fernet:"):
                raise CredentialContractError("credential secret could not be decrypted")
            material = parse_credential_secret(stored.metadata.auth_kind, envelope)
            contexts[selection.slot] = _context(selection, material)
        except HuntVerificationCredentialRefused:
            raise
        except Exception as exc:
            raise _refuse(
                CREDENTIAL_SECRET_UNAVAILABLE,
                "The credential for this slot could not be decrypted.",
                slot=selection.slot, profile_id=selection.profile.profile_id,
            ) from exc
    await record_credential_uses(
        conn, hunt_id=scope.hunt_id, action_id=scope.action_id,
        uses=[
            CredentialUse(
                selection.profile.profile_id, selection.profile.current_version,
                selection.source, _use_slot(selection.slot),
            )
            for selection in selections
        ],
    )
    return contexts


__all__ = [
    "HuntCredentialScope",
    "HuntVerificationCredentialRefused",
    "VERIFIER_CAPABILITY",
    "current_hunt_credential_scope",
    "hunt_credential_scope",
    "resolve_hunt_workflow_principal_contexts",
]
