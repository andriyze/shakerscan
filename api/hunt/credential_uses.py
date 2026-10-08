"""One attached credential list per Hunt, and a record of every credential a Hunt uses.

A Hunt may use every credential attached to its target: the target's own credential profiles
and principals, plus profiles shared to it from other targets through a credential grant
(``POST /credential-profiles/{id}/grants``). Credentials selected at Hunt start narrow or
point that list; they never widen it. Nothing unattached is decrypted or used. A credential
never authorizes a destination; the Hunt's authorized set is checked first, as before.

Every use is appended to ``hunt_credential_uses``: the action, the profile id and version,
where the credential came from (``selected``, ``target_own`` or ``shared_from:<target>``) and
the slot it filled. The table holds ids only, never a secret, collection or evidence.

A credential that is not attached is refused with a reason code from
``CREDENTIAL_REFUSAL_CODES``. Live grants and pre-authorization (design note
``docs/hunt-permission-requests.md``, PR E2) turn that refusal into a permission request.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any
import uuid

from fastapi import HTTPException

try:
    from runtime.credential_refs import (
        CredentialReferenceError,
        select_hunt_immediate_principal_reference,
        select_hunt_principal_reference,
        select_hunt_session_principal_reference,
    )
    from runtime.credentials import SSH_CREDENTIAL_KINDS
except ModuleNotFoundError:
    from ..runtime.credential_refs import (
        CredentialReferenceError,
        select_hunt_immediate_principal_reference,
        select_hunt_principal_reference,
        select_hunt_session_principal_reference,
    )
    from ..runtime.credentials import SSH_CREDENTIAL_KINDS


HUNT_CREDENTIAL_USE_SCHEMA = "hunt-credential-use/v1"

# Additive and idempotent: installed on every start by the unified startup migration
# (api/targets/asset_migration.py, after the frozen baseline) and, with the same definition,
# by db/init.sql on a fresh database.
HUNT_CREDENTIAL_USES_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS hunt_credential_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES hunt_actions(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    source TEXT NOT NULL CHECK (
        source IN ('selected','target_own')
        OR source ~ '^shared_from:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    slot TEXT NOT NULL CHECK (slot ~ '^[a-z0-9:_.-]{1,80}$'),
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT hunt_credential_uses_action_slot_unique UNIQUE (action_id, profile_id, slot)
);
CREATE INDEX IF NOT EXISTS idx_hunt_credential_uses_run
    ON hunt_credential_uses(hunt_run_id, used_at, id);
"""

SOURCE_SELECTED = "selected"
SOURCE_TARGET_OWN = "target_own"
_SHARED_SOURCE_RE = re.compile(
    r"^shared_from:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_SLOT_RE = re.compile(r"^[a-z0-9:_.-]{1,80}$")

# Machine-readable refusals. E2 maps the attachable ones to permission requests.
CREDENTIAL_NOT_ATTACHED = "credential_not_attached"
CREDENTIAL_MISSING_FOR_SLOT = "credential_missing_for_slot"
CREDENTIAL_AMBIGUOUS_FOR_SLOT = "credential_ambiguous_for_slot"
CREDENTIAL_VERSION_CHANGED = "credential_version_changed"
CREDENTIAL_KIND_UNSUPPORTED = "credential_kind_unsupported"
CREDENTIAL_CAPABILITY_NOT_GRANTED = "credential_capability_not_granted"
CREDENTIALS_NOT_DISTINCT = "credentials_not_distinct"
CREDENTIAL_SECRET_UNAVAILABLE = "credential_secret_unavailable"
CREDENTIAL_TARGET_MISMATCH = "credential_target_mismatch"
CREDENTIAL_REFUSAL_CODES = frozenset({
    CREDENTIAL_NOT_ATTACHED,
    CREDENTIAL_MISSING_FOR_SLOT,
    CREDENTIAL_AMBIGUOUS_FOR_SLOT,
    CREDENTIAL_VERSION_CHANGED,
    CREDENTIAL_KIND_UNSUPPORTED,
    CREDENTIAL_CAPABILITY_NOT_GRANTED,
    CREDENTIALS_NOT_DISTINCT,
    CREDENTIAL_SECRET_UNAVAILABLE,
    CREDENTIAL_TARGET_MISMATCH,
})
_ATTACH_HINT = (
    "Attach a credential to this target: create one on the target, or share one from another "
    "target with POST /credential-profiles/{id}/grants."
)


class HuntCredentialRefusal(Exception):
    """A Hunt credential refused before anything was decrypted or sent; ``code`` is stable."""

    status_code = 403

    def __init__(
        self,
        code: str,
        message: str,
        *,
        slot: str | None = None,
        profile_id: str | None = None,
    ) -> None:
        if code not in CREDENTIAL_REFUSAL_CODES:
            raise ValueError(f"unknown credential refusal code: {code}")
        # Not "code:slot": the shared redactor masks the value after a credential-like key, which
        # turned the slot name into "***" (D33).
        super().__init__(f"{code} for slot {slot}" if slot else code)
        self.code = code
        self.message = message
        self.slot = slot
        self.profile_id = profile_id

    def public_detail(self) -> dict[str, Any]:
        detail: dict[str, Any] = {
            "error": "hunt_credential_refused",
            "reason_code": self.code,
            "message": self.message,
        }
        if self.slot:
            detail["slot"] = self.slot
        if self.profile_id:
            detail["profile_id"] = self.profile_id
        if self.code in {CREDENTIAL_NOT_ATTACHED, CREDENTIAL_MISSING_FOR_SLOT}:
            detail["attach"] = _ATTACH_HINT
        return detail

    def http_exception(self) -> HTTPException:
        return HTTPException(status_code=self.status_code, detail=self.public_detail())


@dataclass(frozen=True)
class CredentialUse:
    """One credential one Hunt action used: ids only."""

    profile_id: str
    profile_version: int
    source: str
    slot: str

    def __post_init__(self) -> None:
        uuid.UUID(self.profile_id)
        if type(self.profile_version) is not int or self.profile_version < 1:
            raise ValueError("credential use version must be a positive integer")
        if self.source not in {SOURCE_SELECTED, SOURCE_TARGET_OWN} and not _SHARED_SOURCE_RE.fullmatch(
            self.source
        ):
            raise ValueError("credential use source is invalid")
        if not _SLOT_RE.fullmatch(self.slot):
            raise ValueError("credential use slot is invalid")


def attached_source(*, home_target_id: Any, hunt_target_id: Any) -> str:
    """``target_own`` for the target's own credential, ``shared_from:<home>`` for a grant."""
    home = str(uuid.UUID(str(home_target_id)))
    return SOURCE_TARGET_OWN if home == str(uuid.UUID(str(hunt_target_id))) else f"shared_from:{home}"


def hunt_consuming_target_id(run: Mapping[str, Any]) -> str | None:
    value = run.get("device_target_id") or run.get("target_id")
    return str(value) if value else None


async def record_credential_uses(
    conn: Any, *, hunt_id: Any, action_id: Any, uses: Iterable[CredentialUse],
) -> None:
    """Append each use once per action, profile and slot; a replay records nothing new."""
    hunt_uuid = uuid.UUID(str(hunt_id))
    action_uuid = uuid.UUID(str(action_id))
    for use in uses:
        await conn.execute(
            """INSERT INTO hunt_credential_uses (
                   hunt_run_id, action_id, profile_id, profile_version, source, slot
               ) VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT ON CONSTRAINT hunt_credential_uses_action_slot_unique DO NOTHING""",
            hunt_uuid, action_uuid, uuid.UUID(use.profile_id), use.profile_version,
            use.source, use.slot,
        )


async def read_credential_uses(conn: Any, hunt_id: Any, *, limit: int = 2000) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        """SELECT id, action_id, profile_id, profile_version, source, slot, used_at
           FROM hunt_credential_uses WHERE hunt_run_id=$1
           ORDER BY used_at ASC, id ASC LIMIT $2""",
        uuid.UUID(str(hunt_id)), int(limit),
    )
    return [public_credential_use(row) for row in rows]


def public_credential_use(row: Any) -> dict[str, Any]:
    item = dict(row)
    source = str(item.get("source") or "")
    shared_from = source.split(":", 1)[1] if source.startswith("shared_from:") else None
    used_at = item.get("used_at")
    return {
        "schema_version": HUNT_CREDENTIAL_USE_SCHEMA,
        "id": str(item["id"]),
        "action_id": str(item["action_id"]),
        "profile_id": str(item["profile_id"]),
        "profile_version": int(item["profile_version"]),
        "source": source,
        "shared_from_target_id": shared_from,
        "slot": str(item.get("slot") or ""),
        "used_at": used_at.isoformat() if hasattr(used_at, "isoformat") else used_at,
        "secret_values_visible": False,
    }


def _ssh_reference(context: Mapping[str, Any], capability: str) -> dict[str, Any] | None:
    refs = [
        dict(item) for item in context.get("credential_refs") or ()
        if isinstance(item, Mapping) and item.get("principal_slot") == "ssh"
        and item.get("source") == "credential_profiles"
        and item.get("auth_kind") in SSH_CREDENTIAL_KINDS
        and capability in (item.get("allowed_capabilities") or ())
    ]
    return refs[0] if len(refs) == 1 else None


def action_credential_references(
    capability: str, capability_input: Mapping[str, Any], context: Mapping[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    """The ``(slot, reference)`` pairs an action will use, chosen by the executor's own rule.

    Only references selected at Hunt start can reach an action, so every one is ``selected``.
    An input the executor would refuse yields nothing here; the executor still refuses it.
    """
    try:
        if capability in {"http.request", "collections.replay_safe", "collections.replay_active"}:
            reference = select_hunt_principal_reference(
                context, capability_input.get("as_principal"), capability=capability,
            )
            return [(reference["principal_slot"], reference)] if reference else []
        if capability == "auth.session.establish":
            reference = select_hunt_session_principal_reference(
                context, capability_input.get("as_principal"),
            )
            return [(reference["principal_slot"], reference)]
        if capability == "authz.verify" and capability_input.get("primary_principal"):
            return [
                (slot, select_hunt_immediate_principal_reference(context, slot))
                for slot in ("primary", "secondary")
            ]
    except CredentialReferenceError:
        return []
    if capability in {"ssh.connect", "ssh.exec"}:
        reference = _ssh_reference(context, capability)
        return [("ssh", reference)] if reference else []
    return []


async def admit_action_credentials(
    conn: Any,
    *,
    run: Mapping[str, Any],
    capability: str,
    capability_input: Mapping[str, Any],
    context: Mapping[str, Any],
) -> list[CredentialUse]:
    """Refuse a selected credential that is no longer attached; return the uses to record.

    The same rule the worker enforces before decryption (active profile, unexpired, an active
    unrevoked binding for the consuming target, and the version selected at start), checked
    at admission so the refusal carries a reason code and nothing is reserved for it.
    """
    references = action_credential_references(capability, capability_input, context)
    if not references:
        return []
    consuming = hunt_consuming_target_id(run)
    ids = sorted({str(reference["profile_id"]) for _, reference in references})
    rows = await conn.fetch(
        """SELECT p.id, p.current_version
           FROM credential_profiles p
           JOIN credential_profile_bindings b
             ON b.profile_id=p.id AND b.binding_kind='target'
            AND b.binding_id=$2::text AND b.is_active=true AND b.revoked_at IS NULL
           WHERE p.id = ANY($1::uuid[]) AND p.is_active=true
             AND (p.expires_at IS NULL OR p.expires_at > NOW())""",
        [uuid.UUID(value) for value in ids], str(consuming or ""),
    )
    attached = {str(row["id"]): int(row["current_version"]) for row in rows}
    uses: list[CredentialUse] = []
    for slot, reference in references:
        profile_id = str(reference["profile_id"])
        version = int(reference.get("profile_version") or 0)
        if profile_id not in attached:
            raise HuntCredentialRefusal(
                CREDENTIAL_NOT_ATTACHED,
                "The credential selected for this slot is no longer attached to the Hunt's "
                "target (deactivated, expired, or its grant was revoked).",
                slot=slot, profile_id=profile_id,
            )
        if attached[profile_id] != version:
            raise HuntCredentialRefusal(
                CREDENTIAL_VERSION_CHANGED,
                "The credential selected at Hunt start was rotated; start a Hunt with the "
                "current version.",
                slot=slot, profile_id=profile_id,
            )
        uses.append(CredentialUse(profile_id, version, SOURCE_SELECTED, slot))
    return uses


def unattached_reference_refusal(
    refs: Mapping[str, Any], attached_profiles: Sequence[Any],
) -> HuntCredentialRefusal | None:
    """The first Hunt-start reference that names a credential not attached to the target."""
    attached = {str(profile.profile_id) for profile in attached_profiles}
    for role, raw_profile_id in sorted(refs.items()):
        profile_id = str(raw_profile_id or "").strip()
        if profile_id not in attached:
            return HuntCredentialRefusal(
                CREDENTIAL_NOT_ATTACHED,
                f"{role} names a credential that is not attached to this target.",
                slot=role.removesuffix("_credential_profile_id").removesuffix("_credential_id"),
                profile_id=profile_id[:80] or None,
            )
    return None


__all__ = [
    "CREDENTIAL_REFUSAL_CODES",
    "CredentialUse",
    "HUNT_CREDENTIAL_USES_SCHEMA_SQL",
    "HuntCredentialRefusal",
    "action_credential_references",
    "admit_action_credentials",
    "attached_source",
    "public_credential_use",
    "read_credential_uses",
    "record_credential_uses",
    "unattached_reference_refusal",
]
