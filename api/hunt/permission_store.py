"""Hunt permission requests, grants, pre-authorizations and their append-only audit.

A request exists only because a server refusal on the allowable list raised it
(``permission_reasons.reason_kind``). There is no create route. Its subject holds only values
the server resolved (target id, host, port, profile id and version, capability, dimension) and its
words come from the templates below, never from the agent or a target response.

Requests are deduplicated by subject while pending (a partial unique index), at most
``MAX_PENDING_PER_HUNT`` are pending at once, and each expires after 24 hours or at the Hunt's
duration deadline, whichever comes first. A pending request never changes the Hunt's status.
Every request, decision, automatic grant, use, expiry, withdrawal and revocation is appended to
``hunt_permission_events`` with its actor and source; no row there holds a secret, collection or
evidence, only ids and digests.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any
import uuid

from .credential_uses import live_credential_grants
from .permission_bounds import Bounds, bound_hosts, legacy_host_changes, merge, parse_bounds, stored_bounds
from .permission_reasons import (
    KIND_BUDGET_RAISE,
    KIND_CAPABILITY_ENABLE,
    KIND_CREDENTIAL_USE,
    KIND_PREAUTHORIZATION,
    KIND_SSH_EXEC,
    KIND_SSH_HOST_TRUST,
    KIND_TARGET_AUTHORIZE,
    PERMISSION_KINDS,
)

PERMISSION_REQUEST_SCHEMA = "hunt-permission-request/v1"
MAX_PENDING_PER_HUNT = 20
REQUEST_LIFETIME = timedelta(hours=24)
# After a person denies a subject, the same question is not asked again in that Hunt for this long
# (D46: an agent re-asked under a new key 20 s after a denial). The question is the subject's stable
# identity (``cooldown_identity``), not its digest: a destination's resolved addresses or a credential
# slot the agent chose do not make it a new question.
DENIAL_COOLDOWN = timedelta(minutes=15)
REQUEST_STATUSES = ("pending", "granted", "denied", "expired", "withdrawn")
DECISION_VIA = ("preauthorization", "terminal_stepup", "approver_session", "ui_session", "local_confirm")
EVENTS = ("requested", "decided", "auto_granted", "used", "expired", "withdrawn", "revoked", "preauthorized")
PREAUTHORIZATION_PROOFS = ("stepup", "launch_stepup", "local", "request_approval")
HUNT_ACTION_STATUSES = (
    "reserved", "running", "completed", "blocked", "cancelled", "failed", "partial",
    "awaiting_permission",
)
_UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


# Additive and idempotent: installed on every start by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definitions, by db/init.sql.
HUNT_PERMISSION_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS hunt_preauthorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    bounds_json JSONB NOT NULL,
    bounds_digest TEXT NOT NULL CHECK (bounds_digest ~ '^[0-9a-f]{{64}}$'),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    proof TEXT NOT NULL CHECK (proof IN ({_quoted(PREAUTHORIZATION_PROOFS)})),
    source_request_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hunt_preauthorizations_run
    ON hunt_preauthorizations(hunt_run_id, created_at);
CREATE TABLE IF NOT EXISTS hunt_permission_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ({_quoted(PERMISSION_KINDS)})),
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z_]{{2,63}}$'),
    subject_json JSONB NOT NULL,
    subject_digest TEXT NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{{64}}$'),
    display_json JSONB NOT NULL DEFAULT '{{}}'::jsonb,
    action_id UUID,
    capability_name TEXT,
    input_digest TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ({_quoted(REQUEST_STATUSES)})),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    decided_by TEXT,
    decision_via TEXT CHECK (decision_via IS NULL OR decision_via IN ({_quoted(DECISION_VIA)})),
    decision_scope TEXT CHECK (decision_scope IS NULL OR decision_scope IN ('hunt','target')),
    decision_choice_json JSONB,
    decision_key_sha256 TEXT,
    grant_id UUID,
    CHECK (expires_at > created_at),
    CHECK ((status = 'pending') = (decided_at IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_hunt_permission_requests_pending_subject
    ON hunt_permission_requests(hunt_run_id, subject_digest) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_hunt_permission_requests_run
    ON hunt_permission_requests(hunt_run_id, created_at, id);
CREATE TABLE IF NOT EXISTS hunt_permission_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    request_id UUID NOT NULL REFERENCES hunt_permission_requests(id) ON DELETE CASCADE,
    preauthorization_id UUID REFERENCES hunt_preauthorizations(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ({_quoted(PERMISSION_KINDS)})),
    subject_json JSONB NOT NULL,
    subject_digest TEXT NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{{64}}$'),
    scope TEXT NOT NULL CHECK (scope IN ('hunt','target')),
    effect_json JSONB NOT NULL DEFAULT '{{}}'::jsonb,
    persisted_ref TEXT,
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    CONSTRAINT hunt_permission_grants_request_unique UNIQUE (request_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_permission_grants_live
    ON hunt_permission_grants(hunt_run_id, kind) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS hunt_permission_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    request_id UUID,
    grant_id UUID,
    action_id UUID,
    event TEXT NOT NULL CHECK (event IN ({_quoted(EVENTS)})),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 80),
    detail_json JSONB NOT NULL DEFAULT '{{}}'::jsonb,
    -- clock_timestamp(): several events of one transaction keep their order.
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS idx_hunt_permission_events_run
    ON hunt_permission_events(hunt_run_id, created_at, id);
CREATE OR REPLACE FUNCTION hunt_permission_events_append_only() RETURNS trigger AS $events$
BEGIN
    -- Deleting the Hunt cascades here from a referential trigger (depth > 1); nothing else may
    -- change or remove an audit row.
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'hunt_permission_events is append-only';
END
$events$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS hunt_permission_events_append_only ON hunt_permission_events;
CREATE TRIGGER hunt_permission_events_append_only
    BEFORE UPDATE OR DELETE ON hunt_permission_events
    FOR EACH ROW EXECUTE FUNCTION hunt_permission_events_append_only();
DO $permission_status$
BEGIN
    -- A refused, grantable action is parked under its idempotency key.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='hunt_actions'::regclass AND conname='hunt_actions_status_check'
          AND pg_get_constraintdef(oid) LIKE '%awaiting_permission%'
    ) THEN
        ALTER TABLE hunt_actions DROP CONSTRAINT IF EXISTS hunt_actions_status_check;
        ALTER TABLE hunt_actions ADD CONSTRAINT hunt_actions_status_check CHECK (
            status IN ({_quoted(HUNT_ACTION_STATUSES)})
        );
    END IF;
END
$permission_status$;
"""


def canonical_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


def _iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


# ---------------------------------------------------------------------------------------------
# Rendering. Every word a person reads comes from these templates and server-resolved values.

def _destination_host(value: Any) -> str:
    """``permission_subjects.destination_host``: lowercase IDNA ASCII, as the scope guard."""
    try:
        from action_scope import _canonical_host
    except ModuleNotFoundError:
        from ..action_scope import _canonical_host
    return _canonical_host(value)


def _host_port(subject: Mapping[str, Any]) -> str:
    # The ASCII (punycode) form, so a look-alike spelling cannot pass for another host.
    host = _destination_host(subject.get("host"))
    port = subject.get("port")
    return f"{host}:{port}" if port else host


def _host_forms(value: Any) -> dict[str, str]:
    """The canonical ASCII host (what is matched and connected to) and its Unicode form."""
    try:
        from action_scope import host_forms
    except ModuleNotFoundError:
        from ..action_scope import host_forms
    return host_forms(_destination_host(value))


def _unicode_forms_text(value: Any) -> str:
    """``Canonical ASCII host: xn--... (Unicode: ...). `` for a host with a Unicode form."""
    forms = _host_forms(value)
    if forms["unicode"] == forms["ascii"]:
        return ""
    return (f"Canonical ASCII host (matched and connected to): {forms['ascii']} "
            f"(Unicode: {_label(forms['unicode'], 253)}). ")


def _unicode_note(value: Any) -> str:
    """`` (Unicode: straße.example)`` after an ASCII host that has another form; else empty."""
    forms = _host_forms(value)
    return f" (Unicode: {_label(forms['unicode'], 253)})" if forms["unicode"] != forms["ascii"] else ""


def _label(value: Any, limit: int = 80) -> str:
    """An operator-entered name, shown as a quoted value: printable, one line, bounded."""
    text = " ".join("".join(char if char.isprintable() else " " for char in str(value or "")).split())
    text = text.replace("'", "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _credential_text(subject: Mapping[str, Any], display: Mapping[str, Any]) -> tuple[str, str]:
    """D47: the credential and its home target by name, kind and host; the ids follow. Only
    names and kinds the server read from the profile and target rows, never a secret."""
    version = f"v{subject.get('profile_version')}"
    name, auth_kind = _label(display.get("profile_name")), _label(display.get("auth_kind"), 40)
    credential = (f"'{name}' ({', '.join(item for item in (auth_kind, version) if item)})"
                  if name else f"{subject.get('profile_id')} ({version})")
    home_name = _label(display.get("home_target_name"))
    raw_home = subject.get("home_host")
    home_host = _label(_destination_host(raw_home) or raw_home, 253) if raw_home else ""
    if home_host and _destination_host(raw_home):
        home_host += _unicode_note(raw_home)
    home = (f"target '{home_name}'" if home_name else "another target") + (f" ({home_host})" if home_host else "")
    return credential, home


def render(kind: str, subject: Mapping[str, Any], display: Mapping[str, Any]) -> dict[str, Any]:
    """Title, explanation, effect and choices, from the subject alone."""
    remember = False
    if kind == KIND_BUDGET_RAISE:
        title = f"Raise {subject.get('dimension')} for this Hunt"
        explanation = (
            f"The Hunt reached its {subject.get('dimension')} limit of "
            f"{subject.get('limit')}. The refused action needs a total of "
            f"{display.get('needed_total')}."
        )
        effect = (
            f"Sets the total {subject.get('dimension')} to {display.get('proposed_total')} "
            "(or the total you choose) through one budget amendment, and resumes the Hunt if "
            "it stopped on this limit. Nothing already run is repeated."
        )
    elif kind == KIND_CAPABILITY_ENABLE:
        flag = str(subject.get("flag") or "")
        title = f"Allow {subject.get('capability')} in this Hunt" + (f" ({flag})" if flag else "")
        explanation = (
            f"{subject.get('capability')} needs "
            + (f"the {flag} permission, which this Hunt was started without."
               if flag else "to be enabled for this Hunt; it was not selected at start.")
        )
        effect = (
            "Turns on " + (f"{flag} " if flag else "") + f"for this Hunt only and enables "
            f"{subject.get('capability')}. A budget dimension this needs is set to the profile "
            "default. The target's standing authorization is required."
        )
    elif kind == KIND_TARGET_AUTHORIZE:
        # Remember records the standing authorization of the Hunt's own target, so it applies to
        # another service on the Hunt's host only; another host is a separate target.
        remember = bool(subject.get("same_host"))
        # The title names only the canonical ASCII host (what is matched and connected to), so a
        # look-alike spelling never leads; the explanation adds its Unicode form beside it.
        title = f"Authorize {_host_port(subject)} for this Hunt"
        verdict = f"Scope verdict: {subject.get('scope_verdict') or 'not blocked'}."
        forms = _unicode_forms_text(subject.get("host"))
        if remember:
            explanation = (
                f"The action targets {subject.get('scheme')}://{_host_port(subject)}, another "
                f"service on the Hunt's host {subject.get('host')} that this Hunt may not reach yet. "
                + forms + verdict
            )
            effect = (
                f"Adds {subject.get('origin')} to this Hunt's authorized services. Remember records "
                "the target's standing authorization."
            )
        else:
            addresses = ", ".join(str(item) for item in subject.get("addresses") or ()) or "no address"
            explanation = (
                f"The action targets {subject.get('scheme')}://{_host_port(subject)}, another host: "
                f"{subject.get('host')} is not the Hunt's target, and this Hunt may not reach it yet. "
                f"It resolves to {addresses}, every one public. " + forms + verdict
            )
            effect = (
                f"Adds {subject.get('origin')} to this Hunt's authorized destinations, for this Hunt "
                f"only and pinned to {addresses}. No credential is ever sent to it. It cannot be "
                "remembered: another host is a separate target."
            )
    elif kind == KIND_CREDENTIAL_USE:
        remember = True
        credential, home = _credential_text(subject, display)
        title = f"Use credential {credential} in this Hunt"
        explanation = (
            f"The {subject.get('slot')} credential {credential} belongs to {home} and is not "
            f"attached to this Hunt's target (credential {subject.get('profile_id')}, target "
            f"{subject.get('home_target_id')})."
        )
        effect = (
            "Lets this Hunt use exactly this credential version in that slot. It never "
            "authorizes a destination. Remember shares it with this target (a credential grant)."
        )
    elif kind == KIND_PREAUTHORIZATION:
        allow = [str(item) for item in subject.get("allow") or ()]
        if subject.get("reapproval_of"):
            title = "Pre-authorize these host bounds again, for the hosts they name"
            explanation = (
                "These bounds were pre-authorized for this Hunt before hosts were spelled with IDNA "
                "2008/UTS #46, and were stored as "
                + ", ".join(_label(item, 253) for item in subject.get("previously_stored_as") or ())
                + " under IDNA 2003. They are withheld and cover nothing until you approve them again: "
                + ", ".join(allow) + "."
            )
            effect = (
                "Requests inside these bounds are granted as they arise, for the hosts named below "
                "only. Your other pre-authorized bounds and grants are unchanged."
            )
        else:
            title = "Pre-authorize the bounds the agent proposed for this Hunt"
            explanation = "The Hunt was started through the agent with these allow bounds: " + ", ".join(
                allow
            ) + "."
            if subject.get("supersedes"):
                explanation += (
                    f" This replaces request {_label(subject.get('supersedes'), 40)}, recorded before "
                    "hosts were spelled with IDNA 2008/UTS #46; approve it for the hosts named below."
                )
            effect = (
                "Requests inside these bounds are granted as they arise, as if you had started the "
                "Hunt with them. Hard limits are never covered."
            )
        hosts = bound_hosts(allow)
        if hosts:
            # Each host bound by the canonical ASCII host it covers (IDNA 2008/UTS #46).
            explanation += " Hosts covered: " + "; ".join(
                f"{_label(item['bound'], 300)} covers {_label(item['display'], 600)}" for item in hosts
            ) + "."
    elif kind in {KIND_SSH_EXEC, KIND_SSH_HOST_TRUST}:
        title = f"{kind} for this Hunt"
        explanation = "SSH permission requests are not raised in this release."
        effect = "None."
    else:  # pragma: no cover - the kind is a closed enum
        raise ValueError(f"unknown permission kind: {kind}")
    return {
        "title": title,
        "explanation": explanation,
        "effect": effect,
        "remember_supported": remember,
        "choices": ["allow", "deny"],
        "scopes": ["hunt", "target"] if remember else ["hunt"],
    }


def public_request(row: Any) -> dict[str, Any]:
    item = dict(row)
    subject = _json(item.get("subject_json"), {})
    display = _json(item.get("display_json"), {})
    shown = _public_request(item, subject, display)
    replacement = display.get("superseded_by")
    if display.get("superseded_reason"):
        # A proposal recorded under IDNA 2003 that names a host IDNA 2008 spells differently:
        # withdrawn, and (when its hosts are valid) replaced by the same bounds for the hosts
        # they name, so the person still approves in one terminal step.
        shown["superseded_by"] = replacement
        if replacement:
            shown["title"] = f"Replaced by request {replacement}: run shakerscan approve {replacement}"
            shown["approve_command"] = f"shakerscan approve {replacement}"
        else:
            shown["title"] = "Withdrawn: these proposed bounds name a host that is not valid"
            shown["approve_command"] = None
        shown["explanation"] = f"{shown['explanation']} {display['superseded_reason']}"
    return shown


def _public_request(item: Mapping[str, Any], subject: Mapping[str, Any], display: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": PERMISSION_REQUEST_SCHEMA,
        "id": str(item["id"]),
        "hunt_id": str(item["hunt_run_id"]),
        "kind": item["kind"],
        "reason_code": item["reason_code"],
        "status": item["status"],
        "subject": subject,
        "subject_digest": item["subject_digest"],
        **{key: value for key, value in display.items() if key in {"needed_total", "proposed_total"}},
        **render(str(item["kind"]), subject, display),
        **_request_hosts(str(item["kind"]), subject),
        "action_id": str(item["action_id"]) if item.get("action_id") else None,
        "capability_name": item.get("capability_name"),
        "created_at": _iso(item.get("created_at")),
        "expires_at": _iso(item.get("expires_at")),
        "decided_at": _iso(item.get("decided_at")),
        "decided_by": item.get("decided_by"),
        "decision_via": item.get("decision_via"),
        "decision_scope": item.get("decision_scope"),
        "grant_id": str(item["grant_id"]) if item.get("grant_id") else None,
        "approve_command": f"shakerscan approve {item['id']}",
    }


def _request_hosts(kind: str, subject: Mapping[str, Any]) -> dict[str, Any]:
    """The hosts a request names, canonical ASCII beside Unicode, for clients that show them."""
    if kind == KIND_TARGET_AUTHORIZE and subject.get("host"):
        return {"destination": {**_host_forms(subject.get("host")), "port": subject.get("port"),
                                "scheme": subject.get("scheme")}}
    if kind == KIND_CREDENTIAL_USE and subject.get("home_host"):
        return {"home_host": _host_forms(subject.get("home_host"))}
    if kind == KIND_PREAUTHORIZATION:
        return {"bound_hosts": bound_hosts(str(item) for item in subject.get("allow") or ())}
    return {}


def public_grant(row: Any) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": str(item["id"]),
        "hunt_id": str(item["hunt_run_id"]),
        "request_id": str(item["request_id"]),
        "preauthorization_id": str(item["preauthorization_id"]) if item.get("preauthorization_id") else None,
        "kind": item["kind"],
        "subject": _json(item.get("subject_json"), {}),
        "scope": item["scope"],
        "effect": _json(item.get("effect_json"), {}),
        "persisted_ref": item.get("persisted_ref"),
        "created_by": item["created_by"],
        "created_at": _iso(item.get("created_at")),
        "revoked_at": _iso(item.get("revoked_at")),
        "revoked_by": item.get("revoked_by"),
    }


def public_preauthorization(row: Any) -> dict[str, Any]:
    """A stored pre-authorization. Rows loaded by ``load_preauthorizations`` also name the legacy
    (IDNA 2003) host bounds withheld until a person approves them again."""
    item = dict(row)
    bounds = _json(item.get("bounds_json"), {})
    loaded = item.get("_stored")
    legacy = [entry.public() for entry in loaded.legacy] if loaded is not None else []
    if item.get("_reapproved_by"):
        legacy = []
    return {
        "id": str(item["id"]),
        "bounds": bounds,
        "bounds_digest": item["bounds_digest"],
        "host_canonicalization": bounds.get("host_canonicalization") or "idna2003-legacy",
        "reapproval_required": legacy,
        "reapproved_by": item.get("_reapproved_by"),
        "created_by": item["created_by"],
        "proof": item["proof"],
        "created_at": _iso(item.get("created_at")),
    }


# ---------------------------------------------------------------------------------------------
# Events.

async def record_event(
    conn: Any, *, hunt_id: Any, event: str, actor: str, source: str,
    request_id: Any = None, grant_id: Any = None, action_id: Any = None,
    detail: Mapping[str, Any] | None = None,
) -> None:
    if event not in EVENTS:
        raise ValueError(f"unknown permission event: {event}")
    await conn.execute(
        """INSERT INTO hunt_permission_events
               (hunt_run_id, request_id, grant_id, action_id, event, actor, source, detail_json)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)""",
        uuid.UUID(str(hunt_id)),
        uuid.UUID(str(request_id)) if request_id else None,
        uuid.UUID(str(grant_id)) if grant_id else None,
        uuid.UUID(str(action_id)) if action_id else None,
        event, str(actor)[:200] or "system", str(source)[:80] or "server",
        json.dumps(dict(detail or {}), sort_keys=True),
    )


# ---------------------------------------------------------------------------------------------
# Requests.

def hunt_deadline(run: Mapping[str, Any]) -> datetime | None:
    """The Hunt's duration deadline: created_at plus its max_duration_seconds."""
    created = run.get("created_at")
    budget = _json(run.get("budget_json"), {})
    seconds = int((budget or {}).get("max_duration_seconds") or 0)
    if not isinstance(created, datetime) or seconds <= 0:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created + timedelta(seconds=seconds)


def request_expiry(run: Mapping[str, Any], now: datetime) -> datetime | None:
    """24 h, or the Hunt's duration deadline if earlier; None when that deadline has passed."""
    expiry = now + REQUEST_LIFETIME
    deadline = hunt_deadline(run)
    if deadline is not None:
        if deadline <= now:
            return None
        expiry = min(expiry, deadline)
    return expiry


async def expire_due(conn: Any, hunt_id: Any) -> int:
    """Settle every pending request past its expiry; audited, idempotent."""
    rows = await conn.fetch(
        """UPDATE hunt_permission_requests
           SET status='expired', decided_at=NOW()
           WHERE hunt_run_id=$1 AND status='pending' AND expires_at <= NOW()
           RETURNING id""",
        uuid.UUID(str(hunt_id)),
    )
    for row in rows:
        await record_event(conn, hunt_id=hunt_id, request_id=row["id"], event="expired",
                           actor="system", source="expiry")
    return len(rows)


def subject_digest(kind: str, subject: Mapping[str, Any]) -> str:
    return canonical_digest({"kind": kind, **dict(subject)})


def cooldown_identity(kind: str, subject: Mapping[str, Any]) -> dict[str, Any]:
    """What a person said no to, for the denial cooldown (D46).

    The full subject digest still dedupes pending requests and binds every decision. The cooldown
    keys on what stays the same question: a destination is its scheme, host and port, whatever
    addresses the host resolves to this time (a CDN or round-robin host answers differently from
    one lookup to the next, and every answer used to make a fresh request after a denial); a
    credential is its profile, whichever slot the agent asked to use it in. Any other kind keys on
    its whole subject, which holds only values the server chose.
    """
    if kind == KIND_TARGET_AUTHORIZE:
        port = subject.get("port")
        return {
            "kind": kind, "scheme": str(subject.get("scheme") or "").lower(),
            "host": _destination_host(subject.get("host")),
            "port": int(port) if str(port or "").isdigit() else str(port or ""),
        }
    if kind == KIND_CREDENTIAL_USE:
        return {"kind": kind, "profile_id": str(subject.get("profile_id") or "")}
    return {"kind": kind, **dict(subject)}


async def recent_denial(conn: Any, hunt_id: Any, kind: str, subject: Mapping[str, Any]) -> dict[str, Any] | None:
    """The latest denial of the same question (``cooldown_identity``) in this Hunt within
    ``DENIAL_COOLDOWN``, or None."""
    wanted = cooldown_identity(kind, subject)
    rows = await conn.fetch(
        """SELECT id, subject_json, decided_at, decided_at + $3::interval AS ask_again_after
           FROM hunt_permission_requests
           WHERE hunt_run_id=$1 AND kind=$2 AND status='denied'
             AND decided_at > NOW() - $3::interval
           ORDER BY decided_at DESC, id DESC""",
        uuid.UUID(str(hunt_id)), kind, DENIAL_COOLDOWN,
    )
    for row in rows:
        if cooldown_identity(kind, _json(row["subject_json"], {})) == wanted:
            return {key: row[key] for key in ("id", "decided_at", "ask_again_after")}
    return None


async def raise_request(
    conn: Any,
    *,
    run: Mapping[str, Any],
    kind: str,
    reason_code: str,
    subject: Mapping[str, Any],
    display: Mapping[str, Any] | None = None,
    action_id: Any = None,
    capability_name: str | None = None,
    input_digest: str | None = None,
    actor: str = "agent",
    source: str = "refusal",
) -> tuple[dict[str, Any] | None, bool]:
    """Create the pending request for ``subject`` or return the one already pending.

    Returns ``(row, created)``; ``(None, False)`` when the per-Hunt cap is reached or the Hunt's
    duration deadline has passed, in which case the refusal stays plain. The caller holds the Hunt
    row lock.
    """
    if kind not in PERMISSION_KINDS:
        raise ValueError(f"unknown permission kind: {kind}")
    hunt_uuid = uuid.UUID(str(run["id"]))
    await expire_due(conn, hunt_uuid)
    digest = subject_digest(kind, subject)
    existing = await conn.fetchrow(
        """SELECT * FROM hunt_permission_requests
           WHERE hunt_run_id=$1 AND subject_digest=$2 AND status='pending'""",
        hunt_uuid, digest,
    )
    display = dict(display or {})
    if existing is not None:
        old = _json(existing["display_json"], {})
        if display and display != old:
            merged = {**old, **{
                key: max(int(old.get(key) or 0), int(value)) if isinstance(value, int) else value
                for key, value in display.items()
            }}
            existing = await conn.fetchrow(
                "UPDATE hunt_permission_requests SET display_json=$2::jsonb WHERE id=$1 RETURNING *",
                existing["id"], json.dumps(merged, sort_keys=True),
            )
        return dict(existing), False
    pending = await conn.fetchval(
        "SELECT COUNT(*) FROM hunt_permission_requests WHERE hunt_run_id=$1 AND status='pending'",
        hunt_uuid,
    )
    now = datetime.now(timezone.utc)
    expires = request_expiry(run, now)
    if int(pending or 0) >= MAX_PENDING_PER_HUNT or expires is None:
        return None, False
    row = await conn.fetchrow(
        """INSERT INTO hunt_permission_requests
               (hunt_run_id, kind, reason_code, subject_json, subject_digest, display_json,
                action_id, capability_name, input_digest, created_at, expires_at)
           VALUES ($1,$2,$3,$4::jsonb,$5,$6::jsonb,$7,$8,$9,$10,$11)
           RETURNING *""",
        hunt_uuid, kind, reason_code, json.dumps(dict(subject), sort_keys=True), digest,
        json.dumps(display, sort_keys=True),
        uuid.UUID(str(action_id)) if action_id else None, capability_name, input_digest,
        now, expires,
    )
    await record_event(
        conn, hunt_id=hunt_uuid, request_id=row["id"], action_id=action_id, event="requested",
        actor=actor, source=source,
        detail={"kind": kind, "reason_code": reason_code, "subject_digest": digest},
    )
    return dict(row), True


async def load_request(conn: Any, hunt_id: Any, request_id: Any, *, for_update: bool = False) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        "SELECT * FROM hunt_permission_requests WHERE id=$1 AND hunt_run_id=$2"
        + (" FOR UPDATE" if for_update else ""),
        uuid.UUID(str(request_id)), uuid.UUID(str(hunt_id)),
    )
    return dict(row) if row is not None else None


async def list_requests(conn: Any, hunt_id: Any, *, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        """SELECT * FROM hunt_permission_requests
           WHERE hunt_run_id=$1 AND ($2::text IS NULL OR status=$2)
           ORDER BY created_at ASC, id ASC LIMIT $3""",
        uuid.UUID(str(hunt_id)), status, int(limit),
    )
    return [public_request(row) for row in rows]


async def list_grants(conn: Any, hunt_id: Any) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT * FROM hunt_permission_grants WHERE hunt_run_id=$1 ORDER BY created_at ASC, id ASC",
        uuid.UUID(str(hunt_id)),
    )
    return [public_grant(row) for row in rows]


async def list_events(conn: Any, hunt_id: Any, *, limit: int = 500) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        """SELECT * FROM hunt_permission_events WHERE hunt_run_id=$1
           ORDER BY created_at ASC, id ASC LIMIT $2""",
        uuid.UUID(str(hunt_id)), int(limit),
    )
    return [{
        "id": str(row["id"]), "event": row["event"], "actor": row["actor"], "source": row["source"],
        "request_id": str(row["request_id"]) if row["request_id"] else None,
        "grant_id": str(row["grant_id"]) if row["grant_id"] else None,
        "action_id": str(row["action_id"]) if row["action_id"] else None,
        "detail": _json(row["detail_json"], {}), "created_at": _iso(row["created_at"]),
    } for row in rows]


async def pending_summary(conn: Any, hunt_id: Any) -> list[dict[str, Any]]:
    """The compact pending list ``GET /hunts/{id}`` carries."""
    return [
        {key: item[key] for key in ("id", "kind", "reason_code", "title", "expires_at", "approve_command")}
        for item in await list_requests(conn, hunt_id, status="pending")
    ]


# ---------------------------------------------------------------------------------------------
# Pre-authorization.

async def record_preauthorization(
    conn: Any, *, hunt_id: Any, bounds: Bounds, created_by: str, proof: str,
    source_request_id: Any = None,
) -> dict[str, Any]:
    if proof not in PREAUTHORIZATION_PROOFS:
        raise ValueError("pre-authorization proof is invalid")
    row = await conn.fetchrow(
        """INSERT INTO hunt_preauthorizations
               (hunt_run_id, bounds_json, bounds_digest, created_by, proof, source_request_id)
           VALUES ($1,$2::jsonb,$3,$4,$5,$6) RETURNING *""",
        uuid.UUID(str(hunt_id)), json.dumps(bounds.public(), sort_keys=True), bounds.digest(),
        str(created_by)[:200], proof,
        uuid.UUID(str(source_request_id)) if source_request_id else None,
    )
    await record_event(
        conn, hunt_id=hunt_id, request_id=source_request_id, event="preauthorized",
        actor=created_by, source=proof, detail={"preauthorization_id": str(row["id"]),
                                                "bounds_digest": bounds.digest()},
    )
    return dict(row)


async def _approved_allow(conn: Any, row: Mapping[str, Any]) -> list[str] | None:
    """The ``--allow`` strings a legacy pre-authorization row was parsed from, or None."""
    if row.get("source_request_id"):
        request = await conn.fetchrow(
            "SELECT subject_json FROM hunt_permission_requests WHERE id=$1 AND hunt_run_id=$2",
            row["source_request_id"], row["hunt_run_id"],
        )
        allow = _json(request["subject_json"], {}).get("allow") if request is not None else None
    else:
        run = await conn.fetchrow("SELECT context_pack FROM hunt_runs WHERE id=$1", row["hunt_run_id"])
        context = _json(run["context_pack"], {}) if run is not None else {}
        allow = (context.get("hunt_start_contract") or {}).get("allow")
    return [str(item) for item in allow] if isinstance(allow, list) else None


async def load_preauthorizations(conn: Any, hunt_id: Any) -> list[dict[str, Any]]:
    """The Hunt's pre-authorization rows, each with ``_stored`` (``StoredBounds``).

    A row stored before hosts were spelled with IDNA 2008/UTS #46 has no
    ``host_canonicalization`` marker. It is re-derived from the strings the person approved: a
    host bound whose IDNA 2003 and 2008 encodings differ (or whose source cannot be confirmed) is
    withheld -- it matches nothing and is reported for re-approval -- and an identical one stands.
    """
    rows = [dict(row) for row in await conn.fetch(
        "SELECT * FROM hunt_preauthorizations WHERE hunt_run_id=$1 ORDER BY created_at, id",
        uuid.UUID(str(hunt_id)),
    )]
    reapproved: dict[str, str] = {}
    for row in rows:
        value = _json(row["bounds_json"], {})
        legacy = value.get("host_canonicalization") is None
        source = await _approved_allow(conn, row) if legacy else None
        row["_stored"] = stored_bounds(value, source_allow=source)
        if not legacy and row.get("source_request_id"):
            request = await conn.fetchrow(
                "SELECT subject_json FROM hunt_permission_requests WHERE id=$1", row["source_request_id"])
            original = _json(request["subject_json"], {}).get("reapproval_of") if request is not None else None
            if original:
                reapproved[str(original)] = str(row["id"])
    for row in rows:
        # The person approved this legacy row's withheld bounds again: nothing is left to re-approve.
        row["_reapproved_by"] = reapproved.get(str(row["id"]))
    return rows


async def offer_reapproval(conn: Any, run: Mapping[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Offer the person each legacy row's withheld host bounds as one pending request.

    Only bounds whose original spelling is known and valid (``encoding_changed``) are offered, as
    the person wrote them; approving (``shakerscan approve <id>``) records a new pre-authorization
    under IDNA 2008/UTS #46 beside the old row, so nothing else the person granted is lost. Each
    set is offered once per Hunt: a request already raised for it (pending or decided) is not
    raised again. The caller holds the Hunt row lock.
    """
    offered: list[dict[str, Any]] = []
    for row in rows:
        loaded = row.get("_stored")
        if row.get("_reapproved_by"):
            continue
        # A changed bound is offered as the person wrote it (now spelled with IDNA 2008/UTS #46);
        # an unconfirmed one as the ASCII host it was stored as, shown with its Unicode form.
        changed = [item for item in (loaded.legacy if loaded is not None else ())
                   if item.reason in {"encoding_changed", "source_unconfirmed"}]
        if not changed:
            continue
        allow = list(dict.fromkeys(item.bound for item in changed))
        subject = {
            "allow": allow, "bounds_digest": parse_bounds(allow).digest(),
            "reapproval_of": str(row["id"]),
            "previously_stored_as": list(dict.fromkeys(str(item.stored_as) for item in changed)),
        }
        seen = await conn.fetchval(
            "SELECT 1 FROM hunt_permission_requests WHERE hunt_run_id=$1 AND subject_digest=$2 LIMIT 1",
            uuid.UUID(str(run["id"])), subject_digest(KIND_PREAUTHORIZATION, subject),
        )
        if seen:
            continue
        request, created = await raise_request(
            conn, run=run, kind=KIND_PREAUTHORIZATION, reason_code="preauthorization_reapproval",
            subject=subject, actor="system", source="host_encoding_reapproval",
        )
        if request is not None and created:
            offered.append(request)
    return offered


async def supersede_legacy_proposals(conn: Any, run: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Replace each pending agent proposal recorded under IDNA 2003 whose hosts IDNA 2008 spells
    differently. The old request is withdrawn (it names scope the person never saw) and the same
    ``--allow`` strings are raised again with their IDNA 2008/UTS #46 digest, so the person still
    approves in one terminal step. A proposal naming a host strict processing refuses is withdrawn
    with the reason. The caller holds the Hunt row lock."""
    replaced: list[dict[str, Any]] = []
    rows = await conn.fetch(
        """SELECT * FROM hunt_permission_requests
           WHERE hunt_run_id=$1 AND kind=$2 AND status='pending' ORDER BY created_at, id""",
        uuid.UUID(str(run["id"])), KIND_PREAUTHORIZATION,
    )
    for row in rows:
        subject = _json(row["subject_json"], {})
        if subject.get("reapproval_of") or subject.get("supersedes"):
            continue
        allow = [str(item) for item in subject.get("allow") or ()]
        try:
            bounds: Bounds | None = parse_bounds(allow)
        except ValueError:
            bounds = None
        if bounds is not None and subject.get("bounds_digest") == bounds.digest():
            continue
        changed = legacy_host_changes(allow)
        if bounds is not None and not changed:
            continue  # recorded under IDNA 2003, but every host encodes alike: the same scope
        fresh = None
        if bounds is not None:
            fresh, _created = await raise_request(
                conn, run=run, kind=KIND_PREAUTHORIZATION, reason_code="preauthorization_proposed",
                subject={"allow": allow, "bounds_digest": bounds.digest(), "supersedes": str(row["id"])},
                actor="system", source="host_encoding_superseded",
            )
        reason = " ".join(item.finding() for item in changed) or (
            "A host these bounds name is not a valid IDNA 2008/UTS #46 name.")
        display = {**_json(row["display_json"], {}),
                   "superseded_by": str(fresh["id"]) if fresh is not None else None,
                   "superseded_reason": reason}
        await conn.execute(
            """UPDATE hunt_permission_requests SET status='withdrawn', decided_at=NOW(), display_json=$2::jsonb
               WHERE id=$1 AND status='pending'""",
            row["id"], json.dumps(display, sort_keys=True),
        )
        await record_event(conn, hunt_id=run["id"], request_id=row["id"], event="withdrawn",
                           actor="system", source="host_encoding_superseded",
                           detail={"superseded_by": display["superseded_by"]})
        if fresh is not None:
            replaced.append(fresh)
    return replaced


async def reconcile_host_encoding(conn: Any, run: Mapping[str, Any]) -> None:
    """Offer legacy (IDNA 2003) host bounds back and replace legacy proposals, so the withheld
    bounds, their re-approval request and any replacement appear together. Hunt row locked."""
    await offer_reapproval(conn, run, await load_preauthorizations(conn, run["id"]))
    await supersede_legacy_proposals(conn, run)


async def reconcile_host_encoding_if_needed(conn: Any, hunt_id: Any) -> None:
    """``reconcile_host_encoding`` for a reader, in its own transaction, only when this Hunt has a
    legacy pre-authorization row or a pending proposal (both rare); otherwise no lock is taken."""
    hunt_uuid = uuid.UUID(str(hunt_id))
    needed = await conn.fetchval(
        """SELECT EXISTS(SELECT 1 FROM hunt_preauthorizations
                          WHERE hunt_run_id=$1 AND NOT (bounds_json ? 'host_canonicalization'))
               OR EXISTS(SELECT 1 FROM hunt_permission_requests
                          WHERE hunt_run_id=$1 AND kind=$2 AND status='pending')""",
        hunt_uuid, KIND_PREAUTHORIZATION,
    )
    if not needed:
        return
    async with conn.transaction():
        run = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_uuid)
        if run is not None:
            await reconcile_host_encoding(conn, dict(run))


async def hunt_bounds(conn: Any, hunt_id: Any) -> tuple[Bounds, list[dict[str, Any]]]:
    rows = await load_preauthorizations(conn, hunt_id)
    return merge([row["_stored"].bounds for row in rows]), rows


def covering_preauthorization(rows: list[dict[str, Any]], predicate: Any) -> dict[str, Any] | None:
    """The first stored pre-authorization whose own bounds satisfy ``predicate``."""
    for row in rows:
        stored = row.get("_stored") or stored_bounds(_json(row["bounds_json"], {}))
        if predicate(stored.bounds):
            return row
    return None


__all__ = [
    "DECISION_VIA", "DENIAL_COOLDOWN", "EVENTS", "HUNT_ACTION_STATUSES", "HUNT_PERMISSION_SCHEMA_SQL",
    "MAX_PENDING_PER_HUNT", "PREAUTHORIZATION_PROOFS", "REQUEST_STATUSES", "canonical_digest", "cooldown_identity",
    "covering_preauthorization", "expire_due", "hunt_bounds", "hunt_deadline", "list_events",
    "list_grants", "list_requests", "live_credential_grants", "load_preauthorizations", "load_request",
    "offer_reapproval", "pending_summary", "reconcile_host_encoding", "reconcile_host_encoding_if_needed",
    "supersede_legacy_proposals",
    "public_grant", "public_preauthorization", "public_request", "raise_request", "record_event",
    "recent_denial", "record_preauthorization", "render", "request_expiry", "subject_digest",
]
