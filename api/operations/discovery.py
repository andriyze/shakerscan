"""Targets-page subdomain discovery: admission and the discovery process.

``POST /discovery?root_domain=`` queues ``scanner.py <domain> --subfinder --quick`` on the shared
scan queue. Discovery is passive, but it still has to be tied to a target the person declared
and bounded so one caller cannot flood the queue or third-party sources:

- the domain is a bare host name at or below a registrable domain (``scope.psl.parse_domain``:
  no scheme, path, port, wildcard or address; not a public suffix such as ``co.uk``);
- its apex (eTLD+1) holds a target a person added: not one inserted by discovery, the CT
  monitor, Model Intake, an AI session, AI Gate or an observed device service, nor a ``host``
  row the asset model created as the owner of other rows (archived ones included). A scope
  receipt that names the domain or apex as an allowed root also admits it, but only when the
  receipt is bound to such a declared target (an unbound Arsenal preview admits nothing);
- one discovery per apex is pending or running at a time, and at most
  ``SHAKERSCAN_DISCOVERY_MAX_ACTIVE`` (default 2) across the engine; a run older than
  ``ACTIVE_WINDOW`` no longer holds a slot, so a lost worker cannot block an apex for ever;
- the run records who requested it (``requested_by``). The engine has no per-person identity
  on this route (OSS has one implicit operator; the Enterprise gateway does not forward a
  verified identity), so the value is derived here, never taken from the request: it is
  ``local-operator``. The gateway's own audit names the person.

The checks and the insert run under one transaction-scoped advisory lock, so two concurrent
requests cannot both pass. The worker validates the queued domain again before it spawns
anything, so a job queued before this check fails cleanly instead of running.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import os
from typing import Any
import urllib.parse
import uuid

try:
    from scope.psl import PublicSuffixError, parse_domain, registrable_domain
except ModuleNotFoundError:  # package import (api.operations.discovery)
    from ..scope.psl import PublicSuffixError, parse_domain, registrable_domain

MAX_ACTIVE_ENV = "SHAKERSCAN_DISCOVERY_MAX_ACTIVE"
DEFAULT_MAX_ACTIVE = 2
MAX_ACTIVE_CEILING = 20
ACTIVE_WINDOW = timedelta(hours=2)
ADMISSION_LOCK = 0x5348_4B44_4953_4331  # "SHKDISC1": serializes discovery admission
# Targets inserted by automation do not count as declared by a person.
UNDECLARED_SOURCES = ("subfinder", "gungnir-monitor", "model-intake", "ai_session", "ai_gate",
                      "device-service")
DEFAULT_REQUESTER = "local-operator"


@dataclass
class DiscoveryRefused(Exception):
    status_code: int
    detail: str

    def __str__(self) -> str:
        return self.detail


def max_active() -> int:
    raw = os.environ.get("SHAKERSCAN_DISCOVERY_MAX_ACTIVE", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_ACTIVE
    except ValueError:
        value = DEFAULT_MAX_ACTIVE
    return max(1, min(value, MAX_ACTIVE_CEILING))


def discovery_domain(raw: Any) -> str:
    """The normalized domain to discover, or ``DiscoveryRefused`` (400) naming what is wrong."""
    try:
        return parse_domain(str(raw or ""))
    except PublicSuffixError as exc:
        raise DiscoveryRefused(400, f"Cannot discover subdomains: {exc}.") from exc


def requester() -> str:
    """Who asked, as the engine can establish it: never a caller-supplied value. The single
    place to read a verified principal once the engine has one."""
    return DEFAULT_REQUESTER


# A row counts when a person added it: an active target from no automated source, and for a
# ``host`` row (which the asset model also creates as the owner of web rows) only one with a
# device profile or that owns no rows at all, archived ones included.
_DECLARED = """
    COALESCE({t}.is_active, true)
    AND COALESCE({t}.discovery_source, 'manual') <> ALL($2::text[])
    AND (COALESCE({t}.discovery_source, 'manual') <> 'host'
         OR EXISTS (SELECT 1 FROM target_device_profiles p WHERE p.target_id = {t}.id)
         OR NOT EXISTS (SELECT 1 FROM targets m WHERE m.asset_owner_id = {t}.id))
"""
_DECLARED_TARGETS_SQL = f"""
SELECT t.url FROM targets t
WHERE strpos(lower(t.url), $1) > 0 AND {_DECLARED.format(t='t')}
LIMIT 5000
"""
_DECLARED_SCOPE_SQL = f"""
SELECT EXISTS (
    SELECT 1 FROM scope_receipts s JOIN targets bound ON bound.id = s.target_id
    WHERE s.verdict <> 'blocked'
      AND jsonb_typeof(s.allowed_root_domains) = 'array'
      AND s.allowed_root_domains ?| $1::text[]
      AND {_DECLARED.format(t='bound')}
)
"""


def _host(url: str) -> str:
    text = str(url or "").strip()
    if text.startswith("host://"):
        text = "http://" + text[len("host://"):]
    try:
        host = urllib.parse.urlsplit(text if "://" in text else f"https://{text}").hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


async def _declared(conn: Any, apex: str, domain: str) -> bool:
    """A person-added target lives under ``apex``, or a scope receipt bound to a person-added
    target names ``apex`` or ``domain`` as an allowed root."""
    for row in await conn.fetch(_DECLARED_TARGETS_SQL, apex, list(UNDECLARED_SOURCES)):
        host = _host(row["url"])
        if host == apex or host.endswith("." + apex):
            return True
    return bool(await conn.fetchval(_DECLARED_SCOPE_SQL, sorted({apex, domain}), list(UNDECLARED_SOURCES)))


async def admit_discovery(conn: Any, domain: str, *, requested_by: str) -> uuid.UUID:
    """Record a pending discovery run for ``domain`` after every admission check, or refuse."""
    apex = registrable_domain(domain) or domain
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock($1)", ADMISSION_LOCK)
        if not await _declared(conn, apex, domain):
            raise DiscoveryRefused(403, (
                f"Cannot discover subdomains of {domain}: no target under {apex} has been added. "
                f"Add a target under {apex} first; discovery only expands a domain you declared."
            ))
        active = await conn.fetch(
            """SELECT id, root_domain FROM discovery_runs
               WHERE status IN ('pending', 'running') AND created_at > NOW() - $1::interval""",
            ACTIVE_WINDOW,
        )
        for row in active:
            other = str(row["root_domain"] or "").strip().lower().rstrip(".")
            if (registrable_domain(other) or other) == apex:
                raise DiscoveryRefused(409, (
                    f"Subdomain discovery under {apex} is already queued or running "
                    f"(run {row['id']}, {other}). Wait for it to finish."
                ))
        limit = max_active()
        if len(active) >= limit:
            raise DiscoveryRefused(429, (
                f"{len(active)} subdomain discoveries are already queued or running (the limit is "
                f"{limit}, {MAX_ACTIVE_ENV}). Try again when one finishes."
            ))
        discovery_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO discovery_runs (id, root_domain, status, requested_by)
               VALUES ($1, $2, 'pending', $3)""",
            discovery_id, domain, requested_by,
        )
    return discovery_id


def queued_domain_refusal(root_domain: Any) -> dict[str, Any] | None:
    """The worker's result for a queued domain that fails validation, else None.

    A job queued before admission validation existed (or edited in the queue) fails with an
    ``error`` and the worker spawns nothing. The worker owns the subprocess; this module is
    imported by the API process and must not create child processes (test_api_image_boundary).
    """
    try:
        discovery_domain(root_domain)
    except DiscoveryRefused as exc:
        return {"error": exc.detail, "root_domain": str(root_domain or "")[:300], "subdomains": []}
    return None


__all__ = [
    "ACTIVE_WINDOW", "DEFAULT_MAX_ACTIVE", "DiscoveryRefused", "MAX_ACTIVE_ENV", "admit_discovery",
    "discovery_domain", "max_active", "queued_domain_refusal", "requester",
]
