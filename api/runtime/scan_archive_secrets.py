"""The credential secrets a signed-in Scan or a Hunt used, for withholding from its archive export.

A Scan given a credential profile signs in with it, and the target may echo the secret later: a
login page that reflects the submitted password, an account page, a database dump an injection
tool extracts (sqlmap reading a users table returned the Hub account's password in its wire log).
Such an echo is not under a secret-named key, so the payload redaction keeps it. A Hunt's export
already withholds the saved-login secrets it sent in the whole document; a Scan's did not.

This reads the secret material of every credential profile version a Scan (and the shards included
in its export) was admitted with, decrypted API-side only to build the export's scrubber, and never
returned or logged. Values shorter than six characters are left alone: they would match ordinary
text.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Iterable, Mapping

from .credentials import credential_secret_values, parse_credential_secret

try:
    from secret_store import decrypt_secret
except ModuleNotFoundError:  # package import layout
    from api.secret_store import decrypt_secret

MIN_SECRET_CHARS = 6


def _refs(items: Any) -> list[tuple[uuid.UUID, int | None]]:
    """(profile, version) pairs of credential refs: a Scan's ``credential_profile_refs``, a Hunt's
    ``credential_refs`` (both carry ``profile_id`` and ``profile_version``)."""
    if isinstance(items, str):
        try:
            items = json.loads(items)
        except ValueError:
            return []
    found: list[tuple[uuid.UUID, int | None]] = []
    for item in items or ():
        if not isinstance(item, Mapping):
            continue
        try:
            profile = uuid.UUID(str(item.get("profile_id")))
        except (TypeError, ValueError):
            continue
        version = item.get("profile_version")
        found.append((profile, version if type(version) is int and version > 0 else None))
    return found


def _profile_refs(options: Any) -> list[tuple[uuid.UUID, int | None]]:
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except ValueError:
            return []
    return _refs(options.get("credential_profile_refs")) if isinstance(options, Mapping) else []


def secret_values(material: Mapping[str, Any]) -> list[str]:
    """The envelope's secret strings long enough to withhold (shorter ones match ordinary text)."""
    return [value for value in credential_secret_values(material) if len(value) >= MIN_SECRET_CHARS]


async def profile_secrets(conn: Any, refs: Iterable[tuple[uuid.UUID, int | None]]) -> list[str]:
    """The secrets of the credential profile versions ``refs`` name; a ref without its version
    (older records) withholds every version of that profile. API-private."""
    wanted: dict[uuid.UUID, set[int | None]] = {}
    for profile, version in refs:
        wanted.setdefault(profile, set()).add(version)
    found: list[str] = []
    for profile, versions in wanted.items():
        exact = sorted(v for v in versions if v is not None)
        rows = await conn.fetch(
            """SELECT auth_kind, encrypted_secret FROM credential_profile_versions
               WHERE profile_id = $1 AND ($2::boolean OR version = ANY($3::int[]))""",
            profile, None in versions, exact,
        )
        for row in rows:
            try:
                material = parse_credential_secret(row["auth_kind"], decrypt_secret(row["encrypted_secret"]))
            except Exception:  # noqa: BLE001 - an unreadable version adds nothing
                continue
            found.extend(value for value in secret_values(material) if value not in found)
    return found


def _uuids(values: Iterable[Any]) -> list[uuid.UUID]:
    found = []
    for value in values or ():
        try:
            found.append(uuid.UUID(str(value)))
        except (TypeError, ValueError):
            continue
    return found


async def scan_credential_secrets(conn: Any, scan_ids: Iterable[Any]) -> list[str]:
    """Every credential secret the Scans in ``scan_ids`` were admitted with. API-private."""
    ids = _uuids(scan_ids)
    if not ids:
        return []
    refs: list[tuple[uuid.UUID, int | None]] = []
    for row in await conn.fetch("SELECT options FROM scans WHERE id = ANY($1::uuid[])", ids):
        refs.extend(_profile_refs(row["options"]))
    return await profile_secrets(conn, refs)


async def hunt_credential_secrets(conn: Any, hunt_id: Any) -> list[str]:
    """Every credential profile secret a Hunt was admitted with (its context's ``credential_refs``)
    or used (``hunt_credential_uses``, its sign-in sessions). API-private."""
    ids = _uuids([hunt_id])
    if not ids:
        return []
    hunt = ids[0]
    refs: list[tuple[uuid.UUID, int | None]] = []
    context = await conn.fetchval("SELECT context_pack->'credential_refs' FROM hunt_runs WHERE id=$1", hunt)
    refs.extend(_refs(context))
    for row in await conn.fetch(
            """SELECT profile_id, profile_version FROM hunt_credential_uses WHERE hunt_run_id=$1
               UNION SELECT profile_id, profile_version FROM auth_sessions
               WHERE owner_kind='hunt' AND owner_id=$1""", hunt):
        refs.extend(_refs([dict(row)]))
    return await profile_secrets(conn, refs)
