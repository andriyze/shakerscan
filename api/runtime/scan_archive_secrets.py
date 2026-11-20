"""The credential secrets a signed-in Scan used, for withholding from its archive export.

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

from .credentials import parse_credential_secret

try:
    from secret_store import decrypt_secret
except ModuleNotFoundError:  # package import layout
    from api.secret_store import decrypt_secret

MIN_SECRET_CHARS = 6
SECRET_FIELDS = ("secret", "secondary_secret")


def _profile_refs(options: Any) -> list[tuple[uuid.UUID, int | None]]:
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except ValueError:
            return []
    refs = options.get("credential_profile_refs") if isinstance(options, Mapping) else None
    found: list[tuple[uuid.UUID, int | None]] = []
    for item in refs or ():
        if not isinstance(item, Mapping):
            continue
        try:
            profile = uuid.UUID(str(item.get("profile_id")))
        except (TypeError, ValueError):
            continue
        version = item.get("profile_version")
        found.append((profile, version if type(version) is int and version > 0 else None))
    return found


def secret_values(material: Mapping[str, Any]) -> list[str]:
    """The secret strings of one parsed credential envelope (not its user name or header names)."""
    values = [str(material.get(name) or "") for name in SECRET_FIELDS]
    headers = material.get("custom_headers")
    if isinstance(headers, Mapping):
        values.extend(str(value or "") for value in headers.values())
    elif isinstance(headers, (list, tuple)):
        for header in headers:
            if isinstance(header, Mapping):
                values.append(str(header.get("value") or ""))
    return [value for value in values if len(value) >= MIN_SECRET_CHARS]


async def scan_credential_secrets(conn: Any, scan_ids: Iterable[Any]) -> list[str]:
    """Every credential secret the Scans in ``scan_ids`` were admitted with. API-private."""
    ids = []
    for value in scan_ids or ():
        try:
            ids.append(uuid.UUID(str(value)))
        except (TypeError, ValueError):
            continue
    if not ids:
        return []
    refs: dict[uuid.UUID, set[int | None]] = {}
    for row in await conn.fetch("SELECT options FROM scans WHERE id = ANY($1::uuid[])", ids):
        for profile, version in _profile_refs(row["options"]):
            refs.setdefault(profile, set()).add(version)
    found: list[str] = []
    for profile, versions in refs.items():
        # A ref without its version (older Scans) withholds every version of that profile.
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
