"""Repair targets whose stored host the one canonicalizer now refuses (R3, release audit 2026-10-09).

Before hosts were spelled by ``host_names.canonical_host``, a target URL kept numeric IPv4 text as
typed (``127.1``, ``2852039166``, ``0x7f.0.0.1``, ``010.000.000.001``) and kept IDNA 2003-only
A-labels (``xn--i-7iq.ws``). Those hosts are now refused, so such a target can no longer be
authorized or scanned. This migration runs once:

* a numeric spelling with one reading is rewritten to canonical dotted decimal. The resolver
  (C ``inet_aton``: octal, hex and shortened forms) and PostgreSQL ``inet`` (four decimal parts)
  must agree, or only the resolver reads it. ``127.1`` becomes ``127.0.0.1``, and ``01.02.03.04``
  becomes ``1.2.3.4``. The row keeps its id and history and records ``host_repair`` in its
  metadata. Its standing authorization named the old spelling, so it must be authorized again.
* every other refused host is left as stored and flagged with ``host_canonicalization_review``.
  This covers ``010.0.0.1`` (octal 8.0.0.1 to a resolver, 10.0.0.1 to inet) and IDNA 2003-only
  names. The operator creates the target again with the host they mean; this row keeps its history.
"""
from __future__ import annotations

import json
from typing import Any
import urllib.parse

try:
    from scanner_tools.host_names import HostNameError, canonical_host
except ModuleNotFoundError:  # package import
    from scanner.scanner_tools.host_names import HostNameError, canonical_host

MIGRATION = "target_host_canonical_spelling_v1"
REVIEW_KEY = "host_canonicalization_review"
REPAIR_KEY = "host_repair"


def _number(part: str) -> int | None:
    """One ``inet_aton`` part: 0x hex, leading-zero octal, or decimal."""
    if not part:
        return None
    try:
        if part.startswith("0x"):
            return int(part[2:], 16) if part[2:] else 0
        if len(part) > 1 and part.startswith("0"):
            return int(part, 8)
        return int(part, 10) if part.isdigit() else None
    except ValueError:
        return None


def resolver_reading(text: str) -> str | None:
    """How C ``inet_aton`` reads ``text`` (1 to 4 parts; the last fills the remaining bytes)."""
    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    numbers = [_number(part) for part in parts]
    if any(number is None for number in numbers):
        return None
    *head, last = numbers
    if any(number > 255 for number in head) or last >= 256 ** (5 - len(parts)):
        return None
    value = 0
    for number in head:
        value = value * 256 + number
    value = value * 256 ** (5 - len(parts)) + last
    return ".".join(str((value >> shift) & 255) for shift in (24, 16, 8, 0))


def inet_reading(text: str) -> str | None:
    """How PostgreSQL ``inet`` reads ``text``: four decimal parts, leading zeros ignored."""
    parts = text.split(".")
    if len(parts) != 4 or not all(part.isdigit() and int(part) <= 255 for part in parts):
        return None
    return ".".join(str(int(part)) for part in parts)


def unambiguous_ipv4(text: str) -> str | None:
    """The one address a numeric host spelling names, or None when readers disagree."""
    resolver = resolver_reading(text.lower())
    if resolver is None:
        return None
    inet = inet_reading(text)
    return resolver if inet is None or inet == resolver else None


def _host(url: str) -> tuple[urllib.parse.SplitResult, str] | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
    except ValueError:
        return None
    return (parsed, host) if host else None


def _with_host(parsed: urllib.parse.SplitResult, host: str) -> str:
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


async def repair_target_host_spellings(conn: Any) -> dict[str, list[str]]:
    """Apply once (inside the caller's transaction). Returns ``{"repaired": [...], "flagged": [...]}``
    of target ids."""
    done = {"repaired": [], "flagged": []}
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", MIGRATION):
        return done
    # Host assets first, so a repaired web address joins its repaired asset instead of creating a
    # second one under the canonical spelling.
    rows = await conn.fetch(
        "SELECT id, url, metadata_json FROM targets ORDER BY (url ILIKE 'host://%') DESC, id")
    for row in rows:
        located = _host(str(row["url"] or ""))
        if located is None:
            continue
        parsed, host = located
        try:
            canonical_host(host)
            continue
        except HostNameError as exc:
            refusal = str(exc)
        metadata = row["metadata_json"] or {}
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        address = unambiguous_ipv4(host)
        if address is not None:
            try:
                async with conn.transaction():  # a savepoint: a duplicate canonical row is flagged
                    await conn.execute(
                        "UPDATE targets SET url=$2, metadata_json=$3::jsonb WHERE id=$1",
                        row["id"], _with_host(parsed, address),
                        json.dumps({**metadata, REPAIR_KEY: {
                            "from": host, "to": address,
                            "note": "The numeric spelling had one reading; re-authorize this target.",
                        }}),
                    )
                done["repaired"].append(str(row["id"]))
                continue
            except Exception as exc:  # noqa: BLE001 - the unique canonical key: flag instead
                if type(exc).__name__ != "UniqueViolationError":
                    raise
                refusal = f"{refusal}; {address} is already another target"
        await conn.execute(
            "UPDATE targets SET metadata_json=$2::jsonb WHERE id=$1",
            row["id"], json.dumps({**metadata, REVIEW_KEY: {
                "stored_host": host, "reason": refusal,
                "action": ("Create the target again with the host you mean (dotted-decimal IPv4 or "
                           "an IDNA 2008 name); this target keeps its history and cannot be scanned."),
            }}),
        )
        done["flagged"].append(str(row["id"]))
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", MIGRATION)
    return done


__all__ = ["MIGRATION", "inet_reading", "repair_target_host_spellings", "resolver_reading", "unambiguous_ipv4"]
