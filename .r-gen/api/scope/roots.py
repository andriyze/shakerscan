"""Scope roots (``allowed_root_domains``) that never span registrants.

A root admits its whole subtree, so it must not be a public suffix (``co.uk``) or have one below
it (``amazonaws.com``). Engines before 2.8.2 stored two-label roots (``co.uk`` for
``shop.example.co.uk``) in ``targets.root_domain`` and in queued scope guards; these helpers
drop such roots and recompute the root from the host instead, so an upgraded target keeps
working under ``example.co.uk`` rather than failing or widening.
"""
from __future__ import annotations

from collections.abc import Iterable
import json
from typing import Any

from .psl import registrable_domain, spans_public_suffix


def _name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def root_for_host(host: Any) -> str:
    """The root for a target host: its registrable domain when that covers one registrant,
    else the host itself (``console.amazonaws.com``, an address, ``localhost``)."""
    host = _name(host)
    root = registrable_domain(host)
    return root if root and not spans_public_suffix(root) else host


def binding_roots(stored: Iterable[Any] | None, stored_root: Any, host: Any) -> tuple[str, ...]:
    """``allowed_root_domains`` for a target binding.

    ``stored`` (a guard's roots) wins when any of them is safe. Otherwise the target's stored
    ``root_domain`` is used, recomputed from ``host`` when it is a legacy spanning root; with no
    stored root, the exact ``host`` (as before). A root that would still span is never returned.
    """
    kept = tuple(dict.fromkeys(
        root for root in (_name(item) for item in stored or ()) if root and not spans_public_suffix(root)
    ))
    if kept:
        return kept
    legacy = _name(stored_root)
    if legacy:
        root = legacy if not spans_public_suffix(legacy) else root_for_host(host)
    else:
        root = _name(host)
    return (root,) if root and not spans_public_suffix(root) else ()


def _url_host(url: Any) -> str:
    import urllib.parse

    text = str(url or "").strip()
    if text.startswith("host://"):
        text = "http://" + text[len("host://"):]
    try:
        return _name(urllib.parse.urlsplit(text if "://" in text else f"https://{text}").hostname)
    except ValueError:
        return ""


# Why the startup migration archived a CT-monitor target (metadata_json key and value).
CT_OTHER_REGISTRANT_KEY = "archived_reason"
CT_OTHER_REGISTRANT = "ct_monitor_other_registrant"

# Targets whose root says what this install covers: not the CT monitor's own targets, nor the host
# row the inventory creates under every web target (``attach_target_asset_owner``; a host a person
# added is marked ``declared``). Either kind only repeats the root of the target it came from.
ROOT_SOURCE_SQL = """discovery_source IS DISTINCT FROM 'gungnir-monitor'
    AND NOT (discovery_source IS NOT DISTINCT FROM 'host'
             AND metadata_json->>'declared' IS DISTINCT FROM 'true')"""


async def recompute_spanning_target_roots(conn: Any) -> int:
    """Startup migration: every ``targets.root_domain`` that spans registrants (a legacy two-label
    ``co.uk``, or ``azurecontainerapps.io`` before the list rules marked it shared) becomes the
    root its URL has now (``example.co.uk``), with ``is_root`` to match.

    A target the CT monitor added under such a root is a stranger's host unless its new root is
    the root of a target a person or a Scan added: it is archived (inactive, Continuous ASM off,
    schedules paused, ``archived_reason`` recorded), never deleted, so its history stays and a
    person can restore it. Idempotent; returns the number of rows changed."""
    stored = [row["root_domain"] for row in await conn.fetch(
        "SELECT DISTINCT root_domain FROM targets WHERE COALESCE(root_domain, '') <> ''"
    )]
    spanning = [root for root in stored if spans_public_suffix(root)]
    if not spanning:
        return 0
    updates = []
    from_monitor = []  # (id, new root, stored root) of active CT-monitor targets
    owned: set[str] = set()  # new roots of active targets a person or a Scan added
    for row in await conn.fetch(
        f"""SELECT id, url, root_domain, is_active,
                   discovery_source IS NOT DISTINCT FROM 'gungnir-monitor' AS from_monitor,
                   ({ROOT_SOURCE_SQL}) AS root_source
            FROM targets WHERE root_domain = ANY($1::text[])""", spanning,
    ):
        host = _url_host(row["url"])
        root = root_for_host(host) if host else ""
        if not root or root == row["root_domain"]:
            continue
        updates.append((row["id"], root, host in {root, f"www.{root}"}))
        if row["is_active"] and row["from_monitor"]:
            from_monitor.append((row["id"], root, row["root_domain"]))
        elif row["is_active"] and row["root_source"]:
            owned.add(root)
    owned |= {row["root_domain"] for row in await conn.fetch(
        f"""SELECT DISTINCT root_domain FROM targets
            WHERE is_active AND COALESCE(root_domain, '') <> '' AND {ROOT_SOURCE_SQL}"""
    ) if not spans_public_suffix(row["root_domain"])}
    archive = [
        (target_id, json.dumps({CT_OTHER_REGISTRANT_KEY: CT_OTHER_REGISTRANT, "archived_from_root": stored_root}))
        for target_id, root, stored_root in from_monitor if root not in owned
    ]
    if updates:
        await conn.executemany("UPDATE targets SET root_domain = $2, is_root = $3 WHERE id = $1", updates)
    if archive:
        await conn.executemany(
            """UPDATE schedules SET is_active = false, next_run_at = NULL, updated_at = NOW()
               WHERE target_id = $1 AND (is_active OR next_run_at IS NOT NULL)""",
            [(target_id,) for target_id, _meta in archive],
        )
        await conn.executemany(
            """UPDATE targets SET is_active = false, asm_enabled = false, updated_at = NOW(),
                   metadata_json = COALESCE(metadata_json, '{}'::jsonb) || $2::jsonb
               WHERE id = $1""",
            archive,
        )
        # The host row the inventory made for each one goes with it when nothing else is on it.
        await conn.execute(
            """UPDATE targets host SET is_active = false, asm_enabled = false, updated_at = NOW()
               WHERE host.is_active AND host.discovery_source = 'host'
                 AND host.metadata_json->>'declared' IS DISTINCT FROM 'true'
                 AND EXISTS (SELECT 1 FROM targets app WHERE app.asset_owner_id = host.id
                             AND app.id = ANY($1::uuid[]))
                 AND NOT EXISTS (SELECT 1 FROM targets other WHERE other.asset_owner_id = host.id
                                 AND other.is_active)""",
            [target_id for target_id, _meta in archive],
        )
        print(f"[scope] Archived {len(archive)} CT-monitor target(s) whose registrable domain is "
              "not one of this install's roots", flush=True)
    return len(updates)


def monitored_root(stored_root: Any, url: Any) -> str:
    """The CT-monitor root for a target: its stored root, or (for a legacy spanning root) the
    root its URL has now; "" when neither covers one registrant."""
    root = _name(stored_root)
    if root and not spans_public_suffix(root):
        return root
    host = _url_host(url)
    root = root_for_host(host) if host else ""
    return root if root and not spans_public_suffix(root) else ""


__all__ = [
    "CT_OTHER_REGISTRANT", "CT_OTHER_REGISTRANT_KEY", "ROOT_SOURCE_SQL", "binding_roots", "monitored_root", "recompute_spanning_target_roots", "root_for_host",
]
