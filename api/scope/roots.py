"""Scope roots (``allowed_root_domains``) that never span registrants.

A root admits its whole subtree, so it must not be a public suffix (``co.uk``) or have one below
it (``amazonaws.com``). Engines before 2.8.2 stored two-label roots (``co.uk`` for
``shop.example.co.uk``) in ``targets.root_domain`` and in queued scope guards; these helpers
drop such roots and recompute the root from the host instead, so an upgraded target keeps
working under ``example.co.uk`` rather than failing or widening.
"""
from __future__ import annotations

from collections.abc import Iterable
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


async def recompute_spanning_target_roots(conn: Any) -> int:
    """Startup migration: every ``targets.root_domain`` that spans registrants (a legacy two-label
    ``co.uk``) becomes the root its URL has now (``example.co.uk``), with ``is_root`` to match.
    Idempotent; returns the number of rows changed."""
    stored = [row["root_domain"] for row in await conn.fetch(
        "SELECT DISTINCT root_domain FROM targets WHERE COALESCE(root_domain, '') <> ''"
    )]
    spanning = [root for root in stored if spans_public_suffix(root)]
    if not spanning:
        return 0
    updates = []
    for row in await conn.fetch(
        "SELECT id, url, root_domain FROM targets WHERE root_domain = ANY($1::text[])", spanning,
    ):
        host = _url_host(row["url"])
        root = root_for_host(host) if host else ""
        if root and root != row["root_domain"]:
            updates.append((row["id"], root, host in {root, f"www.{root}"}))
    if updates:
        await conn.executemany(
            "UPDATE targets SET root_domain = $2, is_root = $3 WHERE id = $1", updates,
        )
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
    "binding_roots", "monitored_root", "recompute_spanning_target_roots", "root_for_host",
]
