"""Wildcard DNS among discovered names: detect it, and drop names that are only its echo.

A zone with ``*.dev.example.com`` answers every name below ``dev.example.com``. Passive sources
that collect names seen anywhere (and DNS datasets built by resolving guesses) then hand back
dozens of names that all resolve to the wildcard's answer, and discovery inserted them as targets
until its 100-row limit was full of junk.

Before discovered names under an apex are inserted, the planner resolves a few random labels
(``<16 hex>.<parent>``) for the apex and for each distinct parent the names sit under, bounded in
number. A parent whose random labels resolve publishes a wildcard; its answer set (addresses, and the
first CNAME hop the random labels alias) is recorded. A discovered name is then suppressed when
its own answer is exactly that answer -- the same first CNAME hop, or, without a CNAME, the same
address set -- under its immediate, judged parent, and nothing but DNS speaks for it. A name a
certificate names (Certificate Transparency via Gungnir, crt.sh, or a CT-backed subfinder source)
is kept: someone requested a certificate for it, which a wildcard echo never does.

This module only decides; the lookups are made by ``target_resolution`` with its resolver,
concurrency, per-lookup timeout and overall deadline. Probes are DNS questions for names under
the apex being discovered and never open a connection to any answer, so the destination policy
(private networks, address classes) is untouched: it still judges each name at Scan admission.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
import secrets
from typing import Any

# Random labels per parent, and how many parents (the apex first) are probed per run.
PROBES_PER_PARENT = 2
PARENT_LIMIT = 8
# Bound what a run records about one wildcard.
_RECORDED_ANSWERS = 10

# Sources whose evidence is a certificate rather than a DNS answer. Subfinder reports the
# upstream source of each name (``subfinder:<source>``); only its CT-backed sources count.
CERTIFICATE_SOURCES = frozenset({
    "gungnir", "gungnir-monitor", "crtsh", "certspotter", "censys", "digitorus", "facebook",
})


def _source_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text.split(":", 1)[1] if text.startswith("subfinder:") else text


def has_certificate_evidence(sources: Iterable[Any] | None) -> bool:
    """Whether any source that found the name is a certificate, not a DNS answer."""
    return any(_source_name(source) in CERTIFICATE_SOURCES for source in sources or ())


def _parent(name: str) -> str:
    return name.split(".", 1)[1] if "." in name else ""


def probe_parents(root: str, names: Iterable[str], *, limit: int = PARENT_LIMIT) -> list[str]:
    """The apex, then the parents most discovered names sit under, at most ``limit`` in all."""
    counts: Counter[str] = Counter()
    for name in names:
        parent = _parent(name)
        if parent and parent != root and parent.endswith("." + root):
            counts[parent] += 1
    ordered = [root, *(parent for parent, _count in counts.most_common())]
    return ordered[: max(1, int(limit))]


def probe_names(
    parents: Iterable[str], *, per_parent: int = PROBES_PER_PARENT,
    token: Callable[[int], str] = secrets.token_hex,
) -> list[tuple[str, str]]:
    """``(parent, probe name)`` pairs: random 16-hex labels no one has published."""
    return [
        (parent, f"{token(8)}.{parent}")
        for parent in parents
        for _index in range(max(1, int(per_parent)))
    ]


def wildcard_answers(
    probes: Iterable[tuple[str, str]],
    answers: Mapping[str, tuple[str, list[str], str | None]],
    *, resolves: str, no_address: str, unknown_hop: str = "?",
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Wildcard answer sets by parent, and the parents whose probes were judged.

    A parent is judged when every probe got an answer from the resolver (an address or a clear
    "no record") and every alias's first hop was read; a fault or the deadline leaves it
    unjudged, which suppresses nothing. The answer set is the union over the probes, so a
    wildcard that rotates its addresses is described completely.
    """
    by_parent: dict[str, list[tuple[str, list[str], str | None]]] = {}
    for parent, probe in probes:
        by_parent.setdefault(parent, []).append(answers.get(probe, ("unknown", [], None)))
    wildcards: dict[str, dict[str, Any]] = {}
    judged: set[str] = set()
    for parent, results in by_parent.items():
        resolved = [item for item in results if item[0] == resolves and item[1]]
        if any(item[2] == unknown_hop for item in resolved):
            continue
        if resolved:
            wildcards[parent] = {
                "parent": parent,
                "addresses": sorted({address for item in resolved for address in item[1]}),
                "cnames": sorted({item[2] for item in resolved if item[2]}),
                "probes": len(results),
                "probes_resolved": len(resolved),
            }
            judged.add(parent)
        elif all(item[0] == no_address for item in results):
            judged.add(parent)
    return wildcards, judged


def nearest_wildcard(
    name: str, root: str, judged: set[str], wildcards: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    """The wildcard answering for ``name``: its parent's, when that parent was judged.

    Only the immediate parent is consulted. A parent that was not probed (beyond PARENT_LIMIT)
    or not judged (a resolver fault) suppresses nothing: falling back to an ancestor's wildcard
    would judge the name against a zone cut nobody observed.
    """
    parent = _parent(name)
    if not parent or not (parent == root or parent.endswith("." + root)):
        return None
    return wildcards.get(parent) if parent in judged else None


def is_wildcard_echo(
    addresses: Iterable[str], first_hop: str | None, wildcard: Mapping[str, Any] | None,
    *, unknown_hop: str = "?",
) -> bool:
    """Whether a name's answer IS the wildcard's answer, not merely overlaps it.

    An alias is an echo only when its own first CNAME hop is one the wildcard's random labels
    returned. A name without a CNAME is an echo only when the wildcard has none either and the
    name's address set equals the wildcard's (the union over its probes) exactly: a real host
    that shares one of a rotating wildcard's addresses, or has its own record ending at the
    same CDN edge, is kept.
    """
    if not wildcard or first_hop == unknown_hop:
        return False
    cnames = set(wildcard.get("cnames") or ())
    if first_hop:
        return first_hop in cnames
    answered = set(addresses or ())
    return not cnames and bool(answered) and answered == set(wildcard.get("addresses") or ())


def suppress_echoes(
    root: str,
    judged_names: Iterable[tuple[str, str, list[str], str | None]],
    *,
    wildcards: Mapping[str, Mapping[str, Any]],
    judged_parents: set[str],
    evidence: Mapping[str, Iterable[Any]] | None,
    resolves: str,
) -> tuple[set[str], dict[str, int]]:
    """Names to drop as wildcard echoes, and how many each wildcard parent suppressed."""
    suppressed: set[str] = set()
    per_parent: Counter[str] = Counter()
    for name, status, addresses, first_hop in judged_names:
        if status != resolves:
            continue
        wildcard = nearest_wildcard(name, root, judged_parents, wildcards)
        if not is_wildcard_echo(addresses, first_hop, wildcard):
            continue
        if has_certificate_evidence((evidence or {}).get(name)):
            continue
        suppressed.add(name)
        per_parent[str(wildcard["parent"])] += 1
    return suppressed, dict(per_parent)


def wildcard_summary(
    wildcards: Mapping[str, Mapping[str, Any]], per_parent: Mapping[str, int],
) -> tuple[list[dict[str, Any]], list[str]]:
    """The run's bounded record of each wildcard, and one operator note per wildcard."""
    records: list[dict[str, Any]] = []
    notes: list[str] = []
    for parent in sorted(wildcards):
        item = wildcards[parent]
        count = int(per_parent.get(parent, 0))
        records.append({
            "parent": parent,
            "pattern": f"*.{parent}",
            "addresses": list(item.get("addresses") or ())[:_RECORDED_ANSWERS],
            "cnames": list(item.get("cnames") or ())[:_RECORDED_ANSWERS],
            "suppressed": count,
        })
        notes.append(f"wildcard DNS at *.{parent}; {count} names suppressed")
    return records, notes


def name_sources(by_source: Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
    """Invert ``{source: names}`` into ``{name: sorted sources}``."""
    inverted: dict[str, set[str]] = {}
    for source, names in by_source.items():
        for name in names or ():
            inverted.setdefault(str(name), set()).add(str(source))
    return {name: sorted(sources) for name, sources in sorted(inverted.items())}


__all__ = [
    "CERTIFICATE_SOURCES", "PARENT_LIMIT", "PROBES_PER_PARENT", "has_certificate_evidence",
    "is_wildcard_echo", "name_sources", "nearest_wildcard", "probe_names", "probe_parents",
    "suppress_echoes", "wildcard_answers", "wildcard_summary",
]
