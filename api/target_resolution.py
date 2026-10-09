"""Does a target's hostname publish an address record, and does its www/apex twin?

Names reach the inventory from places that never asked DNS: passive discovery sources and
certificate transparency report every name a certificate or a crawler has seen, whether or not it
publishes an A/AAAA record. A name without one became an ordinary target row with a Scan button,
and Scan admission then refused it with only "DNS resolution failed" -- which the targets page
reduced to "Failed to start scan". The same happens when an operator adds ``example.com`` for a
site that only answers on ``www.example.com``, or the other way round.

This module answers the question once, the same way Scan admission asks it (the system resolver
through ``getaddrinfo``), bounded by a short timeout, and separates three outcomes:

* ``resolves`` -- at least one address came back;
* ``no_address`` -- the resolver answered that the name has no address record (NXDOMAIN or an
  empty answer). This is the only outcome that changes behaviour;
* ``unknown`` -- the resolver failed or timed out. That says nothing about the name, so callers
  keep their previous behaviour instead of dropping or rewriting a target on a resolver fault.

It never admits an address. Destination policy stays with Scan admission, which still classifies
every answer before freezing it; choosing ``www.example.com`` over ``example.com`` here only
changes which name admission is asked about.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import urllib.parse
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any

try:
    import action_scope
    import target_authorization
except ModuleNotFoundError:  # package-native import layout
    from api import action_scope, target_authorization

try:
    import discovery_wildcards
except ModuleNotFoundError:  # package-native import layout
    from api import discovery_wildcards

try:
    from scanner_tools.discovered_names import canonical_name, filter_subdomains, subdomain_of
except ModuleNotFoundError:  # package-native import layout
    from scanner.scanner_tools.discovered_names import canonical_name, filter_subdomains, subdomain_of

RESOLVES = "resolves"
NO_ADDRESS = "no_address"
UNKNOWN = "unknown"
# A name an overall deadline left unjudged. Like UNKNOWN it says nothing about the name, so it
# stays scannable, but it is counted apart so a caller can say the names were never checked.
NOT_CHECKED = "not_checked"

LOOKUP_TIMEOUT_SECONDS = 3.0
DISCOVERY_CONCURRENCY = 16
# Discovery used to insert the first 100 names it found. Resolve a bounded window beyond that so
# names skipped for having no address record leave room for ones that do.
DISCOVERY_TARGET_LIMIT = 100
DISCOVERY_RESOLVE_LIMIT = 300
_REPORTED_NAME_LIMIT = 100

# getaddrinfo's "this name has no address" answers. EAI_AGAIN, EAI_FAIL and the rest describe the
# resolver, not the name.
_NO_RECORD_ERRORS = frozenset(
    code for code in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))
    if code is not None
)

Lookup = Callable[[str], Awaitable[list[str]]]
# Addresses plus the first CNAME hop (None when the name is not an alias, UNKNOWN_HOP when the
# hop could not be read).
Answer = Callable[[str], Awaitable[tuple[list[str], str | None]]]


async def system_lookup(hostname: str) -> list[str]:
    """Every distinct address the system resolver returns for ``hostname``."""
    records = await asyncio.get_running_loop().getaddrinfo(
        hostname, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
    )
    addresses: list[str] = []
    for record in records:
        try:
            address = str(ipaddress.ip_address(str(record[4][0]).split("%", 1)[0]))
        except (IndexError, ValueError):
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


# The CNAME lookup of a name the resolver says is an alias failed: its first hop is unknown,
# so it can never be judged an echo of a wildcard.
UNKNOWN_HOP = "?"


async def first_cname_hop(hostname: str) -> str | None:
    """The name ``hostname``'s own CNAME record points at; None without one, UNKNOWN_HOP on a fault."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = resolver.lifetime = LOOKUP_TIMEOUT_SECONDS
    try:
        answer = await resolver.resolve(hostname, "CNAME", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return None
    except (dns.exception.DNSException, OSError):
        return UNKNOWN_HOP
    if answer.rrset is None:
        return None
    for record in answer.rrset:
        return canonical_name(str(getattr(record, "target", record))) or UNKNOWN_HOP
    return None


async def system_answer(hostname: str) -> tuple[list[str], str | None]:
    """``system_lookup`` plus the first CNAME hop, when the name is an alias.

    The first hop, not the canonical name the chain ends at: two names that alias different
    records can both end at one CDN edge, and only the record a name itself publishes says
    whether it is a wildcard's answer.
    """
    records = await asyncio.get_running_loop().getaddrinfo(
        hostname, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        flags=socket.AI_CANONNAME,
    )
    addresses: list[str] = []
    canonical = ""
    for record in records:
        if not canonical and len(record) > 3 and record[3]:
            canonical = str(record[3])
        try:
            address = str(ipaddress.ip_address(str(record[4][0]).split("%", 1)[0]))
        except (IndexError, ValueError):
            continue
        if address not in addresses:
            addresses.append(address)
    terminal = canonical_name(canonical) if canonical else None
    if not terminal or terminal == _clean_host(hostname):
        return addresses, None
    return addresses, (await first_cname_hop(_clean_host(hostname))) or UNKNOWN_HOP


def lookup_error_status(exc: BaseException) -> str:
    """``no_address`` when the resolver said the name has no record, else ``unknown``."""
    if isinstance(exc, socket.gaierror) and exc.errno in _NO_RECORD_ERRORS:
        return NO_ADDRESS
    return UNKNOWN


def _clean_host(hostname: Any) -> str:
    return str(hostname or "").strip().lower().rstrip(".").strip("[]")


def _is_address_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def lookup_host(
    hostname: str,
    *,
    lookup: Lookup | None = None,
    timeout: float = LOOKUP_TIMEOUT_SECONDS,
) -> tuple[str, list[str]]:
    """Resolve one name: ``(status, addresses)``. An address literal resolves to itself."""
    host = _clean_host(hostname)
    if not host:
        return UNKNOWN, []
    if _is_address_literal(host):
        return RESOLVES, [str(ipaddress.ip_address(host))]
    try:
        addresses = await asyncio.wait_for((lookup or system_lookup)(host), timeout)
    except asyncio.TimeoutError:
        return UNKNOWN, []
    except OSError as exc:
        return lookup_error_status(exc), []
    return (RESOLVES, list(addresses)) if addresses else (NO_ADDRESS, [])


def www_twin(hostname: str) -> str | None:
    """``www.example.com`` for ``example.com`` and the reverse; None for anything else.

    The pair differs by exactly one leading ``www.`` label. This also handles registrable
    names under multi-label public suffixes, such as ``example.co.uk``, without relying on a
    guessed two-label root. No other sibling name is considered.
    """
    host = _clean_host(hostname)
    if not host or _is_address_literal(host):
        return None
    labels = host.split(".")
    if not all(labels):
        return None
    if labels[0] == "www" and len(labels) >= 3:
        return ".".join(labels[1:])
    if len(labels) >= 2 and labels[0] != "www":
        return f"www.{host}"
    return None


async def resolving_twin(
    hostname: str,
    *,
    lookup: Lookup | None = None,
    admit: Callable[[str], bool] | None = None,
    timeout: float = LOOKUP_TIMEOUT_SECONDS,
) -> str | None:
    """The www/apex twin of ``hostname`` when it resolves (to an admitted address, if asked)."""
    twin = www_twin(hostname)
    if twin is None:
        return None
    status, addresses = await lookup_host(twin, lookup=lookup, timeout=timeout)
    if status != RESOLVES:
        return None
    if admit is not None and not any(admit(address) for address in addresses):
        return None
    return twin


def unresolvable_message(hostname: str, *, twin: str | None = None, action: str = "scanned") -> str:
    """The operator-facing reason a name cannot be used, naming the twin that works."""
    message = f"{hostname} does not resolve in DNS (no A/AAAA record), so it cannot be {action}."
    if twin:
        message += f" {twin} does resolve; use {twin} instead."
    return message


def replace_host(value: str, hostname: str) -> str:
    """``value`` with its hostname replaced, keeping scheme, port, path and scheme-lessness."""
    text = str(value or "").strip()
    scheme_less = "://" not in text
    parsed = urllib.parse.urlsplit(f"//{text}" if scheme_less else text)
    host = hostname if ":" not in hostname else f"[{hostname}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    if parsed.username is not None:
        credentials = parsed.username + (f":{parsed.password}" if parsed.password is not None else "")
        netloc = f"{credentials}@{netloc}"
    rebuilt = urllib.parse.urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )
    return rebuilt[2:] if scheme_less and rebuilt.startswith("//") else rebuilt


def canonical_web_key(url: str) -> str:
    """Match the targets table's host/port identity for a normalized HTTP(S) URL."""
    parsed = urllib.parse.urlsplit(url)
    host = str(parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    if port in (None, 443 if parsed.scheme == "https" else 80):
        return f"web:{host}"
    return f"web:{host}:{port}"


def policy_admits(environment: str) -> Callable[[str], bool]:
    """The destination policy Scan admission applies, as a predicate over one address."""
    return lambda address: action_scope._ip_scope_block_reason(address, environment) is None


async def prefer_resolving_twin(
    url: str,
    *,
    environment_of: Callable[[], Awaitable[str]] | None = None,
    lookup: Lookup | None = None,
    timeout: float = LOOKUP_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """When ``url``'s host has no address record but its www/apex twin does, describe the swap.

    Returns None when the host resolves, when the resolver could not say (a fault never rewrites
    what the operator typed), when there is no twin, or when the twin does not resolve either.
    With ``environment_of``, the twin must also resolve to an address the destination policy
    admits in that environment, so a twin pointing at a refused class (the cloud metadata
    address, a private range outside Lab) is never chosen. It is awaited only when a swap is in
    question, so the common case costs one lookup and nothing else.
    """
    host = _clean_host(urllib.parse.urlsplit(str(url or "")).hostname)
    if not host or _is_address_literal(host) or www_twin(host) is None:
        return None
    status, _addresses = await lookup_host(host, lookup=lookup, timeout=timeout)
    if status != NO_ADDRESS:
        return None
    admit = policy_admits(await environment_of()) if environment_of is not None else None
    twin = await resolving_twin(host, lookup=lookup, admit=admit, timeout=timeout)
    if twin is None:
        return None
    return {
        "requested_host": host,
        "resolved_host": twin,
        "resolved_url": replace_host(url, twin),
        "reason": "no_address_record",
        "message": f"{host} has no address record; using {twin}.",
    }


async def scan_target_dns_fallback(url: str, pool: Any) -> tuple[str, dict[str, Any] | None]:
    """The URL a Scan should be submitted for, and the swap made, if any.

    The twin is judged under the environment of the requested target when it is registered
    (production otherwise), the same classification its admission applies. Authorization and
    scope then bind to the twin: the Scan's standing authorization, receipt and target row are
    all resolved from the returned URL.
    """

    async def environment_of() -> str:
        if pool is None:
            return "production"
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT metadata_json FROM targets WHERE canonical_key = $1", canonical_web_key(url),
                )
        except Exception:  # noqa: BLE001 -- unknown environment means the strict one
            return "production"
        metadata = (row or {}).get("metadata_json") if row else None
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except ValueError:
                metadata = None
        return target_authorization.effective_target_environment(metadata)

    fallback = await prefer_resolving_twin(url, environment_of=environment_of)
    return (fallback["resolved_url"], fallback) if fallback else (url, None)


def fallback_response_fields(fallback: Mapping[str, Any] | None, requested: Any) -> dict[str, Any]:
    """Response fields announcing a www/apex swap; empty when none was made."""
    if not fallback:
        return {}
    return {"dns_fallback": dict(fallback), "notice": fallback["message"], "requested_target": requested}


async def classify_hosts(
    names: Iterable[str],
    *,
    lookup: Lookup | None = None,
    concurrency: int = DISCOVERY_CONCURRENCY,
    timeout: float = LOOKUP_TIMEOUT_SECONDS,
    deadline_seconds: float | None = None,
) -> list[tuple[str, str]]:
    """``(name, status)`` for each distinct name, in input order, at bounded concurrency.

    ``deadline_seconds`` bounds the whole classification, not each lookup: a dead resolver
    otherwise costs every name its full timeout, about a minute for a full discovery window.
    Names the deadline leaves unjudged are ``not_checked``.
    """
    judged = await judge_hosts(
        names, lookup=lookup, concurrency=concurrency, timeout=timeout,
        deadline_seconds=deadline_seconds,
    )
    return [(name, status) for name, status, _addresses, _canonical in judged]


async def judge_hosts(
    names: Iterable[str],
    *,
    lookup: Lookup | None = None,
    answer: Answer | None = None,
    concurrency: int = DISCOVERY_CONCURRENCY,
    timeout: float = LOOKUP_TIMEOUT_SECONDS,
    deadline_seconds: float | None = None,
) -> list[tuple[str, str, list[str], str | None]]:
    """``(name, status, addresses, canonical)`` per distinct name, as ``classify_hosts`` judges.

    ``answer`` also reports the CNAME target; with only ``lookup`` (or neither) it is None.
    """
    unique = list(dict.fromkeys(_clean_host(name) for name in names if _clean_host(name)))
    gate = asyncio.Semaphore(max(1, int(concurrency)))
    loop = asyncio.get_running_loop()
    stop_at = None if deadline_seconds is None else loop.time() + max(0.0, float(deadline_seconds))

    async def resolve(host: str) -> tuple[list[str], str | None]:
        if answer is not None:
            return await answer(host)
        return await (lookup or system_lookup)(host), None

    async def one(name: str) -> tuple[str, str, list[str], str | None]:
        async with gate:
            budget = timeout
            if stop_at is not None:
                remaining = stop_at - loop.time()
                if remaining <= 0:
                    return name, NOT_CHECKED, [], None
                budget = min(timeout, remaining)
            canonical: str | None = None
            if _is_address_literal(name):
                status, addresses = RESOLVES, [str(ipaddress.ip_address(name))]
            else:
                try:
                    addresses, canonical = await asyncio.wait_for(resolve(name), budget)
                    addresses = list(addresses)
                    status = RESOLVES if addresses else NO_ADDRESS
                except asyncio.TimeoutError:
                    status, addresses = UNKNOWN, []
                except OSError as exc:
                    status, addresses = lookup_error_status(exc), []
            if status == UNKNOWN and stop_at is not None and loop.time() >= stop_at:
                # Cut off by the deadline, not answered by the resolver.
                return name, NOT_CHECKED, [], None
            return name, status, addresses, canonical

    return list(await asyncio.gather(*(one(name) for name in unique)))


async def plan_discovered_targets(
    names: Iterable[str],
    *,
    root_domain: str | None = None,
    evidence: Mapping[str, Iterable[str]] | None = None,
    lookup: Lookup | None = None,
    answer: Answer | None = None,
    resolve_limit: int = DISCOVERY_RESOLVE_LIMIT,
    deadline_seconds: float | None = None,
) -> dict[str, Any]:
    """Split discovered names into those that can be scanned and those that cannot.

    A name the resolver says has no address record would only be a Scan button that fails, so it
    is reported rather than inserted. A name the resolver could not judge stays scannable, as
    before: a resolver fault must not silently empty the inventory, and Scan admission still
    explains a name that does not resolve. Runs before a database connection is taken, so a slow
    resolver never holds one. A name an overall deadline left unjudged is treated the same way
    and listed under ``not_checked``; names beyond ``resolve_limit`` are counted, not resolved.

    With ``root_domain``, only canonical names strictly below it (on a label boundary) are
    planned; the rest are counted under ``outside_root_count`` and never resolved. Wildcard DNS
    is detected under it too (``discovery_wildcards``): random labels for the apex and a bounded
    set of parents are resolved first, in the same lookups, concurrency and deadline, and a name
    whose answer is only a wildcard's, with no certificate naming it in ``evidence``
    (``{name: [source, ...]}``), is listed under ``wildcard_suppressed`` instead of scannable.
    """
    submitted = list(names or [])
    outside_root = 0
    root = canonical_name(root_domain) if root_domain is not None else None
    if root_domain is not None:
        submitted, outside_root = filter_subdomains(submitted, root_domain)
    candidates = submitted[: max(0, int(resolve_limit))]
    probes = (
        discovery_wildcards.probe_names(discovery_wildcards.probe_parents(root, candidates))
        if root and candidates else []
    )
    if answer is None and lookup is None:
        answer = system_answer
    judged_all = await judge_hosts(
        [probe for _parent, probe in probes] + candidates,
        lookup=lookup, answer=answer, deadline_seconds=deadline_seconds,
    )
    probe_set = {probe for _parent, probe in probes}
    judged = [row for row in judged_all if row[0] not in probe_set]
    wildcards, judged_parents = discovery_wildcards.wildcard_answers(
        probes, {row[0]: row[1:] for row in judged_all if row[0] in probe_set},
        resolves=RESOLVES, no_address=NO_ADDRESS, unknown_hop=UNKNOWN_HOP,
    )
    suppressed, per_parent = discovery_wildcards.suppress_echoes(
        root or "", judged, wildcards=wildcards, judged_parents=judged_parents,
        evidence=evidence, resolves=RESOLVES,
    ) if wildcards else (set(), {})
    records, notes = discovery_wildcards.wildcard_summary(wildcards, per_parent)
    classified = [(name, status) for name, status, *_rest in judged]
    return {
        "scannable": [
            name for name, status in classified
            if status != NO_ADDRESS and name not in suppressed
        ],
        "unresolved": [name for name, status in classified if status == NO_ADDRESS],
        "unknown": [name for name, status in classified if status == UNKNOWN],
        "not_checked": [name for name, status in classified if status == NOT_CHECKED],
        "wildcard_suppressed": [name for name, _status in classified if name in suppressed],
        "wildcards": records,
        "wildcard_notes": notes,
        "wildcard_parents_probed": len({parent for parent, _probe in probes}),
        "submitted_count": len(submitted),
        "resolve_limit": max(0, int(resolve_limit)),
        "outside_root_count": outside_root,
    }


async def store_discovered_targets(
    conn: Any,
    plan: Mapping[str, Any],
    root_domain: str,
    *,
    source: str = "subfinder",
    target_limit: int = DISCOVERY_TARGET_LIMIT,
) -> dict[str, Any]:
    """Insert the plan's scannable names; return the run's content-free DNS outcome.

    The last gate before a row exists: a name that is not strictly below ``root_domain`` on a
    label boundary is never inserted, whichever planner produced the plan.
    """
    planned = list(plan.get("scannable") or [])
    # Insert exactly the canonical name and root this gate validated, never the plan's spelling.
    root = canonical_name(root_domain) or str(root_domain or "")
    scannable = list(dict.fromkeys(
        accepted for name in planned if (accepted := subdomain_of(name, root))
    ))
    outside_root = int(plan.get("outside_root_count") or 0) + len(planned) - len(scannable)
    unresolved = list(plan.get("unresolved") or [])
    suppressed = list(plan.get("wildcard_suppressed") or [])
    added = 0
    failed = 0
    for name in scannable[: max(0, int(target_limit))]:
        try:
            tag = await conn.execute(
                """
                INSERT INTO targets (url, root_domain, is_root, discovery_source)
                VALUES ($1, $2, false, $3)
                ON CONFLICT (canonical_key) DO NOTHING
                """,
                f"https://{name}", root, source,
            )
        except Exception:  # noqa: BLE001 -- one refused row must not drop the rest of the run
            failed += 1
            tag = ""
        if str(tag or "").strip().endswith(" 1"):
            added += 1
    return {
        "checked": len(scannable) + len(unresolved) + len(suppressed),
        "scannable": len(scannable),
        "added": added,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved[:_REPORTED_NAME_LIMIT],
        "unknown_count": len(plan.get("unknown") or []),
        "insert_failed": failed,
        "outside_root_count": outside_root,
        "wildcard_suppressed_count": len(suppressed),
        "wildcard_suppressed": suppressed[:_REPORTED_NAME_LIMIT],
        "wildcards": list(plan.get("wildcards") or []),
        "notes": list(plan.get("wildcard_notes") or []),
    }


def public_discovery_run(row: Mapping[str, Any]) -> dict[str, Any]:
    """A discovery row with its DNS outcome lifted out of ``sources_used`` into ``resolution``.

    The worker keeps the outcome in the existing ``sources_used`` object so no column is added;
    readers see ``sources_used`` exactly as before plus a top-level ``resolution``.
    """
    public = dict(row)
    sources = public.get("sources_used")
    if isinstance(sources, str):
        try:
            sources = json.loads(sources)
        except ValueError:
            sources = None
    if isinstance(sources, Mapping) and "dns_resolution" in sources:
        sources = dict(sources)
        public["resolution"] = sources.pop("dns_resolution")
        public["sources_used"] = sources
    else:
        public.setdefault("resolution", None)
    return public
