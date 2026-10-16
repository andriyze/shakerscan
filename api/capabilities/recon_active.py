"""Authorized active recon: DNS name enumeration, virtual-host discovery, parameter discovery.

These run only in the opt-in ``recon_active`` Scan family. It is outside every preset, so a
saved schedule or policy never gains it by upgrading; it needs the Scan's active-testing
authority and a target-bound approval receipt, and DNS enumeration additionally needs the
policy's subdomain discovery. Each operation:

* reads a fixed list the project authored and bundles (``scanner/wordlists``), never a list a
  caller supplies, and names its version and digest in the receipt;
* is bounded by its durable reservation (names or requests) and a wall deadline, checks
  cancellation between bounded batches, and keeps trustworthy partial output when stopped;
* measures a baseline before it reports anything: random never-published DNS labels (wildcard
  DNS), random never-published virtual-host names (a catch-all server), and a random parameter
  name (a page that echoes or reacts to any parameter);
* reports leads only. An enumerated name is a DNS observation recorded like passive discovery
  (a separate target for its own authorized Scan). A virtual host is a name the bound address
  answered differently for; it never becomes a route or a target. A parameter is a name a route
  observably read; it becomes an input to this Scan's own existing candidate pipeline for that
  already observed route, and is never proof of a vulnerability.

Traffic stays on the binding: DNS questions are only for names under the Scan's bound root
domains; HTTP goes only to the Scan's frozen origin and addresses (``execute_bound_http_request``
with a ``virtual_host`` that must itself be under a bound root). Pure decision logic is separated
from I/O so the controls are unit-testable without a network.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
from pathlib import Path
import secrets
import time
from typing import Any
import urllib.parse

try:
    import discovery_wildcards
    import target_resolution
except ModuleNotFoundError:  # package import (api.capabilities.recon_active)
    from .. import discovery_wildcards, target_resolution
try:
    from scanner_tools.discovered_names import canonical_name, name_under_apex, subdomain_of
except ModuleNotFoundError:  # package import
    from scanner.scanner_tools.discovered_names import canonical_name, name_under_apex, subdomain_of

Cancelled = Callable[[], bool]

DNS_WORDLIST = "dns-corporate.txt"
VHOST_WORDLIST = "vhosts-corporate.txt"
PARAMETER_WORDLIST = "params-corporate.txt"
DNS_BATCH = 32
DNS_CONCURRENCY = 16
VHOST_CONTROLS = 2
VHOST_CONFIRM_LIMIT = 10
PARAMETER_ROUTE_LIMIT = 12
PARAMETER_CONFIRM_PER_ROUTE = 8
LEAD_STATUSES = frozenset({200, 204, 301, 302, 303, 307, 308, 401, 403})
_STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".mp4", ".mp3",
)
# Routes a parameter probe never touches, even with a meaningless value.
_AVOIDED_PATH_WORDS = ("logout", "signout", "sign-out", "log-out", "delete", "remove",
                       "destroy", "unsubscribe", "reset", "revoke", "cancel")


# ---------------------------------------------------------------------------------------------
# Bundled lists


@dataclass(frozen=True)
class BundledList:
    name: str
    version: str
    entries: tuple[str, ...]
    sha256: str

    def receipt(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "entries": len(self.entries),
                "sha256": self.sha256, "provenance": "authored_by_shakerscan"}


def _wordlist_dirs() -> tuple[Path, ...]:
    here = Path(__file__).resolve()
    return (here.parents[2] / "scanner" / "wordlists", Path("/app/wordlists"))


def load_bundled_list(name: str) -> BundledList:
    """One authored list by file name; never a path from a request."""
    if "/" in name or "\\" in name or name not in {DNS_WORDLIST, VHOST_WORDLIST, PARAMETER_WORDLIST}:
        raise ValueError("unknown bundled list")
    for directory in _wordlist_dirs():
        path = directory / name
        if path.is_file():
            lines = path.read_text(encoding="utf-8").splitlines()
            break
    else:
        raise FileNotFoundError(f"bundled list {name} is unavailable")
    version = "unversioned"
    for line in lines:
        if line.startswith("#") and "(" in line and line.rstrip().endswith(")."):
            version = line[line.rindex("(") + 1:line.rindex(")")]
            break
    entries = tuple(dict.fromkeys(
        line.strip() for line in lines
        if line.strip() and not line.startswith("#") and len(line.strip()) <= 63
    ))
    digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
    return BundledList(name, version, entries, digest)


def _bound_roots(roots: Iterable[Any]) -> list[str]:
    """Canonical bound roots that are registrable (a public suffix such as ``co.uk`` is never
    enumerated, so no question is asked about other registrants' names)."""
    return list(dict.fromkeys(
        root for root in (name_under_apex(item, item) for item in roots) if root
    ))


def _elapsed(started: float) -> int:
    return max(1, int(time.monotonic() - started + 0.999))


# ---------------------------------------------------------------------------------------------
# DNS name enumeration


async def enumerate_dns_names(
    *,
    roots: Sequence[str],
    labels: Sequence[str],
    answer: Callable[[str], Awaitable[tuple[list[str], str | None]]],
    name_limit: int,
    deadline_seconds: float,
    cancelled: Cancelled,
    token: Callable[[int], str] = secrets.token_hex,
    wordlist: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Ask the resolver for ``<label>.<root>`` within ``name_limit`` questions (probes included).

    Each root is baselined first with random labels (``discovery_wildcards``); a name whose answer
    is only that wildcard's is suppressed. A name the resolver could not judge is counted, never
    reported as found.
    """
    started = time.monotonic()
    stop_at = started + max(1.0, float(deadline_seconds))
    bound = _bound_roots(roots)
    budget = max(0, int(name_limit))
    attempted = 0
    observations: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    stopped: str | None = None
    for root in bound:
        if budget - attempted <= discovery_wildcards.PROBES_PER_PARENT:
            stopped = stopped or "budget"
            break
        probes = discovery_wildcards.probe_names([root], token=token)
        candidates = [
            name for name in (subdomain_of(f"{label}.{root}", root) for label in labels) if name
        ]
        candidates = list(dict.fromkeys(candidates))
        room = budget - attempted - len(probes)
        planned = candidates[:max(0, room)]
        judged: list[tuple[str, str, list[str], str | None]] = []
        queue = [probe for _parent, probe in probes] + planned
        for offset in range(0, len(queue), DNS_BATCH):
            if cancelled():
                stopped = "cancelled"
                break
            remaining = stop_at - time.monotonic()
            if remaining <= 0:
                stopped = "deadline"
                break
            batch = queue[offset:offset + DNS_BATCH]
            rows = await target_resolution.judge_hosts(
                batch, answer=answer, concurrency=DNS_CONCURRENCY,
                deadline_seconds=remaining,
            )
            judged.extend(rows)
            attempted += sum(1 for row in rows if row[1] != target_resolution.NOT_CHECKED)
        probe_set = {probe for _parent, probe in probes}
        probe_rows = {row[0]: row[1:] for row in judged if row[0] in probe_set}
        wildcards, judged_parents = discovery_wildcards.wildcard_answers(
            probes, probe_rows, resolves=target_resolution.RESOLVES,
            no_address=target_resolution.NO_ADDRESS, unknown_hop=target_resolution.UNKNOWN_HOP,
        )
        names = [row for row in judged if row[0] not in probe_set]
        suppressed, per_parent = discovery_wildcards.suppress_echoes(
            root, names, wildcards=wildcards, judged_parents=judged_parents,
            evidence=None, resolves=target_resolution.RESOLVES,
        ) if wildcards else (set(), {})
        records, _notes = discovery_wildcards.wildcard_summary(wildcards, per_parent)
        found = 0
        for name, status, addresses, first_hop in names:
            if status != target_resolution.RESOLVES or name in suppressed:
                continue
            found += 1
            observations.append({
                "kind": "subdomain", "host": name, "root_domain": root,
                "source": "dns_enumeration", "dns_status": "resolves",
                "address_count": len(addresses), "alias": bool(first_hop),
            })
        statuses = [row[1] for row in names]
        summaries.append({
            "root_domain": root,
            "candidates_in_list": len(candidates),
            "planned": len(planned),
            "judged": sum(1 for status in statuses if status != target_resolution.NOT_CHECKED),
            "found": found,
            "no_address": statuses.count(target_resolution.NO_ADDRESS),
            "unjudged": statuses.count(target_resolution.UNKNOWN),
            "not_checked": statuses.count(target_resolution.NOT_CHECKED) + len(planned) - len(names),
            "wildcard_judged": root in judged_parents,
            "wildcards": records,
            "wildcard_suppressed": len(suppressed),
            "beyond_budget": max(0, len(candidates) - len(planned)),
        })
        if stopped in {"cancelled", "deadline"}:
            break
    partial = stopped is not None or any(item["beyond_budget"] or item["not_checked"] for item in summaries)
    observations.append({
        "kind": "dns_enumeration",
        "wordlist": dict(wordlist or {}),
        "roots": summaries,
        "attempted_questions": attempted,
        "stopped": stopped,
        "partial": partial,
        "scope": "names_under_bound_root_domains_only",
    })
    return {
        "status": "cancelled" if stopped == "cancelled" else "partial" if partial else "success",
        "partial": partial,
        "observations": observations,
        "budget_consumed": {"hosts_attempted": attempted, "tool_wall_seconds": _elapsed(started)},
    }


# ---------------------------------------------------------------------------------------------
# Response signatures shared by virtual-host and parameter discovery


@dataclass(frozen=True)
class ResponseSignature:
    status: int
    length: int
    sha256: str
    location: str | None = None


def _distinct(left: ResponseSignature, right: ResponseSignature) -> bool:
    """Whether two responses differ by more than a dynamic page's noise."""
    if left.status != right.status:
        return True
    if left.location != right.location:
        return True
    if left.sha256 == right.sha256:
        return False
    tolerance = max(64, int(0.10 * max(left.length, right.length)))
    return abs(left.length - right.length) > tolerance


def _similar(left: ResponseSignature, right: ResponseSignature) -> bool:
    if left.status != right.status or left.location != right.location:
        return False
    tolerance = max(64, int(0.05 * max(left.length, right.length)))
    return left.sha256 == right.sha256 or abs(left.length - right.length) <= tolerance


def normalized_location(location: Any, requested_host: str) -> str | None:
    """A redirect target with the requested name replaced, so a server that redirects every
    name to itself (``http://x`` -> ``https://x/``) does not make every name look distinct."""
    text = str(location or "").strip()
    if not text:
        return None
    host = str(requested_host or "").lower()
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return text[:300]
    hostname = (parts.hostname or "").lower()
    if host and hostname == host:
        netloc = parts.netloc.lower().replace(host, "{host}", 1)
        text = urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
    return text[:300]


VirtualHostRequest = Callable[[str | None], Awaitable[ResponseSignature | None]]


async def discover_virtual_hosts(
    *,
    canonical_host: str,
    roots: Sequence[str],
    labels: Sequence[str],
    request: VirtualHostRequest,
    request_limit: int,
    deadline_seconds: float,
    cancelled: Cancelled,
    token: Callable[[int], str] = secrets.token_hex,
    wordlist: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Ask the bound address for ``/`` under other names below the bound root.

    A name is a lead only when its answer differs from the bound name's own answer and from
    every random never-published name (the server's catch-all), with a lead status, and a second
    request reproduces it. ``request(None)`` is the bound name.
    """
    started = time.monotonic()
    stop_at = started + max(1.0, float(deadline_seconds))
    limit = max(0, int(request_limit))
    used = 0
    stopped: str | None = None
    errors = 0
    bound = _bound_roots(roots)
    canonical = canonical_name(canonical_host) or ""

    async def ask(host: str | None) -> ResponseSignature | None:
        nonlocal used, errors
        used += 1
        try:
            return await asyncio.wait_for(request(host), max(0.5, stop_at - time.monotonic()))
        except (asyncio.TimeoutError, OSError, ValueError):
            errors += 1
            return None

    def finish(status: str, observation: dict[str, Any]) -> dict[str, Any]:
        return {"status": status, "partial": status != "success",
                "observations": observation.pop("_leads") + [observation],
                "budget_consumed": {"http_requests": used, "tool_wall_seconds": _elapsed(started)}}

    summary: dict[str, Any] = {"kind": "virtual_host_discovery", "wordlist": dict(wordlist or {}),
                               "bound_host": canonical, "_leads": []}
    if not bound or limit < 2 + VHOST_CONTROLS:
        return finish("success", {**summary, "tested": 0, "skipped": "insufficient_budget_or_scope"})
    baseline = await ask(None)
    controls = [await ask(f"{token(8)}.{bound[0]}") for _ in range(VHOST_CONTROLS)]
    if baseline is None or any(item is None for item in controls):
        return finish("failed", {**summary, "tested": 0, "error": "baseline_unavailable"})
    candidates = [
        name for name in dict.fromkeys(
            subdomain_of(f"{label}.{root}", root) for root in bound for label in labels
        ) if name and name != canonical
    ]
    room = max(0, limit - used - VHOST_CONFIRM_LIMIT)
    tested: list[tuple[str, ResponseSignature]] = []
    for name in candidates[:room]:
        if cancelled():
            stopped = "cancelled"
            break
        if time.monotonic() >= stop_at:
            stopped = "deadline"
            break
        answer = await ask(name)
        if answer is not None:
            tested.append((name, answer))
    leads: list[dict[str, Any]] = []
    for name, answer in tested:
        if answer.status not in LEAD_STATUSES:
            continue
        if not _distinct(answer, baseline) or any(not _distinct(answer, item) for item in controls):
            continue
        if len(leads) >= VHOST_CONFIRM_LIMIT or used >= limit or cancelled():
            stopped = stopped or "confirmation_budget"
            break
        again = await ask(name)
        if again is None or not _similar(answer, again):
            continue
        leads.append({"kind": "virtual_host", "host": name, "status": answer.status,
                      "length": answer.length, "basis": "host_header_response_differs",
                      "confirmed": True, "status_class": "lead",
                      "note": "answered by the bound address; not a DNS record, route or target"})
    summary["_leads"] = leads
    beyond = max(0, len(candidates) - room)
    status = "cancelled" if stopped == "cancelled" else (
        "partial" if stopped or beyond or errors else "success")
    return finish(status, {
        **summary,
        "tested": len(tested), "candidates_in_list": len(candidates), "beyond_budget": beyond,
        "errors": errors, "leads": len(leads), "stopped": stopped,
        "controls": {"random_names": VHOST_CONTROLS,
                     "catch_all": all(not _distinct(item, baseline) for item in controls)},
    })


# ---------------------------------------------------------------------------------------------
# Parameter discovery


@dataclass(frozen=True)
class ParameterResponse:
    signature: ResponseSignature
    reflected: bool


ParameterRequest = Callable[[str, str, Mapping[str, str] | None, str | None],
                            Awaitable[ParameterResponse | None]]


def parameter_routes(
    observations: Iterable[Mapping[str, Any]], *, origin: str, limit: int = PARAMETER_ROUTE_LIMIT,
    excluded_urls: frozenset[str] = frozenset(),
) -> list[str]:
    """Observed GET paths on the Scan's own origin worth asking about parameters, root first."""
    paths: list[str] = ["/"]
    for item in observations:
        kind = str(item.get("kind") or "")
        if kind == "discovered_route" and str(item.get("method") or "GET").upper() != "GET":
            continue
        if kind == "content_discovery":
            status = item.get("status")
            if item.get("negative_control") or type(status) is not int or not 200 <= status < 300:
                continue
            if str(item.get("url") or "") in excluded_urls:
                continue
        elif kind != "discovered_route":
            continue
        try:
            parts = urllib.parse.urlsplit(str(item.get("url") or ""))
        except ValueError:
            continue
        if f"{parts.scheme}://{parts.netloc}".lower() != origin.lower():
            continue
        path = parts.path or "/"
        lowered = path.lower()
        if (lowered.endswith(_STATIC_SUFFIXES) or "<redacted>" in lowered or "{" in path
                or any(word in lowered for word in _AVOIDED_PATH_WORDS)):
            continue
        paths.append(path)
    return list(dict.fromkeys(paths))[:max(1, int(limit))]


def _marker(token: Callable[[int], str]) -> str:
    return f"ssp{token(5)}"


async def discover_parameters(
    *,
    origin: str,
    routes: Sequence[str],
    names: Sequence[str],
    request: ParameterRequest,
    request_limit: int,
    deadline_seconds: float,
    cancelled: Cancelled,
    token: Callable[[int], str] = secrets.token_hex,
    wordlist: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Find parameter names observed routes read, with a random-name control per route.

    ``request(origin, path, query, marker)`` returns the response signature and whether
    ``marker`` was reflected. A route that reflects or reacts to a random name is not
    attributed any name by reflection or by change; a stable route is.
    """
    started = time.monotonic()
    stop_at = started + max(1.0, float(deadline_seconds))
    limit = max(0, int(request_limit))
    used = 0
    errors = 0
    stopped: str | None = None
    found: list[dict[str, Any]] = []
    route_rows: list[dict[str, Any]] = []

    async def ask(path: str, query: Mapping[str, str] | None, marker: str | None):
        nonlocal used, errors
        used += 1
        try:
            return await asyncio.wait_for(request(origin, path, query, marker),
                                          max(0.5, stop_at - time.monotonic()))
        except (asyncio.TimeoutError, OSError, ValueError):
            errors += 1
            return None

    for path in routes:
        if cancelled():
            stopped = "cancelled"
            break
        if time.monotonic() >= stop_at:
            stopped = "deadline"
            break
        if limit - used < 3:
            stopped = "budget"
            break
        base = await ask(path, None, None)
        control_marker = _marker(token)
        control_name = f"zq{token(4)}"
        control = await ask(path, {control_name: control_marker}, control_marker)
        if base is None or control is None:
            route_rows.append({"path": path, "tested": 0, "reason": "baseline_unavailable"})
            continue
        echoes_any = control.reflected
        stable = _similar(base.signature, control.signature)
        tested = 0
        confirmations = 0
        for name in names:
            if cancelled():
                stopped = "cancelled"
                break
            if time.monotonic() >= stop_at:
                stopped = "deadline"
                break
            if limit - used < 1:
                stopped = "budget"
                break
            marker = _marker(token)
            answer = await ask(path, {name: marker}, marker)
            tested += 1
            if answer is None:
                continue
            signals: list[str] = []
            if answer.reflected and not echoes_any:
                signals.append("reflected")
            if stable and answer.signature.status != base.signature.status:
                signals.append("status_change")
            elif stable and _distinct(answer.signature, base.signature) and _distinct(
                    answer.signature, control.signature):
                signals.append("response_change")
            if not signals:
                continue
            if confirmations >= PARAMETER_CONFIRM_PER_ROUTE or limit - used < 1:
                continue
            confirmations += 1
            second_marker = _marker(token)
            again = await ask(path, {name: second_marker}, second_marker)
            if again is None:
                continue
            kept = [signal for signal in signals if (
                (signal == "reflected" and again.reflected)
                or (signal == "status_change" and again.signature.status == answer.signature.status)
                or (signal == "response_change" and _distinct(again.signature, base.signature))
            )]
            if not kept:
                continue
            found.append({"kind": "discovered_parameter", "origin": origin, "path": path,
                          "parameter": name, "signals": kept, "confirmed": True,
                          "status_class": "lead", "location": "query"})
        route_rows.append({"path": path, "tested": tested, "echoes_any_parameter": echoes_any,
                           "stable": stable})
        if stopped in {"cancelled", "deadline"}:
            break
    routes_done = len(route_rows)
    observations: list[dict[str, Any]] = [
        # The same route with the discovered name is an input to this Scan's candidate pipeline:
        # an observed route, never a synthesized one. The query value is a placeholder.
        {"kind": "discovered_route", "method": "GET",
         "url": f"{origin}{item['path']}?{urllib.parse.urlencode({item['parameter']: '1'})}",
         "source": "parameter_discovery"}
        for item in found
    ]
    beyond = max(0, len(routes) - routes_done)
    partial = bool(stopped or beyond or errors)
    observations.extend(found)
    observations.append({
        "kind": "parameter_discovery", "wordlist": dict(wordlist or {}), "origin": origin,
        "routes": route_rows[:PARAMETER_ROUTE_LIMIT], "routes_tested": routes_done,
        "routes_beyond_budget": beyond, "found": len(found), "errors": errors,
        "stopped": stopped, "partial": partial, "method": "GET", "value": "random_marker",
    })
    return {
        "status": "cancelled" if stopped == "cancelled" else "partial" if partial else "success",
        "partial": partial,
        "observations": observations,
        "budget_consumed": {"http_requests": used, "tool_wall_seconds": _elapsed(started)},
    }


__all__ = [
    "BundledList", "DNS_WORDLIST", "PARAMETER_WORDLIST", "ParameterResponse", "ResponseSignature",
    "VHOST_WORDLIST", "discover_parameters", "discover_virtual_hosts", "enumerate_dns_names",
    "load_bundled_list", "normalized_location", "parameter_routes",
]
