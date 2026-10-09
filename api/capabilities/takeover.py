"""Passive subdomain-takeover detection for names a Scan discovered under its bound root.

A name whose CNAME points at a third-party service resource that no longer exists can be claimed
by whoever registers that resource next, and then serves content under the operator's domain.
``check_subdomain_takeover`` (``dig`` CNAME plus a curl fingerprint) existed only in the legacy
scanner path; canonical Scans skipped it as ``canonical_capability_not_registered``.

``subdomains.takeover_check`` is that check as a canonical capability. It is passive: DNS
questions and, for an authorized host only, one GET. It never claims, registers or changes any
resource.

Authorization. A Scan is authorized for its bound target: HTTP traffic goes only to the frozen
origins and addresses of the binding (``allowed_origins`` / ``allowed_addresses``). Names that
subdomain discovery found under the bound root are recorded as *separate* targets for their own
authorized scans (``scan/subdomain_targets.py``); they are not authorized destinations of this
Scan. So:

* every discovered name under the root gets **DNS-level** evidence only -- its CNAME chain and
  whether the chain's terminal name exists. A terminal that does not exist, belongs to a service
  the catalogue rates "vulnerable" with an NXDOMAIN signature (Azure, Elastic Beanstalk), and is
  confirmed NXDOMAIN by an independent resolver (the configured DNS-over-HTTPS resolvers, not the
  system resolver's negative cache) is a verified finding. Any other non-existent terminal is a
  suspected dangling record. A first hop at a service whose signature is an HTTP page is reported
  as ``inconclusive_dns_only``: proving it needs a request this Scan is not authorized to send;
* the Scan's own bound host gets the same DNS evidence and, when its first hop names an
  HTTP-signature service, one same-origin GET through the bound-request path (frozen addresses,
  scope revalidation, archive recording) within the reserved request budget. The service's
  unclaimed-resource page in the bounded body is verified for a "vulnerable" service and
  suspected for an "edge case" one (GitHub Pages, Heroku, Shopify, Tumblr).

DNS questions are asked only for names under the bound root and the CNAME targets those names
publish; nothing is connected to except the bound origin.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import time
from typing import Any
import urllib.parse

try:
    from scanner_tools.discovered_names import canonical_name, name_under_apex
except ModuleNotFoundError:  # package import (api.capabilities.takeover)
    from scanner.scanner_tools.discovered_names import canonical_name, name_under_apex

HOST_LIMIT = 50
CNAME_HOPS = 5
QUERY_TIMEOUT_SECONDS = 3.0
CONCURRENCY = 16

NXDOMAIN = "nxdomain"
NODATA = "nodata"
ANSWER = "answer"
ERROR = "error"

# The catalogue follows can-i-take-over-xyz (EdOverflow), checked 2026-10-09. ``status`` is that
# project's verdict: only "vulnerable" services can produce a verified finding; an "edge case"
# service (a takeover depends on account-side conditions a scanner cannot see) is suspected at
# most. Services it lists as "not vulnerable" (Fastly, Zendesk, ...) are not here at all.
# ``signature`` is "nxdomain" when the documented sign is that the service name does not exist,
# otherwise a case-insensitive regular expression for the unclaimed-resource page.
@dataclass(frozen=True)
class TakeoverService:
    name: str
    suffixes: tuple[str, ...]
    signature: str
    status: str = "vulnerable"  # or "edge_case"

    @property
    def nxdomain(self) -> bool:
        return self.signature == NXDOMAIN


SERVICES: tuple[TakeoverService, ...] = (
    TakeoverService("Microsoft Azure", (
        "cloudapp.net", "cloudapp.azure.com", "azurewebsites.net", "blob.core.windows.net",
        "azure-api.net", "azurehdinsight.net", "azureedge.net", "azurecontainer.io",
        "database.windows.net", "azuredatalakestore.net", "search.windows.net", "azurecr.io",
        "redis.cache.windows.net", "servicebus.windows.net", "visualstudio.com",
    ), NXDOMAIN),
    TakeoverService("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), NXDOMAIN),
    TakeoverService("AWS S3", ("s3.amazonaws.com", "s3-website.amazonaws.com"),
                    r"The specified bucket does not exist"),
    TakeoverService("Bitbucket", ("bitbucket.io",), r"Repository not found"),
    TakeoverService("Ghost", ("ghost.io",),
                    r"Site unavailable\.|Failed to resolve DNS path for this host"),
    TakeoverService("Pantheon", ("pantheonsite.io",), r"404 error unknown site!"),
    TakeoverService("ReadMe", ("readme.io",),
                    r"The creators of this project are still working on making everything perfect!"),
    TakeoverService("Surge.sh", ("surge.sh",), r"project not found"),
    TakeoverService("WordPress.com", ("wordpress.com",), r"Do you want to register .*\.wordpress\.com\?"),
    TakeoverService("GitHub Pages", ("github.io",), r"There isn't a GitHub Pages site here",
                    status="edge_case"),
    TakeoverService("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
                    r"no-such-app|No such app", status="edge_case"),
    TakeoverService("Shopify", ("myshopify.com",), r"Sorry, this shop is currently unavailable",
                    status="edge_case"),
    TakeoverService("Tumblr", ("domains.tumblr.com",),
                    r"Whatever you were looking for doesn't currently exist at this address",
                    status="edge_case"),
)

# (status, values): values are lower-case names without the trailing dot (CNAME targets) or
# addresses (A/AAAA).
DnsQuery = Callable[[str, str], Awaitable[tuple[str, list[str]]]]
# ``{"ok", "response", "body"}``: ``body`` is the worker-private bounded body (bytes).
HttpGet = Callable[[str], Awaitable[Mapping[str, Any]]]
# An independent resolver's verdict on one name: True NXDOMAIN, False exists, None unknown.
NxdomainConfirm = Callable[[str], Awaitable[bool | None]]


def match_service(name: str) -> TakeoverService | None:
    """The takeover-prone service ``name`` belongs to, on label boundaries."""
    for service in SERVICES:
        if any(name == suffix or name.endswith("." + suffix) for suffix in service.suffixes):
            return service
    return None


def doh_name_permitted(name: str) -> bool:
    """Whether a name may be shown to the third-party DoH resolvers at all.

    The same rule ``dns.inspect`` applies: an internal-looking name never leaves the network as a
    resolver query.
    """
    from . import dns as dns_capability

    host = str(name or "").lower().rstrip(".")
    return "." in host and not host.endswith(dns_capability._PRIVATE_NAME_SUFFIXES)


async def doh_nxdomain(name: str) -> bool | None:
    """Ask the configured DNS-over-HTTPS resolvers (``SHAKERSCAN_DNS_DOH_RESOLVERS``).

    A different resolver than the system one, so its answer is not the system resolver's
    negative cache repeating itself. None when no DoH resolver is configured, the name may not
    be shown to them, or none answered. Callers ask only about a catalogue NXDOMAIN-signature
    service name, and only for a binding ``dns.doh_permitted`` allows.
    """
    import dns.rcode

    from . import dns as dns_capability

    if not dns_capability._DOH_RESOLVERS or not doh_name_permitted(name):
        return None
    try:
        message = await dns_capability._doh_query(name, "A")
    except Exception:  # noqa: BLE001 -- an unanswered confirmation confirms nothing
        return None
    return message.rcode() == dns.rcode.NXDOMAIN


async def dnspython_query(name: str, rdtype: str) -> tuple[str, list[str]]:
    """One bounded system-resolver question, reduced to a status and its values."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = QUERY_TIMEOUT_SECONDS
    resolver.lifetime = QUERY_TIMEOUT_SECONDS
    try:
        answer = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return NXDOMAIN, []
    except (dns.exception.DNSException, OSError):
        return ERROR, []
    if answer.rrset is None:
        return NODATA, []
    values = []
    for record in answer.rrset:
        value = getattr(record, "target", None) or getattr(record, "address", None) or record
        values.append(str(value).rstrip(".").lower())
    return ANSWER, values


async def _cname_chain(host: str, query: DnsQuery) -> tuple[list[str], str]:
    """The CNAME chain from ``host`` (excluding it) and how the walk ended."""
    chain: list[str] = []
    current = host
    for _hop in range(CNAME_HOPS):
        status, values = await query(current, "CNAME")
        if status == ERROR:
            return chain, ERROR
        target = canonical_name(values[0]) if status == ANSWER and values else None
        if not target or target in chain or target == host:
            return chain, "complete"
        chain.append(target)
        current = target
    return chain, "hop_limit"


async def _terminal_status(name: str, query: DnsQuery) -> str:
    """``nxdomain``, ``answer`` (an address exists), ``nodata`` or ``error`` for one name."""
    status, values = await query(name, "A")
    if status == ANSWER and values:
        return ANSWER
    if status in {NXDOMAIN, ERROR}:
        return status
    status, values = await query(name, "AAAA")
    return ANSWER if status == ANSWER and values else status


def _fingerprint(result: Mapping[str, Any], service: TakeoverService) -> bool:
    """Match the signature against the bounded body, not the short display sample."""
    raw = result.get("body")
    if isinstance(raw, (bytes, bytearray)):
        body = bytes(raw).decode("utf-8", errors="replace")
    else:
        body = str((result.get("response") or {}).get("body_sample") or "")
    return re.search(service.signature, body, re.IGNORECASE) is not None


async def _check_host(
    host: str, *, authorized: bool, query: DnsQuery, http_get: HttpGet | None,
    origin_of: Callable[[str], str | None], confirm: NxdomainConfirm,
    take_request: Callable[[], bool],
) -> tuple[dict[str, Any] | None, int, int]:
    """The host's takeover observation (None without a CNAME), DNS questions asked, GETs sent."""
    counter = {"queries": 0}

    async def counted(name: str, rdtype: str) -> tuple[str, list[str]]:
        counter["queries"] += 1
        return await query(name, rdtype)

    chain, walk = await _cname_chain(host, counted)
    if not chain:
        return None, counter["queries"], 0
    terminal = chain[-1]
    terminal_status = await _terminal_status(terminal, counted) if walk == "complete" else ERROR
    # Signature semantics decide which name must belong to the service: an NXDOMAIN signature
    # is about the service name that does not exist (the terminal), an HTTP signature about the
    # service the operator's record points at (the first hop). A service anywhere else in the
    # chain says nothing: ``shop -> x.trafficmanager.net -> gone.example`` is a dangling name
    # at ``gone.example``, not an Azure takeover.
    if terminal_status == NXDOMAIN:
        service = match_service(terminal)
        service = service if service and service.nxdomain else None
    else:
        service = match_service(chain[0])
        service = service if service and not service.nxdomain else None
    observation: dict[str, Any] = {
        "kind": "takeover_check",
        "host": host,
        "authorized_destination": authorized,
        "cname_chain": chain,
        "terminal": terminal,
        "terminal_status": terminal_status,
        "service": service.name if service else None,
        "service_status": service.status if service else None,
        "service_signature": (
            ("nxdomain" if service.nxdomain else "http_fingerprint") if service else None
        ),
        "outcome": "not_vulnerable",
        "evidence_basis": "dns",
    }
    gets = 0
    if terminal_status == NXDOMAIN:
        # Asking the same recursive resolver again only replays its negative cache: confirm
        # with an independent resolver, or claim nothing stronger than suspected. Only a
        # catalogue NXDOMAIN-signature service name is ever sent there, and never an internal
        # one: any other dangling terminal is suspected without leaving the network.
        confirmed = (
            await confirm(terminal)
            if service is not None and service.status == "vulnerable" and doh_name_permitted(terminal)
            else None
        )
        observation["terminal_nxdomain_confirmed"] = confirmed is True
        observation["confirmation"] = "independent_doh_resolver" if confirmed is not None else None
        if service and service.status == "vulnerable" and confirmed is True:
            observation.update({
                "outcome": "verified", "evidence_basis": "dns_cname_to_nxdomain_service",
            })
        elif confirmed is False:
            observation.update({"outcome": "inconclusive", "evidence_basis": "resolvers_disagree"})
        else:
            observation.update({"outcome": "suspected", "evidence_basis": "dns_dangling_cname"})
    elif terminal_status == ERROR:
        observation["outcome"] = "inconclusive"
    elif service is not None:
        origin = origin_of(host) if authorized else None
        if origin is None or http_get is None:
            # Proving an HTTP-signature takeover needs a request to this name, which is not an
            # authorized destination of this Scan: report the DNS evidence, claim nothing.
            observation["outcome"] = "inconclusive_dns_only"
        elif not take_request():
            observation["outcome"] = "inconclusive"
            observation["evidence_basis"] = "http_budget_exhausted"
        else:
            gets = 1
            result = await http_get(origin)
            response = result.get("response") if isinstance(result.get("response"), Mapping) else {}
            matched = bool(result.get("ok")) and _fingerprint(result, service)
            observation["http"] = {
                "url": origin,
                "status": response.get("status"),
                "body_sha256": response.get("body_sha256"),
                "fingerprint": service.signature,
                "fingerprint_matched": matched,
            }
            observation["evidence_basis"] = "dns_cname_and_http_fingerprint"
            if matched:
                observation["outcome"] = (
                    "verified" if service.status == "vulnerable" else "suspected"
                )
    return observation, counter["queries"], gets


async def check_takeovers(
    *,
    hosts: Sequence[str],
    root_domains: Sequence[str],
    authorized_origins: Sequence[str],
    query: DnsQuery | None = None,
    http_get: HttpGet | None = None,
    confirm: NxdomainConfirm | None = None,
    independent_confirmation: bool = False,
    deadline_seconds: float = 60.0,
    host_limit: int = HOST_LIMIT + 1,
    request_limit: int = 1,
) -> dict[str, Any]:
    """Check names under the bound roots; return an inline operation result.

    ``host_limit`` is the reserved number of names: the bound host(s) first, then at most
    ``HOST_LIMIT`` discovered names within what remains. ``request_limit`` caps the GETs at
    the reserved ``http_requests``. ``authorized_origins`` are the Scan binding's frozen origins:
    only their hosts may receive the HTTP fingerprint request, and only through ``http_get``.
    """
    query = query or dnspython_query
    if not independent_confirmation:
        # The binding is internal (``dns.doh_permitted`` refused it): nothing about its names
        # goes to a third-party resolver, so nothing can be confirmed and nothing verifies.
        async def confirm(_name: str) -> bool | None:
            return None
    else:
        confirm = confirm or doh_nxdomain
    requests_left = {"count": max(0, int(request_limit))}

    def take_request() -> bool:
        if requests_left["count"] <= 0:
            return False
        requests_left["count"] -= 1
        return True
    origins_by_host: dict[str, str] = {}
    for origin in authorized_origins:
        parsed = urllib.parse.urlsplit(str(origin))
        host = canonical_name(parsed.hostname)
        if host and (host not in origins_by_host or parsed.scheme == "https"):
            origins_by_host[host] = str(origin).rstrip("/")
    accepted: list[str] = []
    refused = 0
    for raw in hosts:
        name = next((n for root in root_domains if (n := name_under_apex(raw, root))), None)
        if name is None:
            refused += 1
        elif name not in accepted:
            accepted.append(name)
    # The bound host first: it is the one that can also get an HTTP fingerprint. It is counted
    # in the reservation, and discovered names never exceed HOST_LIMIT on their own.
    bound = sorted(name for name in accepted if name in origins_by_host)
    discovered = sorted(name for name in accepted if name not in origins_by_host)
    budget = max(0, int(host_limit))
    checked = bound[:budget]
    checked += discovered[: max(0, min(HOST_LIMIT, budget - len(checked)))]
    gate = asyncio.Semaphore(CONCURRENCY)
    loop = asyncio.get_running_loop()
    stop_at = loop.time() + max(0.0, float(deadline_seconds))
    started = time.monotonic()

    async def one(host: str) -> tuple[str, dict[str, Any] | None, int, int, bool]:
        async with gate:
            remaining = stop_at - loop.time()
            if remaining <= 0:
                return host, None, 0, 0, False
            try:
                observation, queries, gets = await asyncio.wait_for(
                    _check_host(
                        host, authorized=host in origins_by_host, query=query,
                        http_get=http_get, origin_of=origins_by_host.get,
                        confirm=confirm, take_request=take_request,
                    ),
                    remaining,
                )
            except asyncio.TimeoutError:
                return host, None, 1, 0, False
            return host, observation, queries, gets, True

    results = await asyncio.gather(*(one(host) for host in checked))
    observations = [observation for _h, observation, _q, _g, _done in results if observation]
    unchecked = [host for host, _o, _q, _g, done in results if not done]
    hosts_queried = sum(1 for _h, _o, queries, _g, _done in results if queries)
    gets = sum(gets for _h, _o, _q, gets, _done in results)
    summary = {
        "kind": "takeover_summary",
        "hosts_considered": len(accepted),
        "hosts_checked": len(checked) - len(unchecked),
        "hosts_beyond_limit": max(0, len(accepted) - len(checked)),
        "hosts_deadline_skipped": len(unchecked),
        "hosts_outside_root": refused,
        "hosts_with_cname": len(observations),
        "http_fingerprint_hosts": sorted(origins_by_host),
        "authorization": (
            "discovered names: DNS evidence only; bound target host: DNS evidence and one "
            "same-origin GET fingerprint"
        ),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    partial = bool(unchecked or summary["hosts_beyond_limit"])
    return {
        "status": "partial" if partial else "success",
        "partial": partial,
        "observations": [*observations, summary],
        "budget_consumed": {"hosts_attempted": hosts_queried, "http_requests": gets},
        "errors": (["takeover_deadline"] if unchecked else []),
    }


def bound_takeover_hosts(
    discovered: Iterable[Mapping[str, Any]], *, canonical_host: str | None,
) -> list[str]:
    """The names to check: every discovered subdomain observation, and the bound host."""
    names = [str(row.get("host") or "") for row in discovered if row.get("kind") == "subdomain"]
    if canonical_host:
        names.insert(0, canonical_host)
    return [name for name in names if name]


__all__ = [
    "HOST_LIMIT", "SERVICES", "TakeoverService", "bound_takeover_hosts", "check_takeovers",
    "dnspython_query", "match_service",
]
