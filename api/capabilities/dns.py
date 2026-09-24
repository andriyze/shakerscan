"""Bounded DNS posture inspection for canonical Scan execution."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import time
from typing import Any, Awaitable, Callable

from runtime.models import TargetBinding


_QUERY_PLAN = (
    ("host_a", "host", "A"),
    ("host_aaaa", "host", "AAAA"),
    ("host_cname", "host", "CNAME"),
    ("root_ns", "root", "NS"),
    ("root_soa", "root", "SOA"),
    ("root_ds", "root", "DS"),
    ("host_mx", "host", "MX"),
    ("host_txt", "host", "TXT"),
    ("host_caa", "host", "CAA"),
    ("host_dnskey", "host", "DNSKEY"),
    ("dmarc", "_dmarc", "TXT"),
    ("tls_rpt", "_smtp._tls", "TXT"),
    ("mta_sts", "_mta-sts", "TXT"),
    # DKIM has no discoverable name: a key is published under a selector the
    # sender chooses, so a scanner can only ask for the conventional ones. These
    # are the selectors the common providers publish, and a miss is silence, not
    # an error. Without them the mail-policy picture stopped at SPF and DMARC and
    # could never say whether the domain signs at all.
    ("dkim_default", "default._domainkey", "TXT"),
    ("dkim_google", "google._domainkey", "TXT"),
    ("dkim_selector1", "selector1._domainkey", "TXT"),
    ("dkim_selector2", "selector2._domainkey", "TXT"),
    ("dkim_k1", "k1._domainkey", "TXT"),
    ("dkim_mail", "mail._domainkey", "TXT"),
)


# Small enough that one resolver answers every wave promptly, large enough that
# the whole plan still finishes well inside the action's wall.
_MAX_CONCURRENT_QUERIES = 4

# Some forwarders answer only the common types. Docker Desktop's embedded DNS
# returned A, MX and TXT in 30 ms and let CAA, DNSKEY, DS and CNAME time out,
# so every local scan reported DNS posture partial and the report could never
# say whether the domain publishes CAA or signs with DNSSEC. When a query
# times out, ask a DNS-over-HTTPS resolver over the HTTPS egress the scan
# already uses. Only for public names: an internal host's name must not leave
# the network as a resolver query.
_DOH_RESOLVERS = tuple(
    item.strip()
    for item in os.environ.get(
        "SHAKERSCAN_DNS_DOH_RESOLVERS",
        "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query",
    ).split(",")
    if item.strip().startswith("https://")
)
_TIMEOUT_CLASSES = frozenset({"LifetimeTimeout", "Timeout", "TimeoutError"})
# A stub resolver that cannot answer a type says so with SERVFAIL, which dnspython
# raises as NoNameservers: systemd-resolved on a stock Ubuntu 24.04 host did that
# for every DS and DNSKEY query. That is the same "this forwarder cannot answer"
# outcome as a timeout, and the fallback must cover it.
_FALLBACK_CLASSES = _TIMEOUT_CLASSES | frozenset({"NoNameservers"})
_PRIVATE_NAME_SUFFIXES = (
    ".local", ".localhost", ".internal", ".test", ".example", ".invalid", ".home.arpa", ".lan",
)

DohQuery = Callable[[str, str], Awaitable[Any]]


def doh_permitted(target: TargetBinding) -> bool:
    """Whether the bound host is public enough for a third-party resolver to see."""
    host = str(target.canonical_host or "").lower().rstrip(".")
    if "." not in host or host.endswith(_PRIVATE_NAME_SUFFIXES):
        return False
    for address in target.allowed_addresses:
        try:
            if not ipaddress.ip_address(str(address)).is_global:
                return False
        except ValueError:
            return False
    return True


class DohAnswerInvalid(ValueError):
    """The resolver answered over HTTP, but not the question that was asked."""


def validate_doh_message(message: Any, name: str, query_type: str) -> Any:
    """Accept only a complete DNS answer to this exact question.

    HTTP success is not DNS success (RFC 8484 §4.2.1): SERVFAIL, REFUSED, a
    truncated message, or an answer to a different name all arrive as 200.
    NXDOMAIN and an empty NOERROR are real negative answers and pass.
    """
    import dns.flags
    import dns.name
    import dns.rcode
    import dns.rdatatype

    rcode = message.rcode()
    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        raise DohAnswerInvalid(f"rcode:{dns.rcode.to_text(rcode)}")
    if int(message.flags) & int(dns.flags.TC):
        raise DohAnswerInvalid("truncated")
    wanted_name = dns.name.from_text(name)
    wanted_type = dns.rdatatype.from_text(query_type)
    questions = list(getattr(message, "question", ()))
    if len(questions) != 1 or questions[0].name != wanted_name or questions[0].rdtype != wanted_type:
        raise DohAnswerInvalid("question_mismatch")
    # Every answer rrset must belong to the asked name or to a CNAME target the
    # answer itself introduces; a record for some other owner is not evidence.
    owners = {wanted_name}
    for rrset in message.answer:
        if rrset.rdtype == dns.rdatatype.CNAME and rrset.name in owners:
            for record in rrset:
                owners.add(record.target)
    for rrset in message.answer:
        if rrset.name not in owners:
            raise DohAnswerInvalid("answer_owner_mismatch")
    return message


async def _doh_query(name: str, query_type: str, *, transport: Any | None = None) -> Any:
    """Resolve over HTTPS; the first resolver with a valid answer wins."""
    import dns.message
    import httpx

    wire = dns.message.make_query(name, query_type).to_wire()
    encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
    last: Exception | None = None
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, transport=transport) as client:
        for url in _DOH_RESOLVERS:
            try:
                response = await client.get(
                    url, params={"dns": encoded}, headers={"accept": "application/dns-message"},
                )
                response.raise_for_status()
                return validate_doh_message(dns.message.from_wire(response.content), name, query_type)
            except Exception as exc:  # noqa: BLE001 - try the next resolver
                last = exc
    raise last or RuntimeError("no DoH resolver configured")


def _safe_text(value: Any, limit: int) -> str:
    return "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in str(value)
    ).strip()[:limit]


def _bound_name(target: TargetBinding, prefix: str) -> str:
    host = str(target.canonical_host or "").lower().rstrip(".")
    roots = tuple(
        str(root).lower().rstrip(".")
        for root in target.allowed_root_domains
        if str(root).strip()
    )
    if (
        not host
        or not roots
        or not any(host == root or host.endswith("." + root) for root in roots)
    ):
        raise ValueError("scope: DNS host is outside the frozen root binding")
    if prefix == "root":
        candidates = sorted(
            (root for root in roots if host == root or host.endswith("." + root)),
            key=len,
            reverse=True,
        )
        if not candidates:
            raise ValueError("scope: DNS root is outside the frozen root binding")
        name = candidates[0]
    else:
        name = host if prefix == "host" else f"{prefix}.{host}"
    if not any(name == root or name.endswith("." + root) for root in roots):
        raise ValueError("scope: DNS query name is outside the frozen root binding")
    return name


def _txt_value(record: Any) -> str:
    strings = getattr(record, "strings", None)
    if strings:
        return _safe_text("".join(
            value.decode("utf-8", errors="replace")
            if isinstance(value, bytes) else str(value)
            for value in strings
        ), 2_000)
    return _safe_text(str(record).strip().strip('"'), 2_000)


def _record_value(query_type: str, record: Any) -> Any:
    if query_type == "MX":
        return {
            "priority": int(getattr(record, "preference", 0)),
            "host": _safe_text(
                str(getattr(record, "exchange", "")).rstrip("."), 253,
            ),
        }
    if query_type == "CAA":
        tag = getattr(record, "tag", b"")
        value = getattr(record, "value", b"")
        return {
            "flags": int(getattr(record, "flags", 0)),
            "tag": _safe_text((
                tag.decode("ascii", errors="replace")
                if isinstance(tag, bytes) else str(tag)
            ), 100),
            "value": _safe_text((
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes) else str(value)
            ), 1_000),
        }
    if query_type == "TXT":
        return _txt_value(record)
    if query_type == "DNSKEY":
        return {
            "flags": int(getattr(record, "flags", 0)),
            "protocol": int(getattr(record, "protocol", 0)),
            "algorithm": int(getattr(record, "algorithm", 0)),
        }
    if query_type == "DS":
        return {
            "key_tag": int(getattr(record, "key_tag", 0)),
            "algorithm": int(getattr(record, "algorithm", 0)),
            "digest_type": int(getattr(record, "digest_type", 0)),
            "digest": _safe_text(str(getattr(record, "digest", "")), 1_000),
        }
    if query_type == "SOA":
        return {
            "primary_nameserver": _safe_text(str(getattr(record, "mname", "")).rstrip("."), 253),
            "responsible_mailbox": _safe_text(str(getattr(record, "rname", "")).rstrip("."), 253),
            "serial": int(getattr(record, "serial", 0)),
            "refresh": int(getattr(record, "refresh", 0)),
            "retry": int(getattr(record, "retry", 0)),
            "expire": int(getattr(record, "expire", 0)),
            "minimum": int(getattr(record, "minimum", 0)),
        }
    return _safe_text(str(record).rstrip("."), 1_000)


async def inspect_dns_posture(
    target: TargetBinding,
    *,
    timeout_seconds: int = 15,
    resolver: Any | None = None,
    doh_query: DohQuery | None = _doh_query,
) -> dict[str, Any]:
    """Query one fixed record plan whose names are derived from the binding."""
    try:
        query_plan = tuple(
            (label, _bound_name(target, prefix), query_type)
            for label, prefix, query_type in _QUERY_PLAN
        )
    except ValueError as exc:
        return {
            "ok": False,
            "status": "blocked",
            "error": str(exc),
            "budget_consumed": {},
        }
    if resolver is None:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver(configure=True)
    started = time.perf_counter()
    authenticated: list[str] = []
    errors: list[str] = []
    fallback_labels: list[str] = []
    use_doh = doh_query is not None and bool(_DOH_RESOLVERS) and doh_permitted(target)

    metadata: dict[str, dict[str, Any]] = {}

    async def over_https(label: str, name: str, query_type: str) -> tuple[str, list[Any]] | None:
        import dns.rdatatype

        try:
            message = await asyncio.wait_for(doh_query(name, query_type), timeout=6)
        except Exception as exc:  # noqa: BLE001 - the primary timeout stays the error
            detail = f":{exc}" if isinstance(exc, DohAnswerInvalid) else ""
            errors.append(f"{label}:doh:{type(exc).__name__}{detail}"[:200])
            return None
        wanted = dns.rdatatype.from_text(query_type)
        records = [
            record for rrset in getattr(message, "answer", ())
            if getattr(rrset, "rdtype", None) == wanted
            for record in rrset
        ]
        ttl = min((int(rrset.ttl) for rrset in message.answer if rrset.rdtype == wanted), default=None)
        metadata[label] = {
            "name": name, "type": query_type, "ttl": ttl,
            "answer_count": len(records[:50]), "resolver": "doh",
        }
        fallback_labels.append(label)
        return label, [_record_value(query_type, record) for record in records[:50]]

    async def query(label: str, name: str, query_type: str) -> tuple[str, list[Any]]:
        try:
            answer = await resolver.resolve(
                name,
                query_type,
                lifetime=max(1, min(5, int(timeout_seconds))),
                search=False,
            )
        except Exception as exc:  # Resolver implementations expose many subclasses.
            class_name = type(exc).__name__
            if class_name in {"NXDOMAIN", "NoAnswer"}:
                return label, []
            if use_doh and class_name in _FALLBACK_CLASSES:
                recovered = await over_https(label, name, query_type)
                if recovered is not None:
                    return recovered
            errors.append(f"{label}:{class_name}"[:200])
            return label, []
        try:
            import dns.flags

            response = getattr(answer, "response", None)
            if response is not None and int(response.flags) & int(dns.flags.AD):
                authenticated.append(label)
        except (AttributeError, ModuleNotFoundError, TypeError, ValueError):
            pass
        values = [_record_value(query_type, record) for record in list(answer)[:50]]
        rrset = getattr(answer, "rrset", None)
        ttl = getattr(rrset, "ttl", None)
        metadata[label] = {
            "name": name,
            "type": query_type,
            "ttl": int(ttl) if isinstance(ttl, int) and ttl >= 0 else None,
            "answer_count": len(values),
        }
        return label, values

    # Bound the fan-out. Firing the whole plan at one resolver at once made
    # later queries report LifetimeTimeout after the full five seconds while the
    # same lookups answer in under a tenth of a second on their own: a measured
    # run lost TXT, CAA, DNSKEY, MX and CNAME that way, so the report silently
    # dropped SPF, CAA policy and DNSSEC while spending a third of its wall.
    gate = asyncio.Semaphore(_MAX_CONCURRENT_QUERIES)

    async def bounded(label: str, name: str, query_type: str) -> tuple[str, list[Any]]:
        async with gate:
            return await query(label, name, query_type)

    # Keep what already answered. Wrapping the whole plan in one deadline and
    # discarding its result on expiry threw away every completed record: a
    # nineteen-query plan run four at a time can cross the deadline mid-wave, and
    # the run then reported nothing at all while its own metadata still showed a
    # dozen answers. Settle each query as it finishes and cancel only the rest.
    records: dict[str, list[Any]] = {}
    tasks = [asyncio.ensure_future(bounded(*item)) for item in query_plan]
    try:
        done, pending = await asyncio.wait(
            tasks,
            timeout=max(1, min(15, int(timeout_seconds))),
            return_when=asyncio.ALL_COMPLETED,
        )
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        raise
    if pending:
        errors.append(f"dns_inspection:Timeout:{len(pending)}")
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        try:
            label, values = task.result()
        except Exception as exc:  # noqa: BLE001 - one query must not lose the rest
            errors.append(f"dns_inspection:{type(exc).__name__}"[:200])
            continue
        records[label] = values
    for label, _name, _query_type in query_plan:
        records.setdefault(label, [])
    bound_ipv4: list[str] = []
    bound_ipv6: list[str] = []
    for address in target.allowed_addresses:
        try:
            parsed_address = ipaddress.ip_address(str(address))
        except ValueError:
            continue
        (bound_ipv4 if parsed_address.version == 4 else bound_ipv6).append(
            str(parsed_address)
        )
    elapsed = max(1, int(time.perf_counter() - started + 0.999))
    observation = {
        "kind": "dns_posture",
        "canonical_host": target.canonical_host,
        "bound_addresses": {"A": bound_ipv4[:50], "AAAA": bound_ipv6[:50]},
        "query_names": {
            label: name for label, name, _query_type in query_plan
        },
        "records": records,
        "record_metadata": metadata,
        "authenticated_queries": sorted(set(authenticated)),
        "query_count": len(query_plan),
        "doh_fallback_queries": sorted(set(fallback_labels)),
        "errors": errors[:20],
    }
    # State why the result is partial ahead of the per-query errors. The receipt
    # takes the first recognised reason code; without one, a partial result was
    # explained as "the bounded output limit was reached", which was false: the
    # queries that are missing timed out or failed at the resolver, nothing was
    # cut off.
    stated: list[str] = []
    if errors:
        # A failed HTTPS fallback is secondary; the primary resolver's outcome
        # is what the receipt states.
        primary = [item for item in errors if ":doh:" not in item] or errors
        stated.append(
            "timed_out"
            if all("Timeout" in item.split(":", 1)[-1] for item in primary)
            else "adapter_failed"
        )
    return {
        "ok": True,
        "status": "partial" if errors else "success",
        "partial": bool(errors),
        "errors": [*stated, *errors[:20]],
        "observation": observation,
        "budget_consumed": {
            "hosts_attempted": len({name for _label, name, _type in query_plan}),
            "tool_wall_seconds": min(max(1, int(timeout_seconds)), elapsed),
        },
    }
