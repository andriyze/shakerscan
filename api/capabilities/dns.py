"""Bounded DNS posture inspection for canonical Scan execution."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

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
)


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

    metadata: dict[str, dict[str, Any]] = {}

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

    try:
        rows = await asyncio.wait_for(
            asyncio.gather(*(query(*item) for item in query_plan)),
            timeout=max(1, min(15, int(timeout_seconds))),
        )
    except asyncio.TimeoutError:
        rows = []
        errors.append("dns_inspection:Timeout")
    records = {label: values for label, values in rows}
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
        "errors": errors[:20],
    }
    return {
        "ok": True,
        "status": "partial" if errors else "success",
        "partial": bool(errors),
        "observation": observation,
        "budget_consumed": {
            "hosts_attempted": len({name for _label, name, _type in query_plan}),
            "tool_wall_seconds": min(max(1, int(timeout_seconds)), elapsed),
        },
    }
