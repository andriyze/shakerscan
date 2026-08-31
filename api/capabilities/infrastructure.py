"""Bounded, informational infrastructure intelligence for canonical Scan.

The capability deliberately produces observations, never findings. Registration,
network ownership, PTR, and ASN data describe infrastructure relationships; none
of them proves a vulnerability or an ownership boundary.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import ipaddress
import json
import math
import time
from typing import Any, Awaitable, Callable, Mapping
import urllib.parse

try:
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.models import TargetBinding


_BOOTSTRAP_URLS = {
    "domain": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
_MAX_ADDRESSES = 8
JsonFetcher = Callable[[str, int], Awaitable[Mapping[str, Any]]]


def _validated_external_url(value: Any) -> str:
    """Accept only a public-looking HTTPS RDAP destination."""
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid RDAP destination") from exc
    host = str(parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not host
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
    ):
        raise ValueError("RDAP destination is not an approved HTTPS host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("RDAP destination is not public")
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


async def _bootstrap(
    kind: str,
    *,
    fetch_json: JsonFetcher,
    timeout_seconds: int,
) -> Mapping[str, Any]:
    url = _BOOTSTRAP_URLS[kind]
    return await fetch_json(url, timeout_seconds)


def _service_rows(bootstrap: Mapping[str, Any]) -> tuple[tuple[list[str], list[str]], ...]:
    rows: list[tuple[list[str], list[str]]] = []
    for raw in bootstrap.get("services") or ():
        if not isinstance(raw, (list, tuple)) or len(raw) != 2:
            continue
        keys = [str(item).strip().lower() for item in raw[0] or () if str(item).strip()]
        urls = [str(item).strip() for item in raw[1] or () if str(item).strip()]
        if keys and urls:
            rows.append((keys, urls))
    return tuple(rows)


def _domain_rdap_base(bootstrap: Mapping[str, Any], domain: str) -> str | None:
    tld = str(domain or "").lower().rstrip(".").rsplit(".", 1)[-1]
    for keys, urls in _service_rows(bootstrap):
        if tld in keys:
            for url in urls:
                try:
                    return _validated_external_url(url)
                except ValueError:
                    continue
    return None


def _ip_rdap_base(bootstrap: Mapping[str, Any], address: str) -> str | None:
    parsed = ipaddress.ip_address(address)
    matches: list[tuple[int, str]] = []
    for keys, urls in _service_rows(bootstrap):
        for key in keys:
            try:
                network = ipaddress.ip_network(key, strict=False)
            except ValueError:
                continue
            if parsed.version != network.version or parsed not in network:
                continue
            for url in urls:
                try:
                    matches.append((network.prefixlen, _validated_external_url(url)))
                except ValueError:
                    continue
    return max(matches, default=(0, None), key=lambda item: item[0])[1]


def _entity_name(entity: Mapping[str, Any]) -> str | None:
    public_ids = entity.get("publicIds")
    if isinstance(public_ids, list):
        for item in public_ids:
            if isinstance(item, Mapping) and str(item.get("identifier") or "").strip():
                return str(item["identifier"]).strip()[:300]
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if (
                isinstance(item, list)
                and len(item) >= 4
                and str(item[0]).lower() in {"fn", "org"}
                and str(item[3]).strip()
            ):
                value = item[3]
                if isinstance(value, list):
                    value = " ".join(str(part) for part in value if str(part).strip())
                return str(value).strip()[:300]
    return None


def _entities(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in value or ():
        if not isinstance(raw, Mapping):
            continue
        roles = sorted({str(item)[:80] for item in raw.get("roles") or () if str(item)})
        row = {
            "handle": str(raw.get("handle") or "")[:200] or None,
            "roles": roles,
            "name": _entity_name(raw),
        }
        if any(row.values()):
            rows.append(row)
    return rows[:20]


def _events(value: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw in value or ():
        if not isinstance(raw, Mapping):
            continue
        action = str(raw.get("eventAction") or "").strip()[:100]
        date = str(raw.get("eventDate") or "").strip()[:100]
        if action or date:
            rows.append({"action": action, "date": date})
    return rows[:30]


def _domain_summary(payload: Mapping[str, Any], *, source_url: str) -> dict[str, Any]:
    nameservers = []
    for raw in payload.get("nameservers") or ():
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("ldhName") or raw.get("unicodeName") or "").lower().rstrip(".")
        if name:
            nameservers.append(name[:253])
    secure = payload.get("secureDNS") if isinstance(payload.get("secureDNS"), Mapping) else {}
    registrar = next((
        item for item in _entities(payload.get("entities"))
        if "registrar" in item.get("roles", ())
    ), None)
    return {
        "source": "rdap",
        "source_url": source_url,
        "handle": str(payload.get("handle") or "")[:200] or None,
        "domain": str(payload.get("ldhName") or payload.get("unicodeName") or "")[:253] or None,
        "status": sorted({str(item)[:100] for item in payload.get("status") or () if str(item)}),
        "events": _events(payload.get("events")),
        "nameservers": sorted(set(nameservers))[:50],
        "dnssec_signed": secure.get("delegationSigned"),
        "registrar": registrar,
        "notices": [
            str(item.get("title") or "")[:200]
            for item in payload.get("notices") or ()
            if isinstance(item, Mapping) and str(item.get("title") or "").strip()
        ][:20],
    }


def _network_summary(payload: Mapping[str, Any], *, source_url: str) -> dict[str, Any]:
    cidrs: list[str] = []
    for raw in payload.get("cidr0_cidrs") or ():
        if not isinstance(raw, Mapping):
            continue
        prefix = raw.get("v4prefix") or raw.get("v6prefix")
        length = raw.get("length")
        if prefix not in (None, "") and isinstance(length, int):
            cidrs.append(f"{prefix}/{length}")
    return {
        "source": "rdap",
        "source_url": source_url,
        "handle": str(payload.get("handle") or "")[:200] or None,
        "name": str(payload.get("name") or "")[:300] or None,
        "type": str(payload.get("type") or "")[:100] or None,
        "country": str(payload.get("country") or "")[:2].upper() or None,
        "start_address": str(payload.get("startAddress") or "")[:80] or None,
        "end_address": str(payload.get("endAddress") or "")[:80] or None,
        "cidrs": cidrs[:20],
        "parent_handle": str(payload.get("parentHandle") or "")[:200] or None,
        "status": sorted({str(item)[:100] for item in payload.get("status") or () if str(item)}),
        "entities": _entities(payload.get("entities")),
    }


def _registration_domain(target: TargetBinding) -> str | None:
    host = str(target.canonical_host or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None
    roots = sorted({
        str(item).lower().rstrip(".")
        for item in target.allowed_root_domains
        if str(item).strip()
        and (host == str(item).lower().rstrip(".") or host.endswith("." + str(item).lower().rstrip(".")))
    }, key=len, reverse=True)
    return roots[0] if roots else host or None


async def _dns_value(resolver: Any, name: str, query_type: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, query_type, lifetime=4, search=False)
    except Exception:  # dnspython exposes resolver-specific subclasses.
        return []
    values: list[str] = []
    for raw in list(answer)[:20]:
        strings = getattr(raw, "strings", None)
        if strings:
            value = "".join(
                item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
                for item in strings
            )
        else:
            value = str(raw).strip().strip('"').rstrip(".")
        if value:
            values.append(value[:1000])
    return values


def _parse_cymru_origin(value: str) -> dict[str, Any] | None:
    parts = [item.strip() for item in str(value or "").strip().strip('"').split("|")]
    if len(parts) < 3 or not parts[0].upper().removeprefix("AS").isdigit():
        return None
    return {
        "source": "team_cymru_dns",
        "asn": parts[0].upper().removeprefix("AS"),
        "prefix": parts[2] or None,
        "country": parts[3].upper() if len(parts) > 3 and parts[3] else None,
        "registry": parts[4].lower() if len(parts) > 4 and parts[4] else None,
        "allocated": parts[5] if len(parts) > 5 and parts[5] else None,
    }


async def inspect_infrastructure_intelligence(
    target: TargetBinding,
    *,
    timeout_seconds: int = 30,
    fetch_json: JsonFetcher | None = None,
    resolver: Any | None = None,
) -> dict[str, Any]:
    """Collect authoritative registration and address context without scoring it."""
    if target.target_kind not in {"web", "api"}:
        return {"ok": False, "status": "blocked", "error": "scope:unsupported target kind", "budget_consumed": {}}
    addresses: list[str] = []
    for raw in target.allowed_addresses:
        try:
            addresses.append(str(ipaddress.ip_address(str(raw))))
        except ValueError:
            continue
    addresses = list(dict.fromkeys(addresses))[:_MAX_ADDRESSES]
    domain = _registration_domain(target)
    if not domain and not addresses:
        return {"ok": False, "status": "blocked", "error": "scope:no bound domain or address", "budget_consumed": {}}
    # RDAP and Team Cymru are non-target egress. Canonical Scan does not own a reviewed
    # transport for them yet, so production execution fails closed instead of opening raw
    # sockets from a capability module. Tests or a future reviewed provider may inject both
    # transports explicitly; neither target credentials nor target routing are passed to them.
    if fetch_json is None or resolver is None:
        return {
            "ok": False,
            "status": "blocked",
            "error": "infrastructure_intelligence_transport_unavailable",
            "budget_consumed": {},
        }
    fetch = fetch_json
    started = time.perf_counter()
    attempts = 0
    errors: list[str] = []
    registration: dict[str, Any] | None = None
    address_rows: list[dict[str, Any]] = []

    async def collect() -> None:
        nonlocal attempts, registration
        bootstrap_timeout = max(2, min(8, int(timeout_seconds) // 3 or 2))
        bootstraps: dict[str, Mapping[str, Any]] = {}
        for kind in ("domain", "ipv4", "ipv6"):
            try:
                attempts += 1
                bootstraps[kind] = await _bootstrap(
                    kind, fetch_json=fetch, timeout_seconds=bootstrap_timeout,
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{kind}_bootstrap:{type(exc).__name__}")

        if domain and "domain" in bootstraps:
            base = _domain_rdap_base(bootstraps["domain"], domain)
            if base:
                url = f"{base.rstrip('/')}/domain/{urllib.parse.quote(domain, safe='')}"
                try:
                    attempts += 1
                    registration = _domain_summary(
                        await fetch(url, bootstrap_timeout), source_url=url,
                    )
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    errors.append(f"domain_rdap:{type(exc).__name__}")
            else:
                errors.append("domain_rdap:service_unavailable")

        async def address_context(address: str) -> dict[str, Any]:
            nonlocal attempts
            row: dict[str, Any] = {"address": address, "scope": "bound_target_address"}
            kind = "ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6"
            bootstrap = bootstraps.get(kind)
            if bootstrap is not None:
                base = _ip_rdap_base(bootstrap, address)
                if base:
                    url = f"{base.rstrip('/')}/ip/{urllib.parse.quote(address, safe='')}"
                    try:
                        attempts += 1
                        row["network"] = _network_summary(
                            await fetch(url, bootstrap_timeout), source_url=url,
                        )
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        errors.append(f"ip_rdap:{address}:{type(exc).__name__}")
                else:
                    errors.append(f"ip_rdap:{address}:service_unavailable")
            try:
                reverse_name = ipaddress.ip_address(address).reverse_pointer
                attempts += 1
                ptr = await _dns_value(resolver, reverse_name, "PTR")
                if ptr:
                    row["ptr_names"] = sorted(set(ptr))[:20]
            except ValueError:
                pass
            try:
                parsed_ip = ipaddress.ip_address(address)
                if parsed_ip.version == 4:
                    origin_name = ".".join(reversed(address.split("."))) + ".origin.asn.cymru.com"
                else:
                    origin_name = ".".join(reversed(parsed_ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
                attempts += 1
                origin = await _dns_value(resolver, origin_name, "TXT")
                asn = _parse_cymru_origin(origin[0]) if origin else None
                if asn:
                    attempts += 1
                    names = await _dns_value(resolver, f"AS{asn['asn']}.asn.cymru.com", "TXT")
                    if names:
                        name_parts = [item.strip() for item in names[0].strip('"').split("|")]
                        if len(name_parts) >= 5:
                            asn["name"] = name_parts[4][:300]
                    row["asn"] = asn
            except ValueError:
                pass
            return row

        address_rows.extend(await asyncio.gather(*(address_context(item) for item in addresses)))

    timed_out = False
    try:
        await asyncio.wait_for(collect(), timeout=max(5, min(30, int(timeout_seconds))))
    except asyncio.TimeoutError:
        timed_out = True
        errors.append("infrastructure_intelligence:Timeout")
    elapsed = max(1, math.ceil(time.perf_counter() - started))
    related_names = sorted({
        name
        for row in address_rows
        for name in row.get("ptr_names") or ()
        if name and name != target.canonical_host
    })[:100]
    observation = {
        "kind": "infrastructure_intelligence",
        "informational_only": True,
        "scoring_effect": "none",
        "canonical_host": target.canonical_host,
        "registration_domain": domain,
        "observed_at": datetime.now(UTC).isoformat(),
        "registration": registration,
        "addresses": address_rows,
        "related_names": [
            {"name": name, "source": "ptr", "scope": "external_unverified"}
            for name in related_names
        ],
        "limitations": [
            "Related names are observations, not proof of ownership or authorization.",
            "Shared-IP discovery is incomplete without a historical passive-DNS corpus.",
            "No related name was scanned by this capability.",
        ],
        "errors": errors[:100],
    }
    # Enrichment availability is deliberately not Scan security coverage. A rate
    # limit or redacted RDAP response remains a successful informational action.
    return {
        "ok": True,
        "status": "success",
        "partial": False,
        "timed_out": timed_out,
        "observation": observation,
        "budget_consumed": {
            "hosts_attempted": min(40, attempts),
            "tool_wall_seconds": min(max(1, int(timeout_seconds)), elapsed),
        },
    }
