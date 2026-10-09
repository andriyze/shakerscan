"""Central scope guard for future state-changing actions.

The guard is deliberately deterministic and side-effect free. API handlers can
persist the returned receipt, but validation itself does not perform network
requests or follow redirects.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
import urllib.parse
from typing import Any

import idna

import deployment_policy

try:
    from scanner_tools.address_classes import (
        IPAddress, always_refused, cloud_service_address, destination_block_reason,
        embedded_ipv4_addresses, judged_addresses, private_class, shared_address_space,
    )
except ModuleNotFoundError:  # package import (api.action_scope)
    from scanner.scanner_tools.address_classes import (
        IPAddress, always_refused, cloud_service_address, destination_block_reason,
        embedded_ipv4_addresses, judged_addresses, private_class, shared_address_space,
    )
try:
    from scope.psl import is_public_suffix, public_suffix_refusal
except ModuleNotFoundError:  # package import (api.action_scope)
    from api.scope.psl import is_public_suffix, public_suffix_refusal


SAFE_LAB_ENVIRONMENTS = {"development", "dev", "preview", "staging", "lab", "test"}
ALLOWED_SCHEMES = {"http", "https"}
CIDR_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w:])")
PRIVATE_NETWORK_TARGETS_DOC = (
    "https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md"
    "#15-safety-model"
)


@dataclass(frozen=True)
class ScopeCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class ScopeReceipt:
    receipt_id: str
    input_scope: dict[str, Any]
    normalized_scope: dict[str, Any]
    verdict: str
    checks: tuple[ScopeCheck, ...]
    blocked_by: tuple[str, ...]
    warnings: tuple[str, ...]
    environment: str
    allowed_hosts: tuple[str, ...]
    allowed_root_domains: tuple[str, ...]
    redirect_destinations: tuple[dict[str, Any], ...]


def _add_check(checks: list[ScopeCheck], name: str, status: str, message: str) -> None:
    checks.append(ScopeCheck(name=name, status=status, message=message))


def _canonical_host(value: str | None) -> str:
    """The ASCII host the HTTP client connects to.

    A non-ASCII host is encoded with IDNA 2008 and the UTS #46 mapping, as httpx and browsers
    resolve it: Python's ``idna`` codec is IDNA 2003, which maps ``straße.example`` to
    ``strasse.example`` while the client connects to ``xn--strae-oqa.example``, so the scope
    decision and the connection named different hosts. Full-width and zero-width spellings map
    to the same ASCII host under both. A host neither encodes is returned unchanged (and is
    refused as an invalid origin where one is required).
    """
    host = str(value or "").strip().strip("[]").lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        if host.isascii():
            return host.encode("idna").decode("ascii")
        return idna.encode(host, uts46=True).decode("ascii").rstrip(".")
    except (UnicodeError, idna.IDNAError):
        return host


def approval_context_value_matches(key: str, actual: Any, expected: Any) -> bool:
    """Compare approval context, treating confirmed origin addresses as an exact set."""
    if key != "direct_origin_addresses":
        return actual == expected
    if not isinstance(actual, (list, tuple)) or not isinstance(expected, (list, tuple)):
        return False
    try:
        actual_addresses = sorted({str(ipaddress.ip_address(str(item))) for item in actual})
        expected_addresses = sorted({str(ipaddress.ip_address(str(item))) for item in expected})
    except (TypeError, ValueError):
        return False
    return actual_addresses == expected_addresses


def approval_context_mismatch(
    actual: dict[str, Any], expected: dict[str, Any],
) -> str | None:
    """Return the first approval context field that does not match."""
    return next((
        key for key, value in expected.items()
        if not approval_context_value_matches(key, actual.get(key), value)
    ), None)


def scope_roots(roots: Any) -> tuple[str, ...]:
    """The ``allowed_root_domains`` that may widen scope: a root that is itself a public suffix
    (``co.uk``, ``github.io``, ``com``; Public Suffix List with its private section) would cover
    every site under it, so it covers nothing. Persisted receipts and guards that carry one fail
    closed through this filter rather than being reinterpreted."""
    return tuple(
        root for root in (str(item or "").strip().lower().rstrip(".") for item in roots or ())
        if root and not is_public_suffix(root)
    )


def _host_matches(host: str, allowed_hosts: tuple[str, ...], allowed_root_domains: tuple[str, ...]) -> bool:
    if host in allowed_hosts:
        return True
    return any(host == root or host.endswith(f".{root}") for root in allowed_root_domains)


def _deployment_allows_private_networks(allow_private_networks: bool | None) -> bool:
    if allow_private_networks is not None:
        return bool(allow_private_networks)
    return deployment_policy.private_network_targets_allowed()


def _ip_scope_block_reason(
    host: str,
    environment: str,
    *,
    allow_private_networks: bool | None = None,
) -> str | None:
    """Why an address is refused, or None.

    Lab environments admit local targets. A deployment that sets
    SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow also admits loopback/private targets in other
    environments; shared address space (100.64.0.0/10, CGNAT and Tailscale) is private here. Special cloud-service destinations, link-local, multicast, unspecified
    addresses and the limited broadcast address remain denied regardless of that permission.
    An IPv6 address that carries an IPv4 address (``embedded_ipv4_addresses``) is judged as
    every address it carries as well as itself.
    """
    lowered = host.lower().strip("[]")
    deployment_allows = _deployment_allows_private_networks(allow_private_networks)
    if lowered in {"localhost", "localhost.localdomain"}:
        if environment in SAFE_LAB_ENVIRONMENTS or deployment_allows:
            return None
        return "loopback_or_private_range"
    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return None
    # ::ffff:a.b.c.d is a.b.c.d, 64:ff9b::a.b.c.d reaches a.b.c.d through NAT64, and so on:
    # every embedded IPv4 address is classified, so another spelling of a restricted address is
    # not admitted where the plain spelling is refused. Restricted classes are tested first, so
    # no label admits them (a Lab label once admitted 169.254.169.254). Shared address space
    # (100.64.0.0/10: CGNAT, Tailscale) is private-class. The decision lives in
    # ``address_classes.destination_block_reason`` so the scanner's own egress shares it.
    return destination_block_reason(
        ip_obj, lab=environment in SAFE_LAB_ENVIRONMENTS, allow_private=deployment_allows,
    )


# Never routable to a real origin, whatever the deployment admits: "this network" and the
# reserved 240.0.0.0/4 (the private setting would otherwise admit them as reserved space).
_NEVER_AN_ORIGIN = tuple(ipaddress.ip_network(raw) for raw in ("0.0.0.0/8", "240.0.0.0/4"))


def direct_origin_refusal(
    value: object, *, allow_private_networks: bool | None = None,
) -> str | None:
    """Why an operator-confirmed Hunt direct-origin address is refused, or None.

    The web scope guard's classification (``_ip_scope_block_reason`` under ``production``: a
    target's Lab label never widens a direct origin), with the cloud metadata and platform-service
    addresses refused in every spelling, and "this network" and 240.0.0.0/4 never an origin. The
    Hunt start contract applies it to every confirmed address and the HTTP capability applies it
    again to the one it connects to. A hostname is refused: the operator names the machine.
    """
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return "not_a_literal_address"
    candidates = judged_addresses(address)
    if any(cloud_service_address(item) for item in candidates):
        return "cloud_service_address"
    if any(item.version == network.version and item in network
           for item in candidates for network in _NEVER_AN_ORIGIN):
        return "non_routable_address"
    return _ip_scope_block_reason(
        str(address), "production", allow_private_networks=allow_private_networks,
    )


def public_unicast_address(value: object) -> bool:
    """A globally routable unicast address no deployment setting is needed to reach.

    The hard limit for a destination a person authorizes for a Hunt (D39), whatever the
    deployment admits for its registered targets: never loopback, private, link-local, reserved,
    shared (100.64.0.0/10), multicast, a cloud metadata or platform-service address, or an IPv6
    spelling (NAT64, mapped, 6to4, Teredo) of any of them.
    """
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return False
    if _ip_scope_block_reason(str(address), "production", allow_private_networks=False) is not None:
        return False
    return all(
        candidate.is_global and not candidate.is_multicast
        for candidate in (address, *embedded_ipv4_addresses(address))
    )


def destination_refusal_explanation(host: str, environment: str) -> str:
    """Why ``host`` is refused as a destination, in words an operator can act on.

    Two different decisions produce the same ``loopback_or_private_range`` code and used to
    produce the same message, so an operator could not tell a class no setting admits (the cloud
    metadata address) from one their own deployment chose to refuse (a private intranet address
    under ``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=refuse``). This names which one it is and, for the
    second, the supported setting that changes it.
    """
    lowered = str(host or "").lower().strip("[]")
    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        ip_obj = None
    if ip_obj is not None:
        # Name the address a translator would reach (NAT64, mapped, 6to4, Teredo), when that is
        # the one refused.
        def weight(item: IPAddress) -> int:
            return (0 if cloud_service_address(item) else 1 if item.is_link_local
                    else 2 if always_refused(item) else 3 if private_class(item) else 4)

        embedded = embedded_ipv4_addresses(ip_obj)
        if embedded:
            first = min(embedded, key=weight)
            if weight(first) < 4 or getattr(ip_obj, "ipv4_mapped", None) is not None:
                ip_obj = first
        restricted = (
            "a cloud metadata or platform-service" if cloud_service_address(ip_obj)
            else "a link-local" if ip_obj.is_link_local
            else "a multicast" if ip_obj.is_multicast
            else "an unspecified" if ip_obj.is_unspecified
            else "the broadcast" if str(ip_obj) == "255.255.255.255"
            else None
        )
        if restricted:
            return f"{lowered} is {restricted} address, which is never scanned in any environment."
        kind = (
            "a loopback" if ip_obj.is_loopback
            else "a private-network" if ip_obj.is_private
            else "a shared-address-space (100.64.0.0/10, CGNAT or Tailscale)"
            if shared_address_space(ip_obj)
            else "a reserved"
        )
    else:
        kind = "a loopback"
    setting = deployment_policy.PRIVATE_NETWORK_TARGETS_ENV
    # The policy environment comes from the target's stored environment or cohort and defaults
    # to production. The target list derives an "internal" cohort from a private address for
    # display only, so "judged as 'production'" beside a target shown as internal read as a
    # contradiction. Name the environment, and say that the address or cohort does not change it.
    judged = str(environment or "").strip().lower()
    if not judged or judged == "unknown":
        judged = "production"
    return (
        f"{lowered} is {kind} address; this deployment does not allow private-network targets "
        f"outside a Lab environment. The target is evaluated under the '{judged}' environment; "
        "a private address or an 'internal' cohort does not make it a Lab target. To scan your "
        f"own network, set {setting}=allow for the API and workers "
        f"({PRIVATE_NETWORK_TARGETS_DOC}), or set the target's cohort to Lab."
    )


def _private_network_admitted_by_policy(host: str, environment: str) -> bool:
    """True when only the deployment policy (not a lab label) made this address admissible."""
    if environment in SAFE_LAB_ENVIRONMENTS:
        return False
    return (
        _ip_scope_block_reason(host, environment, allow_private_networks=False) is not None
        and _ip_scope_block_reason(host, environment) is None
    )


def _cidr_block_reasons(raw: str) -> list[str]:
    reasons: list[str] = []
    for match in CIDR_RE.findall(raw):
        try:
            network = ipaddress.ip_network(match, strict=False)
        except ValueError:
            continue
        if (network.version == 4 and network.prefixlen <= 24) or (network.version == 6 and network.prefixlen <= 64):
            reasons.append("broad_cidr")
    return reasons


def _parse_absolute_http_url(raw_url: str) -> urllib.parse.ParseResult | None:
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return None
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.netloc:
        return None
    return parsed


def _receipt_id(input_payload: dict[str, Any], verdict: str, blocked_by: tuple[str, ...]) -> str:
    material = {
        "input_scope": input_payload,
        "verdict": verdict,
        "blocked_by": list(blocked_by),
    }
    digest = hashlib.sha256(repr(material).encode("utf-8")).hexdigest()
    return digest[:32]


def scope_origin_matches_target(scope_url: Any, target_url: Any) -> bool:
    """True when a scope URL describes the bound web origin or a service of its host asset.

    Web target identity is host-level, so `http://host:1111` and `http://host:2222` resolve to one
    target row. That merge is deliberate, but it means a scope receipt can be written for an origin
    the scan will never touch: the receipt then attests to a subject nobody examined. Path is
    ignored -- narrowing a scope to a route is legitimate -- while scheme, host and port must agree.
    An unparseable or absent side is not a match: unknown identity is exactly what must not be
    attested to.
    """
    def origin(value: Any) -> tuple[str, str, int] | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = urllib.parse.urlsplit(text)
            host = (parsed.hostname or "").lower().rstrip(".")
            scheme = parsed.scheme.lower()
            if scheme not in {"http", "https"} or not host:
                return None
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError:
            return None
        return scheme, host, int(port)

    left, right = origin(scope_url), origin(target_url)
    if left:
        try:
            target = urllib.parse.urlsplit(str(target_url or '').strip())
            if target.scheme.lower() == 'host' and not target.username and not target.password:
                # A host asset has no default web origin. A receipt may name any HTTP(S)
                # service of that exact host; destination policy is evaluated separately.
                target.port  # Reject malformed ports instead of accepting unknown identity.
                return bool(target.hostname and left[1] == _canonical_host(target.hostname))
        except ValueError:
            return False
    return bool(left and right and left == right)

def evaluate_scope(
    raw_url: str,
    *,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    allowed_root_domains: list[str] | tuple[str, ...] | None = None,
    environment: str = "production",
    redirect_urls: list[str] | tuple[str, ...] | None = None,
    target_id: str | None = None,
) -> ScopeReceipt:
    checks: list[ScopeCheck] = []
    blocked: list[str] = []
    warnings: list[str] = []

    raw = str(raw_url or "").strip()
    env = str(environment or "production").strip().lower()
    allow_hosts = tuple(_canonical_host(item) for item in (allowed_hosts or ()) if str(item or "").strip())
    allow_roots = tuple(_canonical_host(item) for item in (allowed_root_domains or ()) if str(item or "").strip())

    input_scope = {
        "url": raw,
        "target_id": target_id,
    }

    # A public-suffix root (co.uk, github.io) never widens scope; a host only it would admit is
    # refused with that reason, and the receipt never stores it.
    suffix_roots = tuple(root for root in allow_roots if root not in scope_roots((root,)))
    if suffix_roots:
        allow_roots = tuple(root for root in allow_roots if root not in suffix_roots)
        _add_check(checks, "allowed_root_public_suffix", "ignored", " ".join(
            f"{public_suffix_refusal(root, wildcard=True)}; it covers nothing." for root in suffix_roots
        ))

    for reason in _cidr_block_reasons(raw):
        blocked.append(reason)
        _add_check(checks, reason, "blocked", "Broad CIDR scope is not allowed in command receipts.")

    if not raw:
        blocked.append("malformed_url")
        _add_check(checks, "malformed_url", "blocked", "URL is required.")
        normalized = {}
    elif raw.startswith("//"):
        blocked.append("scheme_relative_url")
        _add_check(checks, "scheme_relative_url", "blocked", "Scheme-relative URLs are rejected.")
        normalized = {}
    else:
        parsed = _parse_absolute_http_url(raw)
        if parsed is None:
            blocked.append("malformed_url")
            _add_check(checks, "malformed_url", "blocked", "URL must be an absolute http(s) URL.")
            normalized = {}
        else:
            host_raw = parsed.hostname or ""
            host = _canonical_host(host_raw)
            normalized = {
                "scheme": parsed.scheme.lower(),
                "host": host,
                "port": parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                "path": parsed.path or "/",
            }
            _add_check(checks, "malformed_url", "passed", "URL parsed as absolute http(s).")

            if parsed.username or parsed.password or "@" in parsed.netloc.split("@", 1)[0]:
                blocked.append("userinfo")
                _add_check(checks, "userinfo", "blocked", "Userinfo in URLs is rejected.")
            else:
                _add_check(checks, "userinfo", "passed", "No URL userinfo present.")

            if host_raw.endswith("."):
                blocked.append("trailing_dot_host")
                _add_check(checks, "trailing_dot_host", "blocked", "Trailing-dot hostnames are rejected.")
            else:
                _add_check(checks, "trailing_dot_host", "passed", "No trailing-dot hostname.")

            if host_raw and (host_raw.lower() != host or host.startswith("xn--") or ".xn--" in host):
                blocked.append("unicode_or_punycode_confusion")
                _add_check(checks, "unicode_or_punycode_confusion", "blocked", "Unicode/punycode hostnames require explicit review.")
            else:
                _add_check(checks, "unicode_or_punycode_confusion", "passed", "Hostname is plain ASCII.")

            ip_reason = _ip_scope_block_reason(host, env)
            if ip_reason:
                blocked.append(ip_reason)
                _add_check(checks, ip_reason, "blocked", destination_refusal_explanation(host, env))
            elif _private_network_admitted_by_policy(host, env):
                # Recorded on every receipt so a scan of an internal address always shows why
                # it was admitted: the deployment's own policy, not a lab label.
                _add_check(checks, "private_network_scope", "passed", "Private network target admitted by deployment policy (allowed_by_deployment_policy).")
            else:
                _add_check(checks, "loopback_or_private_range", "passed", "No blocked private network scope.")

            if allow_hosts or allow_roots or suffix_roots:
                if not _host_matches(host, allow_hosts, allow_roots):
                    blocked.append("host_out_of_allowed_scope")
                    if _host_matches(host, (), suffix_roots):
                        blocked.append("allowed_root_public_suffix")
                    _add_check(checks, "host_out_of_allowed_scope", "blocked", "Host is outside the provided allowed scope.")
                else:
                    _add_check(checks, "host_out_of_allowed_scope", "passed", "Host matches allowed scope.")
            else:
                warnings.append("no_allowed_scope_supplied")
                _add_check(checks, "host_out_of_allowed_scope", "warning", "No allowed_hosts or allowed_root_domains were supplied.")

    redirect_results: list[dict[str, Any]] = []
    base_host = str(normalized.get("host") or "") if "normalized" in locals() else ""
    for destination in redirect_urls or ():
        dest_raw = str(destination or "").strip()
        dest_parsed = _parse_absolute_http_url(dest_raw)
        if dest_parsed is None:
            blocked.append("redirect_out_of_scope")
            redirect_results.append({"url": dest_raw, "verdict": "blocked", "reason": "malformed_redirect_url"})
            continue
        dest_host = _canonical_host(dest_parsed.hostname or "")
        if allow_hosts or allow_roots or suffix_roots:
            dest_allowed = _host_matches(dest_host, allow_hosts, allow_roots)
        else:
            dest_allowed = bool(base_host and dest_host == base_host)
        if not dest_allowed:
            blocked.append("redirect_out_of_scope")
            redirect_results.append({"url": dest_raw, "host": dest_host, "verdict": "blocked", "reason": "redirect_out_of_scope"})
        else:
            redirect_results.append({"url": dest_raw, "host": dest_host, "verdict": "allowed"})
    if redirect_results:
        if any(item["verdict"] == "blocked" for item in redirect_results):
            _add_check(checks, "redirect_out_of_scope", "blocked", "One or more redirect destinations leave allowed scope.")
        else:
            _add_check(checks, "redirect_out_of_scope", "passed", "Redirect destinations remain in scope.")
    else:
        _add_check(checks, "redirect_out_of_scope", "not_checked", "No redirect destinations supplied.")

    unique_blocked = tuple(dict.fromkeys(blocked))
    unique_warnings = tuple(dict.fromkeys(warnings))
    if unique_blocked:
        verdict = "blocked"
    elif unique_warnings:
        verdict = "needs_approval"
    else:
        verdict = "allowed"

    return ScopeReceipt(
        receipt_id=_receipt_id(input_scope, verdict, unique_blocked),
        input_scope=input_scope,
        normalized_scope=normalized if "normalized" in locals() else {},
        verdict=verdict,
        checks=tuple(checks),
        blocked_by=unique_blocked,
        warnings=unique_warnings,
        environment=env,
        allowed_hosts=allow_hosts,
        allowed_root_domains=allow_roots,
        redirect_destinations=tuple(redirect_results),
    )


def receipt_to_dict(receipt: ScopeReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "input_scope": receipt.input_scope,
        "normalized_scope": receipt.normalized_scope,
        "verdict": receipt.verdict,
        "checks": [check.__dict__ for check in receipt.checks],
        "blocked_by": list(receipt.blocked_by),
        "warnings": list(receipt.warnings),
        "environment": receipt.environment,
        "allowed_hosts": list(receipt.allowed_hosts),
        "allowed_root_domains": list(receipt.allowed_root_domains),
        "redirect_destinations": list(receipt.redirect_destinations),
    }


def _decode_json_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode()
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def runtime_scope_guard_from_scope(scope: dict[str, Any]) -> dict[str, Any]:
    """Build the non-secret scope contract queued workers must re-check."""
    normalized = _decode_json_value(scope.get("normalized_scope")) or {}
    allowed_hosts = _decode_json_value(scope.get("allowed_hosts")) or []
    allowed_roots = _decode_json_value(scope.get("allowed_root_domains")) or []
    if not isinstance(allowed_hosts, list):
        allowed_hosts = []
    if not isinstance(allowed_roots, list):
        allowed_roots = []
    normalized_host = normalized.get("host") if isinstance(normalized, dict) else None
    if normalized_host and not allowed_hosts:
        allowed_hosts = [normalized_host]

    guard = {
        "scope_receipt_id": str(scope.get("id") or ""),
        "environment": str(scope.get("environment") or "production").strip().lower() or "production",
        "allowed_hosts": [str(item) for item in allowed_hosts if str(item or "").strip()],
        "allowed_root_domains": [str(item) for item in allowed_roots if str(item or "").strip()],
        "normalized_scope": normalized if isinstance(normalized, dict) else {},
        "requires_runtime_destination_check": True,
        "requires_runtime_dns_check": True,
    }
    if scope.get("target_id"):
        guard["target_id"] = str(scope.get("target_id"))
    return guard


def _evaluate_runtime_dns_observations(
    urls: tuple[str, ...],
    observations: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None,
    *,
    environment: str,
    allowed_addresses: list[str] | tuple[str, ...] | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    expected_hosts: list[str] = []
    for url in urls:
        parsed = _parse_absolute_http_url(str(url or "").strip())
        host = _canonical_host(parsed.hostname or "") if parsed else ""
        if host and host not in expected_hosts:
            expected_hosts.append(host)

    observations_by_host: dict[str, list[str]] = {}
    for observation in observations or ():
        if not isinstance(observation, dict):
            continue
        host = _canonical_host(observation.get("host"))
        raw_ips = observation.get("ips")
        if not isinstance(raw_ips, (list, tuple)):
            raw_ips = [observation.get("ip")] if observation.get("ip") else []
        ips = [str(item).strip() for item in raw_ips if str(item or "").strip()]
        if host and ips:
            observations_by_host.setdefault(host, []).extend(ips)

    results: list[dict[str, Any]] = []
    blocked: list[str] = []
    warnings: list[str] = []
    frozen_addresses: set[str] = set()
    for raw_address in allowed_addresses or ():
        try:
            frozen_addresses.add(str(ipaddress.ip_address(str(raw_address).strip())))
        except ValueError:
            continue
    for host in expected_hosts:
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        ips = list(dict.fromkeys(observations_by_host.get(host, [])))
        if not ips:
            warnings.append("runtime_dns_unverified")
            results.append({"host": host, "ips": [], "verdict": "degraded", "reason": "runtime_dns_unverified"})
            continue
        result: dict[str, Any] = {"host": host, "ips": ips, "verdict": "allowed"}
        for ip in ips:
            try:
                normalized_ip = str(ipaddress.ip_address(ip))
            except ValueError:
                blocked.append("runtime_dns_invalid")
                result.update({"verdict": "blocked", "reason": "runtime_dns_invalid"})
                continue
            # A canonical Scan freezes exact addresses at admission. Matching
            # those addresses is stronger authority than generic private-range
            # policy and permits explicitly admitted local/lab targets without
            # making arbitrary RFC1918 destinations reachable. Any DNS drift
            # from the frozen set still fails closed.
            if frozen_addresses and normalized_ip not in frozen_addresses:
                blocked.append("runtime_dns_address_drift")
                result.update({"verdict": "blocked", "reason": "runtime_dns_address_drift"})
            elif not frozen_addresses and _ip_scope_block_reason(
                ip, environment, allow_private_networks=False,
            ):
                # Every host reaching here is a name, not a literal address: literal targets are
                # skipped above. A name that resolves into the private space at run time is DNS
                # rebinding, and stays blocked whatever the deployment's private-network policy
                # says. That policy decides whether an address the operator *declared* is in
                # scope; it never lets a public name quietly reach the operator's intranet.
                blocked.append("runtime_dns_private_range")
                result.update({"verdict": "blocked", "reason": "runtime_dns_private_range"})
        results.append(result)
    return results, list(dict.fromkeys(blocked)), list(dict.fromkeys(warnings))


def evaluate_runtime_destination_scope(
    runtime_scope_guard: dict[str, Any] | None,
    destination_url: str | None,
    *,
    redirect_urls: list[str] | tuple[str, ...] | None = None,
    resolution_observations: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, Any]:
    """Re-check actual network destinations against an approval scope guard.

    Network-following workers should call this with the post-resolution or
    post-redirect destination they actually touched. Missing guard/destination
    fails closed so unknown runtime scope cannot be treated as in-scope.
    """
    if not isinstance(runtime_scope_guard, dict) or not runtime_scope_guard:
        return {
            "verdict": "blocked",
            "status": "blocked",
            "blocked_by": ["runtime_scope_guard_missing"],
            "warnings": [],
            "checks": [],
            "redirect_destinations": [],
            "runtime_scope_guard_present": False,
        }
    raw_destination = str(destination_url or "").strip()
    if not raw_destination:
        return {
            "verdict": "blocked",
            "status": "blocked",
            "blocked_by": ["runtime_destination_unverified"],
            "warnings": [],
            "checks": [],
            "redirect_destinations": [],
            "runtime_scope_guard_present": True,
            "scope_receipt_id": runtime_scope_guard.get("scope_receipt_id"),
        }

    normalized = (
        runtime_scope_guard.get("normalized_scope")
        if isinstance(runtime_scope_guard.get("normalized_scope"), dict)
        else {}
    )
    allowed_hosts = (
        runtime_scope_guard.get("allowed_hosts")
        if isinstance(runtime_scope_guard.get("allowed_hosts"), list)
        else []
    )
    allowed_roots = (
        runtime_scope_guard.get("allowed_root_domains")
        if isinstance(runtime_scope_guard.get("allowed_root_domains"), list)
        else []
    )
    if not allowed_hosts and normalized.get("host"):
        allowed_hosts = [normalized["host"]]

    receipt = evaluate_scope(
        raw_destination,
        allowed_hosts=allowed_hosts,
        allowed_root_domains=allowed_roots,
        environment=str(runtime_scope_guard.get("environment") or "production"),
        redirect_urls=redirect_urls,
        target_id=str(runtime_scope_guard.get("target_id") or "") or None,
    )
    payload = receipt_to_dict(receipt)
    dns_results: list[dict[str, Any]] = []
    dns_blocked: list[str] = []
    dns_warnings: list[str] = []
    if runtime_scope_guard.get("requires_runtime_dns_check"):
        dns_results, dns_blocked, dns_warnings = _evaluate_runtime_dns_observations(
            (raw_destination, *(str(item or "") for item in (redirect_urls or ()))),
            resolution_observations,
            environment=str(runtime_scope_guard.get("environment") or "production"),
            allowed_addresses=(
                runtime_scope_guard.get("allowed_addresses")
                if isinstance(runtime_scope_guard.get("allowed_addresses"), list)
                else None
            ),
        )
        if dns_blocked:
            payload.setdefault("checks", []).append({
                "name": "runtime_dns_resolution",
                "status": "blocked",
                "message": "A runtime hostname resolution was missing, invalid, or outside the permitted network scope.",
            })
        elif dns_warnings:
            payload.setdefault("checks", []).append({
                "name": "runtime_dns_resolution",
                "status": "degraded",
                "message": "One or more runtime hostname resolutions were not observed.",
            })
        else:
            payload.setdefault("checks", []).append({
                "name": "runtime_dns_resolution",
                "status": "passed",
                "message": "Observed runtime hostname resolutions remained in policy.",
            })
    payload["resolution_observations"] = dns_results
    payload["blocked_by"] = list(dict.fromkeys([*(payload.get("blocked_by") or []), *dns_blocked]))
    payload["warnings"] = list(dict.fromkeys([*(payload.get("warnings") or []), *dns_warnings]))
    if payload["blocked_by"]:
        payload["verdict"] = "blocked"
        payload["status"] = "blocked"
    elif payload["warnings"]:
        payload["verdict"] = "degraded"
        payload["status"] = "degraded"
    else:
        payload["verdict"] = "allowed"
        payload["status"] = "allowed"
    if payload["status"] == "blocked" and not payload.get("blocked_by"):
        payload["blocked_by"] = ["runtime_destination_unverified"]
    payload["runtime_scope_guard_present"] = True
    payload["scope_receipt_id"] = runtime_scope_guard.get("scope_receipt_id")
    return payload
