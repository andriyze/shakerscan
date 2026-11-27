"""Execution-time DNS revalidation of a frozen ``scan-job/v2`` target binding.

Admission resolves the target name once, classifies every answer under the deployment's
destination policy for the binding's environment, and freezes the survivors into the digested
``TargetBinding.allowed_addresses``. Every execution path then connects only to that set: the
scanner subprocess resolver (``scanner/sitecustomize.py``), ``FrozenTargetSocketFactory`` for
capabilities, the pinned SOCKS proxy for external tools, and the post-run
``runtime_scope_check`` of the addresses actually connected to.

Materialization used to also demand that a fresh lookup be a *subset* of the frozen set. That
is not what the protection is for, and it refused a large share of real targets: a CDN
(CloudFront, Cloudflare, Fastly, Akamai) returns a different subset of its edge addresses on
every lookup, so the worker's answer was routinely disjoint from the admission answer and the
Scan failed with "runtime DNS resolution exceeds the frozen scan-job/v2 target binding".

What the check must guarantee is that execution never reaches a destination the policy would
refuse. So the fresh answer is classified with the same function, environment and deployment
policy admission used:

* an answer that resolves *only* to refused classes (a name rebound to 127.0.0.1, to 10.x under
  a refusing deployment, to 169.254.169.254) fails closed and names the refused addresses;
* a mixed answer drops the refused addresses, exactly as admission does;
* an address-literal target stays exact: its address must be the frozen one;
* every frozen address is re-classified, so a deployment policy tightened after admission is
  honoured before anything connects.

Connections stay pinned to the frozen, digested set. It was classified at admission and is
re-classified here, the plan, action and broker digests all bind it, and CDN edge addresses
serve the distribution regardless of which subset one lookup happened to return. The fresh
answer is recorded as runtime evidence next to the effective (pinned) set; it never mutates the
binding and is never connected to.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from typing import Any

try:
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package import through api.scan
    from ..runtime.models import TargetBinding

try:
    from action_scope import _ip_scope_block_reason
except ModuleNotFoundError:  # package import through api.scan
    from ..action_scope import _ip_scope_block_reason


RUNTIME_DNS_REVALIDATION_SCHEMA = "runtime-dns-revalidation/v1"
RUNTIME_DNS_REVALIDATION_OPTION = "_runtime_dns_revalidation"

Classifier = Callable[[str, str], "str | None"]


class RuntimeDnsRevalidationError(ValueError):
    """The execution-time answer cannot be admitted under the binding's destination policy."""


def _normalized(values: Sequence[str]) -> list[str]:
    addresses: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            address = str(ipaddress.ip_address(text.split("%", 1)[0]))
        except ValueError as exc:
            raise RuntimeDnsRevalidationError(
                "runtime DNS returned an invalid address for scan-job/v2"
            ) from exc
        if address not in addresses:
            addresses.append(address)
    return addresses


def _is_address_literal(host: str | None) -> bool:
    try:
        ipaddress.ip_address(str(host or "").strip("[]"))
    except ValueError:
        return False
    return True


def _describe(refused: Sequence[dict[str, str]]) -> str:
    return ", ".join(f"{item['address']} ({item['reason']})" for item in refused[:8])


def revalidate_runtime_target_addresses(
    binding: TargetBinding,
    observed_addresses: Sequence[str],
    *,
    classify: Classifier | None = None,
) -> dict[str, Any]:
    """Classify an execution-time DNS answer against the frozen binding's destination policy.

    Returns content-free evidence whose ``effective_addresses`` is the set every connection is
    pinned to (the frozen binding). Raises ``RuntimeDnsRevalidationError`` when the answer, or
    the frozen set itself, is refused under the binding's environment.
    """
    classifier = classify or _ip_scope_block_reason
    environment = str(binding.environment or "production").strip().lower() or "production"
    host = str(binding.canonical_host or "")
    frozen = list(binding.allowed_addresses)
    if not frozen:
        raise RuntimeDnsRevalidationError(
            "frozen scan-job/v2 target binding has no admitted address"
        )
    observed = _normalized(observed_addresses)
    if not observed:
        raise RuntimeDnsRevalidationError(
            "runtime DNS returned no usable address for scan-job/v2"
        )

    frozen_refused = [
        {"address": address, "reason": reason}
        for address in frozen
        if (reason := classifier(address, environment)) is not None
    ]
    if frozen_refused:
        raise RuntimeDnsRevalidationError(
            f"frozen scan-job/v2 target address is no longer an allowed destination for "
            f"environment {environment!r} under this deployment's policy: "
            f"{_describe(frozen_refused)}"
        )

    # An address-literal target has no DNS to drift: its authority is the exact address.
    if _is_address_literal(host) and not set(observed).issubset(frozen):
        raise RuntimeDnsRevalidationError(
            "runtime address of an address-literal target differs from the frozen "
            "scan-job/v2 target binding"
        )

    admitted: list[str] = []
    refused: list[dict[str, str]] = []
    for address in observed:
        reason = classifier(address, environment)
        if reason is None:
            admitted.append(address)
        else:
            refused.append({"address": address, "reason": reason})
    if not admitted:
        raise RuntimeDnsRevalidationError(
            f"runtime DNS for {host} now resolves only to destinations this deployment refuses "
            f"for environment {environment!r} ({_describe(refused)}); refusing a possible DNS "
            f"rebinding of the frozen scan-job/v2 target binding"
        )

    frozen_set = set(frozen)
    overlap = [address for address in admitted if address in frozen_set]
    return {
        "schema_version": RUNTIME_DNS_REVALIDATION_SCHEMA,
        "canonical_host": host,
        "environment": environment,
        "frozen_addresses": frozen,
        "observed_addresses": observed,
        "observed_admitted_addresses": admitted,
        "observed_refused_addresses": refused,
        "overlap_addresses": overlap,
        "answer_drifted": set(admitted) != frozen_set,
        # Connections never use the fresh answer; they stay pinned to the digested, admitted
        # and re-classified frozen set.
        "effective_addresses": frozen,
        "pinning": "frozen_target_binding",
    }


def record_runtime_dns_revalidation(metadata: dict[str, Any], options: Any) -> None:
    """Copy materialization's DNS evidence into a Scan result's ``scan_metadata``."""
    evidence = options.get(RUNTIME_DNS_REVALIDATION_OPTION) if isinstance(options, dict) else None
    if isinstance(evidence, dict) and evidence.get("schema_version") == RUNTIME_DNS_REVALIDATION_SCHEMA:
        metadata["runtime_dns_revalidation"] = dict(evidence)
