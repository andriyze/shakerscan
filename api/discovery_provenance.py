"""What a discovered name is known to be, and where that knowledge came from.

Subdomain discovery joins three kinds of evidence that say different things:

* a certificate-transparency record (Gungnir, crt.sh, a CT-backed subfinder source) says that a
  certificate naming the host was *issued* at some point. It is historical issuance, not proof
  that the name exists today or that the operator still controls it;
* a passive DNS dataset or a DNS enumeration answer says the name was *observed* in DNS;
* the run's own DNS check says whether the name *resolves now*.

None of them says a service answers there: reachability is established only by a later,
separately authorized Scan of that target. This module keeps those distinctions on each name a
run records (``targets.metadata_json.discovery``) and in the run's DNS outcome, bounded so a
large run cannot bloat either. It is pure: no network, database or clock access.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

try:
    from discovery_wildcards import has_certificate_evidence
except ModuleNotFoundError:  # package import (api.discovery_provenance)
    from .discovery_wildcards import has_certificate_evidence

SCHEMA = "discovered-name/v1"
MAX_SOURCES_PER_NAME = 8
MAX_NAMES_WITH_SOURCES = 200
MAX_LISTED_KNOWN = 100
CERTIFICATE_MEANING = "historical_certificate_issuance_not_current_ownership"
REACHABILITY_NOT_CHECKED = "not_checked"


def name_sources(evidence: Mapping[str, Iterable[Any]] | None, name: str) -> list[str]:
    """The bounded, sorted source labels that named ``name``."""
    values = (evidence or {}).get(name) or ()
    return sorted({str(item)[:64] for item in values if str(item or "").strip()})[:MAX_SOURCES_PER_NAME]


def name_provenance(
    name: str, *, evidence: Mapping[str, Iterable[Any]] | None, dns_status: str,
    discovery_id: str | None, observed_at: str | None,
) -> dict[str, Any]:
    """The provenance stored on a newly recorded target (``metadata_json.discovery``)."""
    sources = name_sources(evidence, name)
    certificate = has_certificate_evidence(sources)
    return {
        "schema": SCHEMA,
        "observed_as": "dns_name",
        "sources": sources,
        "certificate_observed": certificate,
        **({"certificate_meaning": CERTIFICATE_MEANING} if certificate else {}),
        "dns_status": dns_status,
        "reachability": REACHABILITY_NOT_CHECKED,
        "discovery_id": discovery_id,
        "first_observed_at": observed_at,
        "last_observed_at": observed_at,
    }


def dns_status_of(name: str, plan: Mapping[str, Any]) -> str:
    """``resolves`` for a judged scannable name, ``not_judged`` when the resolver could not say."""
    unjudged = set(plan.get("unknown") or ()) | set(plan.get("not_checked") or ())
    return "not_judged" if name in unjudged else "resolves"


def run_provenance(
    *, found: Iterable[str], plan: Mapping[str, Any], already_known: list[str],
    evidence: Mapping[str, Iterable[Any]] | None,
) -> dict[str, Any]:
    """The run's account of what each class of name means, with bounded per-name sources."""
    names = list(dict.fromkeys(str(item) for item in found))
    sources = {
        name: name_sources(evidence, name)
        for name in names[:MAX_NAMES_WITH_SOURCES] if name_sources(evidence, name)
    }
    certificate_only = sum(
        1 for name in names
        if name_sources(evidence, name) and all(
            has_certificate_evidence([source]) for source in name_sources(evidence, name)
        )
    )
    return {
        "schema": SCHEMA,
        "observation_classes": {
            "dns_name_observed": len(names),
            "named_only_by_certificates": certificate_only,
            "resolves_now": len(plan.get("scannable") or ()) - len(
                set(plan.get("unknown") or ()) | set(plan.get("not_checked") or ())),
            "no_address": len(plan.get("unresolved") or ()),
            "wildcard_echo": len(plan.get("wildcard_suppressed") or ()),
            "reachable_service": REACHABILITY_NOT_CHECKED,
        },
        "already_known_count": len(already_known),
        "already_known": already_known[:MAX_LISTED_KNOWN],
        "sources_by_name": sources,
        "sources_by_name_truncated": len(names) > MAX_NAMES_WITH_SOURCES,
        "certificate_meaning": CERTIFICATE_MEANING,
        "note": ("A certificate record is historical issuance; a resolving name is not a reachable "
                 "service. Neither establishes current ownership or authorizes testing."),
    }


__all__ = [
    "CERTIFICATE_MEANING", "SCHEMA", "dns_status_of", "name_provenance", "name_sources",
    "run_provenance",
]
