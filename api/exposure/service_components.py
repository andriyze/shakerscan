"""Components behind one service: sanitized claims, merged history, provenance and freshness.

A listener carries several components (an edge, a web server, the application under a base path,
its plugins). Each claim names its product and version separately, and its provenance: the
observation it came from, the recipe and its version, the time, the connected address, the
Host/SNI name and the source field. Claims arrive from retained observations of every release:
a fingerprint written before components existed still yields its components when it is read.

Observations are target-influenced. Product names come from the catalogue
(``scanner_tools.web_identity``), a bounded ``Server`` token, a plain plugin slug, or a bounded
network-fingerprint label; versions must look like versions; nothing else is copied.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import re
from typing import Any, Iterable, Mapping
import uuid

try:
    from scanner_tools import web_identity
except ModuleNotFoundError:  # package import
    from scanner.scanner_tools import web_identity

BASES = web_identity.CLAIM_BASES
DISTRIBUTIONS = web_identity.DISTRIBUTIONS
sanitized = web_identity.sanitized_claim
_clean = web_identity._clean
_ROLE_ORDER = {role: index for index, role in enumerate(web_identity.ROLES)}
_VERSION = re.compile(r"[0-9][0-9A-Za-z._+~-]{0,40}")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:.]{2,45}\]")
MAX_COMPONENTS = 24
MAX_COMPONENT_HISTORY = 6
MAX_COMPONENT_EVIDENCE = 6
COMPONENT_NAMESPACE = uuid.UUID("7c0f8f5e-0b1e-4c43-9d55-2f5b1c3f0a61")


def network_component(row: Mapping[str, Any]) -> dict[str, Any] | None:
    """The software a network fingerprint names, as the listener's ``service`` component."""
    product = _clean(row.get("product"), 120)
    if not product:
        return None
    raw_version = _clean(row.get("version"), 120)
    upstream, package, distribution = web_identity.split_package_version(raw_version)
    # The exact announced string (``OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``) keeps the build suffix.
    announced = _clean(row.get("version_reported"), 200)
    if announced and announced != raw_version:
        package = announced
        distribution = distribution or web_identity.split_package_version("0", announced)[2]
    if raw_version and not upstream and _VERSION.fullmatch(raw_version.split()[0]):
        upstream = raw_version.split()[0]
    return sanitized({
        "role": "service", "base_path": "/", "product": product, "product_status": "identified",
        "version": upstream, "version_status": "reported" if upstream else "unknown",
        "package_version": package or (raw_version if raw_version and raw_version != upstream else None),
        "distribution": distribution, "basis": "network_fingerprint",
        "product_source_field": "service.product", "version_source_field": "service.version",
        "cpes": row.get("cpe") if isinstance(row.get("cpe"), list) else [row.get("cpe")] if row.get("cpe") else [],
    }, network_label=True)


def component_key(claim: Mapping[str, Any]) -> tuple[str, str, str]:
    return (claim["role"], claim["product_key"] or str(claim["product"]).lower(), claim["base_path"])


def component_id(service_id: str, key: tuple[str, str, str]) -> str:
    return str(uuid.uuid5(COMPONENT_NAMESPACE, json.dumps([service_id, *key], separators=(",", ":"))))


def _strength(claim: Mapping[str, Any]) -> int:
    return web_identity.PRODUCT_STATUSES[::-1].index(claim["product_status"])


def _version_strength(claim: Mapping[str, Any]) -> int:
    return web_identity.VERSION_STATUSES[::-1].index(claim["version_status"])


def _provenance(claim: Mapping[str, Any], context: Mapping[str, Any], field: str) -> dict[str, Any]:
    return {
        "basis": claim["basis"],
        "source_field": claim["product_source_field" if field == "product" else "version_source_field"],
        "recipe": claim["recipe"], "recipe_version": claim["recipe_version"],
        "signals": list(claim["signals"]) if field == "product" else [],
        "evidence_ref": context.get("evidence_ref"), "observed_at": context.get("observed_at"),
        "connected_address": context.get("connected_address"),
        "host": context.get("host"), "sni": context.get("sni"),
    }


def merge(record: dict[str, Any], claims: Iterable[Mapping[str, Any]], context: Mapping[str, Any],
          *, stale_after: timedelta) -> None:
    """Fold one observation's claims into the service's components (observations in time order).

    A product claim is replaced by an equal or stronger one, or by any newer one once the held
    claim is stale. A version claim is replaced the same way; a claim without a version never
    erases a version observed earlier (that version's own freshness shows its age).
    """
    components: dict[tuple[str, str, str], dict[str, Any]] = record.setdefault("_components", {})
    observed_at = context.get("observed_at")
    when = _time(observed_at)
    for claim in claims:
        key = component_key(claim)
        current = components.get(key)
        if current is None:
            if len(components) >= MAX_COMPONENTS:
                record["components_truncated"] = True
                continue
            current = components[key] = {
                "id": component_id(record["id"], key), "role": claim["role"],
                "base_path": claim["base_path"], "product": claim["product"],
                "product_key": claim["product_key"], "vendor": claim["vendor"],
                "category": claim["category"], "advisory_product": claim["advisory_product"],
                "product_status": claim["product_status"], "version": None,
                "version_status": "unknown", "package_version": None, "distribution": None,
                "cpes": [], "claims": {"product": _provenance(claim, context, "product"), "version": None},
                "first_seen_at": observed_at, "last_seen_at": observed_at,
                "history": [], "evidence_refs": [],
            }
        held = current["claims"]["product"]
        if _strength(claim) >= web_identity.PRODUCT_STATUSES[::-1].index(current["product_status"]) or _older(held, when, stale_after):
            current["product_status"] = claim["product_status"]
            current["claims"]["product"] = _provenance(claim, context, "product")
        if claim["version"]:
            held_version = current["claims"]["version"]
            if (held_version is None or _version_strength(claim) >= web_identity.VERSION_STATUSES[::-1].index(current["version_status"])
                    or _older(held_version, when, stale_after)):
                for name in ("version", "version_status", "package_version", "distribution", "cpes"):
                    current[name] = claim[name]
                current["claims"]["version"] = _provenance(claim, context, "version")
        current["last_seen_at"] = observed_at
        entry = {"product_status": current["product_status"], "version": current["version"],
                 "version_status": current["version_status"], "observed_at": observed_at,
                 "evidence_ref": context.get("evidence_ref")}
        last = current["history"][-1] if current["history"] else None
        if last is None or any(last[k] != entry[k] for k in ("product_status", "version", "version_status")):
            current["history"] = [*current["history"], entry][-MAX_COMPONENT_HISTORY:]
        ref = context.get("evidence_ref")
        if ref and ref not in current["evidence_refs"]:
            current["evidence_refs"] = [*current["evidence_refs"], ref][-MAX_COMPONENT_EVIDENCE:]


def _time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def _older(provenance: Mapping[str, Any] | None, when: datetime | None, stale_after: timedelta) -> bool:
    held = _time((provenance or {}).get("observed_at"))
    return bool(held and when and when - held > stale_after)


def finalize(record: dict[str, Any], *, now: datetime, stale_after: timedelta) -> None:
    """Freshness per field, material changes from retained history, and the unknowns."""
    components = list(record.pop("_components", {}).values())
    service_first = _time(record.get("first_seen_at"))
    for item in components:
        freshness = {}
        for name in ("product", "version"):
            observed = _time((item["claims"].get(name) or {}).get("observed_at"))
            freshness[name] = "unknown" if observed is None else "stale" if now - observed > stale_after else "recent"
        item["freshness"] = freshness
        changes = []
        first = _time(item["first_seen_at"])
        if first and service_first and first > service_first:
            changes.append({"kind": "new_component", "observed_at": item["first_seen_at"]})
        versions = [entry for entry in item["history"] if entry["version"]]
        for before, after in zip(versions, versions[1:]):
            if before["version"] != after["version"]:
                changes.append({"kind": "version_changed", "from": before["version"],
                                "to": after["version"], "observed_at": after["observed_at"]})
        item["changes"] = changes[-4:]
    components.sort(key=lambda c: (_ROLE_ORDER.get(c["role"], 99), c["base_path"], c["product"].lower()))
    record["components"] = components
    if not record.get("product") and components:
        # A listener first named by a recipe: its row shows the most specific identified component.
        ranked = sorted(components, key=lambda c: (
            c["product_status"] != "identified", c["role"] not in {"application", "service"},
            c["version_status"] != "reported", c["base_path"] != "/", _ROLE_ORDER.get(c["role"], 99)))
        record["product"], record["version"] = ranked[0]["product"], ranked[0]["version"]
    unknowns = []
    http = record.get("identity_basis") == "http_response"
    bases = sorted({c["base_path"] for c in components} | ({"/"} if http else set()))
    for base in bases:
        here = [c for c in components if c["base_path"] == base]
        if http and not any(c["role"] in {"application", "plugin"} for c in here):
            unknowns.append({"role": "application", "base_path": base, "field": "product",
                             "component_id": None, "reason": "no_identity_signal"})
    for item in components:
        if item["version_status"] != "reported":
            unknowns.append({"role": item["role"], "base_path": item["base_path"], "field": "version",
                             "component_id": item["id"],
                             "reason": "version_inferred" if item["version_status"] == "inferred_range" else "version_not_reported"})
        if item["distribution"]:
            unknowns.append({"role": item["role"], "base_path": item["base_path"], "field": "backport",
                             "component_id": item["id"], "reason": "distribution_package"})
    record["component_unknowns"] = unknowns[:40]


def provenance_context(item: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Where an observation's claims were read: connected address and Host/SNI names."""
    host = _clean(item.get("_host"), 255).lower() or None
    sni = _clean(item.get("_sni"), 255).lower() or None
    return {
        "evidence_ref": evidence.get("ref"), "observed_at": evidence.get("observed_at"),
        "connected_address": item.get("address"),
        "host": host if host and _HOST.fullmatch(host) else None,
        "sni": sni if sni and _HOST.fullmatch(sni) else None,
    }


__all__ = ["finalize", "merge", "network_component", "provenance_context", "sanitized"]
