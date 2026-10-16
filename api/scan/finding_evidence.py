"""Structured, bounded evidence for Scan findings whose producers observe more than a title.

The TLS capability reads the whole certificate chain and the verifier's refusal reason, and a
template match carries the template's classification and extracted values. A finding that kept
only its check name told the operator nothing the title did not. These helpers copy the facts an
operator needs to act (names, dates, issuers, the failing link, CVE identifiers) into the finding
evidence. Every value is public metadata (certificate fields, template metadata) or a masked,
length-bounded excerpt; nothing here carries key material, credentials or response bodies.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Iterable, Mapping, Sequence

_MAX_SANS = 25
_MAX_TEXT = 300
_MAX_ORIGINS = 10
_MAX_EXTRACTED = 5


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _host_kind(host: Any) -> str:
    try:
        ipaddress.ip_address(str(host or "").strip("[]"))
    except ValueError:
        return "dns"
    return "ip"


def _certificate(item: Mapping[str, Any]) -> dict[str, Any]:
    names = [str(name) for name in item.get("certificate_dns_names") or ()]
    certificate = {
        "subject": _text(item.get("certificate_subject"), 400),
        "subject_cn": _text(item.get("certificate_subject_cn")),
        "issuer": _text(item.get("certificate_issuer"), 400),
        "issuer_cn": _text(item.get("certificate_issuer_cn")),
        "serial_hex": _text(item.get("certificate_serial_hex"), 80),
        "not_before": _text(item.get("certificate_not_before"), 40),
        "not_after": _text(item.get("certificate_not_after"), 40),
        "days_remaining": item.get("certificate_days_remaining"),
        "dns_names": names[:_MAX_SANS],
        "dns_name_count": item.get("certificate_dns_name_count", len(names)),
        "ip_addresses": [str(name) for name in item.get("certificate_ip_addresses") or ()][:_MAX_SANS],
        "self_signed": item.get("certificate_self_signed"),
        "public_key_type": _text(item.get("certificate_public_key_type"), 60),
        "public_key_bits": item.get("certificate_public_key_bits"),
        "signature_hash": _text(item.get("certificate_signature_hash"), 30),
        "aia_ca_issuers": list(item.get("certificate_aia_ca_issuers") or ())[:3],
        "aia_ocsp": list(item.get("certificate_aia_ocsp") or ())[:3],
        "sha256": _text(item.get("certificate_sha256"), 64),
    }
    return {key: value for key, value in certificate.items() if value not in (None, [], "")}


def _chain(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for entry in list(item.get("certificate_chain_details") or ())[:6]:
        if not isinstance(entry, Mapping):
            continue
        chain.append({
            key: entry.get(key) for key in (
                "subject", "subject_cn", "issuer", "issuer_cn", "not_before", "not_after",
                "expired", "self_signed", "is_ca", "sha256", "parse_status",
            ) if entry.get(key) is not None
        })
    return chain


def _trust(item: Mapping[str, Any]) -> dict[str, Any]:
    trust = {
        "result": item.get("certificate_trust"),
        "failure": item.get("certificate_trust_failure"),
        "error": _text(item.get("certificate_trust_error"), 200),
        "error_code": item.get("certificate_trust_error_code"),
    }
    return {key: value for key, value in trust.items() if value is not None}


def _origin_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in {
            "origin": row.get("origin"),
            "pinned_address": row.get("pinned_address"),
            "trust": row.get("certificate_trust"),
            "hostname_matches": row.get("certificate_hostname_matches"),
            "certificate_sha256": row.get("certificate_sha256"),
            "not_after": row.get("certificate_not_after"),
        }.items() if value is not None
    }


def _probe_rows(rows: Any, label: str) -> list[dict[str, Any]]:
    """Value-free raw-probe outcomes (tls_legacy_probe), bounded."""
    keys = (label, "supported", "result", "negotiated_protocol", "cipher", "cipher_bits", "weakness")
    return [
        {key: row.get(key) for key in keys if row.get(key) is not None}
        for row in list(rows or ())[:8] if isinstance(row, Mapping)
    ]


def tls_finding_evidence(
    item: Mapping[str, Any], observations: Sequence[Mapping[str, Any]], *, check: str,
) -> dict[str, Any]:
    """The facts a TLS finding is about, from the capability's observation of that origin.

    ``observations`` are the same action's other origin/address handshakes: they say which
    other origins serve the same certificate and whether another origin presents a valid one.
    """
    requested = item.get("server_hostname")
    evidence: dict[str, Any] = {
        "requested_host": requested,
        "requested_host_kind": _host_kind(requested),
        "cipher_bits": item.get("cipher_bits"),
        "cipher_protocol": item.get("cipher_protocol"),
        "supported_protocols": list(item.get("supported_protocols") or ())[:6],
        "certificate": _certificate(item),
        "chain_status": item.get("certificate_chain_status"),
        "chain_length": item.get("certificate_chain_length"),
        "chain": _chain(item),
        "trust": _trust(item),
    }
    if check == "tls_legacy_protocol":
        evidence["legacy_protocols_supported"] = [
            str(item)[:20] for item in list(item.get("legacy_protocols_supported") or ())[:4]
        ]
        evidence["legacy_protocol_probes"] = _probe_rows(item.get("legacy_protocol_probes"), "protocol")
        evidence["protocol_attempts"] = [
            {key: attempt.get(key) for key in ("protocol", "supported", "negotiated_protocol", "cipher", "error_type")
             if attempt.get(key) is not None}
            for attempt in list(item.get("protocol_attempts") or ())[:6]
            if isinstance(attempt, Mapping)
        ]
    if check == "tls_weak_cipher":
        weak = [str(name)[:80] for name in list(item.get("weak_ciphers_supported") or ())[:12]]
        evidence["weak_ciphers_supported"] = weak
        evidence["weak_cipher_probes"] = _probe_rows(item.get("weak_cipher_probes"), "group")
        if weak:
            # The weakest suite the server accepts is the one the finding is about; the
            # negotiated suite of a modern handshake stays as `negotiated_cipher`.
            evidence["negotiated_cipher"] = item.get("cipher")
            evidence["cipher"] = weak[0]
    if item.get("examined_by"):
        evidence["examined_by"] = str(item["examined_by"])[:40]
    sha = item.get("certificate_sha256")
    same: list[str] = []
    others: list[dict[str, Any]] = []
    for row in observations:
        if not isinstance(row, Mapping) or row.get("kind") != "tls_protocol" or row is item:
            continue
        if row.get("status") != "success":
            continue
        if row.get("origin") == item.get("origin") and row.get("pinned_address") == item.get("pinned_address"):
            continue
        if sha and row.get("certificate_sha256") == sha:
            if row.get("origin") and row.get("origin") != item.get("origin"):
                same.append(str(row["origin"]))
        else:
            others.append(_origin_summary(row))
    if same:
        evidence["same_certificate_origins"] = sorted(set(same))[:_MAX_ORIGINS]
    if others:
        evidence["other_tls_origins"] = others[:_MAX_ORIGINS]
    return {key: value for key, value in evidence.items() if value not in (None, [], {})}


# Template classification fields worth keeping: identifiers and scores, never raw traffic.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d{1,5}$", re.IGNORECASE)


def _strings(values: Any, limit: int, chars: int) -> list[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Iterable):
        return []
    out: list[str] = []
    for value in values:
        text = _text(value, chars)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def template_classification(item: Mapping[str, Any]) -> dict[str, Any]:
    """Template metadata the nuclei result carried: description, tags, CVE/CWE, scores, references."""
    out: dict[str, Any] = {}
    description = _text(item.get("description"), 600)
    if description:
        out["template_description"] = description
    tags = _strings(item.get("tags"), 12, 40)
    if tags:
        out["template_tags"] = tags
    references = [ref for ref in _strings(item.get("reference"), 5, 300) if ref.lower().startswith(("http://", "https://"))]
    if references:
        out["template_references"] = references
    remediation = _text(item.get("template_remediation"), 600)
    if remediation:
        out["template_remediation"] = remediation
    cves = [value.upper() for value in _strings(item.get("cve_id"), 5, 30) if _CVE_RE.match(value)]
    if cves:
        out["cve_ids"] = cves
    cwes = [value.upper() for value in _strings(item.get("cwe_id"), 5, 12) if _CWE_RE.match(value)]
    if cwes:
        out["cwe_ids"] = cwes
    for key, ceiling in (("cvss_score", 10), ("epss_score", 1), ("epss_percentile", 1)):
        value = item.get(key)
        try:
            if value not in (None, "") and not isinstance(value, bool):
                number = float(value)
                if math.isfinite(number) and 0 <= number <= ceiling:
                    out[key] = round(number, 5)
        except (TypeError, ValueError):
            continue
    metrics = _text(item.get("cvss_metrics"), 120)
    if metrics:
        out["cvss_metrics"] = metrics
    cpe = _text(item.get("cpe"), 200)
    if cpe:
        out["cpe"] = cpe
    lengths = item.get("extracted_result_lengths")
    if isinstance(lengths, (list, tuple)):
        out["extracted_result_lengths"] = [value for value in lengths[:_MAX_EXTRACTED]
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2_000_000]
    return out


__all__ = ["template_classification", "tls_finding_evidence"]
