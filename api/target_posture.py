"""Target posture: the latest known headers, TLS, DNS, and network facts for a target.

Fast scan profiles skip some posture checks (cipher enumeration, full DNS), so a result page for
such a run used to show nothing for them even when an earlier run on the same target had the
data. Posture is derived on read from the newest completed scans that actually observed each
section; nothing is copied into a parallel store, and every section names the scan it came from so
the UI can say "observed in this run" or "from an earlier scan" truthfully. Payloads are shaped
to public facts and pass through the shared receipt redactor.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

try:
    from runtime.receipts import redact_receipt_value
except ModuleNotFoundError:  # package-native import layout
    from api.runtime.receipts import redact_receipt_value  # type: ignore[no-redef]

SCHEMA_VERSION = "target-posture/v1"
SECTIONS = ("http_headers", "tls", "dns", "network")

_SECURITY_HEADER_ORDER = (
    "content_security_policy", "strict_transport_security", "x_frame_options",
    "x_content_type_options", "referrer_policy", "permissions_policy",
    "cross_origin_opener_policy", "cross_origin_resource_policy", "cross_origin_embedder_policy",
)


def _record(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _listing(value: Any, limit: int = 20) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)[:limit]
    return []


def _text(value: Any, limit: int = 200) -> str | None:
    if value is None or value == "":
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def shape_http_headers(http: Mapping[str, Any]) -> dict[str, Any] | None:
    http = _record(http)
    present = {
        key: _text(value)
        for key, value in _record(http.get("security_headers")).items()
        if value not in (None, "", False)
    }
    missing = [str(item) for item in _listing(http.get("missing_security_headers"), 30)]
    observed = http.get("posture_observed") is True or bool(present) or bool(missing)
    if not observed:
        return None
    csp = _record(http.get("csp_evaluation"))
    cookies = []
    for cookie in _listing(http.get("cookies") or http.get("set_cookie_metadata"), 20):
        cookie = _record(cookie)
        if not cookie:
            continue
        cookies.append({
            "name": _text(cookie.get("name"), 80),
            "secure": bool(cookie.get("secure")),
            "httponly": bool(cookie.get("httponly") or cookie.get("http_only")),
            "samesite": _text(cookie.get("samesite") or cookie.get("same_site"), 20),
        })
    ordered = {key: present[key] for key in _SECURITY_HEADER_ORDER if key in present}
    ordered.update({key: value for key, value in sorted(present.items()) if key not in ordered})
    return {
        "status": http.get("status"),
        "present": ordered,
        "missing": missing,
        "csp": {
            "present": bool(csp) and csp.get("present") is not False and "content_security_policy" in present,
            "issues": [_text(item, 160) for item in _listing(csp.get("issues") or csp.get("weaknesses"), 8)],
        } if csp or "content_security_policy" in present else None,
        "cookies": cookies,
        "http2": http.get("http2"),
        "http3": http.get("http3"),
        "scheme_redirect": _text(http.get("scheme_redirect"), 40),
    }


def shape_tls(tls: Mapping[str, Any]) -> dict[str, Any] | None:
    tls = _record(tls)
    certificate = _record(tls.get("certificate"))
    endpoints = _listing(tls.get("endpoints"), 10)
    if not certificate and not endpoints:
        return None
    inventory = _record(tls.get("crypto_inventory"))
    testssl = _record(tls.get("testssl"))
    sslyze = _record(tls.get("sslyze"))
    protocols = (
        _listing(inventory.get("protocols"))
        or _listing(sslyze.get("protocols"))
        or _listing(testssl.get("protocols"))
        or sorted(_record(tls.get("cipher_suites")).keys())
    )
    cipher_suites = {}
    for protocol, suites in _record(tls.get("cipher_suites")).items():
        cipher_suites[str(protocol)] = [_text(item, 80) for item in _listing(suites, 40)]
    weak = [
        _text(item, 160) for item in (
            _listing(inventory.get("weak")) or _listing(inventory.get("weaknesses"))
            or _listing(testssl.get("vulnerabilities")) or _listing(sslyze.get("weak_ciphers"))
        )
    ]
    return {
        "certificate": {
            "subject": _text(certificate.get("subject") or certificate.get("subject_cn")),
            "issuer": _text(certificate.get("issuer") or certificate.get("issuer_cn")),
            "not_before": _text(certificate.get("not_before")),
            "not_after": _text(certificate.get("not_after") or certificate.get("expires")),
            "key_algorithm": _text(certificate.get("public_key_algorithm") or certificate.get("key_type"), 40),
            "key_bits": certificate.get("public_key_bits") or certificate.get("key_bits"),
            "signature_algorithm": _text(certificate.get("signature_algorithm"), 60),
            "san_count": len(_listing(certificate.get("subject_alt_names") or certificate.get("san"), 500)),
            "self_signed": certificate.get("self_signed"),
            "expired": certificate.get("expired"),
        } if certificate else None,
        "protocols": [_text(item, 40) for item in protocols],
        "cipher_suites": cipher_suites,
        "weak": [item for item in weak if item],
        "ocsp_stapled": _record(tls.get("ocsp")).get("stapled"),
        "grade": _text(testssl.get("grade") or inventory.get("grade"), 10),
        "sources": [name for name in ("testssl", "sslyze", "nmap", "tlsx") if tls.get(name) or (name == "tlsx" and endpoints)],
    }


def shape_dns(dns: Mapping[str, Any]) -> dict[str, Any] | None:
    dns = _record(dns)
    records = {
        str(name): [_text(item, 120) for item in _listing(values, 10)]
        for name, values in _record(dns.get("records")).items()
        if _listing(values, 1)
    }
    if not records:
        return None
    dmarc = records.get("dmarc") or []
    return {
        "records": records,
        "dnssec": _text(_record(dns.get("dnssec")).get("status"), 40),
        "dmarc_present": bool(dmarc),
        "mta_sts_enabled": _record(dns.get("mta_sts")).get("enabled"),
        "tls_rpt_present": bool(records.get("tls_rpt")),
        "caa_present": bool(records.get("host_caa") or records.get("root_caa")),
    }


def shape_network(infrastructure: Mapping[str, Any]) -> dict[str, Any] | None:
    infra = _record(infrastructure)
    addresses = []
    for item in _listing(infra.get("addresses"), 10):
        item = _record(item)
        if not item:
            continue
        addresses.append({
            "ip": _text(item.get("ip") or item.get("address"), 60),
            "asn": _text(item.get("asn"), 20),
            "organization": _text(item.get("organization") or item.get("org") or item.get("as_name"), 120),
            "country": _text(item.get("country"), 8),
            "provider": _text(item.get("provider") or item.get("cdn") or item.get("hosting"), 80),
        })
    registration = _record(infra.get("registration"))
    if not addresses and not registration:
        return None
    return {
        "addresses": addresses,
        "canonical_host": _text(infra.get("canonical_host"), 253),
        "registration": {
            "domain": _text(registration.get("domain") or infra.get("registration_domain"), 253),
            "registrar": _text(registration.get("registrar"), 120),
            "created": _text(registration.get("created") or registration.get("creation_date")),
            "expires": _text(registration.get("expires") or registration.get("expiration_date")),
        } if registration else None,
        "related_names_count": len(_listing(infra.get("related_names"), 1000)),
        "informational_only": True,
    }


SECTION_SHAPERS = {
    "http_headers": ("http", shape_http_headers),
    "tls": ("tls", shape_tls),
    "dns": ("dns", shape_dns),
    "network": ("infrastructure", shape_network),
}

# Only scans that could have observed a section are candidates. The JSONB predicates keep the
# query on the index and out of the (possibly multi-megabyte) full result payload.
_SECTION_PREDICATES = {
    "http_headers": (
        "(result->'http'->>'posture_observed' = 'true'"
        " OR jsonb_typeof(result->'http'->'security_headers') = 'object'"
        " OR jsonb_typeof(result->'http'->'missing_security_headers') = 'array')"
    ),
    "tls": "(jsonb_typeof(result->'tls'->'certificate') = 'object' OR jsonb_typeof(result->'tls'->'endpoints') = 'array')",
    "dns": "jsonb_typeof(result->'dns'->'records') = 'object'",
    "network": "jsonb_typeof(result->'infrastructure'->'addresses') = 'array'",
}


def posture_sections_from_result(result: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Shape every observed posture section from one scan result (pure; unit-testable)."""
    result = _record(result)
    shaped: dict[str, dict[str, Any]] = {}
    for section, (key, shaper) in SECTION_SHAPERS.items():
        payload = shaper(_record(result.get(key)))
        if payload:
            shaped[section] = redact_receipt_value(payload)
    return shaped


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return _text(value, 40)


async def load_target_posture(
    conn: Any, target_id: str, *, prefer_scan_id: str | None = None,
) -> dict[str, Any]:
    """Each section from the preferred scan when it observed it, else the newest scan that did.

    The results page passes its own scan id so a section this run observed is attributed to this
    run even when a later scan exists; only sections this run skipped fall back to other scans.
    """
    sections: dict[str, Any] = {name: None for name in SECTIONS}
    for section, (key, shaper) in SECTION_SHAPERS.items():
        predicate = _SECTION_PREDICATES[section]
        rows = []
        if prefer_scan_id:
            rows = list(await conn.fetch(
                f"""
                SELECT id, completed_at, created_at, result->'{key}' AS section
                FROM scans
                WHERE target_id = $1 AND id = $2 AND status = 'completed'
                  AND result IS NOT NULL AND {predicate}
                LIMIT 1
                """,
                target_id, prefer_scan_id,
            ))
        rows += list(await conn.fetch(
            f"""
            SELECT id, completed_at, created_at, result->'{key}' AS section
            FROM scans
            WHERE target_id = $1
              AND status = 'completed'
              AND COALESCE(scan_role, '') <> 'shard'
              AND result IS NOT NULL
              AND {predicate}
            ORDER BY completed_at DESC NULLS LAST, created_at DESC
            LIMIT 5
            """,
            target_id,
        ))
        for row in rows:
            raw = row["section"]
            if isinstance(raw, str):
                import json
                try:
                    raw = json.loads(raw)
                except ValueError:
                    raw = {}
            payload = shaper(_record(raw))
            if not payload:
                continue
            sections[section] = {
                "scan_id": str(row["id"]),
                "observed_at": _iso(row["completed_at"] or row["created_at"]),
                "payload": redact_receipt_value(payload),
            }
            break
    return {"schema_version": SCHEMA_VERSION, "target_id": str(target_id), "sections": sections}
