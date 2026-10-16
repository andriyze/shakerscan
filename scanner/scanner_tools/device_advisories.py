"""Offline connected-device advisory matching for compact CPE-native snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import urllib.parse
from dataclasses import dataclass
from typing import Any


MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
BUNDLED_SNAPSHOT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "device_advisories.json",
)
BUNDLED_SNAPSHOT_SHA256 = "bdab781f78f07ab87e27e3e0bcc8d6d4c7131e84f131d37a465d1bfbeeeb191e"
# The built-in snapshot's own generated_at: an external bundle older than this is refused, so a
# stale bundle left on the host cannot replace newer data shipped in a later image.
BUNDLED_SNAPSHOT_GENERATED_AT = "2026-10-13T13:29:01Z"

# A network banner, Nmap guess, or unauthenticated protocol response can produce a
# syntactically exact CPE without proving which firmware is installed. Only authenticated or
# cryptographically attested inventory may turn an advisory match into a verified finding.
AUTHORITATIVE_IDENTITY_EVIDENCE_TIERS = frozenset({
    "authenticated_firmware_inventory",
    "authenticated_package_inventory",
    "signed_firmware_manifest",
    "vendor_attested_inventory",
})
FINGERPRINT_IDENTITY_EVIDENCE_TIER = "network_service_fingerprint"

# Conservative, curated package-name -> (cpe_vendor, cpe_product) map. Only packages whose
# upstream identity is unambiguous appear here: a mapped package earns an authoritative CPE and
# can therefore promote an advisory match, while every unmapped package stays product-name-only
# (a non-promotable candidate at most). The map is intentionally small and exact so an
# authenticated inventory can never manufacture a false verified advisory from a guessed identity.
PACKAGE_CPE_IDENTITY: dict[str, tuple[str, str]] = {
    "openssl": ("openssl", "openssl"),
    "libssl3": ("openssl", "openssl"),
    "libssl1.1": ("openssl", "openssl"),
    "libssl1.0.0": ("openssl", "openssl"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "dropbearmulti": ("dropbear_ssh_project", "dropbear_ssh"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "dnsmasq-full": ("thekelleys", "dnsmasq"),
    "dnsmasq-base": ("thekelleys", "dnsmasq"),
    "busybox": ("busybox", "busybox"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "mosquitto": ("eclipse", "mosquitto"),
    "libmosquitto1": ("eclipse", "mosquitto"),
    "zlib1g": ("zlib", "zlib"),
    "libz1": ("zlib", "zlib"),
    "libcurl3": ("haxx", "libcurl"),
    "libcurl4": ("haxx", "libcurl"),
    "libcurl3-gnutls": ("haxx", "libcurl"),
    "libcurl3-openssl": ("haxx", "libcurl"),
    "libupnp": ("libupnp_project", "libupnp"),
    "libupnp13": ("libupnp_project", "libupnp"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "goahead": ("embedthis", "goahead"),
    "thttpd": ("acme", "thttpd"),
    "libgnutls30": ("gnu", "gnutls"),
    "gnutls-bin": ("gnu", "gnutls"),
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "live555": ("live555", "live555"),
}
AUTHENTICATED_PACKAGE_INVENTORY_TIER = "authenticated_package_inventory"
_MAX_PARSED_PACKAGES = 800


def upstream_package_version(value: Any) -> str:
    """Reduce a distro package version to its upstream component for CPE comparison.

    Strips a Debian/dpkg epoch (``1:8.9p1``) and the distro revision suffix
    (``-3ubuntu0.4`` / ``-r0``) so ``version_in_range`` compares upstream releases.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if ":" in text:
        text = text.split(":", 1)[1]
    text = text.split("-", 1)[0]
    return text.strip()


def _package_inventory_text(host_review: Any) -> str:
    """Extract the software_packages bundle stdout from an SSH host-review result."""
    review = host_review if isinstance(host_review, dict) else {}
    if str(review.get("status") or "") == "rejected":
        return ""
    for bundle in review.get("bundles") or []:
        if isinstance(bundle, dict) and str(bundle.get("bundle") or "") == "software_packages":
            return str(bundle.get("stdout") or "")
    return ""


def parse_authenticated_package_inventory(host_review: Any) -> list[dict[str, Any]]:
    """Parse a credentialed SSH package inventory into authoritative identity records.

    Only produced from an authenticated host review (dpkg/opkg/apk/rpm output), so every
    record is tagged ``authenticated_package_inventory``. Mapped packages carry a curated
    CPE (advisory-promotion eligible); unmapped packages carry only a product name.
    """
    text = _package_inventory_text(host_review)
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in text.splitlines():
        if len(records) >= _MAX_PARSED_PACKAGES:
            break
        line = raw_line.strip()
        if not line:
            continue
        name = ""
        raw_version = ""
        if " - " in line:  # opkg list-installed: "dropbear - 2020.81-1"
            head, _, tail = line.partition(" - ")
            name = head.strip()
            raw_version = tail.strip().split()[0] if tail.strip() else ""
        else:
            tokens = line.split()
            if len(tokens) >= 2:  # dpkg-query "${Package} ${Version}"
                name, raw_version = tokens[0].strip(), tokens[1].strip()
        name = name.lower()
        if not name or not raw_version or any(ch in name for ch in " \t/"):
            continue
        version = upstream_package_version(raw_version)
        if not version:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        identity = PACKAGE_CPE_IDENTITY.get(name)
        cpe = ""
        if identity:
            vendor, product = identity
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        records.append({
            "package": name,
            "product": (identity[1] if identity else name),
            "version": version,
            "raw_version": raw_version[:120],
            "cpe": cpe,
            "identity_evidence_tier": AUTHENTICATED_PACKAGE_INVENTORY_TIER,
            "curated_identity": bool(identity),
        })
    return records


def identity_evidence_tier(service: Any) -> dict[str, Any]:
    """Classify identity provenance without upgrading fingerprints by inference."""
    record = service if isinstance(service, dict) else {}
    metadata = record.get("metadata_json")
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    raw = record.get("identity_evidence_tier") or metadata.get("identity_evidence_tier")
    tier = str(raw or FINGERPRINT_IDENTITY_EVIDENCE_TIER).strip().lower()
    if tier not in AUTHORITATIVE_IDENTITY_EVIDENCE_TIERS:
        tier = FINGERPRINT_IDENTITY_EVIDENCE_TIER
    return {
        "tier": tier,
        "authoritative": tier in AUTHORITATIVE_IDENTITY_EVIDENCE_TIERS,
    }


# The verified snapshot, parsed once per process and file version (path, pinned digest, inode,
# size, mtime): a page of services must not re-read and re-hash a multi-megabyte file each time.
_SNAPSHOT_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}


def _bundle_module():
    # Relative: the same module object whether this package is imported as scanner_tools or
    # scanner.scanner_tools, so trusted keys configured on one are the keys the loader uses.
    from . import intel_bundle
    return intel_bundle


def load_verified_snapshot(
    path: Any, expected_sha256: Any, *, max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """Load the advisory snapshot in force, verified before use.

    An operator pin (``DEVICE_INTEL_DB_PATH``/``DEVICE_INTEL_DB_SHA256`` set at all, even to the
    built-in file) is used as given and freezes the intelligence: no bundle replaces it. The image sets
    neither. Otherwise a signed external bundle (``intel_bundle``) that verifies, and is not below the
    recorded high-water ``bundle_version``, is preferred, and the snapshot built into the image is the
    fallback; ``source`` and ``bundle`` say which was used and why.
    """
    location = str(path or "").strip()
    expected = str(expected_sha256 or "").strip().lower()
    if location or expected:
        return _labelled(_load_pinned_snapshot(location, expected, max_bytes=max_bytes), "operator_pinned", None)
    intel_bundle = _bundle_module()
    bundle = intel_bundle.bundle_status(
        not_older_than=BUNDLED_SNAPSHOT_GENERATED_AT, minimum_version=intel_bundle.read_high_water(),
    )
    if bundle.get("status") == "verified":
        loaded = _load_pinned_snapshot(bundle["snapshot_path"], bundle["snapshot_sha256"], max_bytes=max_bytes)
        public = {key: bundle.get(key) for key in ("status", "bundle_version", "generated_at", "key_id")}
        if loaded.get("status") == "available":
            intel_bundle.note_version_in_force(bundle["bundle_version"])
            return _labelled(loaded, "external_bundle", public)
        # The signed manifest named content the file does not hold: refuse it, keep the built-in data.
        bundle = {"status": f"snapshot_{loaded.get('status') or 'unavailable'}"}
    builtin = _load_pinned_snapshot(BUNDLED_SNAPSHOT_PATH, BUNDLED_SNAPSHOT_SHA256, max_bytes=max_bytes)
    return _labelled(builtin, "builtin", {"status": str(bundle.get("status") or "absent")})


def _labelled(result: dict[str, Any], source: str, bundle: dict[str, Any] | None) -> dict[str, Any]:
    # Labelled in place: a cached snapshot is returned as the same object, not a copy per page.
    result["source"] = source
    if bundle is not None:
        result["bundle"] = bundle
    else:
        result.pop("bundle", None)
    return result


def _load_pinned_snapshot(
    path: Any, expected_sha256: Any, *, max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """Load a regular, no-symlink advisory snapshot only when its pinned digest matches."""
    location = str(path or "").strip()
    expected = str(expected_sha256 or "").strip().lower()
    if not location:
        return {"status": "not_configured", "advisories": []}
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        return {"status": "untrusted_snapshot", "advisories": [], "error": "sha256_required"}
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(location, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return {"status": "unavailable", "advisories": [], "error": "not_regular_file"}
        cache_key = (location, expected, before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        cached = _SNAPSHOT_CACHE.get(cache_key)
        if cached is not None:
            return cached
        if before.st_size > max(1, int(max_bytes)):
            return {
                "status": "snapshot_too_large", "advisories": [],
                "size_bytes": before.st_size, "max_bytes": max_bytes,
            }
        raw = bytearray()
        while len(raw) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            return {"status": "unavailable", "advisories": [], "error": "snapshot_changed_during_read"}
        if len(raw) > max_bytes:
            return {"status": "snapshot_too_large", "advisories": [], "size_bytes": len(raw), "max_bytes": max_bytes}
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            return {
                "status": "integrity_mismatch", "advisories": [],
                "expected_sha256": expected, "actual_sha256": actual,
            }
        decoded = json.loads(bytes(raw).decode("utf-8"))
        records = decoded if isinstance(decoded, list) else decoded.get("advisories", []) if isinstance(decoded, dict) else []
        records = [item for item in records if isinstance(item, dict)][:100_000]
        # Snapshot v2 keeps each CVE's title once, in "titles"; records carry it again here.
        titles = decoded.get("titles") if isinstance(decoded, dict) else None
        if isinstance(titles, dict):
            for item in records:
                if not item.get("title"):
                    title = titles.get(str(item.get("cve") or item.get("advisory_id") or ""))
                    if isinstance(title, str):
                        item["title"] = title[:500]
        result = {
            "status": "available", "advisories": records,
            "snapshot_sha256": actual, "record_count": len(records),
            "generated_at": decoded.get("generated_at") if isinstance(decoded, dict) else None,
        }
        _SNAPSHOT_CACHE.clear()  # one snapshot per process: the one in use
        _SNAPSHOT_CACHE[cache_key] = result
        return result
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "advisories": [], "error": type(exc).__name__}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _version_parts(value: Any) -> tuple[tuple[int, Any], ...]:
    text = str(value or "").strip().lower()
    parts: list[tuple[int, Any]] = []
    for token in re.findall(r"\d+|[a-z]+", text):
        # Numeric segments sort before letter suffixes at the same position
        # (1.0.1 < 1.0.1a < 1.0.1g), matching NVD's letter-suffix release
        # families; zero-padding keeps 1.0 == 1.0.0.
        parts.append((1, int(token)) if token.isdigit() else (2, token))
    return tuple(parts)


def compare_versions(left: Any, right: Any) -> int:
    """Compare common embedded-firmware versions without claiming full vendor semantics."""
    a, b = list(_version_parts(left)), list(_version_parts(right))
    width = max(len(a), len(b))
    a.extend([(1, 0)] * (width - len(a)))
    b.extend([(1, 0)] * (width - len(b)))
    return (a > b) - (a < b)


def version_in_range(version: Any, advisory: dict[str, Any]) -> bool | None:
    current = str(version or "").strip()
    exact = str(advisory.get("version") or "").strip()
    bounds = {
        "start_including": advisory.get("version_start_including"),
        "start_excluding": advisory.get("version_start_excluding"),
        "end_including": advisory.get("version_end_including"),
        "end_excluding": advisory.get("version_end_excluding"),
    }
    if exact and exact not in {"*", "-"}:
        return compare_versions(current, exact) == 0 if current else None
    if not any(value not in (None, "") for value in bounds.values()):
        return True if current else None
    if not current:
        return None
    if bounds["start_including"] not in (None, "") and compare_versions(current, bounds["start_including"]) < 0:
        return False
    if bounds["start_excluding"] not in (None, "") and compare_versions(current, bounds["start_excluding"]) <= 0:
        return False
    if bounds["end_including"] not in (None, "") and compare_versions(current, bounds["end_including"]) > 0:
        return False
    if bounds["end_excluding"] not in (None, "") and compare_versions(current, bounds["end_excluding"]) >= 0:
        return False
    return True


@dataclass(frozen=True)
class _CPEComponent:
    value: str
    wildcard: bool = False
    not_applicable: bool = False


def _split_cpe23_components(value: str) -> list[str]:
    """Split a formatted CPE while preserving escaped delimiters for normalization."""
    components: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            components.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    components.append("".join(current))
    return components


def _cpe_component(raw: Any, *, uri_binding: bool = False) -> _CPEComponent:
    value = urllib.parse.unquote(str(raw or "")) if uri_binding else str(raw or "")
    if value == "*":
        return _CPEComponent("", wildcard=True)
    if value == "-":
        return _CPEComponent("", not_applicable=True)
    if not uri_binding:
        value = re.sub(r"\\(.)", r"\1", value)
    return _CPEComponent(value.strip().lower())


def _cpe_identity(value: Any) -> tuple[_CPEComponent, _CPEComponent, _CPEComponent, _CPEComponent] | None:
    """Return part/vendor/product/version without collapsing CPE wildcard semantics."""
    text = str(value or "").strip()
    if text.startswith("cpe:2.3:"):
        components = _split_cpe23_components(text[len("cpe:2.3:"):])
        if len(components) >= 4:
            return tuple(_cpe_component(item) for item in components[:4])  # type: ignore[return-value]
    # Retain compatibility with the still-common CPE 2.2 URI binding.
    if text.startswith("cpe:/"):
        components = text[5:].split(":")
        if len(components) >= 3:
            padded = (components + [""])[:4]
            return tuple(_cpe_component(item, uri_binding=True) for item in padded)  # type: ignore[return-value]
    return None


def _concrete_identity_matches(
    query: tuple[_CPEComponent, ...], advisory: tuple[_CPEComponent, ...],
) -> bool:
    # A high-confidence software identity requires the same concrete CPE part, vendor, and
    # product. Wildcards remain useful for version evaluation but cannot erase the application /
    # operating-system boundary or manufacture an exact product claim.
    return all(
        not left.wildcard and not left.not_applicable
        and not right.wildcard and not right.not_applicable
        and bool(left.value) and left.value == right.value
        for left, right in zip(query[:3], advisory[:3])
    )


def match_advisories(
    records: Any, *, cpe: str | None, product: str | None, version: str | None,
    identity_evidence_tier: str | None = None, limit: int = 50,
) -> list[dict[str, Any]]:
    query_cpe = str(cpe or "").strip()
    query_identity = _cpe_identity(query_cpe)
    query_product = str(product or "").strip().lower()
    query_version = str(version or "").strip()
    if not query_version and query_identity:
        identity_version = query_identity[3]
        if not identity_version.wildcard and not identity_version.not_applicable:
            query_version = identity_version.value
    matches: list[dict[str, Any]] = []
    for raw in list(records or [])[:100_000]:
        if not isinstance(raw, dict):
            continue
        advisory_cpe = str(raw.get("cpe") or "").strip()
        advisory_identity = _cpe_identity(advisory_cpe)
        exact_identity = bool(
            query_identity and advisory_identity
            and _concrete_identity_matches(query_identity, advisory_identity)
        )
        heuristic_identity = bool(
            not exact_identity and query_product
            and query_product == str(raw.get("product") or "").strip().lower()
        )
        if not exact_identity and not heuristic_identity:
            continue
        evaluation_record = raw
        versions = raw.get("versions")
        if isinstance(versions, list) and versions:
            # Snapshot v2 groups the exact versions NVD lists for one CVE and product: the record
            # applies to exactly these versions, as if each were its own exact-version record.
            listed = [str(item) for item in versions[:5000] if isinstance(item, (str, int, float))]
            same = next((item for item in listed if query_version and compare_versions(query_version, item) == 0), None)
            if query_version and same is None:
                continue
            evaluation_record = {**raw, "version": same or (listed[0] if listed else "")}
        elif advisory_identity and not any(
            raw.get(key) not in (None, "") for key in (
                "version", "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding",
            )
        ):
            advisory_version = advisory_identity[3]
            if not advisory_version.wildcard and not advisory_version.not_applicable and advisory_version.value:
                evaluation_record = {**raw, "version": advisory_version.value}
        affected = version_in_range(query_version, evaluation_record)
        if affected is False:
            continue
        has_version_constraint = any(
            evaluation_record.get(key) not in (None, "", "*", "-") for key in (
                "version", "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding",
            )
        )
        exact_and_bounded = (
            exact_identity and affected is True and bool(query_version) and has_version_constraint
        )
        authoritative_identity = (
            str(identity_evidence_tier or "").strip().lower()
            in AUTHORITATIVE_IDENTITY_EVIDENCE_TIERS
        )
        matches.append({
            "advisory_id": str(raw.get("advisory_id") or raw.get("cve") or "")[:100],
            "title": str(raw.get("title") or "")[:500],
            "severity": str(raw.get("severity") or "unknown")[:30],
            "reference": str(raw.get("reference") or "")[:1000],
            "match_type": "exact_cpe_version_range" if exact_and_bounded else (
                "exact_cpe_version_unknown" if exact_identity else "heuristic_product"
            ),
            "version_evaluation": "affected" if affected is True else "unknown",
            "confidence": "high" if exact_and_bounded else ("medium" if exact_identity else "low"),
            "proof_basis": (
                "authoritative_inventory_advisory_match"
                if exact_and_bounded and authoritative_identity
                else "advisory_matched_fingerprint_only" if exact_and_bounded
                else "signal_only"
            ),
            "advisory_match_complete": exact_and_bounded,
            "identity_evidence_tier": str(
                identity_evidence_tier or FINGERPRINT_IDENTITY_EVIDENCE_TIER
            ).strip().lower(),
            "authoritative_product_identity": authoritative_identity,
            "promotable": exact_and_bounded and authoritative_identity,
            "version_range": {
                    key: evaluation_record.get(key) for key in (
                    "version", "version_start_including", "version_start_excluding",
                    "version_end_including", "version_end_excluding",
                ) if evaluation_record.get(key) not in (None, "")
            },
        })
        if len(matches) >= max(1, min(int(limit), 200)):
            break
    return matches
