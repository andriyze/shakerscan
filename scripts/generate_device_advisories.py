#!/usr/bin/env python3
"""Release-time generator for the shakerscan-device-advisories/v1 snapshot.

Queries the NVD API 2.0 for a curated list of embedded/firmware CPE names and
emits the offline advisory snapshot consumed by
scanner/scanner_tools/device_advisories.py.

Modes:
  * default: query NVD by --cpe prefix (virtualMatchString) and/or --vendor,
    or by explicit --cve CVE-ID list;
  * --from-raw DIR: rebuild from cached raw NVD API responses instead of the
    network (select them with --cve; every *.json in DIR is indexed);
  * --offline: emit only the built-in curated seed below; no network access;
  * --verify PATH: validate an existing snapshot with the real scanner loader
    (hashes the file, no write, no network).

Only unconditional configuration matches explicitly marked vulnerable and carrying
NVD version bounds (or an exact CPE version) are emitted; conditional, negated,
non-vulnerable, and unbounded wildcard matches are skipped.
Matches for products outside the embedded dictionary are skipped too, so a
shared CVE (Heartbleed, etc.) does not drag in vendor appliance noise.

Stdlib only; no API key required (unauthenticated rate limit: ~5 requests per
rolling 30 seconds, hence the default 6 second sleep between requests).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SCHEMA_VERSION = "shakerscan-device-advisories/v1"
SOURCE_LABEL = "NIST National Vulnerability Database CPE configurations"
DESCRIPTION_LIMIT = 500
USER_AGENT = "shakerscan-device-advisory-generator/1.0"
HTTP_BACKOFF_CAP_SECONDS = 120

EMBEDDED_CPE: dict[str, list[str]] = {
    "goahead": ["cpe:2.3:a:embedthis:goahead"],
    "lighttpd": ["cpe:2.3:a:lighttpd:lighttpd"],
    "dnsmasq": ["cpe:2.3:a:thekelleys:dnsmasq"],
    "busybox": ["cpe:2.3:a:busybox:busybox"],
    "dropbear": ["cpe:2.3:a:dropbear_ssh_project:dropbear_ssh"],
    "miniupnpd": ["cpe:2.3:a:miniupnp_project:miniupnpd"],
    "thttpd": ["cpe:2.3:a:acme:thttpd"],
    "boa": ["cpe:2.3:a:boa:boa"],
    "openssl": ["cpe:2.3:a:openssl:openssl"],
    "zlib": ["cpe:2.3:a:zlib:zlib"],
    "libupnp": ["cpe:2.3:a:pupnp:libupnp", "cpe:2.3:a:libupnp_project:libupnp"],
    "gnutls": ["cpe:2.3:a:gnu:gnutls"],
    "wolfssl": ["cpe:2.3:a:wolfssl:wolfssl"],
    "mosquitto": ["cpe:2.3:a:eclipse:mosquitto"],
    "curl": ["cpe:2.3:a:haxx:curl", "cpe:2.3:a:haxx:libcurl"],
    "pcre": ["cpe:2.3:a:pcre:pcre"],
    "expat": ["cpe:2.3:a:libexpat_project:libexpat"],
    "libxml2": ["cpe:2.3:a:xmlsoft:libxml2"],
    "ffmpeg": ["cpe:2.3:a:ffmpeg:ffmpeg"],
    "live555": ["cpe:2.3:a:live555:live555"],
    "gsoap": ["cpe:2.3:a:genivia:gsoap"],
    "civetweb": ["cpe:2.3:a:civetweb_project:civetweb"],
    "mongoose": ["cpe:2.3:a:cesanta:mongoose"],
    "openvpn": ["cpe:2.3:a:openvpn:openvpn"],
    "hostapd": ["cpe:2.3:a:w1.fi:hostapd"],
    "wpa_supplicant": ["cpe:2.3:a:w1.fi:wpa_supplicant"],
    "pure-ftpd": ["cpe:2.3:a:pureftpd:pure-ftpd"],
    "vsftpd": ["cpe:2.3:a:vsftpd:vsftpd"],
    "proftpd": ["cpe:2.3:a:proftpd:proftpd"],
    "ttyd": ["cpe:2.3:a:ttyd_project:ttyd"],
}

# Curated offline seed. Every bound below was verified against the NVD API 2.0
# cve configurations (see docs/connected-device-security.md). Kept deliberately
# small; the bundled snapshot is the authoritative release artifact.
OFFLINE_SEED: list[dict[str, Any]] = [
    {
        "cve": "CVE-2014-0160",
        "title": "The Heartbleed Bug in OpenSSL 1.0.1 through 1.0.1f allows remote attackers to obtain sensitive memory information via crafted TLS heartbeat requests.",
        "severity": "high",
        "cwe": "CWE-125",
        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "product": "openssl",
        "version_start_including": "1.0.1",
        "version_end_excluding": "1.0.1g",
        "published": "2014-04-07",
        "last_modified": "2024-11-21",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
    },
    {
        "cve": "CVE-2017-17562",
        "title": "Embedthis GoAhead before 3.6.5 allows remote code execution via the CGI variable expansion handler when firmware mounts the CGI bin directory.",
        "severity": "high",
        "cpe": "cpe:2.3:a:embedthis:goahead:*:*:*:*:*:*:*:*",
        "product": "goahead",
        "version_end_excluding": "3.6.5",
        "published": "2017-12-12",
        "last_modified": "2021-04-20",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-17562",
    },
    {
        "cve": "CVE-2018-15599",
        "title": "Dropbear SSH through 2018.76 allows user enumeration because a delay does not occur for nonexistent usernames.",
        "severity": "medium",
        "cwe": "CWE-203",
        "cpe": "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*",
        "product": "dropbear",
        "version_end_including": "2018.76",
        "published": "2018-08-21",
        "last_modified": "2023-11-07",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-15599",
    },
    {
        "cve": "CVE-2018-19052",
        "title": "An issue was discovered in mod_alias physical context handling in lighttpd before 1.4.50, leading to path traversal and potential information disclosure.",
        "severity": "high",
        "cpe": "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*",
        "product": "lighttpd",
        "version_end_excluding": "1.4.50",
        "published": "2018-11-07",
        "last_modified": "2021-05-14",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-19052",
    },
    {
        "cve": "CVE-2021-3448",
        "title": "A flaw was found in dnsmasq before 2.85 where the DNSSEC validation code is not properly threaded, allowing an attacker to forge signatures.",
        "severity": "medium",
        "cwe": "CWE-347",
        "cpe": "cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*",
        "product": "dnsmasq",
        "version_end_excluding": "2.85",
        "published": "2021-04-08",
        "last_modified": "2023-11-07",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-3448",
    },
    {
        "cve": "CVE-2022-30065",
        "title": "A heap-use-after-free in BusyBox 1.35.0 awk applet allows code execution via a crafted awk pattern.",
        "severity": "high",
        "cpe": "cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*",
        "product": "busybox",
        "version": "1.35.0",
        "published": "2022-05-18",
        "last_modified": "2024-08-16",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-30065",
    },
    {
        "cve": "CVE-2023-38545",
        "title": "A heap buffer overflow in curl's SOCKS5 proxy handshake (libcurl 7.69.0 through 8.3.0) allows arbitrary code execution when a slow proxy delivers oversized hostname chunks.",
        "severity": "critical",
        "cwe": "CWE-787",
        "cpe": "cpe:2.3:a:haxx:libcurl:*:*:*:*:*:*:*:*",
        "product": "libcurl",
        "version_start_including": "7.69.0",
        "version_end_excluding": "8.4.0",
        "published": "2023-10-18",
        "last_modified": "2024-11-21",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-38545",
    },
]

BOUNDED_KEYS = (
    "version", "version_start_including", "version_start_excluding",
    "version_end_including", "version_end_excluding",
)
RANGE_KEYS = (
    "version_start_including", "version_start_excluding",
    "version_end_including", "version_end_excluding",
)


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_cpe23(value: str) -> list[str]:
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


def unescape_cpe_component(value: str) -> str:
    out: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            out.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            out.append(character)
    return "".join(out)


def cpe_product_key(criteria: str) -> str:
    components = split_cpe23(criteria)
    if len(components) < 5:
        return ""
    vendor = unescape_cpe_component(components[3]).lower()
    product = unescape_cpe_component(components[4]).lower()
    return f"{vendor}:{product}"


def embedded_product_keys() -> set[str]:
    keys: set[str] = set()
    for cpes in EMBEDDED_CPE.values():
        for cpe in cpes:
            key = cpe_product_key(cpe)
            if key:
                keys.add(key)
    return keys


class NvdError(RuntimeError):
    pass


def nvd_request(query: dict[str, str], sleep_seconds: float, max_retries: int = 5) -> dict:
    url = f"{NVD_CVES_URL}?{urllib.parse.urlencode(query)}"
    last_error = ""
    for attempt in range(max_retries + 1):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read(500).decode("utf-8", "replace").strip()
            last_error = f"HTTP {exc.code}: {body}"
            if exc.code in (403, 429) or exc.code >= 500:
                if attempt >= max_retries:
                    break
                backoff = min(HTTP_BACKOFF_CAP_SECONDS, max(sleep_seconds, 6.0) * (2 ** attempt))
                print(f"  NVD {exc.code}; backing off {backoff:.0f}s ({attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(backoff)
                continue
            raise NvdError(f"NVD request rejected: {last_error}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt >= max_retries:
                break
            backoff = min(HTTP_BACKOFF_CAP_SECONDS, max(sleep_seconds, 6.0) * (2 ** attempt))
            print(f"  network error ({last_error}); retrying in {backoff:.0f}s", file=sys.stderr)
            time.sleep(backoff)
    raise NvdError(f"NVD request failed after {max_retries + 1} attempts: {last_error}")


def fetch_cves_for_cpe(cpe: str, sleep_seconds: float, max_per_cpe: int) -> list[dict]:
    collected: list[dict] = []
    start_index = 0
    while len(collected) < max_per_cpe:
        query = {
            "virtualMatchString": cpe,
            "startIndex": str(start_index),
            "resultsPerPage": str(min(2000, max(1, max_per_cpe - len(collected)))),
        }
        payload = nvd_request(query, sleep_seconds)
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            break
        collected.extend(vulnerabilities)
        total = int(payload.get("totalResults", len(collected)))
        start_index += int(payload.get("resultsPerPage", len(vulnerabilities)))
        if start_index >= total or start_index >= max_per_cpe:
            break
        time.sleep(sleep_seconds)
    return collected[:max_per_cpe]


def fetch_cve_by_id(cve_id: str, sleep_seconds: float) -> dict:
    payload = nvd_request({"cveId": cve_id}, sleep_seconds)
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        raise NvdError(f"{cve_id}: no NVD record")
    return vulnerabilities[0]


def load_raw_index(directory: str) -> dict[str, dict]:
    """Index cached NVD API 2.0 JSON responses by CVE id."""
    index: dict[str, dict] = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError) as exc:
            raise NvdError(f"unreadable raw response {path}: {exc}")
        for wrapper in payload.get("vulnerabilities", []) if isinstance(payload, dict) else []:
            cve = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
            cve_id = str(cve.get("id") or "")
            if cve_id:
                index.setdefault(cve_id, wrapper)
    return index


def english_description(cve: dict) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def first_cwe(cve: dict) -> str:
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = str(description.get("value", ""))
            if value.startswith("CWE-"):
                return value
    return ""


def severity_from_metrics(cve: dict) -> str:
    metrics_root: Any = cve.get("metrics", {})
    groups: list[Any] = []
    if isinstance(metrics_root, dict):
        groups = [metrics_root]
    elif isinstance(metrics_root, list):
        groups = metrics_root
    for metric_group in groups:
        if not isinstance(metric_group, dict):
            continue
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = metric_group.get(key, [])
            if metrics:
                severity = metrics[0].get("cvssData", {}).get("baseSeverity")
                if severity:
                    return str(severity).lower()
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get(key, [])
        if metrics:
            severity = metrics[0].get("cvssData", {}).get("baseSeverity")
            if severity:
                return str(severity).lower()
    return "unknown"


def _iter_unconditional_vulnerable_matches(node: Any):
    """Yield only CPEs NVD marks vulnerable outside conditional/negated branches.

    An AND node commonly combines a vulnerable product with ``vulnerable:false``
    platform constraints.  The snapshot schema cannot represent that boolean
    configuration safely, so the entire conditional branch is rejected rather
    than flattening it into a false exact-product advisory.
    """
    if not isinstance(node, dict) or node.get("negate") is True:
        return
    if str(node.get("operator") or "OR").upper() == "AND":
        return
    for match in node.get("cpeMatch", []):
        if not isinstance(match, dict) or match.get("vulnerable") is not True:
            continue
        criteria = str(match.get("criteria", "")).strip()
        if criteria.startswith("cpe:2.3:"):
            yield criteria, match
    for child in node.get("nodes", []):
        yield from _iter_unconditional_vulnerable_matches(child)


def iter_cpe_matches(cve: dict):
    for configuration in cve.get("configurations", []):
        if not isinstance(configuration, dict) or configuration.get("negate") is True:
            continue
        if str(configuration.get("operator") or "OR").upper() == "AND":
            continue
        for node in configuration.get("nodes", []):
            yield from _iter_unconditional_vulnerable_matches(node)


def advisory_from_match(cve: dict, criteria: str, match: dict) -> dict | None:
    """Map one NVD 2.0 cpeMatch entry to the snapshot schema.

    Explicit versionStart/End bounds map verbatim to version_start_/version_end_
    fields; a concrete version component in the criteria maps to an exact
    `version` match; wildcard/unbounded matches carry no promotable signal and
    are rejected (None) so they stay out of the snapshot entirely.
    """
    bounds = {
        "version_start_including": match.get("versionStartIncluding"),
        "version_start_excluding": match.get("versionStartExcluding"),
        "version_end_including": match.get("versionEndIncluding"),
        "version_end_excluding": match.get("versionEndExcluding"),
    }
    bounds = {key: value for key, value in bounds.items() if value not in (None, "")}
    components = split_cpe23(criteria)
    if len(components) < 6:
        return None
    product = unescape_cpe_component(components[4])
    version = unescape_cpe_component(components[5])
    entry: dict[str, Any] = {
        "cve": cve.get("id", ""),
        "title": english_description(cve)[:DESCRIPTION_LIMIT],
        "severity": severity_from_metrics(cve),
        "cwe": first_cwe(cve),
        "cpe": criteria,
        "product": product,
    }
    if bounds:
        entry.update(bounds)
    elif version not in ("*", "-", ""):
        entry["version"] = version
    else:
        return None
    entry["published"] = str(cve.get("published", ""))[:10]
    entry["last_modified"] = str(cve.get("lastModified", ""))[:10]
    entry["reference"] = f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"
    return entry


def collect_entries(vulnerabilities: list[dict], allowed_keys: set[str]) -> tuple[list[dict], int, int]:
    entries: list[dict] = []
    skipped_unbounded = 0
    skipped_product = 0
    seen_cves: set[str] = set()
    for wrapper in vulnerabilities:
        cve = wrapper.get("cve", {})
        if not cve.get("id"):
            continue
        seen_cves.add(str(cve["id"]))
        for criteria, match in iter_cpe_matches(cve):
            if cpe_product_key(criteria) not in allowed_keys:
                skipped_product += 1
                continue
            entry = advisory_from_match(cve, criteria, match)
            if entry is None:
                skipped_unbounded += 1
                continue
            entries.append(entry)
    return entries, skipped_unbounded, skipped_product


def collapse_exact_entries_covered_by_ranges(advisories: list[dict]) -> list[dict]:
    """Drop exact-version duplicates when NVD also lists a bounded range for the same CVE+product."""
    range_keys = {
        (item.get("cve"), cpe_product_key(str(item.get("cpe") or "")))
        for item in advisories
        if any(item.get(key) not in (None, "") for key in RANGE_KEYS)
    }
    kept: list[dict] = []
    for item in advisories:
        key = (item.get("cve"), cpe_product_key(str(item.get("cpe") or "")))
        if item.get("version") and key in range_keys:
            continue
        kept.append(item)
    return kept


def build_snapshot(entries: list[dict]) -> dict:
    deduped: dict[str, dict] = {}
    for entry in entries:
        key = json.dumps(
            [entry.get("cve"), entry.get("cpe"), entry.get("version"),
             entry.get("version_start_including"), entry.get("version_start_excluding"),
             entry.get("version_end_including"), entry.get("version_end_excluding")],
            sort_keys=True,
        )
        deduped.setdefault(key, entry)
    advisories = collapse_exact_entries_covered_by_ranges(list(deduped.values()))
    advisories = sorted(
        advisories,
        key=lambda item: (item.get("cve", ""), item.get("cpe", ""),
                          json.dumps({k: v for k, v in item.items() if k.startswith("version")})),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "source": SOURCE_LABEL,
        "advisories": advisories,
    }


def write_snapshot(snapshot: dict, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    raw = (json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with open(output_path, "wb") as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def probe_versions_for(record: dict) -> list[str]:
    """Return candidate versions that should fall INSIDE the advisory's affected range.

    More than one candidate is needed because the loader's conservative
    comparator treats a numeric base as >= its own alpha-suffixed variants
    (e.g. 1.0.1 vs 1.0.1g), so a range's own start boundary is not always
    in-range under that comparator. Exact-version records probe themselves.
    """
    if record.get("version"):
        return [str(record["version"])]
    candidates: list[str] = []
    start_including = record.get("version_start_including")
    if start_including:
        candidates.extend([str(start_including), f"{start_including}a"])
    if record.get("version_start_excluding"):
        candidates.append("9999")
    if record.get("version_end_including") or record.get("version_end_excluding"):
        candidates.append("0")
    candidates.append("1.0")
    return candidates


def self_check(output_path: str, digest: str) -> None:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from scanner.scanner_tools import device_advisories

    loaded = device_advisories.load_verified_snapshot(output_path, digest)
    if loaded.get("status") != "available":
        raise SystemExit(f"self-check failed: loader returned {loaded}")
    records = loaded["advisories"]
    bounded = 0
    promotable = 0
    for record in records:
        if not any(record.get(key) not in (None, "", "*", "-") for key in BOUNDED_KEYS):
            raise SystemExit(f"self-check failed: unbounded record {record.get('cve')}")
        bounded += 1
        query_cpe_template = record.get("cpe", "")
        promoted = False
        for version in probe_versions_for(record):
            query_cpe = query_cpe_template
            components = split_cpe23(query_cpe)
            if len(components) >= 6:
                components[5] = version
                query_cpe = ":".join(components)
            matches = device_advisories.match_advisories(
                [record], cpe=query_cpe, product=None, version=version,
            )
            if matches and matches[0].get("promotable"):
                promoted = True
                break
        if not promoted:
            raise SystemExit(
                f"self-check failed: {record.get('cve')} is not promotable under the real matcher"
            )
        promotable += 1
    print(f"self-check: loader accepted {len(records)} records; "
          f"{bounded} version-bounded; {promotable} promotable under the real matcher")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cpe", action="append", default=[],
                        help="CPE 2.3 match prefix (e.g. cpe:2.3:a:embedthis:goahead); repeatable")
    parser.add_argument("--cve", action="append", default=[],
                        help="explicit NVD CVE id to include; repeatable (fetched, or selected from --from-raw)")
    parser.add_argument("--vendor", action="append", default=[], choices=sorted(EMBEDDED_CPE),
                        help="expand a built-in embedded product name to its CPE list; repeatable")
    parser.add_argument("--from-raw", metavar="DIR", default=None,
                        help="read raw NVD API 2.0 JSON responses from DIR instead of querying the network")
    parser.add_argument("--output", default=None,
                        help="destination path for the snapshot JSON (required unless --verify)")
    parser.add_argument("--verify", metavar="PATH", default=None,
                        help="validate an existing snapshot with the real scanner loader and exit")
    parser.add_argument("--max-per-cpe", type=int, default=50,
                        help="maximum CVEs collected per CPE query (default 50)")
    parser.add_argument("--sleep", type=float, default=6.0,
                        help="seconds between NVD requests (default 6, unauthenticated limit)")
    parser.add_argument("--offline", action="store_true",
                        help="emit only the built-in curated seed; no network access")
    parser.add_argument("--self-check", action="store_true",
                        help="validate the written file with the real scanner loader")
    args = parser.parse_args(argv)
    if not args.verify and not args.output:
        parser.error("--output is required unless --verify is used")
    if args.verify and (args.offline or args.from_raw or args.cpe or args.cve or args.vendor):
        parser.error("--verify runs standalone; do not combine it with generation options")
    return args


def resolve_allowed_keys(args: argparse.Namespace) -> set[str]:
    allowed = embedded_product_keys()
    for cpe in args.cpe:
        key = cpe_product_key(cpe)
        if key:
            allowed.add(key)
    return allowed


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verify:
        with open(args.verify, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        self_check(args.verify, digest)
        return 0

    if args.offline:
        entries = [dict(entry) for entry in OFFLINE_SEED]
        skipped_unbounded = 0
        skipped_product = 0
        per_cve_counts: dict[str, int] = {"offline_seed": len(entries)}
        zero_result_cpes: list[str] = []
    else:
        allowed_keys = resolve_allowed_keys(args)
        entries = []
        skipped_unbounded = 0
        skipped_product = 0
        zero_result_cpes: list[str] = []
        per_cve_counts: dict[str, int] = {}
        raw_index: dict[str, dict] = {}
        if args.from_raw:
            raw_index = load_raw_index(args.from_raw)

        for index, cve_id in enumerate(args.cve, start=1):
            if index > 1 and not args.from_raw:
                time.sleep(args.sleep)
            print(f"[{index}/{len(args.cve)}] {cve_id}", file=sys.stderr)
            if args.from_raw:
                wrapper = raw_index.get(cve_id)
                if wrapper is None:
                    raise SystemExit(f"error: {cve_id} not present in raw responses under {args.from_raw}")
            else:
                try:
                    wrapper = fetch_cve_by_id(cve_id, args.sleep)
                except NvdError as exc:
                    raise SystemExit(f"error querying {cve_id}: {exc}")
            batch, unbounded, product = collect_entries([wrapper], allowed_keys)
            entries.extend(batch)
            skipped_unbounded += unbounded
            skipped_product += product
            per_cve_counts[cve_id] = len(batch)

        cpes = list(args.cpe)
        for vendor in args.vendor:
            for cpe in EMBEDDED_CPE[vendor]:
                if cpe not in cpes:
                    cpes.append(cpe)
        for index, cpe in enumerate(cpes, start=1):
            if index > 1 or args.cve:
                time.sleep(args.sleep)
            print(f"[{index}/{len(cpes)}] {cpe}", file=sys.stderr)
            try:
                if args.from_raw:
                    vulnerabilities = [
                        raw_index[key] for key in sorted(raw_index)
                        if any(
                            cpe_product_key(criteria) == cpe_product_key(cpe)
                            for criteria, _ in iter_cpe_matches(raw_index[key].get("cve", {}))
                        )
                    ]
                else:
                    vulnerabilities = fetch_cves_for_cpe(cpe, args.sleep, max(1, args.max_per_cpe))
            except NvdError as exc:
                raise SystemExit(f"error querying {cpe}: {exc}")
            batch, unbounded, product = collect_entries(vulnerabilities, allowed_keys)
            entries.extend(batch)
            skipped_unbounded += unbounded
            skipped_product += product
            per_cve_counts[cpe] = len(batch)
            if not vulnerabilities:
                zero_result_cpes.append(cpe)
                print("  zero results; dropping", file=sys.stderr)

    if zero_result_cpes and not args.offline:
        print(f"dropped {len(zero_result_cpes)} CPE(s) with zero NVD results: "
              f"{', '.join(zero_result_cpes)}", file=sys.stderr)
    print(f"collected {len(entries)} bounded advisories; "
          f"skipped {skipped_unbounded} unbounded and {skipped_product} out-of-scope configuration matches",
          file=sys.stderr)
    snapshot = build_snapshot(entries)
    digest = write_snapshot(snapshot, args.output)
    for name, count in per_cve_counts.items():
        print(f"  {count:4d}  {name}", file=sys.stderr)
    print(f"wrote {args.output} ({len(snapshot['advisories'])} advisories)")
    print(f"SHA-256: {digest}")
    print("Operator override:")
    print(f"DEVICE_INTEL_DB_PATH={os.path.abspath(args.output)}")
    print(f"DEVICE_INTEL_DB_SHA256={digest}")
    if args.self_check:
        self_check(args.output, digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
