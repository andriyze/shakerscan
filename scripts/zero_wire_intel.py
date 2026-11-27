#!/usr/bin/env python3
"""Release-time reader for the Cloudflare Radar Zero Wire briefings feed.

Zero Wire (https://radar.cloudflare.com/zero-wire) publishes a small number of curated briefings on
urgent vulnerabilities in internet-facing software. This reads a downloaded copy of its RSS feed
and reduces each briefing to bounded metadata: its slug, publication date, recommended-action
label, tags and the CVE ids it names. Nothing else from the feed is kept: the prose is untrusted
third-party text and never reaches a snapshot, a lead or a planner.

Two uses, both offline:

  * scripts/generate_device_advisories.py --zero-wire FILE marks the snapshot's records for the
    CVEs a briefing names, so service intelligence and Hunt leads rank them early;
  * run directly, it reports the coverage gap: briefed CVEs the snapshot does not carry, and
    briefed CVEs no bundled check names.

    curl -fsS https://radar.cloudflare.com/zero-wire/feed -o zero-wire.rss
    python3 scripts/zero_wire_intel.py --feed zero-wire.rss \
        --snapshot scanner/data/device_advisories.json --templates /path/to/nuclei-templates

A briefing is a prioritisation signal. It is not evidence about any target, changes no score, and
verifies nothing. Stdlib only; no network access.
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import re
import sys
import xml.etree.ElementTree as ElementTree
from typing import Any

SOURCE = "cloudflare_zero_wire"
BRIEFING_URL_PREFIX = "https://radar.cloudflare.com/zero-wire/"
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_BRIEFINGS = 500
MAX_CVES_PER_BRIEFING = 50
MAX_TAGS = 10
REPORT_SCHEMA = "shakerscan-zero-wire-coverage/v1"

_CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,119}")
_TAG = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_ACTION = re.compile(r"[A-Za-z][A-Za-z ]{0,59}")
_LEAD = re.compile(r"<strong>([^<]{1,80})</strong>")


class FeedError(ValueError):
    """The file is not a Zero Wire feed this reader accepts."""


def _slug(link: str) -> str | None:
    if not link.startswith(BRIEFING_URL_PREFIX):
        return None
    slug = link[len(BRIEFING_URL_PREFIX):].strip("/")
    return slug if _SLUG.fullmatch(slug) else None


def _published(value: str) -> str | None:
    try:
        return email.utils.parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError):
        return None


def parse_briefings(raw: bytes) -> list[dict[str, Any]]:
    """Briefings in the feed as bounded metadata, newest first. Items that do not validate are
    skipped; a document that is not RSS, is oversized or declares a DTD is refused."""
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError("feed is larger than the accepted size")
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise FeedError("feed declares a DTD or entity")  # stdlib XML expands internal entities
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise FeedError(f"feed is not well-formed XML: {exc}") from None
    channel = root.find("channel") if root.tag == "rss" else None
    if channel is None:
        raise FeedError("feed is not an RSS 2.0 document")
    briefings: dict[str, dict[str, Any]] = {}
    for item in channel.findall("item")[:MAX_BRIEFINGS]:
        slug = _slug((item.findtext("link") or "").strip())
        published = _published(item.findtext("pubDate") or "")
        if not slug or not published:
            continue
        body = item.findtext(_CONTENT) or ""
        text = " ".join((item.findtext("title") or "", item.findtext("description") or "", body))
        lead = _LEAD.search(body)
        action = lead.group(1).strip() if lead else ""
        tags = []
        for category in item.findall("category"):
            tag = str(category.get("domain") or "").rstrip("/").rsplit("/", 1)[-1]
            if _TAG.fullmatch(tag) and tag not in tags:
                tags.append(tag)
        briefing = {
            "id": slug, "published": published,
            "action": action if _ACTION.fullmatch(action) else None,
            "tags": sorted(tags)[:MAX_TAGS],
            "cves": sorted(set(_CVE.findall(text)))[:MAX_CVES_PER_BRIEFING],
        }
        prior = briefings.get(slug)
        if prior is None or prior["published"] < published:
            briefings[slug] = briefing
    return sorted(briefings.values(), key=lambda entry: (entry["published"], entry["id"]), reverse=True)


def load_briefings(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    with open(path, "rb") as handle:
        return parse_briefings(handle.read(MAX_FEED_BYTES + 1))


def briefings_by_cve(briefings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The newest briefing naming each CVE, as the record a snapshot advisory carries."""
    named: dict[str, dict[str, Any]] = {}
    for briefing in briefings:  # newest first: the first briefing seen for a CVE wins
        for cve in briefing["cves"]:
            named.setdefault(cve, {
                "source": SOURCE, "id": briefing["id"], "published": briefing["published"],
                **({"action": briefing["action"]} if briefing["action"] else {}),
            })
    return named


def coverage_report(briefings: list[dict[str, Any]], snapshot: dict[str, Any],
                    template_checks: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """Which briefed CVEs the snapshot can match to a service, and which have a bundled check.

    ``in_snapshot`` is false when the CVE's product is outside the generator's curated product
    list or NVD publishes no bounded version range for it yet. ``checks`` come from the snapshot
    and, when a templates directory is given, from every template naming the CVE.
    """
    carried: dict[str, set[str]] = {}
    for record in snapshot.get("advisories") or []:
        if not isinstance(record, dict):
            continue
        cve = str(record.get("cve") or "").upper()
        checks = carried.setdefault(cve, set())
        for check in record.get("checks") or []:
            if isinstance(check, dict) and check.get("id"):
                checks.add(str(check["id"]))
    rows = []
    missing: set[str] = set()
    unchecked: set[str] = set()
    for briefing in briefings:
        cves = []
        for cve in briefing["cves"]:
            checks = sorted(carried.get(cve, set()) | set((template_checks or {}).get(cve, [])))
            cves.append({"cve": cve, "in_snapshot": cve in carried, "checks": checks})
            if cve not in carried:
                missing.add(cve)
            if not checks:
                unchecked.add(cve)
        rows.append({**{key: briefing[key] for key in ("id", "published", "action", "tags")},
                     "url": BRIEFING_URL_PREFIX + briefing["id"], "cves": cves})
    named = {cve for briefing in briefings for cve in briefing["cves"]}
    return {
        "schema_version": REPORT_SCHEMA, "source": SOURCE,
        "snapshot_generated_at": snapshot.get("generated_at"),
        "summary": {"briefings": len(briefings), "cves": len(named),
                    "not_in_snapshot": len(missing), "without_check": len(unchecked)},
        "not_in_snapshot": sorted(missing), "without_check": sorted(unchecked),
        "briefings": rows,
    }


def _template_checks(directory: str | None) -> dict[str, list[str]]:
    if not directory:
        return {}
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from generate_device_advisories import load_template_checks
    return load_template_checks(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--feed", required=True, help="downloaded Zero Wire RSS feed")
    parser.add_argument("--snapshot", required=True, help="advisory snapshot JSON to compare against")
    parser.add_argument("--templates", default=None, help="nuclei templates directory (optional)")
    parser.add_argument("--output", default=None, help="write the JSON report here instead of stdout")
    args = parser.parse_args(argv)
    try:
        briefings = load_briefings(args.feed)
    except (OSError, FeedError) as exc:
        raise SystemExit(f"error reading {args.feed}: {exc}")
    with open(args.snapshot, encoding="utf-8") as handle:
        snapshot = json.load(handle)
    report = coverage_report(briefings, snapshot if isinstance(snapshot, dict) else {},
                             _template_checks(args.templates))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)
    summary = report["summary"]
    print(f"{summary['briefings']} briefing(s) name {summary['cves']} CVE(s): "
          f"{summary['not_in_snapshot']} not in the snapshot, {summary['without_check']} without a check",
          file=sys.stderr)
    if report["not_in_snapshot"]:
        print("add to the next snapshot build: "
              + " ".join(f"--cve {cve}" for cve in report["not_in_snapshot"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
