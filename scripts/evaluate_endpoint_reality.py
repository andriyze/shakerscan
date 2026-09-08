#!/usr/bin/env python3
"""Score the PRODUCTION reachability filter against a labeled endpoint sample.

Why this exists
---------------
The Hunt frontier is polluted by discovery noise, and two attempts to score it have already been
withdrawn. The first ranked endpoints by evidence and promoted a junk sample to the top. The second
compared a low-level matcher (``_soft404_matches``) against a new classifier and reported
improvements that production already achieved on its own -- an invalid comparison.

So this evaluates the real entry point, ``filter_reachable_worklist``, by handing it worklist
entries and scoring what it keeps and drops. Production already protects fragment routes and
non-GET entries; any replacement must be measured against that, not against a raw matcher.

What it measures
----------------
Template retention and sample filtering are separate. Dropping an invalid request is not losing
its route when another sample preserves that route. Conversely, retaining only invalid samples
must not conceal the loss of every useful representative. Template identity includes HTTP method
and authentication context; the templates are fixture labels, NOT inferred production groupings.

Unknown-route coverage has its own denominator. No unknown cases means NOT TESTED, never a clean
zero-error result. Keeping an unknown request is retention, not a claim that its route exists.
The production filter returns only kept/dropped, so this measures unknown-route drops, not the
experimental classifier's abstention accuracy. JSON summary schema: endpoint-reality-score/v2.

Usage
-----
    python3 scripts/evaluate_endpoint_reality.py --base-url http://host.docker.internal:3001

Run inside the api container, which holds the dependencies and can reach the lab target. Live
evaluation is anonymous only; non-anonymous fixtures are rejected rather than silently misprobed.
This is diagnostic output, not a release gate; a zero exit code does not establish filter quality.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

DEFAULT_SAMPLE = Path(__file__).resolve().parents[1] / "tests/fixtures/hunt/endpoint_reality_sample.json"
ROUTE_LABELS = frozenset({"real", "absent", "client_route", "unknown"})
SAMPLE_LABELS = frozenset({"valid", "invalid", "not_parameterised", "unknown"})
KNOWN_ROUTES = frozenset({"real", "client_route"})
USEFUL_SAMPLES = frozenset({"valid", "not_parameterised"})
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


def validated_entries(entries: list[dict], *, scored: bool = False) -> list[dict]:
    """Reject missing/contradictory labels instead of producing reassuring empty metrics."""
    if not isinstance(entries, list):
        raise ValueError("entries must be a list")
    normalized = []
    labels: dict[tuple[str, str, str], str] = {}
    seen = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"entry {index} must be an object")
        row = dict(entry)
        method = row.get("method", "GET")
        if not isinstance(method, str) or method.strip().upper() not in METHODS:
            raise ValueError(f"entry {index} has an invalid HTTP method")
        row["method"] = method.strip().upper()
        row.setdefault("auth_context", "anonymous")
        if not isinstance(row["auth_context"], str) or not row["auth_context"].strip():
            raise ValueError(f"entry {index} needs a nonempty auth_context label")
        for field in ("route_template", "request_sample"):
            value = row.get(field)
            if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or any(c.isspace() for c in value):
                raise ValueError(f"entry {index} needs a target-relative {field}")
        if (not isinstance(row.get("route_label"), str) or row["route_label"] not in ROUTE_LABELS
                or not isinstance(row.get("sample_label"), str) or row["sample_label"] not in SAMPLE_LABELS):
            raise ValueError(f"entry {index} has missing or invalid route/sample labels")
        if scored and (not isinstance(row.get("production"), str) or row["production"] not in {"kept", "dropped"}):
            raise ValueError(f"entry {index} needs an explicit kept/dropped production result")
        key = (row["method"], row["route_template"], row["auth_context"])
        if key in labels and labels[key] != row["route_label"]:
            raise ValueError(f"conflicting route labels for {key}")
        labels[key] = row["route_label"]
        identity = (row["method"], row["request_sample"], row["auth_context"])
        if identity in seen:
            raise ValueError(f"duplicate request sample: {identity}")
        seen.add(identity)
        normalized.append(row)
    return normalized


def worklist_entry(entry: dict) -> str:
    """The production filter consumes 'METHOD /path' worklist entries."""
    return f"{entry.get('method', 'GET').upper()} {entry['request_sample']}"


async def evaluate(base_url: str, entries: list[dict], **kwargs) -> list[dict]:
    entries = validated_entries(entries)
    if any(e["auth_context"] != "anonymous" for e in entries):
        raise ValueError("live evaluation currently supports anonymous auth_context only")
    # Scoring and --help are usable offline without importing the scanner runtime.
    from asm_inventory import filter_reachable_worklist

    worklist = [worklist_entry(e) for e in entries]
    kept = set(await filter_reachable_worklist(base_url, worklist, None, **kwargs))
    return [
        {**entry, "entry": item, "production": "kept" if item in kept else "dropped"}
        for entry, item in zip(entries, worklist)
    ]


def score(results: list[dict]) -> dict:
    """Score route loss, useful-representative loss, and sample drops independently."""
    results = validated_entries(results, scored=True)
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in results:
        groups[(row["method"], row["route_template"], row["auth_context"])].append(row)
    known = []
    for (method, template, auth), rows in sorted(groups.items()):
        if rows[0]["route_label"] not in KNOWN_ROUTES:
            continue
        useful = [r for r in rows if r["sample_label"] in USEFUL_SAMPLES]
        known.append({
            "method": method, "route_template": template, "auth_context": auth,
            "route_label": rows[0]["route_label"],
            "samples": len(rows),
            "samples_kept": sum(r["production"] == "kept" for r in rows),
            "useful_samples": len(useful),
            "useful_samples_kept": sum(r["production"] == "kept" for r in useful),
        })
    lost = [g for g in known if not g["samples_kept"]]
    useful_groups = [g for g in known if g["useful_samples"]]
    useful_lost = [g for g in useful_groups if not g["useful_samples_kept"]]
    unknown = [r for r in results if r["route_label"] == "unknown"]
    unknown_dropped = [r for r in unknown if r["production"] == "dropped"]
    totals = Counter(row["route_label"] for row in results)
    dropped = Counter(row["route_label"] for row in results if row["production"] == "dropped")
    # Sample diagnostics are NOT route-loss verdicts. Invalid requests may still be
    # useful for security research, so this evaluator never licenses deleting evidence.
    samples = {}
    for label in sorted(SAMPLE_LABELS):
        rows = [r for r in results if r["route_label"] in KNOWN_ROUTES and r["sample_label"] == label]
        kept_count = sum(r["production"] == "kept" for r in rows)
        samples[label] = {"total": len(rows), "kept": kept_count, "dropped": len(rows) - kept_count}
    return {
        "schema_version": "endpoint-reality-score/v2",
        "totals_by_route_label": dict(totals),
        "dropped_by_route_label": dict(dropped),
        "known_template_count": len(known),
        "known_templates_lost": lost,
        "template_retention_rate": (len(known) - len(lost)) / len(known) if known else None,
        "templates_with_useful_samples": len(useful_groups),
        "templates_losing_all_useful_samples": useful_lost,
        "useful_template_retention_rate": (len(useful_groups) - len(useful_lost)) / len(useful_groups) if useful_groups else None,
        "templates_without_useful_samples": [g for g in known if not g["useful_samples"]],
        "samples_of_known_templates": samples,
        "absent_dropped": [r for r in results if r["route_label"] == "absent" and r["production"] == "dropped"],
        "unknown_route_evaluation": {
            "status": "tested" if unknown else "not_tested",
            "total": len(unknown), "kept": len(unknown) - len(unknown_dropped),
            "dropped": unknown_dropped,
            "drop_rate": len(unknown_dropped) / len(unknown) if unknown else None,
        },
        "distinct_route_templates": len(groups),
        "entries": len(results),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--sample", default=str(DEFAULT_SAMPLE))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        sample = json.loads(Path(args.sample).read_text(encoding="utf-8"))
        results = asyncio.run(evaluate(args.base_url, sample["entries"]))
        summary = score(results)
    except (OSError, ValueError, KeyError) as exc:
        ap.error(str(exc))

    if args.json:
        print(json.dumps({"results": results, "summary": summary}, indent=2))
        return 0

    print(f"target: {args.base_url}   entries: {len(results)}\n")
    print(f"{'route_label':<14}{'sample':<18}{'prod':<9}{'method':<8}path")
    for row in sorted(results, key=lambda r: (r["route_label"], r["request_sample"])):
        print(f"{row['route_label']:<14}{row['sample_label']:<18}{row['production']:<9}"
              f"{row['method']:<8}{row['request_sample']}")

    print("\n--- production filter (filter_reachable_worklist) ---")
    print(f"absent-route samples dropped   : {len(summary['absent_dropped'])}"
          f"/{summary['totals_by_route_label'].get('absent', 0)}")
    print(f"known templates lost           : {len(summary['known_templates_lost'])}"
          f"/{summary['known_template_count']}")
    print(f"last useful representative lost: {len(summary['templates_losing_all_useful_samples'])}"
          f"/{summary['templates_with_useful_samples']}")
    for label, key in (("LOST TEMPLATE", "known_templates_lost"),
                       ("LOST USEFUL SAMPLES", "templates_losing_all_useful_samples")):
        for row in summary[key]:
            print(f"  {label}: {row['method']} {row['route_template']} [{row['auth_context']}]")
    unknown = summary["unknown_route_evaluation"]
    if unknown["status"] == "not_tested":
        print("unknown-route retention        : NOT TESTED (0 labeled cases)")
    else:
        print(f"unknown-route samples dropped  : {len(unknown['dropped'])}/{unknown['total']}")
        for row in unknown["dropped"]:
            print(f"  UNSUPPORTED DROP: {row['entry']}")
    print("\n--- labeled templates and samples (not inferred grouping) ---")
    print(f"{summary['entries']} requests span {summary['distinct_route_templates']} method/template/auth groups")
    print(f"{len(summary['templates_without_useful_samples'])} known templates have no labeled useful sample; "
          "working-request retention for those templates is untested")
    print("sample filtering:", json.dumps(summary["samples_of_known_templates"], sort_keys=True))
    print("Kept means retained, not proven real. This diagnostic is not a quality gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
