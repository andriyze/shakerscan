"""The benchmark scorecard must not credit an expectation with an unrelated finding.

Two defects inflated recall in our own measurements:

* ``route_tokens`` discarded any token shorter than four characters, so a short route like ``/ftp``
  produced an empty set -- and the match loop skipped the route filter entirely when the set was
  empty. Any finding of a compatible class and severity then satisfied that expectation, whatever
  route it was actually about.
* A matched finding was never reserved, so one finding could satisfy several expectations at once.

Both make a scorecard read better than the scan performed, which is worse than a low score.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _benchmark_module():
    path = ROOT / "scripts" / "benchmark_targets.py"
    spec = importlib.util.spec_from_file_location("benchmark_targets_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


benchmark = _benchmark_module()


def test_a_short_route_still_produces_a_constraint():
    # /ftp is three characters. Dropping it left nothing to match on, which silently removed the
    # route constraint rather than making the expectation harder to satisfy.
    tokens = benchmark.route_tokens({"route": "/ftp"})
    assert tokens, "a declared route must always yield at least one matching token"
    assert "ftp" in tokens


def test_declared_routes_of_every_length_yield_tokens():
    for route, expected in (
        ("/ftp", "ftp"),
        ("/api/v1/users", "users"),
        ("/rest/basket/9", "basket/9"),
        ("/#/search", "search"),
    ):
        tokens = benchmark.route_tokens({"route": route})
        assert tokens, route
        assert any(expected in token for token in tokens), (route, tokens)


def test_an_entry_without_a_route_still_matches_on_class_alone():
    # Expectations that name no route are matched by family and severity; that must keep working.
    assert benchmark.route_tokens({}) == set()
    assert benchmark.route_tokens({"route": ""}) == set()


def test_expectation_requires_a_route_match_when_a_route_is_declared():
    # The regression this closes: an expectation for /ftp credited by a finding about /rest/products.
    matched = benchmark.match_expectation(
        {"id": "e1", "family": "sensitive_exposure", "route": "/ftp", "min_severity": "high"},
        [{
            "finding_id": "f1",
            "hay": "sql injection on /rest/products/search",
            "classes": {"sensitive_exposure"},
            "severity": "critical",
            "verified": True,
            "browser_proven": False,
        }],
        set(),
    )
    assert matched is None, "a finding about another route must not credit /ftp"


def test_one_finding_cannot_credit_two_expectations():
    finding = {
        "finding_id": "f1",
        "hay": "sensitive file exposed at /ftp/coupons.txt",
        "classes": {"sensitive_exposure"},
        "severity": "critical",
        "verified": True,
        "browser_proven": False,
    }
    expectation = {"id": "e1", "family": "sensitive_exposure", "route": "/ftp", "min_severity": "high"}
    claimed: set[str] = set()

    first = benchmark.match_expectation(expectation, [finding], claimed)
    assert first is not None
    claimed.add(first["finding_id"])

    second = benchmark.match_expectation(
        dict(expectation, id="e2"), [finding], claimed,
    )
    assert second is None, "each finding may satisfy at most one expectation"


def test_matching_still_honours_severity_and_proof_requirements():
    finding = {
        "finding_id": "f1",
        "hay": "sensitive file exposed at /ftp/coupons.txt",
        "classes": {"sensitive_exposure"},
        "severity": "medium",
        "verified": False,
        "browser_proven": False,
    }
    base = {"id": "e1", "family": "sensitive_exposure", "route": "/ftp"}
    assert benchmark.match_expectation(dict(base, min_severity="high"), [finding], set()) is None

    strong = dict(finding, severity="critical")
    assert benchmark.match_expectation(dict(base, min_severity="high"), [strong], set()) is not None
    # A verified-proof expectation must not be satisfied by a suspected finding.
    assert benchmark.match_expectation(
        dict(base, min_severity="high", proof="verified"), [strong], set()) is None
    assert benchmark.match_expectation(
        dict(base, min_severity="high", proof="verified"),
        [dict(strong, verified=True)], set()) is not None
    # A browser-proof expectation needs browser evidence, not merely verification.
    assert benchmark.match_expectation(
        dict(base, min_severity="high", proof="browser"),
        [dict(strong, verified=True)], set()) is None


def test_browser_proof_route_can_be_attributed_by_its_redacted_network_request():
    fixture = {
        "name": "unit",
        "expected": [{
            "id": "reflected-xss", "family": "xss",
            "route": "/rest/track-order", "min_severity": "high",
            "proof": "browser",
        }],
        "gates": {},
    }
    card = benchmark.collect_scorecard({
        "findings": [{
            "id": "finding-1",
            "title": "Verified cross-site scripting",
            "url": "https://app.test/#/track-result?id=",
            "severity": "high",
            "verified": True,
            "evidence": {
                "request_url": "https://app.test/#/track-result?id=",
                "related_request_urls": [
                    "https://app.test/rest/track-order/<redacted>",
                ],
                "browser_proof": {
                    "proven": True,
                    "proof_producer": "shakerscan",
                    "evidence_type": "dom_execution",
                    "technique": "headless_xss_dom",
                },
            },
        }],
    }, fixture)

    assert [item["id"] for item in card["expected_found"]] == ["reflected-xss"]
