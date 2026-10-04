"""The benchmark scorecard must not credit an expectation with an unrelated finding.

Two defects inflated recall in our own measurements:

* ``route_tokens`` discarded any token shorter than four characters, so a short route like ``/ftp``
  produced an empty set -- and the match loop skipped the route filter entirely when the set was
  empty. Any finding of a compatible class and severity then satisfied that expectation, whatever
  route it was actually about.
* A matched finding was never reserved, so one finding could satisfy several expectations at once.
* ``proof: deterministic`` (also the default) checked only class, route and severity, so an
  unverified lead counted toward ``expected_recall`` exactly like a proven finding.

All of these make a scorecard read better than the scan performed, which is worse than a low score.
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
    # Deliberately changed: this used to assert that an UNVERIFIED critical finding satisfies an
    # expectation with no declared proof. The default proof is "deterministic", which means proven
    # by a deterministic proof contract -- the only thing that sets `verified` -- so crediting an
    # unverified lead counted unproven findings toward expected_recall. The committed Juice Shop
    # sample shows the harm: bfla-users was "found" by an unverified, low-confidence
    # default-credentials finding.
    assert benchmark.match_expectation(dict(base, min_severity="high"), [strong], set()) is None
    assert benchmark.match_expectation(
        dict(base, min_severity="high"), [dict(strong, verified=True)], set()) is not None
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


def _unverified_metrics_report():
    return {
        "findings": [{
            "id": "lead-1",
            "title": "Sensitive exposure: metrics endpoint",
            "url": "https://app.test/metrics",
            "severity": "high",
            "verified": False,
            "proof_state": "likely_vulnerable",
        }],
    }


def _deterministic_fixture():
    return {
        "name": "unit",
        "expected": [{
            "id": "exposed-metrics", "family": "sensitive_exposure",
            "route": "/metrics", "min_severity": "high", "proof": "deterministic",
        }],
        "gates": {},
    }


def test_a_deterministic_expectation_is_not_found_by_an_unverified_finding():
    card = benchmark.collect_scorecard(_unverified_metrics_report(), _deterministic_fixture())

    assert card["expected_found"] == []
    assert [item["id"] for item in card["expected_missed"]] == ["exposed-metrics"]
    assert card["expected_recall"] == 0.0


def test_an_unverified_detection_is_reported_as_a_diagnostic_outside_recall():
    card = benchmark.collect_scorecard(_unverified_metrics_report(), _deterministic_fixture())

    assert card["expected_detected_unproven"] == [{
        "id": "exposed-metrics", "family": "sensitive_exposure", "route": "/metrics",
        "proof": "deterministic", "min_severity": "high",
        "evidence": "Sensitive exposure: metrics endpoint",
        "missing_proof": ["verified"], "proof_state": "likely_vulnerable",
    }]
    # The diagnostic never feeds the recall the gates and the quality bar read.
    assert card["expected_recall"] == 0.0


def test_a_verified_finding_satisfies_a_deterministic_expectation():
    report = _unverified_metrics_report()
    report["findings"][0]["verified"] = True
    card = benchmark.collect_scorecard(report, _deterministic_fixture())

    assert [item["id"] for item in card["expected_found"]] == ["exposed-metrics"]
    assert card["expected_detected_unproven"] == []
    assert card["expected_recall"] == 1.0


def test_a_browser_expectation_reports_a_verified_non_browser_finding_as_unproven():
    fixture = {
        "expected": [{
            "id": "xss", "family": "xss", "route": "/search",
            "min_severity": "high", "proof": "browser",
        }],
    }
    card = benchmark.collect_scorecard({"findings": [{
        "id": "x1", "title": "Cross-site scripting", "url": "https://app.test/search?q=",
        "severity": "high", "verified": True,
    }]}, fixture)

    assert card["expected_found"] == []
    assert card["expected_detected_unproven"][0]["missing_proof"] == ["browser_proven"]


def test_an_unknown_proof_spelling_is_rejected_rather_than_requiring_nothing():
    entry = {"id": "e1", "family": "sensitive_exposure", "route": "/ftp", "proof": "verifed"}
    with pytest.raises(ValueError, match="unknown proof"):
        benchmark.match_expectation(entry, [], set())
    assert benchmark.fixture_problems({"expected": [entry]}) == [
        "expectation 'e1' declares unknown proof 'verifed'; "
        "known: ['browser', 'deterministic', 'verified']"
    ]
