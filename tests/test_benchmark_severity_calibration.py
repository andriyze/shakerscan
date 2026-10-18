"""A severity calibration never lowers a class below what a benchmark answer key requires.

``scan.severity_calibration`` gives some finding classes a calibrated default severity, and a
benchmark expectation (``tests/fixtures/benchmarks/*.yaml``) is only credited by a finding at or
above its ``min_severity`` (``scripts/benchmark_targets.py``, default ``high``). A calibration that
lowers a class below an expectation therefore does not fail any unit test: it fails release
certification, as a miss that looks like lost recall. This test states, for every expectation the
calibration reaches, which class rule produces its finding, runs that rule through the real
``rule_for``/``calibrate_finding`` on a finding of the producer's shape, and requires the result
to be at or above the expectation's ``min_severity``. Either the rule or the answer key must change
deliberately.

The mapping is explicit, keyed the way the calibration keys its rules:

* ``exposure_<exposure_class>`` for ``shakerscan_exposure_probe`` findings: a
  ``sensitive_exposure`` expectation names the class its route is proven as;
* ``missing_header_<header>`` for ``http_baseline`` findings (a ``security_headers`` expectation
  names its ``header``), and ``exposure_verbose_error_disclosure`` for a ``verbose_error``
  expectation. No current answer key has either family; the entries keep the mapping complete.

Expectations no calibration rule reaches are skipped, each with its reason in ``NOT_CALIBRATED``
or ``PRODUCER_SEVERITY_FAMILIES``; an expectation in neither place fails, so a new answer-key entry
must be classified rather than silently passing:

* ``juice_shop/exposed-confidential`` (``/ftp/acquisitions.md``): a ``confidential_file``
  exposure, a class with no calibration rule (the directory-listing rule covers the listing, and
  says files proven sensitive keep their own severity);
* ``honey/data-exposure`` (``/api``): an API response disclosing user records or secrets; no
  exposure class that proves that (``credential_record_disclosure``, the secret-material classes)
  has a calibration rule, and a proven secret keeps the producer's severity under any rule;
* every expectation of a family in ``PRODUCER_SEVERITY_FAMILIES``: ``rule_for`` returns no rule for
  their producers (injection, XSS, access-control and workflow proofs), so producer severity stands.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from api.capabilities.exposure_probe import _CLASS_SEVERITY as EXPOSURE_CLASS_SEVERITY
from api.scan.severity_calibration import CLASS_RULES, SEVERITY_ORDER, calibrate_finding, rule_for

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "benchmarks"

# (benchmark, expectation id) -> the calibration rule whose class proves it.
CALIBRATED_EXPECTATIONS = {
    ("juice_shop", "exposed-metrics"): "exposure_metrics_endpoint",
    ("juice_shop", "exposed-ftp-listing"): "exposure_directory_listing",
}

# A family whose expectations all fall under one rule, or a rule derived from the expectation.
CALIBRATED_FAMILIES = {
    "security_headers": lambda entry: f"missing_header_{str(entry['header']).lower()}",
    "verbose_error": lambda entry: "exposure_verbose_error_disclosure",
}

NOT_CALIBRATED = {
    ("juice_shop", "exposed-confidential"): "confidential_file has no calibration rule",
    ("honey", "data-exposure"): "user-record and secret classes have no rule; a proven secret is never lowered",
}

PRODUCER_SEVERITY_FAMILIES = frozenset({
    "sqli", "nosqli", "xss", "bola", "broken_access_control", "webhook", "approval",
    "path_traversal", "jwt", "xxe",
})


def _expectations():
    for path in sorted(FIXTURES.glob("*.yaml")):
        document = yaml.safe_load(path.read_text()) or {}
        for entry in document.get("expected") or ():
            yield path.stem, entry


def _rule(benchmark: str, entry) -> str | None:
    key = (benchmark, entry["id"])
    if key in CALIBRATED_EXPECTATIONS:
        return CALIBRATED_EXPECTATIONS[key]
    if entry["family"] in CALIBRATED_FAMILIES:
        return CALIBRATED_FAMILIES[entry["family"]](entry)
    return None


def _producer_finding(rule: str) -> dict:
    """A finding as the producer of ``rule``'s class emits it, before calibration."""
    if rule.startswith("exposure_"):
        exposure_class = rule.removeprefix("exposure_")
        return {"tool": "shakerscan_exposure_probe", "severity": EXPOSURE_CLASS_SEVERITY[exposure_class],
                "evidence": {"exposure_class": exposure_class}}
    if rule.startswith(("missing_header_", "session_cookie_missing_")):
        return {"tool": "http_baseline", "severity": "medium", "evidence": {"check": rule}}
    raise AssertionError(f"no producer shape for calibration rule {rule}")


EXPECTATIONS = list(_expectations())


def test_every_answer_key_expectation_is_classified():
    unclassified = [
        f"{benchmark}/{entry['id']} ({entry['family']} {entry.get('route')})"
        for benchmark, entry in EXPECTATIONS
        if _rule(benchmark, entry) is None
        and (benchmark, entry["id"]) not in NOT_CALIBRATED
        and entry["family"] not in PRODUCER_SEVERITY_FAMILIES
    ]
    assert EXPECTATIONS and not unclassified, (
        "classify each new expectation: name the calibration rule its finding falls under, or "
        f"record why none does: {unclassified}")
    stale = set(CALIBRATED_EXPECTATIONS) | set(NOT_CALIBRATED)
    stale -= {(benchmark, entry["id"]) for benchmark, entry in EXPECTATIONS}
    assert not stale, f"mapped expectations no answer key holds: {sorted(stale)}"


@pytest.mark.parametrize(
    "benchmark,entry",
    [(benchmark, entry) for benchmark, entry in EXPECTATIONS if _rule(benchmark, entry)],
    ids=lambda value: value if isinstance(value, str) else value["id"],
)
def test_calibrated_severity_meets_the_answer_key(benchmark, entry):
    rule = _rule(benchmark, entry)
    assert rule in CLASS_RULES, f"{rule} is not a calibration rule"
    finding = _producer_finding(rule)
    assert rule_for(finding) == rule
    severity = calibrate_finding(finding)["severity"]
    required = entry.get("min_severity", "high")
    assert SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(required), (
        f"{benchmark}/{entry['id']} needs {required} but {rule} calibrates to {severity}: change the "
        "rule or re-key the answer key deliberately; certification would report it as a miss")
