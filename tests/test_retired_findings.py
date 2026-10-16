"""Stored findings of kinds the scanner no longer reports are resolved, narrowly (unit fixtures).

The SQL itself runs against the real schema in tests/test_finding_detail_related_postgres.py.
"""

from __future__ import annotations

import asyncio
import json

from api.scan.retired_findings import (
    RETIRED_FINDING_KINDS, baseline_covered_origin, baseline_missing_headers, retire_superseded_findings,
)


class _Conn:
    def __init__(self):
        self.calls: list[tuple] = []

    async def fetch(self, sql, *args):
        self.calls.append(args)
        return [{"id": 1}]


def _report(target="https://app.test", posture_observed=True, missing=("content-security-policy",)):
    return {
        "target": target,
        "http": {"posture_observed": posture_observed},
        "findings": [{
            "tool": "http_baseline", "url": target,
            "evidence": {"check": f"missing_header_{header}"},
        } for header in missing],
    }


def _retire(report, seen=()):
    conn = _Conn()
    count = asyncio.run(retire_superseded_findings(
        conn, target_id="t", scan_id="s", report=report, seen_fingerprints=seen,
    ))
    return count, conn.calls


def test_nothing_is_retired_without_an_observed_baseline():
    assert baseline_covered_origin(_report(posture_observed=False)) is None
    assert _retire(_report(posture_observed=False)) == (0, [])
    assert _retire({"target": "https://app.test"}) == (0, [])


def test_a_template_duplicate_is_retired_only_for_a_header_the_baseline_reports_missing():
    count, calls = _retire(_report(missing=("referrer-policy",)), seen=("fp-1",))
    (args,) = [call for call in calls if json.loads(call[6])["kind"] == "nuclei_missing_header_folded_into_baseline"]
    target, tool, template, headers, origins, seen, retired = args
    assert (target, tool, template) == ("t", "nuclei", "http-missing-security-headers")
    assert headers == ["referrer-policy"], "CSP is present on the baseline: its template rows stay"
    assert origins == ["https://app.test", "https://app.test:443"]
    assert seen == ["fp-1"], "a row this scan reported again is never retired"
    assert json.loads(retired) == {
        "kind": "nuclei_missing_header_folded_into_baseline",
        "reason": "Reported by the baseline response's missing-header finding for this origin (2.11).",
        "scan_id": "s",
    }
    # A header the baseline does not report missing retires none of the folded kind.
    assert not [call for call in _retire(_report(missing=()))[1]
                if json.loads(call[6])["kind"] == "nuclei_missing_header_folded_into_baseline"]


def test_hsts_on_plain_http_is_retired_once_the_baseline_observed_the_origin():
    _count, calls = _retire(_report(target="http://app.test:8080", missing=()))
    (args,) = [call for call in calls if json.loads(call[6])["kind"] == "nuclei_hsts_on_plain_http"]
    assert args[3] == ["strict-transport-security"]
    assert args[4] == ["http://app.test:8080"]
    assert json.loads(args[6])["kind"] == "nuclei_hsts_on_plain_http"


def test_the_baseline_headers_are_read_per_origin():
    report = _report(missing=("permissions-policy",))
    report["findings"].append({"tool": "http_baseline", "url": "https://other.test",
                               "evidence": {"check": "missing_header_referrer-policy"}})
    assert baseline_missing_headers(report, ["https://app.test", "https://app.test:443"]) == {"permissions-policy"}


def test_the_retired_kinds_are_a_list_others_can_extend():
    names = [kind.name for kind in RETIRED_FINDING_KINDS]
    assert len(names) == len(set(names))
    assert all(kind.reason and kind.header_names for kind in RETIRED_FINDING_KINDS)


def test_opt_in_isolation_header_rows_are_retired_once_the_baseline_observed_the_origin():
    from api.scan.posture_findings import OPT_IN_HEADERS
    count, calls = _retire(_report(missing=()))
    by_kind = {json.loads(args[6])["kind"]: args for args in calls}
    assert set(by_kind) == {"nuclei_opt_in_header_absent"}
    assert by_kind["nuclei_opt_in_header_absent"][3] == sorted(OPT_IN_HEADERS)
