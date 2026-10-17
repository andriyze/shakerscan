"""Stored findings of kinds the scanner no longer reports are resolved, narrowly (unit fixtures).

The SQL itself runs against the real schema in tests/test_finding_detail_related_postgres.py.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from api.scan.retired_findings import (
    RETIRE_BASELINE_SQL, RETIRE_EXPOSURE_SQL, RETIRE_SQL, RETIRED_FINDING_KINDS, baseline_covered_origin,
    baseline_missing_headers, retire_superseded_findings, without_superseded_duplicates,
)


class _Conn:
    def __init__(self, available: int = 1):
        self.calls: list[tuple] = []
        self.sql: list[str] = []
        self.available = available

    async def fetch(self, sql, *args):
        self.calls.append(args)
        self.sql.append(sql)
        taken = min(self.available, args[9])
        self.available -= taken
        return [{"id": index} for index in range(taken)]


def _report(target="https://app.test", posture_observed=True, missing=("content-security-policy",),
            status="complete"):
    return {
        "target": target,
        "scan_metadata": {"status": status, "partial": status == "partial", "cancelled": status == "cancelled"},
        "http": {"posture_observed": posture_observed},
        "findings": [{
            "tool": "http_baseline", "url": target,
            "evidence": {"check": f"missing_header_{header}"},
        } for header in missing],
    }


def _retire(report, seen=(), **kwargs):
    conn = _Conn()
    count = asyncio.run(retire_superseded_findings(
        conn, target_id="t", scan_id="s", report=report, seen_fingerprints=seen, **kwargs,
    ))
    return count, conn.calls


def test_nothing_is_retired_without_an_observed_baseline():
    assert baseline_covered_origin(_report(posture_observed=False)) is None
    assert _retire(_report(posture_observed=False)) == (0, [])
    assert _retire({"target": "https://app.test"}) == (0, [])


def test_a_template_duplicate_is_retired_only_for_a_header_the_baseline_reports_missing():
    count, calls = _retire(_report(missing=("referrer-policy",)), seen=("fp-1",))
    (args,) = [call for call in calls if json.loads(call[6])["kind"] == "nuclei_missing_header_folded_into_baseline"]
    target, tool, template, headers, origins, seen, retired, scan, severities, limit = args
    assert (target, tool, template, scan, severities) == ("t", "nuclei", "http-missing-security-headers", "s", None)
    assert limit == 500
    assert headers == ["referrer-policy"], "CSP is present on the baseline: its template rows stay"
    assert origins == ["https://app.test", "https://app.test:443"]
    assert seen == ["fp-1"], "a row this scan reported again is never retired"
    assert json.loads(retired) == {
        "kind": "nuclei_missing_header_folded_into_baseline",
        "reason": "Reported by the baseline response's missing-header finding for this origin (2.11).",
        "release": "2.11.0",
        "scan_id": "s",
        "superseded_by": {"origin": "https://app.test"},
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
    assert all(kind.reason for kind in RETIRED_FINDING_KINDS)
    assert all(bool(kind.header_names) == (kind.predicate == "header") for kind in RETIRED_FINDING_KINDS)
    assert all(bool(kind.exposure_classes) == (kind.predicate == "exposure_proof") for kind in RETIRED_FINDING_KINDS)


def test_opt_in_isolation_header_rows_are_retired_once_the_baseline_observed_the_origin():
    from api.scan.posture_findings import OPT_IN_HEADERS
    count, calls = _retire(_report(missing=()))
    by_kind = {json.loads(args[6])["kind"]: args for args in calls}
    assert set(by_kind) == {"nuclei_opt_in_header_absent"}
    assert by_kind["nuclei_opt_in_header_absent"][3] == sorted(OPT_IN_HEADERS)


@pytest.mark.parametrize("status", ["partial", "failed", "cancelled", None])
def test_a_scan_that_did_not_complete_retires_nothing(status):
    report = _report(missing=("referrer-policy",), status=status)
    report["findings"].append(_exposure_proof())
    assert _retire(report) == (0, [])
    report["scan_metadata"] = {"status": "complete", "partial": True}
    assert _retire(report) == (0, [])
    report.pop("scan_metadata")
    assert _retire(report) == (0, [])


def _exposure_proof(url="https://app.test/.git/config", exposure_class="version_control_exposure",
                    severity="high", proof_state="verified"):
    return {"tool": "shakerscan_exposure_probe", "url": url, "severity": severity, "proof_state": proof_state,
            "evidence": {"exposure_class": exposure_class}}


def _folded_calls(report):
    _count, calls = _retire(report)
    return {json.loads(call[6])["kind"]: call for call in calls if "exposure_proof" in json.loads(call[6])["kind"]}


def test_a_folded_template_is_retired_only_at_a_location_this_scan_verified_for_its_class():
    report = _report(missing=())
    report["findings"].append(_exposure_proof(url="https://app.test:443/.git/config/"))
    calls = _folded_calls(report)
    # Only git-config detects version_control_exposure; git-credentials / web-config / openapi stay.
    assert set(calls) == {"nuclei_git_config_folded_into_exposure_proof"}
    target, tool, template, paths, origins, _seen, record, _scan, severities, _limit, exposure_class = calls[
        "nuclei_git_config_folded_into_exposure_proof"]
    assert exposure_class == "version_control_exposure", "the stored proof row of this class must exist"
    assert (tool, template, paths) == ("nuclei", "git-config", ["/.git/config"])
    assert origins == ["https://app.test", "https://app.test:443"]
    assert severities == ["high", "info", "low", "medium"], "never a template row more severe than the proof"
    assert json.loads(record)["superseded_by"] == {
        "exposure_class": "version_control_exposure", "location": "https://app.test/.git/config"}


def test_no_folded_template_is_retired_without_a_verified_proof_or_on_an_unobserved_origin():
    for proof in (
        _exposure_proof(proof_state="candidate"),
        _exposure_proof(exposure_class=""),
        _exposure_proof(url="ftp://app.test/.git/config"),
        _exposure_proof(severity="bogus"),
        {**_exposure_proof(), "tool": "nuclei"},
    ):
        report = _report(missing=())
        report["findings"].append(proof)
        assert _folded_calls(report) == {}, proof
    # The exposure retirement does not need the baseline, but the header kinds still do.
    report = _report(missing=("referrer-policy",), posture_observed=False)
    report["findings"].append(_exposure_proof())
    kinds = {json.loads(call[6])["kind"] for call in _retire(report)[1]}
    assert kinds == {"nuclei_git_config_folded_into_exposure_proof"}


def test_one_proof_class_maps_to_every_template_of_that_class():
    report = _report(missing=())
    report["findings"].append(_exposure_proof(url="https://app.test/web.config",
                                              exposure_class="configuration_secret_file", severity="medium"))
    assert set(_folded_calls(report)) == {
        "nuclei_git_credentials_disclosure_folded_into_exposure_proof",
        "nuclei_web_config_folded_into_exposure_proof",
    }


def test_retirement_is_batched_and_bounded_per_scan():
    conn = _Conn(available=10_000)
    count = asyncio.run(retire_superseded_findings(
        conn, target_id="t", scan_id="s", report=_report(missing=("referrer-policy",)), seen_fingerprints=(),
        batch_size=100, max_rows=250,
    ))
    assert count == 250
    assert [call[9] for call in conn.calls] == [100, 100, 50]


def test_the_retire_statements_never_touch_triaged_or_re_reported_rows():
    for sql in (RETIRE_SQL, RETIRE_BASELINE_SQL, RETIRE_EXPOSURE_SQL):
        compact = " ".join(sql.split())
        for clause in (
            "target_id = $1 AND status = 'active'",
            "analyst_verdict IS NULL AND analyst_verdict_at IS NULL",
            "NULLIF(btrim(COALESCE(notes, '')), '') IS NULL",
            "NULLIF(btrim(COALESCE(analyst_verdict_notes, '')), '') IS NULL",
            "COALESCE(last_verification_status, '') NOT IN ('queued', 'running')",
            "NOT (COALESCE(evidence, '{}'::jsonb) ? 'retired')",
            "NOT (fingerprint = ANY($6::text[]))",
            "last_seen_scan_id::text IS DISTINCT FROM $8::text",
            "FROM finding_exceptions",
            "LIMIT $10",
            "FOR UPDATE SKIP LOCKED",
        ):
            assert clause in compact, (clause, sql)
    assert "header_name', '') = ''" in RETIRE_EXPOSURE_SQL
    # A superseded row is retired only while the finding that carries it is stored for this scan.
    assert "FROM findings replacement" not in RETIRE_SQL
    for sql, tool in ((RETIRE_BASELINE_SQL, "http_baseline"), (RETIRE_EXPOSURE_SQL, "shakerscan_exposure_probe")):
        compact = " ".join(sql.split())
        assert "AND EXISTS ( SELECT 1 FROM findings replacement" in compact
        assert f"replacement.tool = '{tool}'" in compact
        assert "replacement.last_seen_scan_id::text = $8::text" in compact
        assert "replacement.status IN ('active', 'accepted_risk', 'false_positive')" in compact
    assert "replacement.evidence->>'exposure_class' = $11::text" in RETIRE_EXPOSURE_SQL
    assert "'missing_header_' || lower(COALESCE(findings.evidence" in RETIRE_BASELINE_SQL


def test_the_baseline_folded_kinds_use_the_statement_that_requires_the_stored_baseline_row():
    conn = _Conn()
    asyncio.run(retire_superseded_findings(
        conn, target_id="t", scan_id="s", report=_report(missing=("referrer-policy",)), seen_fingerprints=()))
    by_kind = {json.loads(args[6])["kind"]: sql for args, sql in zip(conn.calls, conn.sql)}
    assert by_kind["nuclei_missing_header_folded_into_baseline"] == RETIRE_BASELINE_SQL
    assert by_kind["nuclei_opt_in_header_absent"] == RETIRE_SQL, "never a finding: nothing replaces it"


def test_an_older_finalizers_unfolded_duplicates_are_not_saved():
    """A pre-2.11 fleet node reports the template duplicate beside the finding that superseded it."""
    report = _report(missing=("referrer-policy",))
    proof = _exposure_proof()
    template = {"template_id": "http-missing-security-headers"}
    duplicate = {"tool": "nuclei", "url": "https://app.test/about", "severity": "info",
                 "evidence": {**template, "header_name": "referrer-policy"}}
    opt_in = {"tool": "nuclei", "url": "https://app.test:443/", "severity": "info",
              "evidence": {**template, "header_name": "cross-origin-embedder-policy"}}
    other_header = {"tool": "nuclei", "url": "https://app.test/", "severity": "info",
                    "evidence": {**template, "header_name": "content-security-policy"}}
    other_origin = {**duplicate, "url": "https://other.test/about"}
    git = {"tool": "nuclei", "url": "https://app.test/.git/config/", "severity": "medium",
           "proof_state": "candidate", "evidence": {"template_id": "git-config"}}
    git_more_severe = {**git, "severity": "critical"}
    git_elsewhere = {**git, "url": "https://app.test/sub/.git/config"}
    report["findings"] += [proof, duplicate, opt_in, other_header, other_origin, git, git_more_severe, git_elsewhere]
    kept = without_superseded_duplicates(report, report["findings"])
    assert duplicate not in kept and opt_in not in kept and git not in kept
    for finding in (proof, other_header, other_origin, git_more_severe, git_elsewhere, *report["findings"][:1]):
        assert finding in kept
    # A current report has none of them: nothing is dropped. Not a mapping report: nothing either.
    current = _report(missing=("referrer-policy",))
    assert without_superseded_duplicates(current, current["findings"]) == current["findings"]
    assert without_superseded_duplicates(None, [duplicate]) == [duplicate]
    # The duplicates are dropped even from a partial scan's report (they never belong in the table).
    report["scan_metadata"]["status"] = "partial"
    assert duplicate not in without_superseded_duplicates(report, report["findings"])


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        pool = self

        class _Acquire:
            async def __aenter__(self):
                return pool.conn

            async def __aexit__(self, *exc):
                return False
        return _Acquire()


class _TxConn(_Conn):
    def transaction(self):
        class _Tx:
            async def __aenter__(self):
                return None

            async def __aexit__(self, *exc):
                return False
        return _Tx()


def test_the_worker_step_refreshes_counts_and_never_raises():
    from api.scan.retired_findings import retire_after_scan
    refreshed = []

    async def refresh(_conn, target):
        refreshed.append(target)

    target = "22222222-2222-4222-8222-222222222222"

    def run(report, pool, *, findings=(), saved_count=0, coverage_status="complete"):
        return asyncio.run(retire_after_scan(
            pool, scan_id="s", target_id=target, report=report, findings=list(findings),
            refresh_active_count=refresh, saved_count=saved_count, coverage_status=coverage_status))
    assert run(_report(missing=("referrer-policy",)), _Pool(_TxConn())) >= 1
    assert len(refreshed) == 1
    assert run(None, _Pool(_TxConn())) == 0, "no report, nothing to do"

    class _Broken:
        def acquire(self):
            raise RuntimeError("database down")
    assert run(_report(), _Broken()) == 0


def test_the_worker_step_retires_nothing_unless_every_finding_saved_and_coverage_is_complete():
    from api.scan.retired_findings import retire_after_scan

    async def refresh(_conn, _target):
        return None

    def run(**kwargs):
        conn = _TxConn()
        retired = asyncio.run(retire_after_scan(
            _Pool(conn), scan_id="s", target_id="22222222-2222-4222-8222-222222222222",
            report=_report(missing=("referrer-policy",)), refresh_active_count=refresh, **kwargs))
        return retired, len(conn.calls)
    finding = {"tool": "http_baseline", "url": "https://app.test", "title": "Missing Referrer-Policy",
               "evidence": {"check": "missing_header_referrer-policy"}}
    assert run(findings=[finding], saved_count=1, coverage_status="complete")[0] >= 1
    # save_findings raised (the worker passes None), or saved fewer rows than the report held.
    assert run(findings=[finding], saved_count=None, coverage_status="complete") == (0, 0)
    assert run(findings=[finding], saved_count=0, coverage_status="complete") == (0, 0)
    # The report says complete but the action-receipt rollup downgraded the scan's coverage.
    for status in ("partial", "failed", "cancelled", None, ""):
        assert run(findings=[finding], saved_count=1, coverage_status=status) == (0, 0), status


def test_the_worker_saves_without_superseded_duplicates_and_gates_retirement_on_the_save():
    """The save path: a failed save is passed as None, and the worker's final coverage gates."""
    from pathlib import Path
    source = Path(__file__).resolve().parents[1].joinpath("api", "worker.py").read_text()
    save = source[source.index("saved_count, web_findings = "):source.index("elif ai_target_id and findings:")]
    assert "without_superseded_duplicates(result, findings)" in save
    assert "save_findings(scan_id, target_id, web_findings)" in save
    assert "saved_count = None" in save, "an exception is never read as a complete save"
    call = source[source.index("await retire_after_scan("):]
    call = call[:call.index("\n\n")]
    for argument in ("findings=web_findings", "saved_count=saved_count", "coverage_status=coverage_status"):
        assert argument in call
