"""The actual merge worker must persist the same assessment its report exposes."""
import asyncio
import json
import uuid
from datetime import datetime, timezone

import pytest

from tests import test_worker_scan_ai_gating as cases


def test_merge_worker_persists_no_grade_for_redirect_only_children(monkeypatch):
    worker = cases.worker
    parent_id = "55555555-5555-5555-5555-555555555555"
    now = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)

    class Conn:
        def __init__(self):
            self.updates = []

        async def fetchrow(self, query, *args):
            return {"target_id": None, "target_url": "https://example.test",
                    "options": {"parallel_strategy": "family"}, "scan_type": "smart",
                    "created_at": now, "started_at": now, "job_id": "parent-job",
                    "status": "running", "campaign_id": None}

        async def fetch(self, query, *args):
            return [{"id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
                "status": "completed", "score": 100, "grade": "A*", "findings_count": 0,
                "shard_index": 0, "options": {"parallel_backbone": True},
                "started_at": now, "completed_at": now, "campaign_id": None,
                "error_message": None,
                "result": {"schema_version": "canonical-scan-report/v2",
                           "target": "https://example.test", "findings": [],
                           "reachability": {"status": "reachable"},
                           "result": {"application_observed": False,
                                      "risk_assessment_state": "not_examined",
                                      "score": 100, "grade": "A*", "grade_reliable": False}}}]

        async def execute(self, query, *args):
            self.updates.append((query, args))
            return "UPDATE 1"

    conn = Conn()
    monkeypatch.setattr(worker, "db_pool", cases._FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: cases._FakeJobRedis())
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    asyncio.run(worker.process_scan_merge_job({"parent_scan_id": parent_id}))
    updates = [args for query, args in conn.updates if "UPDATE scans SET status = $1" in query]
    assert len(updates) == 1
    args = updates[0]
    assert args[0] == "completed"  # a reachable redirect is not failed preflight
    assert args[2] is None and args[3] is None
    report = json.loads(args[1])
    assert report["result"]["risk_assessment_state"] == "not_examined"
    assert report["result"]["grade"] is None
    assert report["result"]["risk_score"] is None


def test_merge_grades_the_union_when_a_finding_has_no_cvss_score(monkeypatch):
    # A verified XSS finding carries cvss_score None (CWE-79 has no universal score). The merge's
    # summary grader compared it with 0 and raised, so the parent kept a shard's stale summary.
    worker = cases.worker
    parent_id = "55555555-5555-5555-5555-555555555555"
    now = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)

    def finding(title, url, cvss, cwe):
        return {"title": title, "severity": "medium", "tool": "shakerscan_browser_proof", "url": url,
                "cvss_score": cvss, "cwe": cwe, "verified": True, "proof_state": "verified",
                "evidence": {"url": url}}

    def shard(index, findings, summary):
        # Each shard alone graded better than the union, so the union's grade is the parent's.
        return {"id": uuid.UUID(f"{index + 1}" * 8 + "-1111-1111-1111-111111111111"),
                "status": "completed", "score": 100, "grade": "A", "findings_count": len(findings),
                "shard_index": index, "options": {}, "started_at": now, "completed_at": now,
                "campaign_id": None, "error_message": None,
                "result": {"target": "https://example.test", "findings": findings,
                           "reachability": {"status": "reachable"},
                           "result": {"score": 100, "grade": "A", "summary": summary,
                                      "compliance": {"owasp_top10": ["stale shard value"]}}}}

    children = [
        shard(0, [finding("Verified cross-site scripting", "https://example.test/a?q=1", None,
                          "CWE-79")], "shard summary: 1 issue"),
        shard(1, [finding("Verified SQL injection", "https://example.test/b?id=1", 8.0,
                          "CWE-89")], "shard summary: 1 issue"),
    ]

    class Conn:
        def __init__(self):
            self.updates = []

        async def fetchrow(self, query, *args):
            return {"target_id": None, "target_url": "https://example.test",
                    "options": {"parallel_strategy": "coverage"}, "scan_type": "smart",
                    "created_at": now, "started_at": now, "job_id": "parent-job",
                    "status": "running", "campaign_id": None}

        async def fetch(self, query, *args):
            return children

        async def execute(self, query, *args):
            self.updates.append((query, args))
            return "UPDATE 1"

    conn = Conn()
    monkeypatch.setattr(worker, "db_pool", cases._FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: cases._FakeJobRedis())
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    asyncio.run(worker.process_scan_merge_job({"parent_scan_id": parent_id}))
    updates = [args for query, args in conn.updates if "UPDATE scans SET status = $1" in query]
    assert len(updates) == 1
    report = json.loads(updates[0][1])
    assert [item["cvss_score"] for item in report["findings"]].count(None) == 1
    # The union's summary and grade, not a shard's.
    assert "2 issue(s) found" in report["result"]["summary"]
    assert report["result"]["cvss_metrics"]["maximum"] == 8.0
    assert report["result"]["score"] < 100 and updates[0][2] == report["result"]["score"]
    # The grader's compliance narrative is not copied over the report's own block.
    assert report["result"]["compliance"] == {"owasp_top10": ["stale shard value"]}


def test_the_summary_grader_accepts_a_finding_without_a_cvss_score():
    from grading import grade

    graded = grade({"target": "https://example.test", "result": {}, "findings": [
        {"title": "Verified cross-site scripting", "severity": "medium", "cvss_score": None,
         "cwe": "CWE-79", "url": "https://example.test/a"},
        {"title": "Missing Content Security Policy header", "severity": "low", "cvss_score": 3.0,
         "cwe": "CWE-693", "url": "https://example.test/"},
    ]})
    assert graded["cvss_metrics"] == {"average": 3.0, "maximum": 3.0, "scores": [3.0]}
    assert "2 issue(s) found" in graded["summary"]


@pytest.mark.parametrize("score,counted", [
    ("7.5", 7.5), (7, 7), ("N/A", None), ("", None), ("nan", None), ("inf", None), (True, None),
])
def test_the_summary_grader_reads_a_score_given_as_text_and_skips_one_it_cannot_read(score, counted):
    # Unit fixtures: a stored score may be a numeric string; an unreadable one counts as none
    # rather than failing the grader (the merge would then keep a shard's summary).
    from grading import grade

    graded = grade({"target": "https://example.test", "result": {}, "findings": [
        {"title": "Finding A", "severity": "medium", "cvss_score": score, "cwe": "CWE-79",
         "url": "https://example.test/a"},
        {"title": "Finding B", "severity": "low", "cvss_score": 3.0, "cwe": "CWE-693",
         "url": "https://example.test/"},
    ]})
    expected = sorted([value for value in (counted, 3.0) if value is not None], reverse=True)
    assert graded["cvss_metrics"]["scores"] == expected
    assert graded["cvss_metrics"]["maximum"] == expected[0]
    assert "2 issue(s) found" in graded["summary"]


@pytest.mark.parametrize("owasp,cwe,soc2", [
    (["A03:2021 - Injection", "A05:2025 - Injection"], ["CWE-79", "CWE-80"], ["CC6.1"]),
    ({"2021": "A03:2021 - Injection"}, "CWE-79", [{"criterion": "CC6.1"}]),
    (3, 79, "CC6.1"),
])
def test_the_summary_grader_accepts_owasp_and_cwe_that_are_not_text(owasp, cwe, soc2):
    # Unit fixtures: a finding whose owasp, cwe or soc2 is a list, a mapping or a number made the
    # grader raise, so the merge kept a shard's summary. Only text labels are collected.
    from grading import grade

    graded = grade({"target": "https://example.test", "result": {}, "findings": [
        {"title": "Finding A", "severity": "medium", "cvss_score": 6.1, "cwe": cwe,
         "owasp": owasp, "soc2": soc2, "url": "https://example.test/a"},
        {"title": "Finding B", "severity": "low", "cvss_score": 3.0, "cwe": "CWE-693",
         "owasp": "A05:2021 - Security Misconfiguration", "url": "https://example.test/"},
    ]})
    assert "2 issue(s) found" in graded["summary"]
    assert graded["cvss_metrics"]["maximum"] == 6.1
    compliance = graded["compliance"]
    assert "A05:2021 - Security Misconfiguration" in compliance["owasp_top10"]
    assert all(isinstance(label, str) for label in compliance["owasp_top10"])
    assert all(isinstance(label, str) for label in compliance["soc2_criteria"])
    assert "CWE-693" in compliance["cwe_ids"]
    if isinstance(owasp, list):
        assert set(owasp) <= set(compliance["owasp_top10"])
        assert {"CWE-79", "CWE-80"} <= set(compliance["cwe_ids"])
    if isinstance(cwe, int):
        # A bare CWE number is still printed, as before.
        assert "79" in compliance["cwe_ids"]
