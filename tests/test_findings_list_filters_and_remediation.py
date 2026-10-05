"""GET /findings severity and proof filters, and the fix guidance on a finding.

Compatibility import layout, like tests/test_finding_proof_state.py: the findings router runs on
the flat runtime path, so it is reached through the api module that composes it.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *a, **k):
            pass

        def add_middleware(self, *a, **k):
            return None

        def _decorator(self, *a, **k):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = _decorator

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = lambda default=None, **k: default
    fastapi_mod.HTTPException = type("_HTTPExc", (Exception,), {})
    fastapi_mod.Query = lambda default=None, **k: default
    fastapi_mod.Request = type("_Req", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi"] = fastapi_mod
    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_CORS", (), {})
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_mod
    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = type("_Resp", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402

findings_router = sys.modules["finding_routes.router"]
from capabilities import exposure_probe  # noqa: E402
from finding_routes.list_filters import PROOF_STATES, parse_choice_list  # noqa: E402
from finding_routes.remediation import finding_remediation  # noqa: E402



class HTTPException(Exception):
    """Stands in for fastapi's, which the import stubs replace with one that takes no arguments."""

    def __init__(self, status_code=None, detail=None, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _Request:
    def __init__(self, **params):
        self.query_params = params


class _Conn:
    """The database's side of the list query: the SQL proof predicate (answered with the Python
    projection it must equal; tests/test_findings_proof_sql_postgres.py proves that on real
    PostgreSQL), LIMIT/OFFSET, and the undetermined-row check."""

    def __init__(self, rows, *, undetermined=False):
        self.rows = rows
        self.undetermined = undetermined
        self.queries: list[tuple[str, tuple]] = []

    def _answer(self, query, args):
        rows = [dict(row) for row in self.rows]
        if findings_router.FINDING_PROOF_STATE_SQL in query:
            states = next(arg for arg in args if isinstance(arg, list) and set(arg) <= set(PROOF_STATES))
            rows = [row for row in rows if findings_router.finding_proof_fields(dict(row))["proof_state"] in states]
            for row in rows:
                row["total_count"] = len(rows)
        if "OFFSET $" in query:
            rows = rows[args[-1]:args[-1] + args[-2]]
        elif "LIMIT $" in query:
            rows = rows[:args[-1]]
        return rows

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return self._answer(query, args)

    async def fetchval(self, query, *args):
        self.queries.append((query, args))
        if query.startswith("SELECT EXISTS"):
            return self.undetermined
        return len(self.rows)


def _list(monkeypatch, rows, conn=None, **params):
    conn = conn or _Conn(rows)

    class _Pool:
        @asynccontextmanager
        async def acquire(self):
            yield conn

    monkeypatch.setattr(findings_router, "_pool", lambda: _Pool())
    monkeypatch.setattr(findings_router, "HTTPException", HTTPException)
    defaults = dict(severity=None, status=None, source_type=None, target_id=None, ai_target_id=None,
                    device_target_id=None, scan_id=None, hunt_id=None, root_domain=None,
                    verification_verdict=None, verification_mode=None, verified_only=False,
                    proof_state=None, driven_by=None, research_campaign_id=None, search=None,
                    seen_within_days=None, not_seen_within_days=None, first_seen_within_days=None,
                    resolved_within_days=None, sort_by=None, sort_order="desc",
                    include_candidates=False, limit=100, offset=0, include_details=False)
    defaults.update(params)
    request = _Request(**{key: value for key, value in params.items() if value not in (None, False)})
    result = asyncio.run(findings_router.list_findings(request, **defaults))
    return result, conn


def _row(identifier, severity, **fields):
    row = {"id": identifier, "title": f"finding {identifier}", "severity": severity, "status": "active",
           "evidence": None, "last_verification_verdict": None, "latest_retest_mode": None, "total_count": 3}
    row.update(fields)
    return row


def test_severity_takes_several_values_and_refuses_unknown_ones(monkeypatch):
    _, conn = _list(monkeypatch, [], severity="critical,HIGH,critical")
    query, args = conn.queries[0]
    assert "f.severity = ANY($1::text[])" in query
    assert args[0] == ["critical", "high"]
    with pytest.raises(HTTPException) as refused:
        _list(monkeypatch, [], severity="critical,severe")
    assert refused.value.status_code == 400 and "'severe'" in refused.value.detail


def test_the_proof_filter_returns_exactly_what_the_badge_says_and_paginates(monkeypatch):
    rows = [
        # Proven by a deterministic retest, exactly as finding_proof_fields decides it.
        _row("a", "high", last_verification_verdict="exploited", latest_retest_mode="deterministic"),
        # An AI verdict is not proof: suspected.
        _row("b", "critical", last_verification_verdict="exploited", latest_retest_mode="ai_driven"),
        _row("c", "medium"),
        _row("d", "high", last_verification_verdict="exploited", latest_retest_mode="deterministic"),
    ]
    proven, conn = _list(monkeypatch, rows, proof_state="verified", limit=1, offset=1)
    assert proven["total"] == 2
    assert [item["id"] for item in proven["findings"]] == ["d"]
    assert proven["findings"][0]["proof_state"] == "verified"
    # The proof filter is one more WHERE clause, paginated by the database like any other.
    exists, _ = conn.queries[0]
    query, args = conn.queries[1]
    assert exists.startswith("SELECT EXISTS") and findings_router.FINDING_PROOF_UNDETERMINED_SQL in exists
    assert f"{findings_router.FINDING_PROOF_STATE_SQL} = ANY(" in query and ["verified"] in args
    assert "OFFSET" in query and list(args[-2:]) == [1, 1]
    leads, _ = _list(monkeypatch, rows, proof_state="suspected,unverified")
    assert [(item["id"], item["proof_state"]) for item in leads["findings"]] == [("b", "suspected"), ("c", "unverified")]


class _StreamingConn(_Conn):
    """A connection whose rows include one the SQL projection cannot decide."""

    def __init__(self, rows):
        super().__init__(rows, undetermined=True)
        self.streamed: list[str] = []

    @asynccontextmanager
    async def transaction(self):
        yield

    def cursor(self, query, *args, prefetch=None):
        self.streamed.append(query)
        rows = [dict(row) for row in self.rows]

        class _Cursor:
            def __aiter__(self):
                return self._iterate()

            async def _iterate(self):
                for row in rows:
                    yield row

        return _Cursor()


def test_an_undecidable_row_sends_the_filter_through_the_python_projection(monkeypatch):
    rows = [_row(str(n), "high" if n % 3 else "low") for n in range(40)]
    conn = _StreamingConn(rows)
    result, _ = _list(monkeypatch, rows, conn=conn, proof_state="suspected", limit=5, offset=20)
    # Nothing is refused or sampled: every row is projected from a cursor, in query order.
    expected = [str(n) for n in range(40) if n % 3]
    assert result["total"] == len(expected)
    assert [item["id"] for item in result["findings"]] == expected[20:25]
    (query,) = conn.streamed
    assert findings_router.FINDING_PROOF_STATE_SQL not in query and "LIMIT" not in query.split("ORDER BY")[-1]


class _ConnWithCandidates(_Conn):
    """Answers the candidate query with its own rows, the findings query with the findings."""

    def __init__(self, rows, candidates):
        super().__init__(rows)
        self.candidates = candidates

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        if "investigation_candidates" in query:
            return [dict(row) for row in self.candidates]
        return self._answer(query, args)


def _candidate(identifier, severity):
    return {"id": identifier, "target_id": None, "family": "access_control", "canonical_locus": {"route": "/api/x"},
            "title": f"lead {identifier}", "claimed_severity": severity, "evidence_refs": [], "status": "new",
            "first_seen_at": None, "last_seen_at": None, "target_url": None, "target_name": None,
            "root_domain": None, "total_count": 1}


def _list_with_candidates(monkeypatch, rows, candidates, **params):
    return _list(monkeypatch, rows, conn=_ConnWithCandidates(rows, candidates), **params)


def test_a_proven_only_filter_leaves_out_hunt_candidates(monkeypatch):
    # A candidate is an unproven lead: it can never answer "verified" or "unverified".
    for proof_state in ("verified", "unverified", "verified,unverified"):
        result, conn = _list_with_candidates(monkeypatch, [], [_candidate("lead-1", "high")],
                                             proof_state=proof_state, include_candidates=True)
        assert not any("investigation_candidates" in query for query, _ in conn.queries)
        assert result["candidates_total"] == 0


def test_a_suspected_filter_includes_hunt_candidates_with_the_same_label(monkeypatch):
    rows = [
        _row("b", "critical", last_verification_verdict="exploited", latest_retest_mode="ai_driven"),
        _row("a", "high", last_verification_verdict="exploited", latest_retest_mode="deterministic"),
    ]
    candidates = [_candidate("lead-1", "medium")]
    result, conn = _list_with_candidates(monkeypatch, rows, candidates,
                                         proof_state="suspected", include_candidates=True)
    assert any("investigation_candidates" in query for query, _ in conn.queries)
    labels = {item["id"]: (item["proof_state"], item["is_suspected"]) for item in result["findings"]}
    # The proven finding is filtered out; the suspected finding and the lead stay, labelled alike.
    assert labels == {"b": ("suspected", True), "lead-1": ("suspected", True)}
    assert result["total"] == 2 and result["included_candidates"] == 1
    # Pagination covers both: the second page holds the remaining item.
    second, _ = _list_with_candidates(monkeypatch, rows, candidates,
                                      proof_state="suspected", include_candidates=True, limit=1, offset=1)
    assert len(second["findings"]) == 1
    assert {item["id"] for item in second["findings"]} < {"b", "lead-1"}


def test_choice_lists_parse_blank_as_no_filter():
    assert parse_choice_list(None, ("a",), "x") is None
    assert parse_choice_list(" , ", ("a",), "x") is None
    assert parse_choice_list("A, a", ("a",), "x") == ["a"]


# --- Fix guidance -------------------------------------------------------------------------------

def test_every_exposure_the_prover_promotes_has_class_guidance():
    promotable = [name for name in exposure_probe._CLASS_SEVERITY if exposure_probe.is_sensitive_exposure_class(name)]
    assert promotable, "the prover's promotable classes moved"
    for exposure_class in promotable:
        guidance = finding_remediation({"title": "anything", "evidence": {"exposure_class": exposure_class}})
        assert guidance and guidance["matched_by"] == "exposure_class" and guidance["steps"], exposure_class


def test_guidance_prefers_the_exposure_class_over_title_words():
    # The heap dump is classified environment_secret_file; its title says nothing a keyword knows.
    guidance = finding_remediation({
        "title": "Sensitive exposure: environment secret file",
        "evidence": json.dumps({"exposure_class": "environment_secret_file"}),
    })
    assert guidance["title"] == "Publicly Served File Containing Secrets"
    assert any("Rotate every secret" in step for step in guidance["steps"])
    assert {example["label"] for example in guidance["code_examples"]} >= {"nginx", "apache"}


def test_title_matches_are_labelled_and_unknown_findings_get_none():
    csp = finding_remediation({"title": "CSP header missing"})
    assert csp["matched_by"] == "title" and "Content Security Policy" in csp["title"]
    # Model Intake governance gaps have no entry: the right steps depend on that workflow.
    assert finding_remediation({"title": "Model monitoring plan missing", "tool": "model_intake", "source": "model_intake"}) is None


def test_a_path_in_the_title_does_not_choose_the_guidance():
    cors = finding_remediation({"title": "CORS allows credentialed cross-origin reads: /api/openapi.json"})
    assert cors["title"] == "CORS Misconfiguration"
    assert finding_remediation({"title": "JWT / bearer token exposed in response: /api/openapi.json"}) is None


def test_a_weak_policy_is_not_reported_as_a_missing_one():
    for title in ("CSP: style-src allows 'unsafe-inline'.", "CSP: script-src allows 'unsafe-eval'.",
                  "CSP: Trusted Types not required (optional)."):
        assert finding_remediation({"title": title})["title"] == "Content Security Policy Allows Unsafe Sources", title
    assert "Not Configured" in finding_remediation({"title": "CSP header missing"})["title"]


@pytest.mark.parametrize(("finding", "title"), [
    ({"title": "Missing HTTP response header: Referrer-Policy", "tool": "nuclei"}, "Referrer-Policy Header Missing"),
    ({"title": "Permissions-Policy missing", "tool": "http_headers"}, "Permissions-Policy Header Missing"),
    ({"title": "HTTP Missing Security Headers", "tool": "nuclei"}, "Security Headers Missing"),
    ({"title": "No rate limiting detected on https://app.test/login", "tool": "rate_limiting"}, "No Rate Limiting"),
    ({"title": "Brute-force protection missing: https://app.test/api/auth", "tool": "bruteforce_protection"}, "Brute-Force Protection Missing"),
    ({"title": "CAA record missing", "tool": "dns_policy"}, "CAA Record Missing"),
    ({"title": "Exposed file: .env (+6 duplicate paths) (confidence: medium)", "tool": "exposed_files"}, "Publicly Served File Containing Secrets"),
    ({"title": "Webhook signature verification bypass: /api/webhooks/stripe", "tool": "webhook_checks"}, "Webhook Signature Not Verified"),
    ({"title": "AWS access key id exposed: /api/cloud/metadata", "tool": "data_exposure"}, "Exposed Cloud Credentials"),
    ({"title": "Database connection string exposed: /mcp/resources", "tool": "data_exposure"}, "Sensitive Data in API Response"),
    ({"title": "Accessible Cloud Metadata: /.aws/config", "tool": "forced_browsing"}, "Exposed Cloud Credentials"),
    # Reached only by the .aws alternative (no "cloud metadata" in the title); an over-escaped
    # pattern sent it to the generic confidential-file guidance.
    ({"title": "Accessible Sensitive File: /.aws/credentials", "tool": "forced_browsing"}, "Exposed Cloud Credentials"),
    ({"title": "Legacy TLS protocol negotiated", "tool": "tls.inspect"}, "Weak TLS Configuration"),
    # AI Gate: the catalog title decides, whatever probe family produced it.
    ({"title": "PII or credential pattern in response", "source": "ai_gate", "evidence": {"family": "tool_abuse"}}, "Sensitive Data in AI Responses"),
    ({"title": "Excessive agency (LLM08)", "source": "ai_gate"}, "Excessive Agency"),
    ({"title": "Executable content in model output", "source": "ai_gate", "evidence": {"family": "data_exfiltration"}}, "Unsafe Handling of Model Output"),
    # A catalog title not listed falls back to the probe family.
    ({"title": "A future probe title", "source": "ai_gate", "evidence": {"family": "prompt_leakage"}}, "System Prompt Leakage"),
    # Nuclei: the reviewed template id decides; neither title names ".git" or "git directory".
    ({"title": "Git Credentials - Detect", "tool": "nuclei", "evidence": {"template_id": "git-credentials-disclosure"}}, "Publicly Served File Containing Secrets"),
    ({"title": "Git Configuration - Detect", "tool": "nuclei", "evidence": {"template_id": "git-config"}}, "Exposed .git Directory"),
    # Connected-device checks.
    ({"title": "SSH Password Authentication Enabled", "tool": "device_ssh", "source": "device"}, "SSH Password Authentication Enabled"),
    ({"title": "SSH Keyboard-Interactive Authentication Enabled", "tool": "device_ssh", "source": "device"}, "SSH Keyboard-Interactive Authentication Enabled"),
    ({"title": "SSH Negotiated Weak Cryptographic Algorithm", "tool": "device_ssh", "source": "device"}, "Weak SSH Algorithms Negotiated"),
    ({"title": "Device service requirement not met: ssh on 22/tcp", "tool": "device_policy", "source": "device"}, "Device Service Outside the Approved Policy"),
    ({"title": "Deny device service: telnet on 23/tcp", "tool": "device_policy", "source": "device"}, "Device Service Outside the Approved Policy"),
    ({"title": "Review device service: http on 80/tcp", "tool": "device_policy", "source": "device"}, "Device Service Outside the Approved Policy"),
    ({"title": "Device HTTPS trust could not be established", "tool": "device_tls", "source": "device"}, "Device Management Certificate Not Trusted"),
    # Written directly by the device candidate route, with no producer text to fall back on.
    ({"title": "Affected connected-device software: CVE-2024-0001", "tool": "device_candidate_verifier", "source": "device"}, "Known-Vulnerable Device Software"),
])
def test_findings_are_matched_by_what_produced_them(finding, title):
    guidance = finding_remediation(finding)
    assert guidance and guidance["title"] == title and guidance["matched_by"] == "finding_type", guidance


def test_positive_observations_get_no_guidance():
    assert finding_remediation({"title": "WAF Detected: cloudflare", "tool": "waf_detection"}) is None
    assert finding_remediation({"title": "Input validation detected (attack payloads blocked)", "tool": "input_validation"}) is None


def test_titles_without_a_template_id_still_find_the_git_guidance():
    # Rows persisted before template ids were matched keep a title backstop.
    assert finding_remediation({"title": "Git Credentials - Detect", "tool": "nuclei"})["title"] == "Publicly Served File Containing Secrets"
    assert finding_remediation({"title": "Git Configuration - Detect", "tool": "nuclei"})["title"] == "Exposed .git Directory"


def test_producer_guidance_is_the_floor_and_labelled():
    unknown = {"title": "Unrecognised probe", "tool": "device_request_dast"}
    guidance = finding_remediation({**unknown, "evidence": {"remediation": "Require auth on /api/x"}})
    assert guidance["matched_by"] == "producer" and guidance["steps"] == ["Require auth on /api/x"]
    assert guidance["title"] == "Unrecognised probe" and guidance["code_examples"] == []
    # SSH rows persisted before the fix carry the check's text under evidence.recommendation.
    guidance = finding_remediation({**unknown, "evidence": json.dumps({"recommendation": "Do X"})})
    assert guidance["matched_by"] == "producer" and guidance["steps"] == ["Do X"]
    guidance = finding_remediation({**unknown, "evidence": {"remediation": ["a", "b"]}})
    assert guidance["matched_by"] == "producer" and guidance["steps"] == ["a", "b"]
    # Structured grading output is not guidance text.
    assert finding_remediation({**unknown, "evidence": {"remediation": {"x": 1}}}) is None
    assert finding_remediation({**unknown, "evidence": {"remediation": ["a", {"x": 1}]}}) is None
    assert finding_remediation({**unknown, "evidence": {"remediation": "   "}}) is None
    # A knowledge-base match wins over the check's own text.
    known = finding_remediation({
        "title": "SSH Password Authentication Enabled", "tool": "device_ssh",
        "evidence": {"recommendation": "Disable password authentication"},
    })
    assert known["matched_by"] == "finding_type"


def test_every_mapped_key_has_an_entry():
    from scanner_tools import remediation_kb, remediation_kb_findings as tables
    keys = set(tables.TOOL_REMEDIATION.values()) | set(tables.HEADER_REMEDIATION.values())
    keys |= set(tables.TEMPLATE_REMEDIATION.values())
    keys |= set(tables.EXACT_TITLE_REMEDIATION.values()) | set(tables.AI_FAMILY_REMEDIATION.values())
    keys |= {key for patterns in tables.TOOL_TITLE_REMEDIATION.values() for _, key in patterns}
    keys |= set(remediation_kb.EXPOSURE_CLASS_REMEDIATION.values())
    assert keys <= set(remediation_kb.REMEDIATION_DATABASE), sorted(keys - set(remediation_kb.REMEDIATION_DATABASE))
