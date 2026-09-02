"""Tests for the Continuous ASM endpoint inventory pure helpers (docs §16)."""

import os
import sys
import asyncio
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import asm_inventory as a  # noqa: E402


class _FakeRedis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def eval(self, _script, _numkeys, key, amount, cap, _ttl, all_or_nothing="0"):
        current = int(self.values.get(key) or 0)
        amount = int(amount)
        cap = int(cap)
        if amount <= 0:
            return 0
        if cap <= 0:
            return 0
        if current >= cap:
            return 0
        if str(all_or_nothing) == "1" and current + amount > cap:
            return 0
        granted = min(amount, cap - current)
        self.values[key] = current + granted
        return granted


def test_inventory_semantics_does_not_call_scanner_candidates_confirmed_routes():
    item = a.endpoint_inventory_semantics({
        "source": "coverage_discovery",
        "test_status": "tested",
        "last_reachability_at": None,
        "last_http_status": None,
        "unreachable_streak": 0,
    })

    assert item["provenance_kind"] == "scanner_discovered"
    assert item["provenance_label"] == "Scanner candidate"
    assert item["reachability_state"] == "not_checked"
    assert "not proof" in item["provenance_explanation"]


def test_inventory_semantics_keeps_reachability_separate_from_test_status():
    item = a.endpoint_inventory_semantics({
        "source": "scan_telemetry",
        "test_status": "stale",
        "last_reachability_at": "2026-08-29T00:00:00Z",
        "last_http_status": 401,
        "unreachable_streak": 0,
    })

    assert item["provenance_kind"] == "response_observed"
    assert item["reachability_state"] == "reachable_observed"
    assert item["test_status"] == "stale"


def test_inventory_semantics_marks_soft_404_retirement_explicitly():
    item = a.endpoint_inventory_semantics({
        "source": "scan",
        "test_status": "gone",
        "last_reachability_at": "2026-08-29T00:00:00Z",
        "last_http_status": 200,
        "unreachable_streak": 2,
    })

    assert item["reachability_state"] == "retired_unreachable"
    assert item["reachability_label"] == "Retired"


def test_domain_rate_reservation_zero_remaining_cap_denies():
    redis = _FakeRedis()

    assert a.reserve_domain_rate(redis, "example.test", 0, 1) == 0
    assert a.reserved_domain_rate_count(redis, "example.test") == 0


def test_domain_rate_reservation_caps_at_positive_limit():
    # With a non-zero cap (now the default), reservations are bounded by the
    # remaining per-domain headroom and denied once the cap is reached.
    redis = _FakeRedis()

    assert a.reserve_domain_rate(redis, "example.test", 100, 60) == 60
    assert a.reserved_domain_rate_count(redis, "example.test") == 60
    assert a.reserve_domain_rate(redis, "example.test", 100, 60) == 40  # clamped to headroom
    assert a.reserve_domain_rate(redis, "example.test", 100, 1) == 0    # cap reached


def test_filter_reachable_worklist_drops_404_paths(monkeypatch):
    # Clean-404 server (honey-style): a literal 404 proves the GET path is not
    # reachable, but not that method-specific POST/PUT routes are absent.
    async def fake_status(base_url, path, auth_args, timeout):
        if path.startswith("/api/ai-redteam") or "shakerscan-probe" in path:
            return ("404", 9)
        return ("200", 512)
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = [
        "GET /rest/products/1?id=2",
        "GET /api/ai-redteam/user_consent",
        'POST /api/ai-redteam/user_consent json:{"a":1}',
        "PUT /api/ai-redteam/tools.list",
    ]
    kept = asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {}))
    assert kept == [
        "GET /rest/products/1?id=2",
        'POST /api/ai-redteam/user_consent json:{"a":1}',
        "PUT /api/ai-redteam/tools.list",
    ]


def test_filter_reachable_worklist_keeps_non_404(monkeypatch):
    # Real 200 endpoints (distinct from the decoy 404 signature) are kept.
    async def fake_status(base_url, path, auth_args, timeout):
        if "shakerscan-probe" in path:
            return ("404", 9)
        return ("200", 700)
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /a", "POST /b form:x=1", "DELETE /c"]
    assert asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {})) == worklist


def test_filter_reachable_worklist_disabled_skips_probing(monkeypatch):
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "0")
    calls = {"n": 0}
    async def fake_status(*_a, **_k):
        calls["n"] += 1
        return ("404", 9)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /api/ai-redteam/x"]
    assert asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {})) == worklist
    assert calls["n"] == 0


def test_filter_reachable_worklist_drops_soft404_500(monkeypatch):
    # App returns 500 (~3060b) for unknown /api routes, NEVER 404 (Juice Shop
    # style). A literal-404 filter would keep them; soft-404 signature matching
    # drops them while keeping the real endpoint (distinct status/size).
    async def fake_status(base_url, path, auth_args, timeout):
        if path == "/api/Products":
            return ("200", 13212)
        return ("500", 3060)  # unknown /api routes incl. decoys
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.delenv("ASM_SOFT404_DETECT", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /api/Products", "GET /api/v3/auth", "GET /api/Addresss/login"]
    kept = asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {}))
    assert kept == ["GET /api/Products"]


def test_filter_reachable_worklist_drops_spa_200_catchall(monkeypatch):
    # SPA serves a 200 index shell for unknown routes (incl. client routes like
    # /login); real API endpoints have distinct sizes. Drop the shell, keep the API.
    async def fake_status(base_url, path, auth_args, timeout):
        if path == "/rest/products/search":
            return ("200", 631)
        return ("200", 75055)  # SPA index shell for unknown routes incl. decoys
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.delenv("ASM_SOFT404_DETECT", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /rest/products/search", "GET /login", "GET /made/up/route"]
    kept = asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {}))
    assert kept == ["GET /rest/products/search"]


def test_filter_reachable_worklist_soft404_detect_off_keeps_soft404s(monkeypatch):
    # With soft-404 detection off, only literal 404s are dropped; 500-for-unknown
    # phantoms are kept (back-compat with the original literal-404 behaviour).
    async def fake_status(base_url, path, auth_args, timeout):
        return ("500", 3060)
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.setenv("ASM_SOFT404_DETECT", "0")
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /api/v3/auth", "GET /api/Products"]
    assert asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {})) == worklist


def test_filter_reachable_worklist_honors_large_explicit_probe_limit(monkeypatch):
    async def fake_status(base_url, path, auth_args, timeout):
        if path == "/api/real":
            return ("200", 1200)
        return ("401", 42)

    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.delenv("ASM_SOFT404_DETECT", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = [f"GET /api/generated-{i}" for i in range(2005)] + ["GET /api/real"]

    kept = asyncio.run(
        a.filter_reachable_worklist(
            "http://t.test",
            worklist,
            {},
            max_probe=3000,
            concurrency=64,
        )
    )

    assert kept == ["GET /api/real"]


def test_filter_reachable_worklist_keeps_on_probe_error(monkeypatch):
    # Inconclusive probes (transient error/timeout) never drop a real endpoint.
    async def fake_status(base_url, path, auth_args, timeout):
        return ("ERR", -1)
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /a", "GET /b"]
    assert asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {})) == worklist


def test_path_prefix_and_soft404_matches():
    assert a._path_prefix("/api/v3/users") == "/api"
    assert a._path_prefix("/login") == "/"
    assert a._path_prefix("/") == "/"
    assert a._path_prefix("/rest/products?q=1") == "/rest"
    # status must match, size within tolerance
    assert a._soft404_matches(("500", 3060), ("500", 3047)) is True
    assert a._soft404_matches(("200", 13212), ("500", 3060)) is False  # status differs
    assert a._soft404_matches(("200", 631), ("200", 75055)) is False   # size differs
    assert a._soft404_matches(("ERR", -1), ("500", 3060)) is False     # inconclusive


def test_is_unreachable_classification():
    # literal 404 -> phantom
    assert a._is_unreachable(("404", 9), []) is True
    # soft-404 match -> phantom
    assert a._is_unreachable(("500", 3060), [("500", 3055)]) is True
    # reachable (status differs from the not-found signature) -> keep
    assert a._is_unreachable(("200", 631), [("500", 3060)]) is False
    # inconclusive probe -> None (leave unchanged / keep)
    assert a._is_unreachable(("ERR", -1), [("404", 9)]) is None


def test_reachability_verdict_method_aware():
    assert a._reachability_verdict(("404", 9), []) == "hard_404"
    assert a._reachability_verdict(("500", 3060), [("500", 3055)]) == "soft_404"
    assert a._reachability_verdict(("200", 631), [("500", 3060)]) == "reachable"
    assert a._reachability_verdict(("ERR", -1), [("404", 9)]) == "inconclusive"
    # 405 = method not allowed = the path EXISTS -> reachable, never dropped
    assert a._reachability_verdict(("405", 144), [("404", 9)]) == "reachable"


def test_filter_soft404_keeps_non_get_methods(monkeypatch):
    # On a soft-404 app (500-for-unknown), a path whose GET hits the error page
    # must still keep its real POST/PUT entries (GET evidence is method-specific).
    async def fake_status(base_url, path, auth_args, timeout):
        return ("500", 3060)  # path + decoys all return the app error page
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.delenv("ASM_SOFT404_DETECT", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /api/login", 'POST /api/login json:{"u":1}', "PUT /api/login"]
    kept = asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {}))
    assert "GET /api/login" not in kept          # GET dropped (soft-404)
    assert 'POST /api/login json:{"u":1}' in kept  # non-GET kept
    assert "PUT /api/login" in kept


def test_filter_hard404_keeps_non_get_methods(monkeypatch):
    # Even a literal 404 is still evidence from a GET probe. Some routers return
    # 404 for unsupported methods while a POST/PUT route exists, so preserve non-GET.
    async def fake_status(base_url, path, auth_args, timeout):
        return ("404", 9)
    monkeypatch.setenv("ASM_VALIDATE_REACHABILITY", "1")
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    worklist = ["GET /ghost", "POST /ghost form:x=1", "DELETE /ghost"]
    assert asyncio.run(a.filter_reachable_worklist("http://t.test", worklist, {})) == [
        "POST /ghost form:x=1",
        "DELETE /ghost",
    ]


class _SweepConn:
    """Minimal asyncpg-conn stand-in for sweep_endpoint_reachability: returns the
    inventory paths from fetch(), records execute()s, and reports a retired count
    from each fetchval() equal to the path array it is handed."""
    def __init__(self, paths):
        self._paths = paths
        self.executes = []
        self.fetchvals = []  # list of (query, args)

    async def fetch(self, query, *args):
        return [{"path": p} for p in self._paths]

    async def execute(self, query, *args):
        self.executes.append((query, args))
        return "UPDATE 1"

    async def fetchval(self, query, *args):
        self.fetchvals.append((query, args))
        # retire calls pass (tid, paths, threshold) -> simulate all hitting threshold.
        # the §7.5 GC purge call passes (tid, retention_days) -> no paths, purge 0.
        paths = args[1] if len(args) > 1 else None
        return len(paths) if isinstance(paths, (list, tuple)) else 0

    @property
    def fetchval_args(self):  # the last RETIRE call's args (ignores the GC purge call)
        retire = [a for (_q, a) in self.fetchvals if len(a) >= 3]
        if retire:
            return retire[-1]
        return self.fetchvals[-1][1] if self.fetchvals else None


_TID = "11111111-1111-1111-1111-111111111111"


def test_sweep_retires_phantoms_and_keeps_real(monkeypatch):
    # Clean-404 server: one real path, two phantom 404s. Sweep retires the 2.
    async def fake_status(base_url, path, auth_args, timeout):
        return ("200", 512) if path == "/api/real" else ("404", 9)
    monkeypatch.delenv("ASM_REACHABILITY_SWEEP", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    conn = _SweepConn(["/api/real", "/api/phantom1", "/api/phantom2"])
    res = asyncio.run(a.sweep_endpoint_reachability(conn, "http://t.test", _TID, {}, retire_threshold=1))
    assert res["probed"] == 3
    assert res["reachable"] == 1
    assert res["unreachable"] == 2
    assert res["retired"] == 2
    # the retire query was handed exactly the two unreachable paths + threshold 1
    assert sorted(conn.fetchval_args[1]) == ["/api/phantom1", "/api/phantom2"]
    assert conn.fetchval_args[2] == 1


def test_sweep_classifies_soft404_500_as_unreachable(monkeypatch):
    # 500-for-unknown app: real 200 endpoint kept, 500 phantoms retired.
    async def fake_status(base_url, path, auth_args, timeout):
        return ("200", 13212) if path == "/api/Products" else ("500", 3060)
    monkeypatch.delenv("ASM_REACHABILITY_SWEEP", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    conn = _SweepConn(["/api/Products", "/api/v3/auth", "/api/fake"])
    res = asyncio.run(a.sweep_endpoint_reachability(conn, "http://t.test", _TID, {}, retire_threshold=1))
    assert res["reachable"] == 1 and res["unreachable"] == 2


def test_sweep_inconclusive_probe_leaves_row_untouched(monkeypatch):
    async def fake_status(base_url, path, auth_args, timeout):
        return ("ERR", -1)
    monkeypatch.delenv("ASM_REACHABILITY_SWEEP", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    conn = _SweepConn(["/a", "/b"])
    res = asyncio.run(a.sweep_endpoint_reachability(conn, "http://t.test", _TID, {}, retire_threshold=1))
    assert res["reachable"] == 0 and res["unreachable"] == 0 and res["retired"] == 0


def test_sweep_disabled_via_env(monkeypatch):
    async def fake_status(*_a, **_k):
        raise AssertionError("should not probe when disabled")
    monkeypatch.setenv("ASM_REACHABILITY_SWEEP", "0")
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    conn = _SweepConn(["/a"])
    res = asyncio.run(a.sweep_endpoint_reachability(conn, "http://t.test", _TID, {}))
    assert res.get("disabled") is True and res["probed"] == 0


def test_sweep_soft404_retires_get_rows_only(monkeypatch):
    # Soft-404 paths: only the GET method rows may be retired (a real POST/PUT on
    # the same path must survive). The retire SQL must restrict to method='GET'.
    async def fake_status(base_url, path, auth_args, timeout):
        return ("500", 3060)
    monkeypatch.delenv("ASM_REACHABILITY_SWEEP", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    conn = _SweepConn(["/api/a", "/api/b"])
    res = asyncio.run(a.sweep_endpoint_reachability(conn, "http://t.test", _TID, {}, retire_threshold=1))
    assert res["soft_404"] == 2 and res["hard_404"] == 0
    soft_retire = [q for q, _ in conn.fetchvals if "method = 'GET'" in q]
    assert soft_retire, "soft-404 retire must restrict to GET rows"


def test_sweep_hard404_retires_get_rows_only(monkeypatch):
    # Literal-404 paths are still based on a GET probe; method-specific non-GET
    # routes may exist, so retire SQL must restrict to method='GET'.
    async def fake_status(base_url, path, auth_args, timeout):
        return ("404", 9)
    monkeypatch.delenv("ASM_REACHABILITY_SWEEP", raising=False)
    monkeypatch.setattr(a, "_probe_path_status", fake_status)
    conn = _SweepConn(["/x", "/y"])
    res = asyncio.run(a.sweep_endpoint_reachability(conn, "http://t.test", _TID, {}, retire_threshold=1))
    assert res["hard_404"] == 2 and res["soft_404"] == 0
    get_method_retire = [q for q, _ in conn.fetchvals if "method = 'GET'" in q]
    assert get_method_retire, "hard-404 retire must restrict to GET rows"


def test_normalize_path_templates_volatile_ids():
    assert a.normalize_path("/users/42") == "/users/{id}"
    assert a.normalize_path("/u/550e8400-e29b-41d4-a716-446655440000/x") == "/u/{uuid}/x"
    assert a.normalize_path("/blob/0123456789abcdef0123456789abcdef") == "/blob/{hash}"
    assert a.normalize_path("/rest/products/search") == "/rest/products/search"


def test_parse_worklist_entry_shapes():
    assert a.parse_worklist_entry("GET /rest/products/1?q=x&id=2") == ("GET", "/rest/products/1", "id,q")
    assert a.parse_worklist_entry("POST /login form:email=1&password=1") == ("POST", "/login", "email,password")
    assert a.parse_worklist_entry('POST /api json:{"a":1,"b":2}') == ("POST", "/api", "a,b")
    assert a.parse_worklist_entry('POST /api json:{"user":{"id":1},"qty":2}') == ("POST", "/api", "qty,user.id")
    assert a.parse_worklist_entry("/ftp") == ("GET", "/ftp", "")
    assert a.parse_worklist_entry("GET rel/path") == ("GET", "/rel/path", "")
    assert a.parse_worklist_entry("") is None
    assert a.parse_worklist_entry(None) is None


def test_priority_prefers_canonical_auth_and_search_over_version_fanout():
    canonical_login = a.priority_score("POST", "/rest/user/login", "email,password")
    version_guess = a.priority_score("POST", "/rest/v2/auth/login", "email,password,token")
    search = a.priority_score("GET", "/rest/products/search", "q")
    api_base = a.priority_score("GET", "/api", "")

    assert canonical_login > version_guess
    assert search > api_base
    assert search > a.priority_score("GET", "/rest", "")


def test_priority_lifts_state_changing_resource_endpoints():
    basket_item = a.priority_score("POST", "/api/BasketItems", "ProductId,BasketId,quantity")
    order = a.priority_score("GET", "/workshop/api/shop/orders/{id}", "id")
    order_list = a.priority_score("GET", "/workshop/api/shop/orders/all", "")
    generic = a.priority_score("GET", "/api/status", "")

    assert basket_item > generic
    assert order > generic
    assert order_list > generic


def test_parse_worklist_entry_detail_preserves_replay_context():
    form = a.parse_worklist_entry_detail("POST /login form:email=1&password=1")
    assert form is not None
    assert form.param_location == "form"
    assert form.content_type == "application/x-www-form-urlencoded"
    assert form.replay_spec == "POST /login form:email=1&password=1"

    json_body = a.parse_worklist_entry_detail('POST /api json:{"a":1,"b":2}')
    assert json_body is not None
    assert json_body.param_location == "json"
    assert json_body.content_type == "application/json"
    assert json_body.replay_spec == 'POST /api json:{"a":1,"b":2}'

    query = a.parse_worklist_entry_detail("GET rel/path?x=seed")
    assert query is not None
    assert query.replay_spec == "GET /rel/path?x=seed"


def test_fingerprint_collapses_volatile_ids():
    f1 = a.endpoint_fingerprint("GET", "/users/42", "id")
    f2 = a.endpoint_fingerprint("GET", "/users/43", "id")
    assert f1 == f2  # same logical endpoint
    # method, path, and param set all matter
    assert a.endpoint_fingerprint("POST", "/users/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/orders/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id,extra") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id", auth_state="user1") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id", param_location="form") != f1


def test_auth_state_from_options_prefers_explicit_and_primary_auth():
    assert a.auth_state_from_options({}) == "anonymous"
    assert a.auth_state_from_options({"auth_header": "Bearer x"}) == "user1"
    assert a.auth_state_from_options({"auth_state": "user2", "auth_header": "Bearer x"}) == "user2"
    assert a.auth_state_from_options({"auth_state": "invalid"}) == "anonymous"


def test_priority_score_ranks_high_value_and_params():
    admin = a.priority_score("POST", "/admin/login", "user,pass")
    static = a.priority_score("GET", "/assets/style.css", "")
    api_param = a.priority_score("GET", "/api/items", "id")
    assert admin > api_param > static
    assert admin == 10 + 20 + 15 + 5  # high-value + param + write method


def test_to_custom_endpoint_roundtrips_params():
    assert a.to_custom_endpoint("POST", "/login", "email,password") == "POST /login?email=1&password=1"
    assert (
        a.to_custom_endpoint("POST", "/login", "email,password", param_location="form")
        == "POST /login form:email=1&password=1"
    )
    assert (
        a.to_custom_endpoint("POST", "/api", "a,b", param_location="json")
        == 'POST /api json:{"a":"test","b":"test"}'
    )
    assert (
        a.to_custom_endpoint("POST", "/login", "email,password", param_location="json")
        == 'POST /login json:{"email":"test@example.com","password":"TestPass123!"}'
    )
    assert (
        a.to_custom_endpoint("POST", "/api", "qty,user.id", param_location="json")
        == 'POST /api json:{"qty":1,"user":{"id":1}}'
    )
    assert (
        a.to_custom_endpoint("POST", "/api", "a,b", replay_spec='POST /api json:{"a":"seed","b":2}')
        == 'POST /api json:{"a":"seed","b":2}'
    )
    assert a.to_custom_endpoint("GET", "/ftp", "") == "GET /ftp"


def test_normalize_worklist_dedupes_by_fingerprint():
    wl = ["GET /a/1?x=1", "GET /a/2?x=1", "GET /b", "GET /b", 123, None]
    out = a.normalize_worklist(wl)
    # /a/1 and /a/2 collapse (same fingerprint); /b dedupes; non-strings dropped
    assert out == [("GET", "/a/1", "x"), ("GET", "/b", "")]


def test_normalize_worklist_respects_limit():
    wl = [f"GET /e{i}?x=1" for i in range(100)]
    assert len(a.normalize_worklist(wl, limit=10)) == 10


class _CoverageConn:
    def __init__(self, status_row, attempt_rows):
        self.rows = [status_row]
        self.attempt_rows = attempt_rows
        self.queries = []

    async def fetchrow(self, query, *args):
        self.queries.append((query, args))
        return self.rows.pop(0)

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return self.attempt_rows


def test_coverage_summary_defaults_to_endpoint_status_without_attempts():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 4,
            "tested": 1,
            "untested": 2,
            "in_progress": 0,
            "stale": 1,
            "gone": 0,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 1,
        },
        [],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["coverage_basis"] == "endpoint_status"
    assert summary["tested"] == 1
    assert summary["coverage"] == 0.25
    assert summary["status_coverage"]["tested"] == 1
    assert summary["attempt_coverage"]["attempted"] == 0


def test_coverage_summary_uses_latest_attempt_ledger_when_present():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 5,
            "canonical_routes": 2,
            "canonical_routes_ever_completed": 1,
            "variants_ever_completed": 3,
            "proof_bearing_variants": 1,
            "execution_attempts": 12,
            "snapshot_at": None,
            "tested": 1,
            "untested": 4,
            "in_progress": 0,
            "stale": 0,
            "gone": 1,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 0,
        },
        [
            {"status": "completed", "scanner_telemetry_json": {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}}},
            {"status": "completed", "scanner_telemetry_json": {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}}},
            {"status": "partial", "scanner_telemetry_json": {"per_endpoint_telemetry": False}},
        ],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["coverage_basis"] == "attempt_ledger"
    assert summary["total"] == 5
    assert summary["tested"] == 2
    assert summary["untested"] == 1  # one non-gone endpoint has no attempt
    assert summary["partial"] == 1
    assert summary["coverage"] == 0.5  # completed / non-gone endpoints
    assert summary["status_coverage"]["coverage"] == 0.25
    assert summary["attempt_coverage"] == {
        "total": 4,
        "denominator": 4,
        "denominator_label": "testable",
        "attempted": 3,
        "completed": 2,
        "tested": 2,
        "untested": 1,
        "partial": 1,
        "auth_blocked": 0,
        "rate_limited": 0,
        "error": 0,
        "coverage": 0.5,
        "basis": "latest_attempt_per_endpoint",
    }
    # §11: headline carries one labeled denominator (testable = total - gone).
    assert summary["denominator"] == 4
    contract = summary["metric_contract"]
    assert contract["schema_version"] == "asm_coverage_metrics/v2"
    assert contract["inventory"] == {
        "canonical_routes": 2,
        "route_variants": 4,
        "retired_variants": 1,
    }
    assert contract["examination"]["variants_ever_completed"] == 3
    assert contract["execution"]["attempts"] == 12
    assert contract["proof"]["proof_bearing_variants"] == 1
    assert "method + normalized path + auth state" in contract["definitions"]["route_variant"]


def test_coverage_summary_degrades_unversioned_completed_attempt():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 1,
            "tested": 1,
            "untested": 0,
            "in_progress": 0,
            "stale": 0,
            "gone": 0,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 0,
        },
        [{"status": "completed", "scanner_telemetry_json": {"per_endpoint_telemetry": True}}],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["tested"] == 0
    assert summary["partial"] == 1
    assert summary["coverage"] == 0.0
    assert summary["testable"] == 1
    assert summary["coverage_reconciles"] is True


def test_coverage_summary_treats_completed_without_endpoint_telemetry_as_partial():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 1,
            "tested": 1,
            "untested": 0,
            "in_progress": 0,
            "stale": 0,
            "gone": 0,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 0,
        },
        [
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": False},
            }
        ],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["coverage_basis"] == "attempt_ledger"
    assert summary["tested"] == 0
    assert summary["partial"] == 1
    assert summary["coverage"] == 0.0
    assert summary["attempt_coverage"]["completed"] == 0
    assert summary["attempt_coverage"]["partial"] == 1
    assert summary["status_coverage"]["tested"] == 1


class _CampaignAttemptConn:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return self.rows


def test_campaign_attempt_summary_uses_expected_denominator_and_telemetry_guard():
    campaign_id = uuid.uuid4()
    conn = _CampaignAttemptConn(
        [
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}},
                "attempted_params_count": 3,
                "completed_params_count": 3,
            },
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}},
                "attempted_params_count": 2,
                "completed_params_count": 2,
            },
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": False},
                "attempted_params_count": 1,
                "completed_params_count": 0,
            },
            {
                "status": "auth_missing",
                "scanner_telemetry_json": {"per_endpoint_telemetry": False},
                "attempted_params_count": 1,
                "completed_params_count": 0,
            },
        ]
    )

    summary = asyncio.run(a.campaign_attempt_summary(conn, str(campaign_id), expected_total=6))

    assert summary == {
        "total": 6,
        # §11: single labeled denominator (coverage == tested / denominator).
        "denominator": 6,
        "denominator_label": "assigned_auth_scoped_endpoints",
        "attempted": 4,
        "completed": 2,
        "tested": 2,
        "untested": 2,
        "partial": 1,
        "auth_blocked": 1,
        "rate_limited": 0,
        "error": 0,
        "attempted_params": 7,
        "completed_params": 5,
        "coverage": 0.333,
        "basis": "campaign_attempt_ledger",
        "coverage_denominator": "assigned_auth_scoped_endpoints",
    }
    assert conn.queries[0][1] == (campaign_id, None)


def test_campaign_attempt_summary_can_count_endpoint_family_attempts():
    campaign_id = uuid.uuid4()
    conn = _CampaignAttemptConn(
        [
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}},
                "attempted_params_count": 1,
                "completed_params_count": 1,
            },
            {
                "status": "partial",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}},
                "attempted_params_count": 1,
                "completed_params_count": 0,
            },
        ]
    )

    summary = asyncio.run(
        a.campaign_attempt_summary(
            conn,
            str(campaign_id),
            expected_total=6,
            check_families=["all", "sqli", "xss"],
            family_aware=True,
        )
    )

    assert summary["basis"] == "campaign_family_attempt_ledger"
    assert summary["coverage_denominator"] == "assigned_endpoint_family_attempts"
    assert summary["total"] == 6
    assert summary["attempted"] == 2
    assert summary["completed"] == 1
    assert summary["partial"] == 1
    query, args = conn.queries[0]
    assert "DISTINCT ON (aea.endpoint_id, COALESCE(aea.check_family, 'all'))" in query
    assert args == (campaign_id, ["all", "sqli", "xss"])


# ---- Allocator helpers -----------------------------------------------------

class _AsyncTx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _ClaimConn:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []
        self.fetchrow_calls = []
        self.fetch_calls = []

    def transaction(self):
        return _AsyncTx()

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "UPDATE 0" if "lease_expired" in query else f"UPDATE {len(self.rows)}"

    async def executemany(self, query, args):
        self.executed.append((query, args))
        return None

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        return {"auth_state": "anonymous"} if self.rows else None

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        return self.rows


def test_claim_test_batch_sets_durable_lease_fields():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "GET",
            "path": "/api/orders",
            "param_shape": "id",
            "auth_state": "anonymous",
            "param_location": "query",
            "replay_spec": "GET /api/orders?id=1",
            "content_type": None,
            "campaign_id": None,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    claimed = asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            limit=10,
            stale_days=7,
            lease_owner="worker-a:job",
            lease_ttl_seconds=120,
            campaign_id=str(campaign_id),
        )
    )

    assert claimed[0]["id"] == endpoint_id
    update_query, update_args = conn.executed[-1]
    assert "lease_owner = $2" in update_query
    assert "lease_expires_at = NOW() + ($3 || ' seconds')::interval" in update_query
    assert "attempt_count = COALESCE(attempt_count, 0) + 1" in update_query
    assert update_args[1] == "worker-a:job"
    assert update_args[2] == "120"
    assert update_args[3] == campaign_id


def test_load_leased_test_batch_preserves_admitted_order_and_owner():
    first_id = uuid.uuid4()
    second_id = uuid.uuid4()
    rows = [
        {"id": second_id, "method": "POST", "path": "/b"},
        {"id": first_id, "method": "GET", "path": "/a"},
    ]
    conn = _ClaimConn(rows)

    loaded = asyncio.run(a.load_leased_test_batch(
        conn,
        [first_id, second_id],
        lease_owner="job-v2",
    ))

    assert [item["id"] for item in loaded] == [first_id, second_id]
    query, args = conn.fetch_calls[-1]
    assert "test_status = 'in_progress'" in query
    assert "lease_expires_at > NOW()" in query
    assert args == ([first_id, second_id], "job-v2")


def test_release_leased_test_batch_is_exact_and_owner_bound():
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([{"id": endpoint_id}])

    released = asyncio.run(a.release_leased_test_batch(
        conn,
        [endpoint_id],
        lease_owner="job-v2",
        reason="queue_failed",
    ))

    assert released == 1
    query, args = conn.executed[-1]
    assert "test_status = 'untested'" in query
    assert "lease_owner = $2" in query
    assert args == ([endpoint_id], "job-v2", "queue_failed")


def test_claim_test_batch_can_scope_to_campaign_inventory():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    conn = _ClaimConn([])

    asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_id=str(campaign_id),
            campaign_only=True,
            check_family="sqli",
        )
    )

    first_query, first_args = conn.fetchrow_calls[0]
    assert "NOT EXISTS" in first_query
    assert "COALESCE(aea.check_family, 'all') = $3" in first_query
    assert first_args[1] == campaign_id
    assert first_args[2] == "sqli"
    assert "completed" in first_args[3]
    assert "leased" in first_args[3]
    assert "te.test_status <> 'gone'" in first_query
    assert "te.test_status NOT IN ('gone', 'in_progress')" not in first_query


def test_claim_test_batch_can_scope_to_auth_state():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    conn = _ClaimConn([])

    asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_id=str(campaign_id),
            campaign_only=True,
            check_family="sqli",
            auth_state="user2",
        )
    )

    first_query, first_args = conn.fetchrow_calls[0]
    assert "AND te.auth_state = $5" in first_query
    assert first_args[4] == "user2"


def test_claim_test_batch_uses_bola_read_resource_ordering():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "GET",
            "path": "/workshop/api/shop/orders/all",
            "param_shape": "",
            "auth_state": "user1",
            "param_location": "query",
            "replay_spec": "GET /workshop/api/shop/orders/all",
            "content_type": None,
            "campaign_id": campaign_id,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_id=str(campaign_id),
            campaign_only=True,
            check_family="bola",
            lease_owner="worker-a:job",
        )
    )

    first_query, first_args = conn.fetchrow_calls[0]
    rows_query, rows_args = conn.fetch_calls[0]
    assert "CASE" in first_query
    assert "te.method = 'GET'" in first_query
    assert "te.method IN ('POST', 'PUT', 'PATCH', 'DELETE') THEN -75" in rows_query
    assert "te.priority_score DESC" in rows_query
    assert first_args[2] == "bola"
    assert rows_args[4] == "bola"


def test_claim_test_batch_default_ordering_stays_generic_priority():
    target_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "POST",
            "path": "/api/login",
            "param_shape": "email,password",
            "auth_state": "anonymous",
            "param_location": "json",
            "replay_spec": 'POST /api/login json:{"email":"test@example.com","password":"TestPass123!"}',
            "content_type": "application/json",
            "campaign_id": None,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    asyncio.run(a.claim_test_batch(conn, str(target_id), check_family="sqli"))

    first_query, _first_args = conn.fetchrow_calls[0]
    rows_query, _rows_args = conn.fetch_calls[0]
    assert "CASE" in first_query
    assert "te.path ~*" in rows_query
    assert "THEN -300" in rows_query
    assert "te.priority_score DESC" in rows_query


def test_claim_test_batch_auth_family_keeps_auth_flow_priority():
    target_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "POST",
            "path": "/api/auth/login",
            "param_shape": "email,password",
            "auth_state": "anonymous",
            "param_location": "json",
            "replay_spec": 'POST /api/auth/login json:{"email":"test@example.com","password":"TestPass123!"}',
            "content_type": "application/json",
            "campaign_id": None,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    asyncio.run(a.claim_test_batch(conn, str(target_id), check_family="auth"))

    first_query, _first_args = conn.fetchrow_calls[0]
    rows_query, _rows_args = conn.fetch_calls[0]
    assert "CASE" not in first_query
    assert "ORDER BY te.priority_score DESC, te.last_seen_at DESC" in rows_query


def test_claim_test_batch_writes_campaign_family_lease_attempt():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "POST",
            "path": "/api/login",
            "param_shape": "email,password",
            "auth_state": "anonymous",
            "param_location": "json",
            "replay_spec": 'POST /api/login json:{"email":"test@example.com","password":"TestPass123!"}',
            "content_type": "application/json",
            "campaign_id": campaign_id,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    claimed = asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_id=str(campaign_id),
            campaign_only=True,
            check_family="sqli",
            lease_owner="worker-a:job",
        )
    )

    assert claimed[0]["id"] == endpoint_id
    lease_query, lease_args = conn.executed[-2]
    assert "INSERT INTO asm_endpoint_attempts" in lease_query
    assert "status, attempted_params_count" in lease_query
    assert lease_args[0][0] == endpoint_id
    assert lease_args[0][1] == campaign_id
    assert lease_args[0][2] == "worker-a:job"
    assert lease_args[0][4] == "sqli"


def test_claim_test_batch_can_scope_to_api_endpoint_filter():
    target_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "POST",
            "path": "/api/orders",
            "param_shape": "id",
            "auth_state": "anonymous",
            "param_location": "json",
            "replay_spec": 'POST /api/orders json:{"id":1}',
            "content_type": "application/json",
            "campaign_id": None,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    claimed = asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            endpoint_filter="api",
        )
    )

    assert claimed[0]["id"] == endpoint_id
    first_query, _first_args = conn.fetchrow_calls[0]
    rows_query, _rows_args = conn.fetch_calls[0]
    assert "te.path LIKE '/api/%'" in first_query
    assert "te.method <> 'GET'" in first_query
    assert "te.param_location IN ('json', 'form')" in rows_query


def test_claim_test_batch_campaign_only_without_campaign_fails_closed():
    target_id = uuid.uuid4()
    conn = _ClaimConn([{"id": uuid.uuid4(), "auth_state": "anonymous"}])

    claimed = asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_only=True,
        )
    )

    assert claimed == []
    assert conn.fetchrow_calls == []
    assert conn.fetch_calls == []


class _ClaimableCountConn:
    def __init__(self):
        self.calls = []

    async def fetchval(self, query, *args):
        self.calls.append((query, args))
        return 3


def test_claimable_count_can_scope_to_api_endpoint_filter():
    target_id = uuid.uuid4()
    conn = _ClaimableCountConn()

    count = asyncio.run(a.claimable_count(conn, str(target_id), endpoint_filter="api"))

    assert count == 3
    query, args = conn.calls[0]
    assert "FROM target_endpoints te" in query
    assert "te.path LIKE '/api/%'" in query
    assert args == (target_id, "30")


def test_endpoint_filter_rejects_unknown_values():
    with pytest.raises(ValueError, match="unsupported endpoint_filter"):
        a.normalize_endpoint_filter("everything")


class _RecordAttemptConn:
    def __init__(self, endpoint_id):
        self.endpoint_id = endpoint_id
        self.executemany_calls = []
        self.executed = []

    async def fetch(self, query, *args):
        return [{
            "id": self.endpoint_id,
            "param_shape": "id,sort",
            "auth_state": "user1",
            "campaign_id": None,
        }]

    async def executemany(self, query, records):
        self.executemany_calls.append((query, list(records)))

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "DELETE 1"


def test_record_endpoint_attempts_defaults_completed_param_counts():
    endpoint_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    conn = _RecordAttemptConn(endpoint_id)

    written = asyncio.run(
        a.record_endpoint_attempts(
            conn,
            [endpoint_id],
            scan_id=str(scan_id),
            worker_id="worker-a",
            status="completed",
            scanner_telemetry_json={"per_endpoint_telemetry": True},
        )
    )

    assert written == 1
    query, records = conn.executemany_calls[0]
    assert "INSERT INTO asm_endpoint_attempts" in query
    record = records[0]
    assert record[0] == endpoint_id
    assert record[1] == scan_id
    assert record[5] == "user1"
    assert record[6] == "all"
    assert record[9] == "completed"
    assert record[10] == 2
    assert record[11] == 2


def test_record_endpoint_attempts_allows_conservative_partial_counts():
    endpoint_id = uuid.uuid4()
    conn = _RecordAttemptConn(endpoint_id)

    asyncio.run(
        a.record_endpoint_attempts(
            conn,
            [endpoint_id],
            status="timeout",
            attempted_params_count=0,
            completed_params_count=0,
            error_summary="partial_timeout",
        )
    )

    record = conn.executemany_calls[0][1][0]
    assert record[6] == "all"
    assert record[9] == "timeout"
    assert record[10] == 0
    assert record[11] == 0
    assert record[13] == "partial_timeout"


def test_record_endpoint_attempts_can_replace_existing_for_idempotent_merge():
    endpoint_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    parent_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    conn = _RecordAttemptConn(endpoint_id)

    asyncio.run(
        a.record_endpoint_attempts(
            conn,
            [endpoint_id],
            scan_id=str(scan_id),
            parent_scan_id=str(parent_id),
            campaign_id=str(campaign_id),
            check_family="xss",
            status="completed",
            replace_existing=True,
        )
    )

    assert conn.executed
    query, args = conn.executed[0]
    assert "DELETE FROM asm_endpoint_attempts" in query
    assert "COALESCE(check_family, 'all') = $5" in query
    assert args == ([endpoint_id], scan_id, parent_id, campaign_id, "xss")


class _EndpointIdsConn:
    def __init__(self, target_id, rows):
        self.target_id = target_id
        self.rows = rows
        self.fetch_args = None

    async def fetch(self, query, *args):
        self.fetch_args = args
        return self.rows


def test_endpoint_ids_for_worklist_resolves_existing_inventory_rows_in_input_order():
    target_id = uuid.uuid4()
    first_id = uuid.uuid4()
    second_id = uuid.uuid4()
    first_fp = a.endpoint_fingerprint("GET", "/a", "x", auth_state="user1")
    second_fp = a.endpoint_fingerprint(
        "POST",
        "/b",
        "name",
        param_location="form",
        auth_state="user1",
    )
    conn = _EndpointIdsConn(
        target_id,
        [
            {"id": second_id, "fingerprint": second_fp},
            {"id": first_id, "fingerprint": first_fp},
        ],
    )

    ids = asyncio.run(
        a.endpoint_ids_for_worklist(
            conn,
            str(target_id),
            ["GET /a?x=1", "POST /b form:name=alice"],
            auth_state="user1",
        )
    )

    assert ids == [first_id, second_id]
    assert conn.fetch_args[0] == target_id
    assert conn.fetch_args[1] == [first_fp, second_fp]


# ---- Continuous dispatcher policy (Phase 3/4) -----------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402


def _utc(y=2026, mo=6, d=15, h=12, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc)


def test_merge_asm_config_defaults_and_clamping():
    cfg = a.merge_asm_config(None)
    assert cfg["batch_size"] == a.DEFAULT_ASM_CONFIG["batch_size"]
    # New targets store an empty asm_config, so the default per-root-domain rate
    # cap must be non-zero — otherwise the dispatcher/worker skip the throttle
    # (every gate is `if cap > 0`) and Continuous ASM can hammer a domain.
    assert a.DEFAULT_ASM_CONFIG["max_requests_per_hour_per_domain"] > 0
    assert a.merge_asm_config({})["max_requests_per_hour_per_domain"] > 0
    # clamps out-of-range and ignores junk, keeps valid overrides
    cfg = a.merge_asm_config({"batch_size": 99999, "stale_days": -5, "exploit_depth": 1, "bogus": "x"})
    assert cfg["batch_size"] == 1000          # clamped to max
    assert cfg["stale_days"] == 0             # clamped to min
    assert cfg["exploit_depth"] is True
    assert "bogus" not in cfg


def test_merge_asm_config_window_days():
    cfg = a.merge_asm_config({"window_days": [0, 1, 7, "x", 4]})
    assert cfg["window_days"] == [0, 1, 4]    # dedup, drop invalid (7, "x")
    assert a.merge_asm_config({"window_days": []})["window_days"] is None


def test_within_window():
    # no window config -> always allowed
    assert a.within_window(_utc(h=3), {}) is True
    # 2:00-6:00 window
    win = {"window_start_hour": 2, "window_end_hour": 6}
    assert a.within_window(_utc(h=3), win) is True
    assert a.within_window(_utc(h=7), win) is False
    # wraps midnight 22:00-04:00
    wrap = {"window_start_hour": 22, "window_end_hour": 4}
    assert a.within_window(_utc(h=23), wrap) is True
    assert a.within_window(_utc(h=2), wrap) is True
    assert a.within_window(_utc(h=12), wrap) is False
    # 2026-06-15 is a Monday (weekday 0); restrict to Tue/Wed
    assert a.within_window(_utc(), {"window_days": [1, 2]}) is False
    assert a.within_window(_utc(), {"window_days": [0]}) is True


def test_decide_action_handles_mixed_datetime_awareness():
    # Regression: the dispatcher passes a NAIVE now (utc_now()) but last_test_at
    # comes from a TIMESTAMPTZ column (tz-aware). Subtracting the two must not
    # raise "can't subtract offset-naive and offset-aware".
    naive_now = datetime(2026, 6, 16, 13, 0)  # naive
    aware_recent = datetime(2026, 6, 16, 12, 55, tzinfo=timezone.utc)  # aware, 5 min ago
    d = a.decide_asm_action(
        now=naive_now, last_test_at=aware_recent, last_recon_at=None,
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 0, "min_interval_minutes": 60},
    )
    assert d["action"] == "none"  # within min interval (5 < 60), no crash
    # naive now + aware OLD last_test_at -> test fires
    aware_old = datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc)  # 3h ago
    d2 = a.decide_asm_action(
        now=naive_now, last_test_at=aware_old, last_recon_at=None,
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 0, "min_interval_minutes": 60},
    )
    assert d2["action"] == "test"


def test_decide_action_recon_when_due():
    d = a.decide_asm_action(
        now=_utc(), last_test_at=None, last_recon_at=None,
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 168},
    )
    assert d["action"] == "recon"
    assert d["blocked_by"] is None
    assert d["claimable"] == 100
    assert d["daily_cap_remaining"] is not None


def test_decide_action_test_when_recon_not_due():
    d = a.decide_asm_action(
        now=_utc(), last_test_at=None,
        last_recon_at=_utc() - timedelta(hours=1),  # recent recon
        has_active_scan=False, claimable=100, tested_today=0,
        domain_rate_remaining=15,
        config={"recon_interval_hours": 168},
    )
    assert d["action"] == "test"
    assert d["rate_cap_remaining"] == 15


def test_decide_action_skips():
    base = dict(now=_utc(), last_test_at=None, last_recon_at=_utc(),
                has_active_scan=False, claimable=100, tested_today=0,
                config={"recon_interval_hours": 0})  # recon off -> consider test
    # active scan blocks everything
    active = a.decide_asm_action(**{**base, "has_active_scan": True})
    assert active["action"] == "none"
    assert active["blocked_by"] == "active_scan"
    # nothing claimable
    no_work = a.decide_asm_action(**{**base, "claimable": 0})
    assert no_work["action"] == "none"
    assert no_work["blocked_by"] == "no_claimable_endpoints"
    # within min interval
    interval = a.decide_asm_action(**{**base, "last_test_at": _utc() - timedelta(minutes=5),
                                      "config": {"recon_interval_hours": 0, "min_interval_minutes": 60}})
    assert interval["action"] == "none"
    assert interval["blocked_by"] == "min_interval"
    assert interval["next_eligible_at"]
    # daily cap reached
    daily = a.decide_asm_action(**{**base, "tested_today": 5000,
                                   "config": {"recon_interval_hours": 0, "daily_endpoint_cap": 2000}})
    assert daily["action"] == "none"
    assert daily["blocked_by"] == "daily_endpoint_cap"
    assert daily["daily_cap_remaining"] == 0
    # per-domain rate limit
    rate = a.decide_asm_action(**{**base, "domain_rate_exceeded": True, "domain_rate_remaining": 0})
    assert rate["action"] == "none"
    assert rate["blocked_by"] == "domain_rate_cap"
    assert rate["rate_cap_remaining"] == 0
    # outside time window
    window = a.decide_asm_action(**{**base, "config": {"recon_interval_hours": 0,
                                      "window_start_hour": 2, "window_end_hour": 6}})
    assert window["action"] == "none"
    assert window["blocked_by"] == "outside_window"
    assert window["next_eligible_at"]


# §7.5: GC of long-retired ('gone') endpoint rows -----------------------------
def test_gc_endpoint_inventory_purges_and_is_bounded():
    import asyncio as _aio

    class _GcConn:
        def __init__(self):
            self.calls = []
        async def fetchval(self, query, *args):
            self.calls.append((query, args))
            return 7  # simulate 7 stale-gone rows deleted

    conn = _GcConn()
    n = _aio.run(a.gc_endpoint_inventory(conn, _TID, gone_retention_days=30))
    assert n == 7
    q, args = conn.calls[-1]
    assert "DELETE FROM target_endpoints" in q
    assert "test_status = 'gone'" in q
    assert args[1] == 30  # retention days passed through

    # retention <= 0 disables GC (no DB call)
    conn2 = _GcConn()
    assert _aio.run(a.gc_endpoint_inventory(conn2, _TID, gone_retention_days=0)) == 0
    assert conn2.calls == []


def test_probe_auth_curl_config_builds_header_and_cookie_lines():
    cfg = a._probe_auth_curl_config({
        "auth_header": "Bearer secret-token-xyz",
        "auth_cookies": "session=abc123",
        "auth_headers_json": '{"X-API-Key": "key-987"}',
    })
    assert 'header = "Authorization: Bearer secret-token-xyz"' in cfg
    assert 'cookie = "session=abc123"' in cfg
    assert 'header = "X-API-Key: key-987"' in cfg


def test_probe_path_status_keeps_auth_off_argv(monkeypatch):
    """The reachability probe must not expose auth secrets on the curl argv."""
    captured = {}

    class _FakeProc:
        returncode = 0

        def kill(self):
            pass

        async def communicate(self, input=None):
            captured["stdin"] = input
            return (b"200 12", b"")

    async def fake_exec(*cmd, stdin=None, stdout=None, stderr=None):
        captured["cmd"] = list(cmd)
        return _FakeProc()

    monkeypatch.setattr(a.asyncio, "create_subprocess_exec", fake_exec)

    auth_config = a._probe_auth_curl_config({"auth_header": "Bearer secret-token-xyz"})
    code, size = asyncio.run(a._probe_path_status("https://app.test", "/api/orders", auth_config, timeout=5))

    assert code == "200"
    # The secret is passed via `-K -` on stdin, never on argv.
    assert "secret-token-xyz" not in " ".join(captured["cmd"])
    assert "-K" in captured["cmd"] and "-" in captured["cmd"]
    assert b"secret-token-xyz" in (captured["stdin"] or b"")
