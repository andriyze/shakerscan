"""Which settled Hunt steps a finish proposes for reuse, fed through the real input redaction.

Every input below goes through ``_hunt_redacted_capability_input`` with the API's own payload
redaction wired in, exactly as the action ledger stores it, so the retention filter is tested
against what it really reads. Every value is a synthetic fixture, never a real secret.
"""
import asyncio
import json
from uuid import uuid4

import pytest

import api.api  # noqa: F401 - wires the API's payload redaction into the Hunt router
from hunt import interaction_router
from hunt.saved_actions import (
    RETAINED_STEP_FIELDS, merge_retained_steps, recipe_steps, retain_hunt_action, retained_step,
)

HOST = "app.test"


def ledger(name, values, status="completed"):
    """One hunt_actions row as admission records it: the redacted planner input."""
    return {"id": uuid4(), "capability_name": name, "status": status,
            "input_summary": {"schema_version": "hunt-capability-input-summary/v1",
                              "input": interaction_router._hunt_redacted_capability_input(name, values)}}


REUSABLE = [
    ("http.request", {"method": "GET", "path": "/health", "origin": "https://app.test:8443"}),
    ("http.request", {"method": "HEAD", "path": "/static/app.css"}),
    ("web.crawl", {"origin": "https://app.test"}),
    ("web.content_discover", {"origin": "https://app.test", "wordlist": "common"}),
    ("web.probe", {}),
    ("javascript.analyze", {"path": "/static/app.js"}),
    ("browser.navigate", {"origin": "https://app.test", "path": "/dashboard", "wait_until": "load"}),
    ("xss.verify", {"path": "/search", "severity": "medium"}),
    ("tls.inspect", {"origin": "https://app.test"}),
    ("http.request", {"method": "GET", "path": "/api/v1/users/42"}),
    ("http.request", {"method": "GET", "path": "/docs/getting-started"}),
    ("device.http.probe", {"method": "GET", "path": "/cgi-bin/status.cgi", "origin_port": 80}),
    # One letter/digit alternation is a route word; camelCase route words stay.
    ("http.request", {"method": "GET", "path": "/shop/Category12"}),
    ("http.request", {"method": "GET", "path": "/api/userProfile"}),
    ("http.request", {"method": "GET", "path": "/api/Reports/Monthly"}),
    ("http.request", {"method": "GET", "path": "/status/online"}),
]

# GETs that act: each names an action, so none is proposed for reuse.
ACTING_HTTP_PATHS = (
    "/admin/users/5/ban", "/api/cache/purge", "/api/cache/flush", "/admin/queue/clear", "/api/jobs/5/stop",
    "/api/orders/42/refund", "/coupon/redeem", "/reward/claim", "/posts/9/like", "/db/migrate",
    "/pr/5/merge", "/mail/resend", "/cart/empty",
)
ACTING_DEVICE_PATHS = (
    "/relay/on", "/relay/off", "/door/open", "/alarm/disarm", "/disk/format", "/camera/ptz/move", "/wol/wake",
)
# Capability tokens made of letters only: mixed case and long, or base64url-shaped.
LETTER_TOKEN_PATHS = ("/share/AbCdEfGhIjKlMnOp", "/p/ZXhhbXBsZQ", "/s/QWxhZGRpbjpvcGVu")

NOT_REUSABLE = [
    *(("http.request", {"method": "GET", "path": path}) for path in ACTING_HTTP_PATHS + LETTER_TOKEN_PATHS),
    *(("device.http.probe", {"method": "GET", "path": path, "origin_port": 80}) for path in ACTING_DEVICE_PATHS),
    # Exactly two letter/digit alternations: a code, not a route word.
    ("http.request", {"method": "GET", "path": "/x/abc123def"}),
    # Query values: the ledger keeps the names and masks the values as %3Credacted%3E.
    ("http.request", {"method": "GET", "path": "/api/items?id=5&sort=asc", "origin": "https://app.test"}),
    ("sqli.verify", {"path": "/product?id=1"}),
    ("browser.navigate", {"origin": "https://app.test", "path": "/search?q=hunter2"}),
    ("http.request", {"method": "GET", "path": "/items", "query": {"reset": "9f8e7d6c5b4a39281706f5e4d3c2b1a0"}}),
    # Request headers and bodies, kept verbatim or reduced to a shape by the ledger.
    ("http.request", {"method": "GET", "path": "/debug", "headers": {"X-Debug-Auth": "letmein-2026"}}),
    ("http.request", {"method": "POST", "path": "/login", "form_body": {"user": "a", "pin": "4821"}}),
    ("http.request", {"method": "POST", "path": "/api/items", "json_body": {"name": "x"}}),
    ("http.request", {"method": "DELETE", "path": "/api/items/1"}),
    # A token in the path that the ledger does not recognise as one.
    ("http.request", {"method": "GET", "path": "/reset/7c1f9a2b3c4d5e6f7a8b9c0d1e2f3a4b"}),
    ("http.request", {"method": "GET", "path": "/invite/Zx9Qp2Lm7Rt4Wv8Yb3Nc"}),
    ("http.request", {"method": "GET", "path": "/logout"}),
    # Browser input values, sessions, credentials and capture state.
    ("browser.interact", {"path": "/login", "steps": [{"action": "fill", "selector": "#pin", "value": "4821"}]}),
    ("browser.workflow", {"path": "/settings", "steps": [{"action": "fill", "selector": "#name", "value": "x"}]}),
    ("browser.navigate", {"path": "/account", "session_ref": str(uuid4())}),
    ("http.request", {"method": "GET", "path": "/account", "session_ref": str(uuid4())}),
    ("web.crawl", {"origin": "https://app.test", "as_principal": "primary"}),
    ("http.request", {"method": "GET", "path": "/me", "as_principal": "primary"}),
    ("http.request", {"method": "GET", "path": "/", "capture": [{"name": "csrf", "from": "body"}]}),
    ("browser.login_check", {"origin": "https://app.test", "profile_ref": str(uuid4())}),
    ("artifact.inspect", {"path": "/backup.sql", "search_terms": ["password"]}),
    # A GET that acts: device controls and web state changes the crawler's words do not name.
    ("device.http.probe", {"method": "GET", "path": "/goform/reboot", "origin_port": 80}),
    ("device.http.probe", {"method": "GET", "path": "/api/system/restart", "origin_port": 80}),
    ("device.http.probe", {"method": "GET", "path": "/shutdown", "origin_port": 80}),
    ("device.http.probe", {"method": "GET", "path": "/cgi-bin/firmware_upgrade.cgi", "origin_port": 80}),
    ("device.http.probe", {"method": "GET", "path": "/apply.cgi", "origin_port": 80}),
    ("http.request", {"method": "GET", "path": "/admin/reboot"}),
    ("http.request", {"method": "GET", "path": "/api/cart/checkout"}),
    ("http.request", {"method": "GET", "path": "/api/transfer"}),
    # Attack payloads: quotes, command substitution, dot segments.
    ("http.request", {"method": "GET", "path": "/api/users/1'OR'1'='1"}),
    ("http.request", {"method": "GET", "path": "/$(id)"}),
    ("http.request", {"method": "GET", "path": "/index.php/../../../../etc/passwd"}),
    ("javascript.analyze", {"path": "/static/./app.js"}),
    # Short tokens and credential segments the ledger keeps.
    ("http.request", {"method": "GET", "path": "/verify-email/MTIzNDU2Nzg5MA"}),
    ("http.request", {"method": "GET", "path": "/activate/3f2a9c1b"}),
    ("http.request", {"method": "GET", "path": "/r/ab12CD34ef56GH78"}),
    ("http.request", {"method": "GET", "path": "/u/4821/pin/4821"}),
    ("http.request", {"method": "GET", "path": "/p/7Hq2xK9m"}),
    ("http.request", {"method": "GET", "path": "/s/abcdefghIJKL.mnopqrstUVWX.yzabcdEFGH"}),  # signed-token shape
    # Any origin other than the Hunt target's own host, such as a granted destination.
    ("http.request", {"method": "GET", "path": "/health", "origin": "https://other.test"}),
    ("web.crawl", {"origin": "https://api.app.test"}),
    # Control-plane, recipe and shell steps.
    ("findings.create", {"title": "x"}),
    ("targets.actions.create", {"name": "x"}),
    ("ssh.exec", {"command": "id"}),
]


def test_reusable_steps_survive_the_real_ledger_redaction_unchanged():
    for name, values in REUSABLE:
        row = ledger(name, values)
        step = retained_step(name, row["input_summary"]["input"], HOST)
        assert step == {"capability": name, "input": values}, (name, values, row["input_summary"])


@pytest.mark.parametrize("name,values", NOT_REUSABLE)
def test_steps_carrying_values_sessions_or_other_origins_are_never_proposed(name, values):
    row = ledger(name, values)
    assert retained_step(name, row["input_summary"]["input"], HOST) is None, row["input_summary"]
    assert recipe_steps([row], HOST) == ([], [])


def test_nothing_secret_or_off_host_reaches_a_proposed_recipe():
    rows = [ledger(name, values) for name, values in REUSABLE + NOT_REUSABLE]
    steps, evidence = recipe_steps(rows, HOST)
    text = json.dumps(steps)
    for value in ("redacted", "letmein", "4821", "9f8e7d6c", "7c1f9a2b", "Zx9Qp2Lm", "other.test",
                  "api.app.test", "hunter2", "session_ref", "as_principal", "headers", "?", "reboot",
                  "restart", "shutdown", "firmware", "apply", "checkout", "transfer", "'", "$(", "..",
                  "MTIzNDU2", "3f2a9c1b", "ab12CD34", "pin", "7Hq2xK9m", "abc123def", "AbCdEf", "ZXhhbX",
                  "QWxhZGRp", *(f'"{path}"' for path in ACTING_HTTP_PATHS + ACTING_DEVICE_PATHS)):
        assert value not in text, value
    assert len(steps) == len(REUSABLE) and len(evidence) == len(REUSABLE)


def test_a_retained_proposal_describes_its_steps_for_review_not_as_read_only():
    from hunt import saved_actions
    text = saved_actions.RETAINED_INSTRUCTIONS.lower()
    assert "read-only" not in text and "review" in text
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for note in ("docs/hunt-recording-and-budgets.md", "docs/hunt-operator-workflows.md", "docs/releases/2.11.1.md",
                 "skills/hunt/SKILL.md", "api/hunt/saved_actions.py"):
        prose = " ".join((root / note).read_text(encoding="utf-8").split()).lower()
        for claim in ("read-only and verification steps", "never proposed as a read", "another read of the target"):
            assert claim not in prose, (note, claim)


def test_a_failed_or_partial_action_is_not_a_step():
    for status in ("failed", "partial", "blocked", "running"):
        assert recipe_steps([ledger("web.crawl", {"origin": "https://app.test"}, status=status)], HOST) == ([], [])


def test_the_allowlist_names_only_fields_that_carry_no_values_or_credentials():
    forbidden = {"headers", "query", "json_body", "form_body", "capture", "request_bindings", "session_ref",
                 "primary_session_ref", "secondary_session_ref", "as_principal", "principal_binding_digest",
                 "profile_ref", "steps", "search_terms", "via_address", "body", "selector", "value"}
    for name, fields in RETAINED_STEP_FIELDS.items():
        assert not fields & forbidden, name


@pytest.mark.parametrize("summary", ["null", "{broken", [], {"input": []}, {"input": "x"}])
def test_a_malformed_historical_summary_does_not_lose_other_reusable_steps(summary):
    bad = {**ledger("web.crawl", {"origin": "https://app.test"}), "input_summary": summary}
    good = ledger("javascript.analyze", {"path": "/static/app.js"})
    steps, evidence = recipe_steps([bad, good], HOST)
    assert len(steps) == 1 and evidence == [str(good["id"])]


def test_identical_steps_are_proposed_once():
    rows = [ledger("web.crawl", {"origin": "https://app.test"}) for _ in range(3)]
    steps, evidence = recipe_steps(rows, HOST)
    assert len(steps) == 1 and evidence == [str(rows[0]["id"])]


def test_a_device_locator_is_the_host_a_step_must_stay_on():
    row = ledger("http.request", {"method": "GET", "path": "/status", "origin": "http://[2001:db8::5]:8080"})
    assert recipe_steps([row], "2001:db8::5")[0]
    assert recipe_steps([row], "2001:db8::6") == ([], [])
    probe = ledger("device.http.probe", {"method": "GET", "path": "/status", "origin_port": 8080})
    assert recipe_steps([probe], "2001:db8::5")[0]


def test_the_rolling_proposal_keeps_one_copy_of_each_step_and_the_newest_when_full():
    def step(index):
        return {"capability": "javascript.analyze", "input": {"path": f"/static/{index}.js"}}
    previous = [{**step(index), "description": ""} for index in range(3)]  # as a stored recipe holds them
    merged = merge_retained_steps(previous, [step(2), step(3), step(0)], saved=[{**step(1), "description": ""}],
                                  limit=16)
    assert merged == [step(0), step(2), step(3)]
    merged = merge_retained_steps([step(index) for index in range(16)], [step(16), step(17)], saved=[], limit=16)
    assert merged == [step(index) for index in range(2, 18)]


def test_metadata_opt_out_prevents_any_retention(monkeypatch):
    from targets import hunt_authority

    async def authority(*args, lock=False):
        assert lock is False, "finish holds the target row already; retention never takes a row lock"
        return {"id": uuid4(), "url": "host://app.test", "is_active": True,
                "metadata_json": {"hunt_authority": {"target_url": "host://app.test",
                                  "metadata_changes": False, "instruction_changes": True}}}
    monkeypatch.setattr(hunt_authority, "authority_row", authority)
    result = asyncio.run(retain_hunt_action(object(), {"id": uuid4(), "target_id": uuid4()}))
    assert result == {"status": "skipped", "reason": "target_metadata_changes_disabled"}


def test_finish_retention_never_writes_a_saved_action_directly():
    import ast
    from pathlib import Path
    source = Path(__file__).resolve().parents[1] / "api/hunt/saved_actions.py"
    calls = {getattr(node.func, "id", None) or getattr(node.func, "attr", None)
             for node in ast.walk(ast.parse(source.read_text())) if isinstance(node, ast.Call)}
    assert "write_target_action" not in calls and "create_action_proposal" not in calls
    assert "refresh_retained_proposal" in calls


class SqliteConn:
    """Unit fixture: runs the production SQL text on SQLite (``$n`` becomes ``?n``), so a test
    exercises the query's own filter and order rather than a hand-written stand-in."""

    def __init__(self, schema):
        import sqlite3
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(schema)

    def _run(self, query, args):
        import re
        from uuid import UUID
        return self.db.execute(re.sub(r"\$(\d+)", r"?\1", query),
                               [str(value) if isinstance(value, UUID) else value for value in args])

    async def fetch(self, query, *args):
        return [dict(row) for row in self._run(query, args).fetchall()]

    async def fetchval(self, query, *args):
        row = self._run(query, args).fetchone()
        return None if row is None else row[0]


def _retention_fixture(monkeypatch, conn, captured):
    from targets import hunt_authority, instruction_proposals

    async def authority(*args, lock=False):
        return {"id": uuid4(), "url": "https://app.test", "is_active": True, "metadata_json": {}}

    async def refresh(conn, target_id, *, steps, evidence_refs, **kwargs):
        captured.update(steps=steps, evidence=evidence_refs)
        return {"status": "proposed", "proposal_id": "proposal-1", "step_count": len(steps)}
    monkeypatch.setattr(hunt_authority, "authority_row", authority)
    monkeypatch.setattr(instruction_proposals, "refresh_retained_proposal", refresh)


def test_finish_proposes_the_newest_completed_steps_and_returns_the_proposal_outcome(monkeypatch):
    """A long Hunt has more completed actions than one finish reads: it reads the newest, in the
    order they ran, so the rolling proposal's newest steps are the Hunt's newest steps."""
    from hunt.saved_actions import _LIMIT_ACTIONS
    conn = SqliteConn("""CREATE TABLE hunt_actions (id TEXT, hunt_run_id TEXT, capability_name TEXT,
        status TEXT, input_summary TEXT, completed_at INTEGER)""")
    hunt = uuid4()
    total = _LIMIT_ACTIONS + 100
    for index in range(total):
        row = ledger("http.request", {"method": "GET", "path": f"/items/{index}"})
        conn.db.execute("INSERT INTO hunt_actions VALUES (?,?,?,?,?,?)", (str(row["id"]), str(hunt),
                        "http.request", "completed", json.dumps(row["input_summary"]), index))
    captured = {}
    _retention_fixture(monkeypatch, conn, captured)
    run = {"id": hunt, "target_id": uuid4(), "context_pack": {"target": {"url": "https://app.test"}}}
    result = asyncio.run(retain_hunt_action(conn, run))
    assert result == {"status": "proposed", "proposal_id": "proposal-1", "step_count": _LIMIT_ACTIONS}
    paths = [step["input"]["path"] for step in captured["steps"]]
    assert paths == [f"/items/{index}" for index in range(total - _LIMIT_ACTIONS, total)]
    assert len(captured["evidence"]) == _LIMIT_ACTIONS


def test_the_retained_proposal_is_not_counted_against_the_planner_pending_quota():
    """19 planner proposals and the rolling retained one are pending: the planner's 20th files."""
    from fastapi import HTTPException
    from targets.instruction_proposals import MAX_PENDING_PER_TARGET, RETAINED_PROPOSER, _check_pending_quota
    conn = SqliteConn("""CREATE TABLE target_instruction_proposals (target_id TEXT, status TEXT, kind TEXT,
        proposed_by TEXT)""")
    target, planner = uuid4(), f"hunt:{uuid4()}"
    rows = [(str(target), "pending", "saved_action", planner)] * (MAX_PENDING_PER_TARGET - 1)
    rows.append((str(target), "pending", "saved_action", RETAINED_PROPOSER))
    conn.db.executemany("INSERT INTO target_instruction_proposals VALUES (?,?,?,?)", rows)
    asyncio.run(_check_pending_quota(conn, target, planner, "saved_action"))  # the 20th files
    conn.db.execute("INSERT INTO target_instruction_proposals VALUES (?,?,?,?)",
                    (str(target), "pending", "saved_action", planner))
    with pytest.raises(HTTPException) as full:
        asyncio.run(_check_pending_quota(conn, target, planner, "saved_action"))
    assert full.value.status_code == 429
