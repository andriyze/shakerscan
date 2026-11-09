"""A Scan's archive accounts for tunnelled capability traffic, read back from PostgreSQL.

The Scan runs as ``_execute_reserved_deterministic_scan`` runs it (the real backend, executor and
orchestrator over the installed schema, with the fixture dispatcher of
``test_scan_local_revocation_postgres``), and stops at its time limit, so one verifier settles
``timed_out`` without sending anything. The worker's capture then holds what the run's tunnels
and in-process calls recorded (fixture records, identified as such: no target is contacted) and
is archived with the real ``archive_scan_capture``. The real reader must then:

* not name the tunnelled template capability as unarchived (its tunnel row is in the archive);
* not name the verifier the time limit stopped before it started (zero consumed);
* name every destination and every destination the tunnel refused, from one read.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace

from runtime.http_archive import archive_scan_capture
from runtime.http_archive_reader import archive_fidelity, read_archive_stats
from scan.action_plan import ScanActionPlan
from scanner_tools import http_archive_capture as capture

from tests.test_scan_local_revocation_postgres import (  # noqa: F401  (template_database is a fixture)
    FixtureToolDispatcher,
    _action,
    _scan,
    scan_database,
    template_database,
)
from tests.test_scan_time_limit_postgres import _deadline_in, _run


def _plan(scan_id):
    first = _action("baseline.http", 0, "http.request")
    templates = _action("templates.active", 1, "templates.scan", (first.action_id,))
    stopped = _action("verify.nosqli", 2, "nosqli.verify_batch", (templates.action_id,))
    # The report sends nothing: it reserves no requests (the fixture default reserves one).
    final = replace(_action("finalize.report", 3, "scan.finalize",
                            (first.action_id, templates.action_id, stopped.action_id)),
                    requested_budget={"tool_wall_seconds": 30}, action_digest=None)
    return ScanActionPlan(scan_id=str(scan_id), execution_plan_digest="b" * 64,
                          target_binding_digest="a" * 64, actions=(first, templates, stopped, final))


def _fixture_capture():
    """What the run's recorders wrote (fixture records): one in-process call and one cleartext
    tunnel with two request lines and a refused destination."""
    capture.start_capture()
    capture.record_scan_call(
        {"method": "GET", "url": "http://revocation.test/", "status_code": 200,
         "fidelity": "wire_request"},
        capability_name="http.request",
    )
    capture.record_tunnel({
        "scheme": "http", "host": "revocation.test", "port": 80,
        "address_connections": {"192.0.2.10": 1}, "connections_attempted": 2,
        "connections_opened": 1, "connections_rejected": 0, "bytes_to_target": 180,
        "bytes_from_target": 900, "http_requests_observed": 2, "content_readable": True,
        "methods_observed": {"GET": 2},
        "request_lines": [
            {"method": "GET", "target": "/.git/config", "host": "revocation.test"},
            {"method": "GET", "target": "/admin", "host": "revocation.test"},
        ],
        "request_lines_dropped": 0,
        "refused_destinations": [{"destination": "oob.example.net:80", "attempts": 1}],
        "refused_destinations_other": 0,
    }, capability_name="templates.scan", tool="nuclei")
    return capture.drain_capture()


def test_tunnelled_and_stopped_capabilities_are_accounted_for_from_the_database(template_database, tmp_path):  # noqa: F811
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool, plan=_plan)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"templates.active"}))
            await _run(scan, dispatcher, _deadline_in(1.0))
            actions = await scan.actions()
            assert actions["verify.nosqli"][0] == "timed_out"  # stopped before it started
            async with pool.acquire() as conn:
                await archive_scan_capture(conn, _fixture_capture(), scan_id=str(scan.scan_id),
                                           target_id=scan.target_id, results_dir=tmp_path)
                stats = await read_archive_stats(conn, scan_id=str(scan.scan_id), hunt_run_id=None)
            assert stats["attempted"] == stats["stored"] == 4
            assert stats["unarchived_http_capabilities"] == []
            assert stats["tunnel_records"] == 1 and stats["opaque_tunnels"] == 0
            assert stats["destinations"] == [{"origin": "http://revocation.test", "calls": 4}]
            assert stats["refused_destinations"] == [
                {"destination": "oob.example.net:80", "attempts": 1},
            ]
            fidelity, detail = archive_fidelity(stats, total=4)
            # Request lines carry no response: partial, and nothing is named as unarchived.
            assert fidelity == "partial"
            assert "2 calls have adapter-limited wire detail" in detail
            assert "no archived calls" not in detail and "not archived" not in detail

    asyncio.run(run())


def test_without_its_tunnel_row_the_template_capability_is_named(template_database, tmp_path):  # noqa: F811
    """The same run archived before this change: the gap is still reported, not hidden."""
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool, plan=_plan)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"templates.active"}))
            await _run(scan, dispatcher, _deadline_in(1.0))
            captured = _fixture_capture()
            captured["calls"] = [call for call in captured["calls"]
                                 if call["capability_name"] == "http.request"]
            async with pool.acquire() as conn:
                await archive_scan_capture(conn, captured, scan_id=str(scan.scan_id),
                                           target_id=scan.target_id, results_dir=tmp_path)
                stats = await read_archive_stats(conn, scan_id=str(scan.scan_id), hunt_run_id=None)
            assert stats["unarchived_external_tool_capabilities"] == ["templates.scan"]
            assert stats["unarchived_engine_capabilities"] == []  # the stopped verifier is not one
            assert stats["refused_destinations"] == []

    asyncio.run(run())


def _encrypted_capture_with_wire_log():
    """An HTTPS verifier's tunnel (encrypted: the engine reads no request) with the requests its
    own wire log recorded, as the worker attaches them (fixture records): two sign-in POSTs and
    one request the log names on another host, which is never archived."""
    capture.start_capture()
    capture.record_tunnel({
        "scheme": "https", "host": "revocation.test", "port": 443,
        "address_connections": {"192.0.2.10": 1}, "connections_attempted": 1,
        "connections_opened": 1, "connections_rejected": 0, "bytes_to_target": 4000,
        "bytes_from_target": 9000, "http_requests_observed": 0, "content_readable": False,
        "methods_observed": {}, "request_lines": [], "request_lines_dropped": 0,
        "refused_destinations": [], "refused_destinations_other": 0,
        "wire_log_transactions": [
            {"method": "POST", "url": "https://revocation.test/hub/login",
             "request_headers": {"content-type": "application/x-www-form-urlencoded"},
             "request_body": f"username=admin%27--&password={secret}", "status_code": 200,
             "response_headers": {"content-type": "text/html"}, "response_body": "<p>bad</p>"}
            for secret in ("Fixture-Secret-1", "Fixture-Secret-2")
        ] + [{"method": "GET", "url": "https://other.test/", "request_headers": {},
              "request_body": None, "status_code": 200, "response_headers": {}, "response_body": None}],
    }, capability_name="templates.scan", tool="sqlmap",
        tool_input={"url": "https://revocation.test/hub/login", "method": "POST",
                    "body_field_names": ["password", "username"]})
    return capture.drain_capture()


def test_an_encrypted_tunnels_wire_log_is_archived_and_masked_on_export(template_database, tmp_path):  # noqa: F811
    """Over HTTPS the sign-in POSTs a verifier sent were only a CONNECT row. Its own wire log now
    puts each one in the archive (method, URL, status, headers, body), the tunnel no longer
    counts as opaque, and a masked export withholds the password values."""
    from runtime.http_archive_reader import project, read_transactions

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool, plan=_plan)
            async with pool.acquire() as conn:
                await archive_scan_capture(conn, _encrypted_capture_with_wire_log(),
                                           scan_id=str(scan.scan_id), target_id=scan.target_id,
                                           results_dir=tmp_path)
                stats = await read_archive_stats(conn, scan_id=str(scan.scan_id), hunt_run_id=None)
                rows = await read_transactions(conn, scan_id=str(scan.scan_id), hunt_run_id=None,
                                               payloads=True, results_dir=tmp_path)
            assert stats["opaque_tunnels"] == 0 and stats["capture_limited"] == 0
            logins = [row for row in rows if row["method"] == "POST"]
            assert len(logins) == 2 and {row["url"] for row in logins} == {"https://revocation.test/hub/login"}
            assert all(row["status_code"] == 200 for row in logins)
            assert not any("other.test" in str(row["url"]) for row in rows)
            shown = json.dumps([project(row, redaction="redacted") for row in logins], default=str)
            assert "Fixture-Secret-1" not in shown and "Fixture-Secret-2" not in shown
            assert "/hub/login" in shown

    asyncio.run(run())
