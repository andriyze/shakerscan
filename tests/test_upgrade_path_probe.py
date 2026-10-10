"""The upgrade-path gate's judgement: which releases to upgrade from, what the sweep calls, and when
it fails. The HTTP tests run the probe against an in-process fake API (a unit fixture, not a
ShakerScan stack); scripts/upgrade_path_smoke.sh runs it against a real upgraded install."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "upgrade_path_probe.py"
spec = importlib.util.spec_from_file_location("upgrade_path_probe", SCRIPT)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
sys.modules["upgrade_path_probe"] = probe
spec.loader.exec_module(probe)

STATE = {
    "apex": "upgrade-path.test", "apex_url": "http://app.upgrade-path.test:8000",
    "fixture_target_id": "11111111-1111-4111-8111-111111111111",
    "apex_target_id": "22222222-2222-4222-8222-222222222222",
    "seed_target_id": "33333333-3333-4333-8333-333333333333",
    "apex_receipt_id": "receipt-1", "scan_id": "44444444-4444-4444-8444-444444444444",
    "scan_status": "completed", "finding_id": "f1", "device_id": "d1", "schedule_id": "s1",
    "discovery_id": "disc-1", "hunt_id": "h1", "totals": {"targets": 3, "scans": 1, "findings": 1},
}


def openapi(extra_gets: int = 120) -> dict:
    paths = {
        "/targets": {"get": {}, "post": {}},
        "/targets/{target_id}": {"get": {}, "patch": {}},
        "/targets/{target_id}/authorization": {"get": {}},
        "/scans/{scan_id}": {"get": {}},
        "/findings/{finding_id}": {"get": {}},
        "/compare": {"get": {"parameters": [
            {"name": "baseline_scan_id", "in": "query", "required": True},
            {"name": "other", "in": "query", "required": True},
            {"name": "optional", "in": "query", "required": False},
        ]}},
    }
    for index in range(extra_gets):
        paths[f"/area{index}/{{target_id}}/{{scan_id}}"] = {"get": {}}
    return {"paths": paths}


# ---------------------------------------------------------------------------------------------
# Baselines


def test_baselines_are_stable_plus_the_newest_published_patch_below_the_candidate():
    published = ["v2.7.1", "v2.8.0", "v2.8.1", "v2.8.2", "v2.9.0-rc.1", "junk"]
    assert probe.select_baselines("2.8.1", published, "2.8.3") == ["2.8.1", "2.8.2"]


def test_a_candidate_directly_above_stable_upgrades_from_stable_only():
    assert probe.select_baselines("2.8.1", ["2.8.1"], "2.8.2") == ["2.8.1"]
    # A published tag of the candidate itself (a rebuild) is never its own baseline.
    assert probe.select_baselines("2.8.1", ["2.8.1", "2.8.2"], "2.8.2") == ["2.8.1"]


def test_baselines_refuse_a_stable_channel_that_is_not_older_than_the_candidate():
    with pytest.raises(ValueError):
        probe.select_baselines("2.8.2", [], "2.8.2")
    with pytest.raises(ValueError):
        probe.select_baselines("latest", [], "2.8.2")


# ---------------------------------------------------------------------------------------------
# Probes


def test_every_get_is_called_with_an_unknown_id_and_seeded_routes_again_with_the_seed():
    probes = probe.build_probes(openapi(0), STATE)
    by_path = {(p.template, p.seeded): p.path for p in probes}
    assert by_path[("/targets/{target_id}", False)] == f"/targets/{probe.UNKNOWN_ID}"
    assert by_path[("/targets/{target_id}", True)] == f"/targets/{STATE['apex_target_id']}"
    assert by_path[("/scans/{scan_id}", True)] == f"/scans/{STATE['scan_id']}"
    assert ("/targets", True) not in by_path  # nothing to seed in a collection route
    assert {p.template for p in probes} == set(openapi(0)["paths"])


def test_required_query_parameters_are_filled_and_optional_ones_left_out():
    path = next(p.path for p in probe.build_probes(openapi(0), STATE) if p.template == "/compare")
    assert f"baseline_scan_id={STATE['scan_id']}" in path
    assert f"other={probe.UNKNOWN_ID}" in path
    assert "optional" not in path


def test_skipped_templates_are_not_called():
    probes = probe.build_probes(openapi(0), STATE, skip=["/compare"])
    assert all(p.template != "/compare" for p in probes)


# ---------------------------------------------------------------------------------------------
# Sweep judgement


def outcomes_for(doc: dict, status: int = 200) -> list:
    return [probe.Outcome("GET", p.template, p.path, p.seeded, status, 0.01)
            for p in probe.build_probes(doc, STATE)]


def test_a_clean_sweep_passes():
    doc = openapi()
    assert probe.judge_sweep(doc, outcomes_for(doc), skipped=[]) == []


@pytest.mark.parametrize("status", [500, 502, 503, 0])
def test_any_5xx_or_missing_response_fails_and_names_the_route(status):
    doc = openapi()
    outcomes = outcomes_for(doc)
    outcomes[3] = probe.Outcome("GET", outcomes[3].template, outcomes[3].path, False, status, 0.1,
                                "UndefinedColumnError: requested_by")
    problems = probe.judge_sweep(doc, outcomes, skipped=[])
    assert len(problems) == 1
    assert outcomes[3].path in problems[0] and "UndefinedColumnError" in problems[0]


def test_a_thin_document_or_an_unreached_sweep_cannot_pass():
    small = openapi(extra_gets=5)
    assert any("only" in p and "GET operations" in p for p in probe.judge_sweep(small, outcomes_for(small), skipped=[]))
    doc = openapi()
    half = outcomes_for(doc)[: len(doc["paths"]) // 2]
    assert any("reached" in p for p in probe.judge_sweep(doc, half, skipped=[]))
    # Skipping cannot be used to empty the sweep: coverage is of the document, minus a skip list.
    assert any("seeded record" in p for p in probe.judge_sweep(doc, outcomes_for(doc, 404), skipped=[]))


def test_public_contract_routes_missing_from_the_running_api_fail():
    doc = openapi()
    problems = probe.judge_sweep(doc, outcomes_for(doc), skipped=[], required_templates=["/discovery"])
    assert problems == ["public GET operations missing from the running API: /discovery"]


def test_identity_requires_the_candidate_version_revision_and_a_uniform_fleet():
    health = {"status": "healthy", "scanner_version": "2.8.2", "source_revision": "a" * 40,
              "worker_build": {"fleet_uniform": True, "scanner_version": "2.8.2"}}
    assert probe.identity_problems(health, "2.8.2", "a" * 40) == []
    assert probe.identity_problems(health, "2.8.3")
    assert probe.identity_problems(health, "2.8.2", "b" * 40)
    stale = dict(health, worker_build={"fleet_uniform": False, "scanner_version": "2.8.1"})
    assert probe.identity_problems(stale, "2.8.2")


# ---------------------------------------------------------------------------------------------
# Against a fake API


class FakeApi(BaseHTTPRequestHandler):
    discovery_status = 200
    standing = True
    missing_scan = False

    def log_message(self, *args):
        return

    def _send(self, status: int, body) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/openapi.json":
            return self._send(200, openapi())
        if path == "/health":
            return self._send(200, {"status": "healthy", "scanner_version": "2.8.2",
                                    "worker_build": {"fleet_uniform": True, "scanner_version": "2.8.2"}})
        if path in ("/targets", "/scans", "/findings"):
            return self._send(200, {"total": 5})
        if path.startswith("/scans/"):
            if FakeApi.missing_scan and path == f"/scans/{STATE['scan_id']}":
                return self._send(404, {"detail": "not found"})
            return self._send(200, {"status": "completed"})
        if path.endswith("/authorization"):
            return self._send(200, {"authorization": {"standing": FakeApi.standing,
                                                      "approval_receipt_id": "receipt-1"}})
        if path == f"/targets/{STATE['apex_target_id']}":
            return self._send(200, {"name": "upgrade-path apex (upgraded)"})
        if probe.UNKNOWN_ID in path:
            return self._send(404, {"detail": "not found"})
        return self._send(200, {})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        path = self.path.split("?")[0]
        if path == "/discovery":
            if FakeApi.discovery_status >= 500:
                return self._send(500, {"detail": 'column "requested_by" of relation "discovery_runs" does not exist'})
            return self._send(200, {"discovery_id": "disc-2"})
        if path == "/scans":
            return self._send(200, {"scan_id": "scan-2"})
        if path.endswith("/authorization"):
            FakeApi.standing = True
        return self._send(200, {})

    def do_PATCH(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        return self._send(200, {})

    def do_DELETE(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        FakeApi.standing = False
        return self._send(200, {})


@pytest.fixture
def fake_api(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    FakeApi.discovery_status, FakeApi.standing = 200, True
    state = tmp_path / "state.json"
    state.write_text(json.dumps(STATE), encoding="utf-8")
    yield f"http://127.0.0.1:{server.server_address[1]}", state, tmp_path / "report.json"
    server.shutdown()


def test_check_passes_on_a_healthy_upgraded_api(fake_api):
    base, state, report = fake_api
    code = probe.main(["check", "--api", base, "--state", str(state), "--report", str(report),
                       "--expect-version", "2.8.2"])
    result = json.loads(report.read_text(encoding="utf-8"))
    assert code == 0, result["failures"]
    assert result["result"] == "pass"
    assert result["checks"]["POST /discovery for the person-added apex"] == "pass"


def test_check_fails_when_discovery_admission_hits_a_missing_column(fake_api):
    """The 2.8.1 -> 2.8.2 defect: the column existed only on fresh databases."""
    base, state, report = fake_api
    FakeApi.discovery_status = 500
    code = probe.main(["check", "--api", base, "--state", str(state), "--report", str(report),
                       "--expect-version", "2.8.2"])
    result = json.loads(report.read_text(encoding="utf-8"))
    assert code == 1
    failure = next(f for f in result["failures"] if f.startswith("POST /discovery"))
    assert "-> 500" in failure and "requested_by" in failure


def test_check_fails_on_the_wrong_version(fake_api):
    base, state, report = fake_api
    assert probe.main(["check", "--api", base, "--state", str(state), "--report", str(report),
                       "--expect-version", "2.8.3"]) == 1
    assert json.loads(report.read_text(encoding="utf-8"))["checks"]["candidate identity"] == "fail"


def test_a_seeded_read_that_worked_before_the_upgrade_must_still_work():
    baseline = {"/targets/{target_id}": 200, "/scans/{scan_id}": 200, "/gone/{scan_id}": 200, "/x/{scan_id}": 404}
    upgraded = {"/targets/{target_id}": 200, "/scans/{scan_id}": 404, "/x/{scan_id}": 404}
    assert probe.seeded_regressions(baseline, upgraded) == [
        "GET /scans/{scan_id}: 200 before the upgrade, 404 after"]


def test_a_rewritten_field_is_a_change():
    assert probe.snapshot_changes({"url": "http://a", "name": "n"}, {"url": "http://a", "name": None}) == [
        "name: 'n' -> None"]
    assert probe.snapshot_changes({"url": "http://a"}, {"url": "http://a", "extra": 1}) == []


def test_a_previous_release_that_made_no_hunt_record_fails_the_check(fake_api):
    base, state, report = fake_api
    state.write_text(json.dumps(dict(STATE, hunt_id=None, hunt_seed="refused 422")), encoding="utf-8")
    assert probe.main(["check", "--api", base, "--state", str(state), "--report", str(report),
                       "--expect-version", "2.8.2"]) == 1
    assert json.loads(report.read_text(encoding="utf-8"))["checks"]["seeded Hunt record"] == "fail"


def test_lost_seeded_reads_fail_against_the_baseline_sweep(fake_api, tmp_path):
    base, state, report = fake_api
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"sweep": {"seeded_statuses": {"/targets/{target_id}": 200}}}), encoding="utf-8")
    assert probe.main(["check", "--api", base, "--state", str(state), "--report", str(report),
                       "--expect-version", "2.8.2", "--baseline-sweep", str(baseline)]) == 0
    baseline.write_text(json.dumps({"sweep": {"seeded_statuses": {"/compare": 200, "/scans/{scan_id}": 200}}}),
                        encoding="utf-8")
    FakeApi.missing_scan = True
    try:
        code = probe.main(["check", "--api", base, "--state", str(state), "--report", str(report),
                           "--expect-version", "2.8.2", "--baseline-sweep", str(baseline)])
    finally:
        FakeApi.missing_scan = False
    assert code == 1
    assert json.loads(report.read_text(encoding="utf-8"))["checks"]["seeded GETs still read their records"] == "fail"
