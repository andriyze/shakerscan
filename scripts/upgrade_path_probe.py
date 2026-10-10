#!/usr/bin/env python3
"""Seed an installed release through its public API, then prove the upgraded stack still serves it.

`scripts/upgrade_path_smoke.sh` drives this helper around a real installer upgrade:

    baselines  which published releases to upgrade from (the stable channel, plus the newest
               published release between stable and the candidate when it differs)
    seed       on the previous release: person-added targets with standing authorization, a
               completed passive Scan of a local fixture, a manual finding, a device, a schedule,
               a discovery run and a Hunt record, all through the public API (never SQL)
    sweep      every GET operation in the running API's OpenAPI document, path parameters filled
               with the seeded identifiers and, separately, with an unknown identifier; any 5xx or
               a hang fails
    check      after the upgrade: build identity, every seeded record still readable, targeted
               writes (POST /discovery for a person-added apex, a new Scan run to completion,
               target update, authorization revoke and re-create, a finding, a schedule update,
               a Hunt cancel), and the sweep

Every subcommand that judges writes a JSON report and exits 1 on a failure, naming the route and an
excerpt of the response body. Nothing here prints request or response secrets: the seeded data is
synthetic and the stack runs without credentials.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "shakerscan-upgrade-path/v1"
BODY_EXCERPT = 400
# A Hunt or a target folder identifier is not always a UUID, but every route below answers an
# unknown one with 4xx; this value can never collide with a seeded record.
UNKNOWN_ID = "00000000-0000-4000-8000-00000000dead"
# The sweep must reach this share of the running API's GET operations, so a document that lost
# most of its routes, or a sweep that silently skipped them, cannot pass.
MIN_COVERAGE = 0.95
MIN_GET_OPERATIONS = 100
MIN_SEEDED_PROBES = 20
TERMINAL_SCAN_STATES = {"completed", "partial", "failed", "error", "cancelled", "stopped"}
PASSING_SCAN_STATES = {"completed", "partial"}
SCAN_CEILING_SECONDS = 600

# Fields read back before and after the upgrade: a migration that nulls or rewrites them fails.
# Responses nest records differently by route, so each field lists its flat and nested spellings.
SNAPSHOTS = {
    "fixture target": ("fixture_target_id", "/targets/{}", ("url", "name", "cohort")),
    "apex target": ("apex_target_id", "/targets/{}", ("url", "name", "cohort")),
    "discovery seed target": ("seed_target_id", "/targets/{}", ("url", "name", "cohort")),
    "scan": ("scan_id", "/scans/{}", ("status", "target_url", "target_id", "scan_type")),
    "finding": ("finding_id", "/findings/{}", ("title", "severity", "target_id")),
    "device": ("device_id", "/devices/{}", ("primary_locator", "name", "environment")),
    "schedule": ("schedule_id", "/schedules/{}", ("frequency", "day_of_week", "time_of_day", "target_id")),
    "discovery run": ("discovery_id", "/discovery/{}", ("root_domain",)),
    "hunt": ("hunt_id", "/hunts/{}", ("target_id", "objective", "target_kind")),
}
SNAPSHOT_WRAPPERS = ("", "target.", "scan.", "finding.", "device.", "schedule.", "hunt.", "run.")

# Path parameter name -> seeded state key. Parameters not listed (or not seeded) get UNKNOWN_ID.
SEEDED_PARAMETERS = {
    "target_id": "apex_target_id",
    "scan_id": "scan_id",
    "finding_id": "finding_id",
    "device_id": "device_id",
    "schedule_id": "schedule_id",
    "discovery_id": "discovery_id",
    "hunt_id": "hunt_id",
    "run_id": "hunt_id",
}
SEEDED_QUERY = {
    "target_id": "apex_target_id",
    "scan_id": "scan_id",
    "baseline_scan_id": "scan_id",
    "target_kind": "web",
}


@dataclass
class Response:
    status: int
    body: str
    elapsed: float
    error: str = ""

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None


@dataclass
class Probe:
    method: str
    template: str
    path: str
    seeded: bool


@dataclass
class Outcome:
    method: str
    template: str
    path: str
    seeded: bool
    status: int
    seconds: float
    excerpt: str = ""


@dataclass
class Report:
    phase: str
    failures: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def check(self, name: str, ok: bool, problem: str = "") -> bool:
        self.checks[name] = "pass" if ok else "fail"
        if not ok:
            self.failures.append(f"{name}: {problem}" if problem else name)
        return ok


# ---------------------------------------------------------------------------------------------
# Pure logic


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", text.strip())
    return tuple(int(part) for part in match.groups()) if match else None  # type: ignore[return-value]


def select_baselines(stable: str, published: Iterable[str], candidate: str) -> list[str]:
    """The releases a candidate must upgrade from: stable, plus the newest published patch above it.

    Only final releases (X.Y.Z) older than the candidate count; a candidate that is itself
    published (a rebuild of a tag) is not its own baseline.
    """
    stable_v, candidate_v = parse_version(stable), parse_version(candidate)
    if stable_v is None:
        raise ValueError(f"stable version is not X.Y.Z: {stable!r}")
    if candidate_v is not None and stable_v >= candidate_v:
        raise ValueError(f"stable {stable} is not older than the candidate {candidate}")
    newer = sorted(
        {v for v in (parse_version(item) for item in published) if v is not None
         and v > stable_v and (candidate_v is None or v < candidate_v)}
    )
    baselines = [".".join(map(str, stable_v))]
    if newer:
        baselines.append(".".join(map(str, newer[-1])))
    return baselines


def is_server_error(status: int) -> bool:
    """5xx, or no HTTP response at all (status 0: refused, reset or timed out)."""
    return status == 0 or status >= 500


def excerpt(text: str, limit: int = BODY_EXCERPT) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[:limit] + "..."


def get_operations(openapi: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return sorted(
        (path, operation)
        for path, operations in (openapi.get("paths") or {}).items()
        for method, operation in (operations or {}).items()
        if method.lower() == "get"
    )


def _query_string(operation: dict[str, Any], state: dict[str, Any]) -> str:
    query = {}
    for parameter in operation.get("parameters") or []:
        if parameter.get("in") != "query" or not parameter.get("required"):
            continue
        name = parameter.get("name", "")
        key = SEEDED_QUERY.get(name)
        value = state.get(key) if key in state else key
        query[name] = value if value else UNKNOWN_ID
    return ("?" + urllib.parse.urlencode(query)) if query else ""


def build_probes(openapi: dict[str, Any], state: dict[str, Any],
                 skip: Iterable[str] = ()) -> list[Probe]:
    """One probe per GET operation with unknown identifiers, plus one with seeded identifiers for
    every operation whose path parameters are all seeded (that is where stored rows are read)."""
    skipped = set(skip)
    probes: list[Probe] = []
    for template, operation in get_operations(openapi):
        if template in skipped:
            continue
        names = re.findall(r"{(\w+)}", template)
        query = _query_string(operation, state)
        unknown = re.sub(r"{\w+}", UNKNOWN_ID, template)
        probes.append(Probe("GET", template, unknown + query, seeded=False))
        if names and all(state.get(SEEDED_PARAMETERS.get(name, "")) for name in names):
            path = template
            for name in names:
                path = path.replace("{" + name + "}", urllib.parse.quote(str(state[SEEDED_PARAMETERS[name]]), safe=""))
            probes.append(Probe("GET", template, path + query, seeded=True))
    return probes


def judge_sweep(openapi: dict[str, Any], outcomes: list[Outcome], *, skipped: Iterable[str],
                required_templates: Iterable[str] = ()) -> list[str]:
    """Failures for a sweep: a 5xx or no response, and coverage too thin to mean anything."""
    problems = [
        f"GET {o.path} -> {o.status or 'no response'} {o.excerpt}".rstrip()
        for o in outcomes if is_server_error(o.status)
    ]
    operations = {template for template, _ in get_operations(openapi)}
    skipped = set(skipped) & operations
    reached = {o.template for o in outcomes if o.status}
    if len(operations) < MIN_GET_OPERATIONS:
        problems.append(f"the OpenAPI document lists only {len(operations)} GET operations "
                        f"(at least {MIN_GET_OPERATIONS} expected)")
    sweepable = operations - skipped
    if sweepable and len(reached & sweepable) / len(sweepable) < MIN_COVERAGE:
        problems.append(f"the sweep reached {len(reached & sweepable)} of {len(sweepable)} GET operations")
    seeded_ok = sum(1 for o in outcomes if o.seeded and 200 <= o.status < 300)
    if seeded_ok < MIN_SEEDED_PROBES:
        problems.append(f"only {seeded_ok} GET operations returned a seeded record "
                        f"(at least {MIN_SEEDED_PROBES} expected)")
    missing = sorted(set(required_templates) - operations)
    if missing:
        problems.append("public GET operations missing from the running API: " + ", ".join(missing[:20]))
    return problems


def identity_problems(health: dict[str, Any], version: str, sha: str = "") -> list[str]:
    problems = []
    if health.get("status") != "healthy":
        problems.append(f"health status is {health.get('status')!r}")
    if health.get("scanner_version") != version:
        problems.append(f"API reports {health.get('scanner_version')!r}, expected {version!r}")
    if sha and health.get("source_revision") != sha:
        problems.append(f"API source revision {health.get('source_revision')!r}, expected {sha!r}")
    worker = health.get("worker_build") or {}
    if worker.get("fleet_uniform") is not True or worker.get("scanner_version") not in (None, version):
        problems.append(f"worker fleet is not uniformly {version}: {excerpt(json.dumps(worker), 200)}")
    return problems


def public_get_templates(manifest: dict[str, Any]) -> list[str]:
    """GET paths of the candidate's committed public API contract (docs/generated)."""
    return sorted(key.split(" ", 1)[1] for key in manifest.get("operations", {}) if key.startswith("GET "))


def first(data: Any, *paths: str) -> Any:
    """The first present value among dotted paths (responses nest ids differently by route)."""
    for dotted in paths:
        value = data
        for part in dotted.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (None, ""):
            return value
    return None


# ---------------------------------------------------------------------------------------------
# HTTP


class Api:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def call(self, method: str, path: str, body: Any = None, timeout: float | None = None) -> Response:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base + path, method=method, data=data,
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                raw = response.read(1 << 20)
                return Response(response.status, raw.decode("utf-8", "replace"), time.monotonic() - started)
        except urllib.error.HTTPError as exc:
            raw = exc.read(1 << 16) if exc.fp else b""
            return Response(exc.code, raw.decode("utf-8", "replace"), time.monotonic() - started)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            return Response(0, "", time.monotonic() - started, error=f"{type(exc).__name__}: {exc}")

    def ok(self, method: str, path: str, body: Any = None, *, what: str) -> Any:
        response = self.call(method, path, body)
        if not 200 <= response.status < 300:
            raise ProbeError(f"{what}: {method} {path} -> {response.status or response.error} "
                             f"{excerpt(response.body)}")
        return response.json()


class ProbeError(RuntimeError):
    pass


def wait_for_scan(api: Api, scan_id: str, deadline_seconds: int) -> str:
    deadline = time.monotonic() + deadline_seconds
    status = "unknown"
    while time.monotonic() < deadline:
        response = api.call("GET", f"/scans/{scan_id}")
        if response.status == 200:
            status = str((response.json() or {}).get("status") or "unknown")
            if status in TERMINAL_SCAN_STATES:
                return status
        elif is_server_error(response.status):
            raise ProbeError(f"GET /scans/{scan_id} -> {response.status or response.error} {excerpt(response.body)}")
        time.sleep(5)
    return f"timeout ({status})"


def start_scan(api: Api, url: str, name: str) -> str:
    created = api.ok("POST", "/scans", {
        "target": url, "name": name, "budget_profile": "fast", "policy": {"active_testing": False},
        # The fixture is one static page; the ceiling only bounds a stuck run.
        "advanced": {"max_duration_seconds": SCAN_CEILING_SECONDS},
    }, what="start a passive Scan")
    scan_id = first(created, "scan_id", "id")
    if not scan_id:
        raise ProbeError(f"POST /scans returned no scan id: {excerpt(json.dumps(created))}")
    return str(scan_id)


# ---------------------------------------------------------------------------------------------
# Subcommands


def seed(api: Api, fixture: str, apex: str, seed_apex: str, scan_deadline: int) -> dict[str, Any]:
    """Data an operator of the previous release would have. Every id the checks need is returned."""
    host = f"app.{apex}"
    state: dict[str, Any] = {"apex": apex, "seed_apex": seed_apex, "fixture": fixture,
                             "apex_url": f"http://{host}:8000"}
    fixture_target = api.ok("POST", "/targets", {
        "url": f"http://{fixture}:8000", "name": "upgrade-path fixture", "cohort": "lab",
        "authorized_by": "upgrade-path-smoke",
    }, what="create the fixture target with standing authorization")
    state["fixture_target_id"] = first(fixture_target, "id", "target.id")
    apex_target = api.ok("POST", "/targets", {
        "url": state["apex_url"], "name": "upgrade-path apex", "cohort": "lab",
    }, what="create a person-added target under the discovery apex")
    state["apex_target_id"] = first(apex_target, "id", "target.id")
    authorization = api.ok("POST", f"/targets/{state['apex_target_id']}/authorization", {
        "approved_by": "upgrade-path-smoke", "environment": "lab",
    }, what="authorize the apex target")
    state["apex_receipt_id"] = first(authorization, "authorization.approval_receipt_id")
    seed_target = api.ok("POST", "/targets", {
        "url": f"http://www.{seed_apex}", "name": "upgrade-path discovery seed", "cohort": "lab",
    }, what="create a person-added target for the seeded discovery run")
    state["seed_target_id"] = first(seed_target, "id", "target.id")
    discovery = api.ok("POST", "/discovery?" + urllib.parse.urlencode({"root_domain": seed_apex}),
                       what="request discovery on the previous release")
    state["discovery_id"] = first(discovery, "discovery_id", "id")
    finding = api.ok("POST", "/findings/manual", {
        "target": state["apex_url"], "title": "upgrade-path seeded finding", "severity": "low",
        "description": "Seeded before the upgrade.", "url": state["apex_url"] + "/seeded",
    }, what="create a manual finding")
    state["finding_id"] = first(finding, "id", "finding_id", "finding.id")
    device = api.ok("POST", "/devices", {
        "name": "upgrade-path device", "primary_locator": "192.0.2.10", "environment": "lab",
    }, what="create a device")
    state["device_id"] = first(device, "device.id", "id")
    schedule = api.ok("POST", "/schedules", {
        "target_id": state["apex_target_id"], "name": "upgrade-path weekly", "frequency": "weekly",
        "day_of_week": 6, "time_of_day": "03:00",
    }, what="create a schedule")
    state["schedule_id"] = first(schedule, "id", "schedule_id", "schedule.id")
    hunt = api.call("POST", "/hunts", {
        "target_id": state["apex_target_id"], "target_kind": "web",
        "goal": "upgrade-path seeded Hunt record", "budget_profile": "fast", "policy": {},
    })
    # A Hunt needs no model to exist as a record; a release that refuses one is reported, not seeded.
    state["hunt_id"] = first(hunt.json(), "hunt_id", "id") if 200 <= hunt.status < 300 else None
    state["hunt_seed"] = "created" if state["hunt_id"] else f"refused {hunt.status} {excerpt(hunt.body, 200)}"
    state["scan_id"] = start_scan(api, state["apex_url"], "upgrade-path baseline")
    state["scan_status"] = wait_for_scan(api, state["scan_id"], scan_deadline)
    if state["scan_status"] not in PASSING_SCAN_STATES:
        raise ProbeError(f"the baseline Scan {state['scan_id']} ended {state['scan_status']}")
    missing = [key for key in ("fixture_target_id", "apex_target_id", "apex_receipt_id", "seed_target_id",
                               "discovery_id", "finding_id", "device_id", "schedule_id", "scan_id")
               if not state.get(key)]
    if missing:
        raise ProbeError("seed responses carried no id for: " + ", ".join(missing))
    state["totals"] = totals(api)
    state["snapshots"] = {}
    for name in SNAPSHOTS:
        if not state.get(SNAPSHOTS[name][0]):
            continue
        fields = snapshot(api, state, name)
        if not fields:
            raise ProbeError(f"the seeded {name} has none of the fields the check compares")
        state["snapshots"][name] = fields
    return state


def snapshot(api: Api, state: dict[str, Any], name: str) -> dict[str, Any]:
    """The comparable fields of one seeded record, keyed by the field name."""
    key, template, fields = SNAPSHOTS[name]
    body = api.ok("GET", template.format(state[key]), what=f"read the seeded {name}")
    values = {}
    for field_name in fields:
        value = first(body, *(wrapper + field_name for wrapper in SNAPSHOT_WRAPPERS))
        if value is not None:
            values[field_name] = value
    return values


def snapshot_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return [f"{field_name}: {value!r} -> {after.get(field_name)!r}"
            for field_name, value in sorted(before.items()) if after.get(field_name) != value]


def seeded_regressions(baseline: dict[str, int], upgraded: dict[str, int]) -> list[str]:
    """Seeded GETs that read a record on the previous release and no longer do."""
    return [f"GET {template}: {baseline[template]} before the upgrade, {upgraded[template]} after"
            for template in sorted(baseline)
            if 200 <= baseline[template] < 300 and template in upgraded
            and not 200 <= upgraded[template] < 300]


def totals(api: Api) -> dict[str, int]:
    counts = {}
    for collection in ("targets", "scans", "findings"):
        body = api.ok("GET", f"/{collection}?limit=1", what=f"count {collection}")
        total = first(body, "total")
        if not isinstance(total, int) or total < 1:
            raise ProbeError(f"GET /{collection}?limit=1 reports total {total!r} after rows were seeded")
        counts[collection] = total
    return counts


def sweep(api: Api, openapi: dict[str, Any], state: dict[str, Any], skip: Iterable[str],
          timeout: float) -> list[Outcome]:
    outcomes = []
    for probe in build_probes(openapi, state, skip):
        response = api.call(probe.method, probe.path, timeout=timeout)
        outcomes.append(Outcome(
            probe.method, probe.template, probe.path, probe.seeded, response.status,
            round(response.elapsed, 3),
            excerpt(response.body or response.error) if is_server_error(response.status) else "",
        ))
    return outcomes


def check_preserved(api: Api, state: dict[str, Any], report: Report) -> None:
    reads = {
        "fixture target": f"/targets/{state['fixture_target_id']}",
        "apex target": f"/targets/{state['apex_target_id']}",
        "discovery seed target": f"/targets/{state['seed_target_id']}",
        "scan": f"/scans/{state['scan_id']}",
        "finding": f"/findings/{state['finding_id']}",
        "device": f"/devices/{state['device_id']}",
        "schedule": f"/schedules/{state['schedule_id']}",
        "discovery run": f"/discovery/{state['discovery_id']}",
    }
    report.check("seeded Hunt record", bool(state.get("hunt_id")),
                 f"the previous release did not create one: {state.get('hunt_seed')}")
    if state.get("hunt_id"):
        reads["hunt"] = f"/hunts/{state['hunt_id']}"
    for name, path in reads.items():
        response = api.call("GET", path)
        if not report.check(f"preserved {name}", response.status == 200,
                            f"GET {path} -> {response.status or response.error} {excerpt(response.body)}"):
            continue
        before = state.get("snapshots", {}).get(name)
        if before is not None:
            try:
                changes = snapshot_changes(before, snapshot(api, state, name))
            except ProbeError as exc:
                changes = [str(exc)]
            report.check(f"unchanged {name}", not changes, "; ".join(changes))
    scan = api.call("GET", f"/scans/{state['scan_id']}").json() or {}
    report.check("preserved scan status", scan.get("status") == state["scan_status"],
                 f"{state['scan_status']} -> {scan.get('status')}")
    for key in ("fixture_target_id", "apex_target_id"):
        auth = api.call("GET", f"/targets/{state[key]}/authorization")
        standing = first(auth.json(), "authorization.standing")
        report.check(f"preserved standing authorization ({key})", auth.status == 200 and standing is True,
                     f"-> {auth.status} {excerpt(auth.body, 200)}")
    auth = api.call("GET", f"/targets/{state['apex_target_id']}/authorization").json()
    report.check("preserved authorization receipt",
                 first(auth, "authorization.approval_receipt_id") == state["apex_receipt_id"],
                 "the apex target's approval receipt changed")
    try:
        after = totals(api)
    except ProbeError as exc:
        report.check("preserved totals", False, str(exc))
    else:
        shrunk = {k: (v, after.get(k)) for k, v in state["totals"].items() if after.get(k, -1) < v}
        report.check("preserved totals", not shrunk, f"counts shrank: {shrunk}")


def targeted_writes(api: Api, state: dict[str, Any], report: Report, scan_deadline: int) -> None:
    def write(name: str, method: str, path: str, body: Any = None) -> Any:
        response = api.call(method, path, body)
        report.details.setdefault("writes", []).append(
            {"check": name, "method": method, "path": path.split("?")[0], "status": response.status})
        ok = 200 <= response.status < 300
        report.check(name, ok, f"{method} {path} -> {response.status or response.error} {excerpt(response.body)}")
        return response.json() if ok else None

    apex, target = state["apex"], state["apex_target_id"]
    discovery = write("POST /discovery for the person-added apex", "POST",
                      "/discovery?" + urllib.parse.urlencode({"root_domain": apex}))
    if discovery is not None:
        found = api.call("GET", f"/discovery/{first(discovery, 'discovery_id', 'id')}")
        report.check("new discovery run readable", found.status == 200,
                     f"-> {found.status} {excerpt(found.body)}")
    write("PATCH /targets/{id}", "PATCH", f"/targets/{target}", {"name": "upgrade-path apex (upgraded)"})
    renamed = first(api.call("GET", f"/targets/{target}").json(), "name", "target.name")
    report.check("target update visible", renamed == "upgrade-path apex (upgraded)", f"name is {renamed!r}")
    write("DELETE /targets/{id}/authorization", "DELETE", f"/targets/{target}/authorization",
          {"revoked_by": "upgrade-path-smoke", "reason": "upgrade-path revoke check"})
    revoked = first(api.call("GET", f"/targets/{target}/authorization").json(), "authorization.standing")
    report.check("authorization revoke visible", revoked is not True, f"standing is {revoked!r}")
    write("POST /targets/{id}/authorization", "POST", f"/targets/{target}/authorization",
          {"approved_by": "upgrade-path-smoke", "environment": "lab"})
    write("POST /findings/manual", "POST", "/findings/manual", {
        "target": state["apex_url"], "title": "upgrade-path post-upgrade finding", "severity": "info",
        "url": state["apex_url"] + "/upgraded"})
    write("PATCH /schedules/{id}", "PATCH", f"/schedules/{state['schedule_id']}", {"is_active": False})
    if state.get("hunt_id"):
        write("POST /hunts/{id}/cancel", "POST", f"/hunts/{state['hunt_id']}/cancel", {})
    # Every create the seed made, again on the upgraded schema: a column added only on the
    # fresh-database path breaks the insert, not the read.
    new_apex = "upgrade-path-new.test"
    created = write("POST /targets", "POST", "/targets", {
        "url": f"http://www.{new_apex}", "name": "upgrade-path created after the upgrade", "cohort": "lab"})
    new_target = first(created, "id", "target.id")
    if new_target:
        write("POST /targets/{id}/authorization (new target)", "POST", f"/targets/{new_target}/authorization",
              {"approved_by": "upgrade-path-smoke", "environment": "lab"})
        write("POST /schedules", "POST", "/schedules", {
            "target_id": new_target, "name": "upgrade-path daily", "frequency": "daily", "time_of_day": "04:00"})
        write("POST /discovery for a target added after the upgrade", "POST",
              "/discovery?" + urllib.parse.urlencode({"root_domain": new_apex}))
    write("POST /devices", "POST", "/devices", {
        "name": "upgrade-path device (upgraded)", "primary_locator": "192.0.2.11", "environment": "lab"})
    hunt = write("POST /hunts", "POST", "/hunts", {
        "target_id": target, "target_kind": "web", "goal": "upgrade-path Hunt after the upgrade",
        "budget_profile": "fast", "policy": {}})
    hunt_id = first(hunt, "hunt_id", "id")
    if hunt_id:
        write("GET /hunts/{id} (new)", "GET", f"/hunts/{hunt_id}")
        write("POST /hunts/{id}/cancel (new)", "POST", f"/hunts/{hunt_id}/cancel", {})
    try:
        scan_id = start_scan(api, state["apex_url"], "upgrade-path upgraded")
        status = wait_for_scan(api, scan_id, scan_deadline)
    except ProbeError as exc:
        report.check("new Scan completes after the upgrade", False, str(exc))
    else:
        report.details["upgraded_scan"] = {"id": scan_id, "status": status}
        report.check("new Scan completes after the upgrade", status in PASSING_SCAN_STATES,
                     f"Scan {scan_id} ended {status}")


def run_sweep(api: Api, report: Report, state: dict[str, Any], args: argparse.Namespace) -> None:
    response = api.call("GET", "/openapi.json")
    openapi = response.json() if response.status == 200 else None
    if not isinstance(openapi, dict):
        report.check("OpenAPI document", False, f"GET /openapi.json -> {response.status} {excerpt(response.body)}")
        return
    required = []
    if args.public_manifest:
        required = public_get_templates(json.loads(Path(args.public_manifest).read_text(encoding="utf-8")))
    outcomes = sweep(api, openapi, state, args.skip, args.request_timeout)
    problems = judge_sweep(openapi, outcomes, skipped=args.skip, required_templates=required)
    report.details["sweep"] = {
        "get_operations": len(get_operations(openapi)),
        "requests": len(outcomes),
        "seeded_requests": sum(1 for o in outcomes if o.seeded),
        "skipped": sorted(args.skip),
        "status_counts": _status_counts(outcomes),
        "server_errors": [asdict(o) for o in outcomes if is_server_error(o.status)],
        "seeded_statuses": {o.template: o.status for o in outcomes if o.seeded},
        "slowest": [asdict(o) for o in sorted(outcomes, key=lambda o: -o.seconds)[:5]],
    }
    report.check("GET sweep", not problems, "; ".join(problems[:40]))
    if args.command == "check" and args.baseline_sweep:
        try:
            baseline = json.loads(Path(args.baseline_sweep).read_text(encoding="utf-8"))["sweep"]["seeded_statuses"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            report.check("seeded GETs still read their records", False, f"no baseline sweep to compare: {exc}")
        else:
            lost = seeded_regressions(baseline, report.details["sweep"]["seeded_statuses"])
            report.check("seeded GETs still read their records", not lost, "; ".join(lost[:40]))


def _status_counts(outcomes: list[Outcome]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[str(outcome.status)] = counts.get(str(outcome.status), 0) + 1
    return dict(sorted(counts.items()))


def write_report(path: str, report: Report, **extra: Any) -> None:
    payload = {"schema": SCHEMA, "phase": report.phase, "result": "fail" if report.failures else "pass",
               "failures": report.failures, "checks": report.checks, **extra, **report.details}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    baselines = sub.add_parser("baselines")
    baselines.add_argument("--stable", required=True)
    baselines.add_argument("--candidate", required=True)
    baselines.add_argument("--published", default="", help="whitespace-separated published versions or tags")

    for name in ("seed", "sweep", "check"):
        command = sub.add_parser(name)
        command.add_argument("--api", required=True)
        command.add_argument("--state", required=True)
        command.add_argument("--report", required=name != "seed")
        command.add_argument("--scan-deadline", type=int, default=600)
        command.add_argument("--request-timeout", type=float, default=30.0)
        command.add_argument("--skip", action="append", default=[],
                             help="GET path template not to call (a streaming route); repeatable")
        command.add_argument("--public-manifest", default="",
                             help="docs/generated/public-openapi-manifest.json whose GETs must all be served")
        if name == "seed":
            command.add_argument("--fixture", required=True)
            command.add_argument("--apex", required=True)
            command.add_argument("--seed-apex", required=True)
        if name == "check":
            command.add_argument("--expect-version", required=True)
            command.add_argument("--expect-sha", default="")
            command.add_argument("--baseline-sweep", default="",
                                 help="the sweep report from the previous release, to compare seeded reads")
    args = parser.parse_args(argv)

    if args.command == "baselines":
        for version in select_baselines(args.stable, args.published.split(), args.candidate):
            print(version)
        return 0

    api = Api(args.api, timeout=args.request_timeout)
    if args.command == "seed":
        try:
            state = seed(api, args.fixture, args.apex, args.seed_apex, args.scan_deadline)
        except ProbeError as exc:
            print(f"upgrade-path seed failed: {exc}", file=sys.stderr)
            return 1
        Path(args.state).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"seeded: {', '.join(sorted(k for k in state if k.endswith('_id')))}; hunt {state['hunt_seed']}")
        return 0

    state = json.loads(Path(args.state).read_text(encoding="utf-8"))
    report = Report(phase=args.command)
    report.details["seed"] = {"hunt": state.get("hunt_seed"), "snapshots": state.get("snapshots")}
    if args.command == "check":
        health = api.call("GET", "/health")
        problems = identity_problems(health.json() or {}, args.expect_version, args.expect_sha) \
            if health.status == 200 else [f"GET /health -> {health.status} {excerpt(health.body)}"]
        report.details["identity"] = {k: (health.json() or {}).get(k) for k in ("scanner_version", "source_revision")}
        report.check("candidate identity", not problems, "; ".join(problems))
        check_preserved(api, state, report)
        targeted_writes(api, state, report, args.scan_deadline)
    run_sweep(api, report, state, args)
    write_report(args.report, report)
    for failure in report.failures:
        print(f"FAIL {failure}", file=sys.stderr)
    print(f"upgrade-path {args.command}: {len(report.checks) - len(report.failures)}/{len(report.checks)} checks passed")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
