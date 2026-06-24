"""Shared end-to-end test harness (stdlib only).

These tests drive the REAL running stack through the public HTTP API — submit a
job, let a worker process it against a real target/network, then assert on the
real result. They deliberately do NOT import scanner internals or mock the fetch
/ scan / redaction seams (that is where the escaped bugs lived). See
docs/E2E_TEST_PLAN.md.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("SHAKERSCAN_API", "http://localhost:8080")
TERMINAL = {"completed", "failed", "cancelled", "error"}


def _req(method: str, path: str, body: dict | None = None, timeout: int = 60, retries: int = 3):
    url = path if path.startswith("http") else f"{API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    last_exc: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError:
            raise  # HTTP 4xx/5xx are real answers — let callers handle them
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            # Transient transport hiccup under load — retry rather than fail the case.
            last_exc = e
            time.sleep(2 * (attempt + 1))
    raise last_exc  # type: ignore[misc]


def get(path: str, timeout: int = 60):
    return _req("GET", path, timeout=timeout)[1]


def post(path: str, body: dict, timeout: int = 30):
    """POST returning (status_code, json). Raises only on transport errors; HTTP
    error bodies are returned so cases can assert on 4xx/409 gates."""
    try:
        return _req("POST", path, body, timeout=timeout)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def wait_for_scan(scan_id: str, timeout: int = 600, poll: int = 5, label: str = "") -> dict:
    """Poll GET /scans/{id} until terminal or timeout. Returns the scan dict.
    A timeout (stuck/reaped scan) raises — silence is a failure, not a pass."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        scan = get(f"/scans/{scan_id}")
        status = str(scan.get("status") or "")
        if status != last:
            print(f"    [{label or scan_id[:8]}] status={status}", flush=True)
            last = status
        if status in TERMINAL:
            return scan
        time.sleep(poll)
    raise TimeoutError(f"scan {scan_id} did not reach a terminal state within {timeout}s (last={last})")


def scan_result(scan_id: str) -> dict:
    return get(f"/scans/{scan_id}/result")


class Scorecard:
    """Collects per-assertion pass/fail across an area; gate() is the hard CI gate."""

    def __init__(self, area: str):
        self.area = area
        self.rows: list[dict] = []

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.rows.append({"name": name, "passed": bool(passed), "skipped": False, "detail": detail})
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""), flush=True)
        return bool(passed)

    def skip(self, name: str, reason: str) -> None:
        """Record a SKIP — a prerequisite is missing (e.g. no responsive AI endpoint).
        Skips do NOT fail the gate, but they are loud and counted so coverage gaps
        are never silently passed."""
        self.rows.append({"name": name, "passed": True, "skipped": True, "detail": reason})
        print(f"  [SKIP] {name} — {reason}", flush=True)

    def error(self, name: str, exc: Exception) -> None:
        self.rows.append({"name": name, "passed": False, "skipped": False, "detail": f"ERROR: {exc}"})
        print(f"  [FAIL] {name} — ERROR: {exc}", flush=True)

    @property
    def passed(self) -> bool:
        return bool(self.rows) and all(r["passed"] for r in self.rows)

    def summary(self) -> dict:
        ok = sum(1 for r in self.rows if r["passed"] and not r["skipped"])
        skipped = sum(1 for r in self.rows if r["skipped"])
        return {"area": self.area, "passed": ok, "skipped": skipped, "total": len(self.rows),
                "gate": "pass" if self.passed else "fail", "rows": self.rows}


def preflight(require_honey: list[str] | None = None) -> None:
    """Fail loudly if the stack or required honey targets are not reachable."""
    h = get("/health")
    if not h:
        raise RuntimeError(f"API not healthy at {API}")
    for url in (require_honey or []):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status >= 500:
                    raise RuntimeError(f"honey target {url} unhealthy ({r.status})")
        except Exception as e:
            raise RuntimeError(f"required honey target unreachable: {url} ({e})")
