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


def _req(
    method: str,
    path: str,
    body: dict | None = None,
    timeout: int = 60,
    retries: int = 5,
    headers: dict[str, str] | None = None,
):
    url = path if path.startswith("http") else f"{API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    last_exc: Exception | None = None
    for attempt in range(retries):
        request_headers = {"Content-Type": "application/json"} if data else {}
        request_headers.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
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


def get(path: str, timeout: int = 60, headers: dict[str, str] | None = None):
    return _req("GET", path, timeout=timeout, headers=headers)[1]


def post(path: str, body: dict, timeout: int = 30, headers: dict[str, str] | None = None):
    """POST returning (status_code, json). Raises only on transport errors; HTTP
    error bodies are returned so cases can assert on 4xx/409 gates."""
    try:
        return _req("POST", path, body, timeout=timeout, headers=headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def put(path: str, body: dict, timeout: int = 30, headers: dict[str, str] | None = None):
    try:
        return _req("PUT", path, body, timeout=timeout, headers=headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def patch(path: str, body: dict, timeout: int = 30, headers: dict[str, str] | None = None):
    try:
        return _req("PATCH", path, body, timeout=timeout, headers=headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def delete(path: str, timeout: int = 30, headers: dict[str, str] | None = None):
    try:
        return _req("DELETE", path, timeout=timeout, headers=headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def model_intake_operator_headers() -> dict[str, str]:
    """Load the local release-test credential without printing or persisting it."""
    token = os.environ.get("SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_TOKEN", "").strip()
    if not token:
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
        try:
            with open(env_path, encoding="utf-8") as handle:
                for raw_line in handle:
                    key, separator, value = raw_line.strip().partition("=")
                    if separator and key == "MODEL_INTAKE_OPERATOR_TOKEN":
                        token = value.strip().strip('"').strip("'")
                        break
        except OSError:
            pass
    if len(token) < 32:
        raise RuntimeError(
            "Model Intake operator credential is unavailable; start ShakerScan or set "
            "SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_TOKEN"
        )
    return {"Authorization": f"Bearer {token}"}


def wait_for_scan(scan_id: str, timeout: int = 600, poll: int = 5, label: str = "") -> dict:
    """Poll GET /scans/{id} until terminal or timeout. Returns the scan dict.
    A timeout (stuck/reaped scan) raises — silence is a failure, not a pass.

    A single poll that errors (transient API slowness under a loaded fleet — the
    aggregate run hammers the API) is tolerated: keep polling. Only a SUSTAINED
    run of poll failures raises, so the gate isn't flaky on a blip."""
    deadline = time.time() + timeout
    last = None
    consecutive_errors = 0
    while time.time() < deadline:
        try:
            scan = get(f"/scans/{scan_id}")
            consecutive_errors = 0
        except Exception as e:  # transient transport blip — log and keep polling
            consecutive_errors += 1
            print(f"    [{label or scan_id[:8]}] poll error {consecutive_errors}/8: {e}", flush=True)
            if consecutive_errors >= 8:
                raise
            time.sleep(poll)
            continue
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
        if passed:
            print(f"  [PASS] {name}" + (" — detail recorded" if detail else ""), flush=True)
        else:
            # A failing assertion must be diagnosable from the run log alone. The PR
            # smoke lane uploads no scorecard artifact, so hiding the detail behind
            # "detail recorded" left every red check with no visible cause.
            print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""), flush=True)
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
    """Fail loudly if the stack is unhealthy, the worker fleet is build-skewed, or
    required honey targets are unreachable."""
    h = get("/health")
    if not h:
        raise RuntimeError(f"API not healthy at {API}")
    # A build-skewed fleet (mixed worker code) makes scans nondeterministic — the
    # exact failure that flapped MI-1 (stale model_intake.py on API-scaled workers).
    # The build_fingerprint now covers model_intake/ai_gate_scan/redaction, so a
    # skewed fleet is detectable here. Refuse to run e2e on one.
    workers = get("/workers")
    if isinstance(workers, dict):
        uniform = workers.get("fleet_uniform")
        stale = workers.get("stale_count") or len(workers.get("stale_workers") or [])
        if uniform is False or stale:
            raise RuntimeError(
                f"worker fleet is NOT uniform (fleet_uniform={uniform}, stale={stale}, "
                f"distinct={workers.get('distinct_fingerprints')}) — refresh ALL workers "
                "(docker restart every shakerscan-worker-*, not just compose replicas) before running e2e")
    for url in (require_honey or []):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status >= 500:
                    raise RuntimeError(f"honey target {url} unhealthy ({r.status})")
        except Exception as e:
            raise RuntimeError(f"required honey target unreachable: {url} ({e})")
