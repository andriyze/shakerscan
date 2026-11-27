"""A hostile target cannot stall the worker with what it serves to the exposure probe.

Audit M2: scrypt ran on every secret-named value before the evidence list was cut, several
parsers backtracked quadratically (``<add`` without ``>``, ``# HELP`` without ``# TYPE``, a run
of blank lines against ``(?m)^\\s*``), and all of it ran synchronously on the event loop, so a
5.5 KB .env took seconds and a megabyte of crafted XML took minutes while heartbeats and
cancellation stood still. Each adversarial body below sits at the 1 MB read cap and must
classify in bounded time; the bound is generous (the fixed parsers take well under a second
here, the old ones took 30 s to hours), so a slow CI runner does not make it flaky.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAP = 1_000_000
BOUND_SECONDS = 10.0
KILL_SECONDS = 30.0

# Each case builds its body inside a fresh interpreter, so a parser that never returns is
# killed rather than hanging the suite.
_CASE_SOURCE = r'''
import json, sys, time
from api.capabilities.exposure_probe import classify_exposure, redacted_exposure_excerpt
CAP = 1_000_000
def fill(unit):
    return (unit * (CAP // len(unit) + 1)).encode()[:CAP]
def secret(i):
    return "Q%07dzX9vB4nR8tK1wP6hD" % i
cases = {
    "dotenv_many_secret_values": lambda: (("\n".join(
        f"DB_PASSWORD_{i}={secret(i)}" for i in range(CAP // 40))).encode()[:CAP], "/.env",
        "text/plain"),
    "xml_add_without_close": lambda: (b"<configuration><appSettings>" + fill("<add "),
                                      "/web.config", "text/plain"),
    "xml_add_key_without_value": lambda: (b"<configuration><appSettings>" + fill('<add key="a" '),
                                          "/web.config", "text/plain"),
    "metrics_help_without_type": lambda: (fill("# HELP x y\n"), "/metrics", "text/plain"),
    "blank_lines": lambda: (b"\n" * CAP, "/.git/config", "text/plain"),
    "blank_lines_with_spaces": lambda: (fill(" \n"), "/.git/config", "text/plain"),
    "phpinfo_rows_without_close": lambda: (
        b"<html><title>phpinfo()</title>PHP Version 8.1 " + fill("<tr"), "/phpinfo.php",
        "text/html"),
    "phpinfo_rows_with_whitespace": lambda: (
        b"<html><title>phpinfo()</title>PHP Version 8.1 " + fill("<tr><td>" + " " * 300),
        "/phpinfo.php", "text/html"),
    "warning_without_line": lambda: (fill("Warning: "), "/error", "text/plain"),
    "json_config_many_secrets": lambda: (json.dumps(
        {f"k{i}_password": secret(i) for i in range(CAP // 50)}).encode(), "/appsettings.json",
        "application/json"),
    "actuator_many_secrets": lambda: (json.dumps({"propertySources": [{"name": "env",
        "properties": {f"p{i}.password": {"value": secret(i)} for i in range(CAP // 60)}}]}
        ).encode(), "/actuator/env", "application/json"),
}
body, path, content_type = cases[sys.argv[1]]()
body = body[:CAP]  # the probe reads at most this many bytes
started = time.perf_counter()
signature = classify_exposure(path=path, status=200, headers={"Content-Type": content_type},
                              body=body)
if signature is not None:
    redacted_exposure_excerpt(body, signature)
print(json.dumps({"seconds": time.perf_counter() - started,
                  "secrets": len(signature.secrets) if signature is not None else 0}))
'''

ADVERSARIAL_CASES = (
    "dotenv_many_secret_values", "xml_add_without_close", "xml_add_key_without_value",
    "metrics_help_without_type", "blank_lines", "blank_lines_with_spaces",
    "phpinfo_rows_without_close", "phpinfo_rows_with_whitespace", "warning_without_line",
    "json_config_many_secrets", "actuator_many_secrets",
)


@pytest.mark.parametrize("case", ADVERSARIAL_CASES)
def test_adversarial_bodies_at_the_read_cap_classify_in_bounded_time(case):
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(ROOT / "api"), str(ROOT / "scanner"),
                                                       str(ROOT)))}
    try:
        completed = subprocess.run(
            [sys.executable, "-c", _CASE_SOURCE, case], cwd=ROOT, env=env,
            capture_output=True, text=True, timeout=KILL_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{case}: classification did not finish within {KILL_SECONDS}s")
    assert completed.returncode == 0, completed.stderr[-2000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["seconds"] < BOUND_SECONDS, (case, result)
    # Evidence names a bounded number of secrets however many the body holds.
    assert result["secrets"] <= 20, (case, result)


def test_values_are_cut_and_deduplicated_before_any_fingerprint(monkeypatch):
    from api.capabilities import secret_material
    from api.capabilities.exposure_probe import classify_exposure

    calls: list[int] = []
    real = secret_material.value_fingerprint

    def counting(value):
        calls.append(len(value))
        return real(value)

    monkeypatch.setattr(secret_material, "value_fingerprint", counting)
    # 500 distinct secret-named values, each repeated under a second key.
    lines = [f"DB_PASSWORD_{i}=Q{i:07d}zX9vB4nR8tK1wP6hD" for i in range(500)]
    lines += [f"API_SECRET_{i}=Q{i:07d}zX9vB4nR8tK1wP6hD" for i in range(500)]
    signature = classify_exposure(path="/.env", status=200, headers={}, body="\n".join(lines).encode())
    assert signature is not None and signature.exposure_class == "environment_secret_file"
    assert len(signature.secrets) == 20
    assert len(calls) == 20


def test_the_cut_keeps_the_provider_secret_that_decides_severity():
    from api.capabilities.exposure_probe import classify_exposure

    aws_id = "AK" + "IA" + "Q7RZ2VX9LM4TB8NC"
    lines = [f"DB_PASSWORD_{i}=Q{i:07d}zX9vB4nR8tK1wP6hD" for i in range(60)]
    lines.append(f"AWS_ACCESS_KEY={aws_id}")
    signature = classify_exposure(path="/.env", status=200, headers={},
                                  body="\n".join(lines).encode())
    assert signature is not None and len(signature.secrets) == 20
    assert signature.severity == "critical"
    categories = {item["field"]: item["category"] for item in signature.secret_evidence()}
    assert categories["AWS_ACCESS_KEY"] == "aws_access_key"


def test_exposure_classification_runs_off_the_event_loop(monkeypatch):
    """Heartbeats keep ticking while a slow body is classified."""
    import scan.action_adapter as action_adapter_module
    from runtime.models import ScanPolicy
    from scan.action_plan import ScanActionPlan

    from tests.test_exposure_probe_batch_controls import DOTENV, _manifest, _Transport
    from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

    windows: list[tuple[float, float]] = []
    real = action_adapter_module.classify_exposure

    def slow_classify(**kwargs):
        if not str(kwargs["path"]).endswith("/.env"):
            return real(**kwargs)
        started = time.monotonic()
        time.sleep(0.4)  # stands in for a CPU-heavy parse
        result = real(**kwargs)
        windows.append((started, time.monotonic()))
        return result

    monkeypatch.setattr(action_adapter_module, "classify_exposure", slow_classify)
    scan_id = str(uuid.uuid4())
    manifest = _manifest(scan_id, ("/app",))
    transport = _Transport(lambda url: (200, DOTENV) if url.endswith("/.env") else (404, b"no"))
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    action = _action(
        "verify.exposure", "exposure.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100}, "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    action = type(action)(**{**action.__dict__, "requested_budget": {
        "http_requests": 300, "tool_wall_seconds": 180,
    }})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    dispatcher = _dispatcher(plan, Backend(manifests={manifest.manifest_id: manifest}),
                             policy=ScanPolicy())

    async def scenario():
        ticks: list[float] = []
        done = asyncio.Event()

        async def heartbeat_ticker():
            while not done.is_set():
                ticks.append(time.monotonic())
                await asyncio.sleep(0.01)

        ticker = asyncio.create_task(heartbeat_ticker())
        receipt = await dispatcher(action, _lease(plan, action), _noop)
        done.set()
        await ticker
        return receipt, ticks

    receipt, ticks = asyncio.run(scenario())
    assert [item["exposure_class"] for item in receipt.observations
            if item.get("kind") == "sensitive_exposure_proof"] == ["environment_secret_file"]
    assert windows, "the .env body was never classified"
    for started, ended in windows:
        inside = [tick for tick in ticks if started + 0.05 < tick < ended - 0.05]
        assert len(inside) >= 5, "the event loop was blocked during classification"
