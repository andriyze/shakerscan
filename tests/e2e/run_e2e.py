#!/usr/bin/env python3
"""End-to-end test runner — drives the real running stack against real targets.

Usage:
    python -m tests.e2e.run_e2e --area all
    python -m tests.e2e.run_e2e --area model_intake
    python -m tests.e2e.run_e2e --area ai_gate
    python -m tests.e2e.run_e2e --area dast

Exit code is non-zero if any area's gate fails (hard CI gate). See
docs/E2E_TEST_PLAN.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    from . import harness as H
except ImportError:  # run as a plain script: python tests/e2e/run_e2e.py
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import harness as H


# Full-artifact LFS digest of nex-agi/Nex-N2-mini shard 1 (the artifact that
# produced the false mismatch). The shard is multi-GB, so intake caps the
# download at 10MB and must report truncated — never compare a 10MB prefix
# against this full digest as a "mismatch".
NEX_N2_SHARD = ("https://huggingface.co/nex-agi/Nex-N2-mini/resolve/"
                "ca218dcb1fbe05f84d1807d180cb5d9bcb1c5c93/model-00001-of-00016.safetensors")
NEX_N2_FULL_SHA = "d6b15ebf2a6b81f62c9a913bc340486a7a1a97cbbf97a50abf9be53ddcd4f5dc"


def run_model_intake() -> H.Scorecard:
    sc = H.Scorecard("model_intake")
    print("\n== Model Intake e2e ==", flush=True)

    # MI-1: a real large multi-shard HF artifact must NOT false-mismatch.
    try:
        _, resp = H.post("/model-intake/scan", {
            "artifact_url": NEX_N2_SHARD,
            "expected_sha256": NEX_N2_FULL_SHA,
            "metadata_json": {"license": "apache-2.0"},
        })
        scan_id = resp.get("scan_id")
        sc.check("MI-1 submit accepted", bool(scan_id), str(resp)[:120])
        if scan_id:
            H.wait_for_scan(scan_id, timeout=300, label="MI-1")
            res = H.scan_result(scan_id)
            summary = ((res.get("model_intake") or {}).get("summary")) or {}
            findings = res.get("findings") or []
            fids = {str(f.get("id")) for f in findings}
            status = summary.get("checksum_status")
            scope = summary.get("sha256_scope")
            sc.check("MI-1 truncated download flagged (not mismatch)",
                     status == "known_unverified_truncated", f"checksum_status={status}")
            sc.check("MI-1 sha256 scope is inspected_bytes",
                     scope == "inspected_bytes", f"sha256_scope={scope}")
            sc.check("MI-1 no false sha256_mismatch finding",
                     "model_intake:sha256_mismatch" not in fids, f"findings={sorted(fids)[:6]}")
            crit = [f for f in findings if str(f.get("severity")).lower() == "critical"
                    and "checksum" in str(f.get("id")).lower() or str(f.get("id")) == "model_intake:sha256_mismatch"]
            sc.check("MI-1 no critical checksum block", not crit, f"critical_checksum={[f.get('id') for f in crit]}")
    except Exception as e:
        sc.error("MI-1 real HF intake", e)

    return sc


# Targets must be reachable from the WORKER container, not the host: inside the
# compose network the honey apps are at host.docker.internal, not localhost (a
# localhost:3001 target resolves to the worker itself and fails pre-scan
# validation). Override SHAKERSCAN_E2E_HONEY_HOST on Linux CI (e.g. the compose
# service name / bridge IP).
HONEY_HOST = os.environ.get("SHAKERSCAN_E2E_HONEY_HOST", "host.docker.internal")
AI_ENDPOINT = os.environ.get(
    "SHAKERSCAN_E2E_AI_ENDPOINT", f"http://{HONEY_HOST}:3001/rest/chatbot/respond")


import time as _time

# Unique per run so the endpoint_url uniqueness constraint never collides with a
# prior run's (possibly soft-deleted) target. The extra query param is ignored by
# the target endpoint.
_RUN_NONCE = f"{os.getpid()}-{int(_time.time())}"


def _ai_endpoint(tag: str) -> str:
    sep = "&" if "?" in AI_ENDPOINT else "?"
    return f"{AI_ENDPOINT}{sep}e2e={tag}-{_RUN_NONCE}"


def _create_ai_target(name: str, production: bool) -> str | None:
    _, resp = H.post("/ai/targets", {
        "name": f"{name}-{_RUN_NONCE}", "target_type": "api_chat", "endpoint_url": _ai_endpoint(name),
        "method": "POST", "headers_template": {"Content-Type": "application/json"},
        "request_template": {"action": "query", "query": "{{prompt}}"},
        "response_path": "$.body", "production_mode": production,
        "rate_limit_rps": 4, "request_budget": 6,
    })
    return (resp.get("target") or {}).get("id")


def run_ai_gate() -> H.Scorecard:
    sc = H.Scorecard("ai_gate")
    print("\n== AI Gate e2e ==", flush=True)

    # AI-4: a production scan is refused without explicit confirmation.
    prod_id = None
    try:
        prod_id = _create_ai_target("e2e-ai-prod-gate", production=True)
        sc.check("AI-4 prod target created", bool(prod_id))
        if prod_id:
            code_no, _ = H.post(f"/ai/targets/{prod_id}/scan",
                                {"probe_pack": "shaker-ai-smoke", "scan_profile": "smoke", "environment": "production"})
            sc.check("AI-4 prod scan refused without confirm", code_no == 409, f"http={code_no}")
    except Exception as e:
        sc.error("AI-4 confirm_production gate", e)
    finally:
        if prod_id:
            H._req("DELETE", f"/ai/targets/{prod_id}")

    # AI-1/AI-2: a real smoke scan completes and its transcript is redaction-gated.
    tid = None
    try:
        tid = _create_ai_target("e2e-ai-smoke", production=False)
        sc.check("AI-1 target created", bool(tid))
        if tid:
            code, resp = H.post(f"/ai/targets/{tid}/scan",
                                {"probe_pack": "shaker-ai-smoke", "scan_profile": "smoke", "environment": "staging"})
            scan_id = resp.get("scan_id") or resp.get("id")
            sc.check("AI-1 smoke scan accepted", bool(scan_id) and code in (200, 202), f"http={code}")
            if scan_id:
                scan = H.wait_for_scan(scan_id, timeout=420, label="AI-1")
                status = str(scan.get("status"))
                if status != "completed":
                    # The default Juice Shop chatbot needs auth, so probes fail and
                    # no transcript is produced. Skip (loud) rather than fake-pass —
                    # set SHAKERSCAN_E2E_AI_ENDPOINT to a responsive honey AI app to
                    # exercise the detection + transcript-redaction assertions.
                    sc.skip("AI-1/AI-2 live scan + transcript redaction",
                            f"AI scan status={status}; no responsive AI endpoint at {AI_ENDPOINT}")
                else:
                    sc.check("AI-1 smoke scan completed", True, f"status={status}")
                    tr = H.get(f"/ai/scans/{scan_id}/transcript")
                    applied = tr.get("redaction_applied")
                    blob = json.dumps(tr)
                    leaks = [p for p in ("password=", "api_key=", "client_secret:", "-----BEGIN ")
                             if p.lower() in blob.lower() and "***" not in blob]
                    sc.check("AI-2 transcript redaction applied", applied is True, f"redaction_applied={applied}")
                    sc.check("AI-2 no obvious secret survives transcript", not leaks, f"leaks={leaks}")
    except Exception as e:
        sc.error("AI-1/AI-2 smoke scan + redaction", e)
    finally:
        if tid:
            H._req("DELETE", f"/ai/targets/{tid}")

    return sc


JUICE_SHOP = os.environ.get("SHAKERSCAN_E2E_DAST_TARGET", f"http://{HONEY_HOST}:3001")


def run_dast() -> H.Scorecard:
    sc = H.Scorecard("dast")
    print("\n== DAST e2e ==", flush=True)

    # D-1 (fast gate): a standard scan of Juice Shop must COMPLETE (catches the
    # finalize-hang / NUL-byte-crash / reaper classes) and produce a graded report
    # with findings. Active recall (SQLi/XSS/BOLA, the 70% benchmark) is too slow
    # for a per-PR gate and runs NIGHTLY via tests/benchmark/run_benchmarks.py.
    try:
        _, resp = H.post("/scans", {
            "target": JUICE_SHOP,
            "options": {"scan_type": "standard"},
        })
        scan_id = resp.get("scan_id") or resp.get("id")
        sc.check("D-1 scan accepted", bool(scan_id), str(resp)[:120])
        if scan_id:
            scan = H.wait_for_scan(scan_id, timeout=1200, poll=10, label="D-1")
            status = str(scan.get("status"))
            sc.check("D-1 scan completes (no hang/crash/reap)", status == "completed", f"status={status}")
            res = H.scan_result(scan_id)
            findings = res.get("findings") or []
            grade = res.get("grade") or (res.get("result") or {}).get("grade")
            sc.check("D-1 graded report produced", bool(grade), f"grade={grade}")
            sc.check("D-1 findings persisted (no save crash)", len(findings) > 0, f"findings={len(findings)}")
            # D-4: the 3 removed phantom attack chains must never be reported.
            chains = json.dumps((res.get("attack_chains") or {}))
            phantom = [c for c in ("auth_bypass_to_admin_access", "open_redirect_to_phishing",
                                   "info_disclosure_to_exploitation") if c in chains]
            sc.check("D-4 no phantom attack chains reported", not phantom, f"phantom={phantom}")
    except Exception as e:
        sc.error("D-1 standard scan", e)

    return sc


AREAS = {
    "model_intake": run_model_intake,
    "ai_gate": run_ai_gate,
    "dast": run_dast,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--area", default="all", choices=["all", *AREAS.keys()])
    args = ap.parse_args()

    H.preflight()
    areas = list(AREAS.values()) if args.area == "all" else [AREAS[args.area]]
    cards = [fn() for fn in areas]

    print("\n== Scorecard ==", flush=True)
    failed = False
    for c in cards:
        s = c.summary()
        print(f"  {s['area']}: {s['passed']}/{s['total']} — gate {s['gate'].upper()}", flush=True)
        failed = failed or not c.passed
    print(("\nE2E GATE: FAIL" if failed else "\nE2E GATE: PASS"), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
