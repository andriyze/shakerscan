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
    from .fixtures import fixtures_server as FX
except ImportError:  # run as a plain script: python tests/e2e/run_e2e.py
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import harness as H
    from fixtures import fixtures_server as FX


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

    fx_good = f"{FIXTURES_BASE}/models/good.safetensors"
    fx_pickle = f"{FIXTURES_BASE}/models/dangerous.pkl"
    fx_large = f"{FIXTURES_BASE}/models/large.safetensors"

    def _mi_scan(opts: dict, label: str, timeout: int = 180) -> dict:
        _, r = H.post("/model-intake/scan", opts)
        sid = r.get("scan_id")
        if not sid:
            raise RuntimeError(f"submit rejected: {r}")
        H.wait_for_scan(sid, timeout=timeout, label=label)
        return H.scan_result(sid)

    # MI-1 (deterministic hard gate): a 206 partial download capped below the full
    # artifact must report known_unverified_truncated, NOT a false sha256_mismatch
    # against the full-artifact digest. Local fixture — no network flakiness.
    try:
        res = _mi_scan({"artifact_url": fx_large, "expected_sha256": FX.LARGE_SHA,
                        "max_download_bytes": 4096}, "MI-1")
        s = (res.get("model_intake") or {}).get("summary") or {}
        fids = {str(f.get("id")) for f in (res.get("findings") or [])}
        sc.check("MI-1 206 partial download flagged truncated (not mismatch)",
                 s.get("checksum_status") == "known_unverified_truncated",
                 f"checksum_status={s.get('checksum_status')}")
        sc.check("MI-1 sha256 scope is inspected_bytes",
                 s.get("sha256_scope") == "inspected_bytes", f"sha256_scope={s.get('sha256_scope')}")
        sc.check("MI-1 no false sha256_mismatch finding",
                 "model_intake:sha256_mismatch" not in fids, f"findings={sorted(fids)[:6]}")
    except Exception as e:
        sc.error("MI-1 local 206 truncation", e)

    # MI-1-HF (opt-in / nightly): the real multi-GB HuggingFace shard — useful
    # coverage for the original 206 bug, but an external dependency, so NOT a hard
    # PR gate. Runs only when SHAKERSCAN_E2E_HF=1.
    if os.environ.get("SHAKERSCAN_E2E_HF") == "1":
        try:
            res = _mi_scan({"artifact_url": NEX_N2_SHARD, "expected_sha256": NEX_N2_FULL_SHA,
                            "metadata_json": {"license": "apache-2.0"}}, "MI-1-HF", timeout=300)
            intake = res.get("model_intake") or {}
            s = intake.get("summary") or {}
            fids = {str(f.get("id")) for f in (res.get("findings") or [])}
            header = (((intake.get("supply_chain") or {}).get("format_inspection") or {})
                      .get("safetensors_header") or {})
            sc.check("MI-1-HF real HF shard not false-mismatched",
                     s.get("checksum_status") == "known_unverified_truncated",
                     f"checksum_status={s.get('checksum_status')}")
            sc.check("MI-1-HF truncated shard uses full size for structural validation",
                     header.get("valid") is True
                     and header.get("validation_complete") is True
                     and header.get("payload_bounds_checked") is True
                     and "model_intake:safetensors_header_invalid" not in fids,
                     f"valid={header.get('valid')} payload_size={header.get('payload_size')} "
                     f"findings={sorted(fids)[:6]}")
        except Exception as e:
            sc.error("MI-1-HF real HF intake", e)
    else:
        sc.skip("MI-1-HF real HuggingFace shard",
                "external dependency; set SHAKERSCAN_E2E_HF=1 (nightly/manual)")

    # MI-2: correct digest on a fully-downloadable artifact -> verified.
    try:
        s = (_mi_scan({"artifact_url": fx_good, "expected_sha256": FX.GOOD_SHA}, "MI-2")
             .get("model_intake") or {}).get("summary") or {}
        sc.check("MI-2 correct digest verifies",
                 s.get("checksum_status") == "verified" and s.get("sha256_scope") == "full_artifact",
                 f"checksum_status={s.get('checksum_status')} scope={s.get('sha256_scope')}")
    except Exception as e:
        sc.error("MI-2 verified checksum", e)

    # MI-3: a tampered artifact (wrong expected hash, full download) -> critical
    # sha256_mismatch (the real tamper path, which the 206 false-mismatch masked).
    try:
        res = _mi_scan({"artifact_url": fx_good, "expected_sha256": FX.WRONG_SHA}, "MI-3")
        fids = {str(f.get("id")) for f in (res.get("findings") or [])}
        sc.check("MI-3 tampered artifact -> critical sha256_mismatch",
                 "model_intake:sha256_mismatch" in fids, f"findings={sorted(fids)[:6]}")
    except Exception as e:
        sc.error("MI-3 tamper detection", e)

    # MI-4: a dangerous pickle (os.system reduce) -> unsafe-serialization finding.
    try:
        res = _mi_scan({"artifact_url": fx_pickle, "require_hash": False}, "MI-4")
        ids = [(str(f.get("id")) + " " + str(f.get("title"))).lower() for f in (res.get("findings") or [])]
        flagged = any(any(k in x for k in ("pickle", "serial", "unsafe", "risky", "deserial")) for x in ids)
        sc.check("MI-4 dangerous pickle flagged", flagged,
                 f"findings={[str(f.get('id')) for f in (res.get('findings') or [])][:6]}")
    except Exception as e:
        sc.error("MI-4 unsafe serialization", e)

    # MI-5: a VALID self-signed signature with no configured trust anchor must read
    # as untrusted_root, never "verified" (the trust-root bug). Signature material
    # rides in metadata_json (the verifier's metadata fallback); trust anchors are
    # operator-config only, so MI-6 (anchor -> verified) needs the worker env var.
    try:
        s = (_mi_scan({"artifact_url": fx_good, "expected_sha256": FX.GOOD_SHA,
                       "metadata_json": {"signature_public_key": FX.SIGNING_PUB_PEM,
                                         "signature_value": FX.SIGNATURE_B64}}, "MI-5")
             .get("model_intake") or {}).get("summary") or {}
        sc.check("MI-5 valid self-signed -> untrusted_root (not verified)",
                 s.get("signature_verification_status") == "untrusted_root"
                 and s.get("signature_verified") is False,
                 f"status={s.get('signature_verification_status')} valid={s.get('signature_valid')}")
    except Exception as e:
        sc.error("MI-5 trust-root (untrusted)", e)
    # MI-6: a valid signature whose key is supplied as an operator trust anchor in
    # the SAME request now verifies (F1 — trust anchors reachable via the API, not
    # just worker env). This is the enforced positive control for MI-5.
    try:
        s = (_mi_scan({"artifact_url": fx_good, "expected_sha256": FX.GOOD_SHA,
                       "signature_public_key": FX.SIGNING_PUB_PEM,
                       "signature_value": FX.SIGNATURE_B64,
                       "signature_trusted_keys": [FX.SIGNING_PUB_PEM]}, "MI-6")
             .get("model_intake") or {}).get("summary") or {}
        sc.check("MI-6 trusted-anchor signature verifies",
                 s.get("signature_verification_status") == "verified"
                 and s.get("signature_verified") is True
                 and s.get("signature_trusted_root") is True,
                 f"status={s.get('signature_verification_status')} trusted_root={s.get('signature_trusted_root')}")
    except Exception as e:
        sc.error("MI-6 trusted-anchor verify", e)

    return sc


# Targets must be reachable from the WORKER container, not the host: inside the
# compose network the honey apps are at host.docker.internal, not localhost (a
# localhost:3001 target resolves to the worker itself and fails pre-scan
# validation). Override SHAKERSCAN_E2E_HONEY_HOST on Linux CI (e.g. the compose
# service name / bridge IP).
HONEY_HOST = os.environ.get("SHAKERSCAN_E2E_HONEY_HOST", "host.docker.internal")
# The local fixtures server (started in main) — worker-reachable, deterministic,
# and deliberately leaky, so the AI detection/redaction and Model-Intake artifact
# assertions run without external honey apps. Override SHAKERSCAN_E2E_AI_ENDPOINT
# to point at a real honey AI app instead.
FIXTURES_PORT = int(os.environ.get("SHAKERSCAN_E2E_FIXTURES_PORT", "18099"))
FIXTURES_BASE = f"http://{HONEY_HOST}:{FIXTURES_PORT}"
AI_ENDPOINT = os.environ.get("SHAKERSCAN_E2E_AI_ENDPOINT", f"{FIXTURES_BASE}/ai/chat")


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
        "response_path": "$.answer", "production_mode": production,
        "rate_limit_rps": 8, "request_budget": 8,
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
                using_fixture = AI_ENDPOINT.startswith(FIXTURES_BASE)
                if status != "completed" and not using_fixture:
                    # Only an OVERRIDDEN external endpoint may legitimately skip.
                    sc.skip("AI-1/AI-2 live scan + transcript redaction",
                            f"AI scan status={status}; external endpoint {AI_ENDPOINT} not completed")
                elif status != "completed":
                    # The local fixture is deterministic and always responsive — a
                    # non-completed scan is a REAL failure, never a passing skip.
                    sc.check("AI-1 smoke scan completed (deterministic fixture)", False,
                             f"status={status} endpoint={AI_ENDPOINT}")
                else:
                    sc.check("AI-1 smoke scan completed", True, f"status={status}")
                    tr = H.get(f"/ai/scans/{scan_id}/transcript")
                    blob = json.dumps(tr)
                    # AI-2: the leaky fixture leaks password=/api_key=sk_live_/client_secret:
                    # in EVERY response. The transcript must have CAPTURED that response
                    # (non-vacuous) and yet contain NONE of the planted secrets — the
                    # real judge-redactor-leak regression.
                    captured = "Internal config dump" in blob  # proves the leaky response was stored
                    survived = [t for t in FX.PLANTED_TOKENS if t in blob]
                    sc.check("AI-2 transcript redaction applied", tr.get("redaction_applied") is True,
                             f"redaction_applied={tr.get('redaction_applied')}")
                    sc.check("AI-2 leaky response was captured (test not vacuous)", captured, f"captured={captured}")
                    sc.check("AI-2 no planted secret survives transcript", not survived,
                             f"survived={survived} redaction_markers={blob.count('***')}")
    except Exception as e:
        sc.error("AI-1/AI-2 smoke scan + redaction", e)
    finally:
        if tid:
            H._req("DELETE", f"/ai/targets/{tid}")

    # AI-3: production principal-probe filter. A generated cross-principal
    # admin-impersonation probe (family=tool_abuse, non_production_only) must be
    # BLOCKED in production and never executed — the bypass bug. Non-vacuous: the
    # SAME probe is generated in a staging control.
    rag_id = None
    try:
        _, resp = H.post("/ai/targets", {
            "name": f"e2e-ai-principal-{_RUN_NONCE}", "target_type": "rag",
            "endpoint_url": _ai_endpoint("principal"),
            "method": "POST", "headers_template": {"Content-Type": "application/json"},
            "request_template": {"message": "{{prompt}}"}, "response_path": "$.answer",
            "production_mode": False, "rate_limit_rps": 8, "request_budget": 12,
        })
        rag_id = (resp.get("target") or {}).get("id")
        sc.check("AI-3 rag target created", bool(rag_id))
        if rag_id:
            for role in ("attacker", "admin", "victim"):
                H.post(f"/ai/targets/{rag_id}/principals",
                       {"label": f"{role}-a", "role": role, "tenant_id": f"tenant-{role}"})

            def _principal_manifest(environment, confirm):
                body = {"probe_pack": "shaker-agent-abuse", "scan_profile": "standard", "environment": environment}
                if confirm:
                    body["confirm_production"] = True
                _, r = H.post(f"/ai/targets/{rag_id}/scan", body)
                sid = r.get("scan_id") or r.get("id")
                if not sid:
                    raise RuntimeError(f"principal scan rejected: {r}")
                H.wait_for_scan(sid, timeout=420, label=f"AI-3:{environment}")
                ep = (((H.scan_result(sid).get("ai_gate") or {}).get("execution_plan")) or {})
                man = ep.get("probe_manifest") or {}
                return {
                    "blocked": man.get("blocked_for_production_probe_ids") or [],
                    "pair": man.get("principal_pair_probe_ids") or [],
                    "executed": ep.get("executed") or [],
                }

            ADMIN = "agent-admin-action"
            prod = _principal_manifest("production", True)
            sc.check("AI-3 admin-impersonation probe blocked in production",
                     any(ADMIN in p for p in prod["blocked"]), f"blocked={prod['blocked'][:4]}")
            sc.check("AI-3 admin-impersonation probe NOT executed in production",
                     not any(ADMIN in p for p in prod["executed"]), f"executed={prod['executed'][:4]}")
            stg = _principal_manifest("staging", False)
            sc.check("AI-3 control: same probe IS generated in staging (non-vacuous)",
                     any(ADMIN in p for p in stg["pair"]), f"staging_pair={stg['pair'][:4]}")
    except Exception as e:
        sc.error("AI-3 production principal-probe filter", e)
    finally:
        if rag_id:
            H._req("DELETE", f"/ai/targets/{rag_id}")

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

    # D-2 (active recall): a BOUNDED, un-sharded active scan of Juice Shop's known
    # SQL-injectable login must detect the SQLi. Bounding is essential — an
    # unbounded smart scan auto-shards into ~25 shards with multi-hour budgets; with
    # parallel disabled + a tight budget it completes in ~30-60s AND detects.
    try:
        _, resp = H.post("/scans", {
            "target": JUICE_SHOP,
            "options": {
                "scan_type": "smart", "sqli": True, "parallel": False,
                "custom_endpoints": [
                    'POST /rest/user/login json:{"email":"test@test.com","password":"test"}',
                    "GET /rest/products/search?q=apple",
                ],
                "custom_budget": {"max_urls": 40, "active_max_endpoints": 8,
                                  "active_max_seconds": 420, "browser_max_pages": 5,
                                  "nuclei_max_targets": 0},
            },
        })
        scan_id = resp.get("scan_id") or resp.get("id")
        sc.check("D-2 bounded active scan accepted", bool(scan_id), str(resp)[:100])
        if scan_id:
            scan = H.wait_for_scan(scan_id, timeout=600, poll=8, label="D-2")
            sc.check("D-2 bounded active scan completes", str(scan.get("status")) == "completed",
                     f"status={scan.get('status')}")
            findings = (H.scan_result(scan_id).get("findings") or [])
            sqli = [f for f in findings
                    if "sql" in (str(f.get("category")) + str(f.get("title"))).lower()]
            sc.check("D-2 detects SQLi on injectable login", bool(sqli),
                     f"sqli={[str(f.get('title'))[:45] for f in sqli][:3]}")
    except Exception as e:
        sc.error("D-2 bounded active SQLi detection", e)

    # D-3 (active recall, XSS): a bounded scan detects DOM-based XSS on Juice Shop.
    try:
        _, resp = H.post("/scans", {
            "target": JUICE_SHOP,
            "options": {
                "scan_type": "smart", "xss": True, "parallel": False, "deep_domxss": True,
                "custom_endpoints": ["GET /rest/products/search?q=apple", "GET /#/search?q=apple"],
                "custom_budget": {"max_urls": 60, "active_max_endpoints": 12, "active_max_seconds": 420,
                                  "browser_max_pages": 8, "nuclei_max_targets": 0},
            },
        })
        scan_id = resp.get("scan_id") or resp.get("id")
        sc.check("D-3 bounded XSS scan accepted", bool(scan_id), str(resp)[:100])
        if scan_id:
            scan = H.wait_for_scan(scan_id, timeout=600, poll=8, label="D-3")
            sc.check("D-3 bounded XSS scan completes", str(scan.get("status")) == "completed",
                     f"status={scan.get('status')}")
            findings = (H.scan_result(scan_id).get("findings") or [])
            xss = [f for f in findings if "xss" in (str(f.get("category")) + str(f.get("title"))).lower()]
            sc.check("D-3 detects XSS", bool(xss),
                     f"xss={[str(f.get('title'))[:40] for f in xss][:3]}")
    except Exception as e:
        sc.error("D-3 bounded XSS detection", e)

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
    # Start the local fixtures server (leaky AI endpoint + model artifacts); the
    # worker reaches it at host.docker.internal:FIXTURES_PORT.
    FX.start(FIXTURES_PORT)
    print(f"fixtures server on :{FIXTURES_PORT} (worker URL {FIXTURES_BASE})", flush=True)
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
