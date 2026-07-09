#!/usr/bin/env python3
"""End-to-end DAST benchmark runner (proposed-next-steps.md §1).

Submits a Smart scan per target fixture, waits for completion, fetches the report,
and writes a compact scorecard under results/benchmark-runs/. Scores verified vs
suspected High/Critical, coverage, blocked/timeout/error, and matches expected bug
CLASSES (route-anchored, not app secrets) so a regression that drops Juice Shop
SQLi/XSS or crAPI BOLA is visible immediately.

Usage:
  python3 scripts/benchmark_targets.py juice_shop [crapi honey ...]
      [--api http://localhost:8080] [--timeout 2400] [--auth] [--no-submit SCAN_ID]

Fixtures: tests/fixtures/benchmarks/<name>.yaml
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURE_DIR = os.path.join(REPO, "tests", "fixtures", "benchmarks")
OUT_DIR = os.path.join(REPO, "results", "benchmark-runs")
SCANNER_DIR = os.path.join(REPO, "scanner")
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from scanner_tools.benchmark_summary import collect_body_completion_diagnostics  # noqa: E402

# Coarse finding-class detection (mirrors measure.py, kept route-anchored).
CLASS_KEYWORDS = {
    "sqli": ["sql injection", "sqli"],
    "nosqli": ["nosql", "mongo"],
    "xss": ["xss", "cross-site scripting", "script execution"],
    "bola": ["bola", "idor", "object authorization", "broken object level"],
    "broken_access_control": ["forced browsing", "access control", "bfla",
                               "function level", "broken function", "default credentials",
                               "debug/development", "accessible debug", "actuator", "admin"],
    "sensitive_exposure": ["exposed", "exposure", "sensitive", "disclosure",
                            "directory listing", "backup", "secret", "confidential",
                            "private key", "credentials", "allowlist bypass"],
    "webhook": ["webhook"],
    "approval": ["approval", "approve", "delegate", "impersonate"],
    "path_traversal": ["path traversal", "directory traversal", "lfi", "file inclusion"],
    "jwt": ["jwt", "json web token"],
    "xxe": ["xxe", "xml external entity"],
}
COMPAT = {
    "sqli": {"sqli"}, "nosqli": {"nosqli", "sqli"}, "xss": {"xss"},
    "bola": {"bola", "broken_access_control"},
    "broken_access_control": {"broken_access_control", "bola", "sensitive_exposure"},
    "sensitive_exposure": {"sensitive_exposure", "broken_access_control"},
    "webhook": {"webhook"}, "approval": {"approval"},
    "path_traversal": {"path_traversal"}, "jwt": {"jwt"}, "xxe": {"xxe"},
}
STOP = {"rest", "api", "http", "https", "html", "json", "www", "v1", "v2", "v3",
        "id", "user", "users", "identity", "workshop", "community"}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FOCUSED_FAMILY_FOR_BENCHMARK_MISS = {
    "sqli": "sqli",
    # NoSQL probes run under the SQLi/body-injection focused lane.
    "nosqli": "sqli",
    "xss": "xss",
    "bola": "bola",
    "broken_access_control": "auth",
}
AUTH_REQUIRED_FAMILIES = {"bola", "broken_access_control"}


def _get(url, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _norm_live_finding(f):
    """Map a /findings DB row to the report-finding shape collect_scorecard reads.

    Crucially, a finding counts as ``verified`` if the deterministic auto-retest
    proved it (``last_verification_verdict == 'exploited'``), not only the scan-time
    triage flag — this is the whole point of the post-retest re-score (docs §6).
    """
    verdict = str(f.get("last_verification_verdict") or "").lower()
    return {
        "title": f.get("title"),
        "url": f.get("url"),
        "category": f.get("category") or f.get("cwe"),
        "type": f.get("type"),
        "cwe": f.get("cwe"),
        "description": f.get("description"),
        "severity": f.get("severity"),
        "verified": bool(f.get("verified")) or verdict == "exploited",
        "confidence_tier": f.get("confidence_tier"),
    }


def fetch_live_findings(api, scan_id, timeout=30):
    """Live findings for a scan, carrying post-retest verdicts (docs §6)."""
    try:
        data = _get(f"{api}/findings?scan_id={scan_id}&limit=500", timeout=timeout)
    except Exception:
        return None
    rows = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return None
    return [_norm_live_finding(f) for f in rows]


def wait_for_retest_settle(api, timeout=600, poll=15):
    """Wait for the async auto-retest wave to drain (docs §6 — the verified lift
    happens AFTER the scan, so the scorecard must read once retests settle)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            q = _get(f"{api}/queue/stats", timeout=20)
        except Exception:
            return False
        pending = sum(int(q.get(k) or 0) for k in
                      ("retest_pending", "retest_queued", "retest_running"))
        if pending == 0:
            return True
        time.sleep(poll)
    return False


def check_fleet(api):
    """Return (uniform, summary) for the worker fleet (docs §3/§10 gate)."""
    try:
        w = _get(f"{api}/workers", timeout=20)
    except Exception as e:
        return False, {"error": str(e)}
    return bool(w.get("fleet_uniform")), {
        "count": w.get("count"), "current": w.get("current_count"),
        "stale": w.get("stale_count"), "pending": w.get("pending_count"),
        "fingerprints": w.get("distinct_fingerprints"),
    }


def _post(url, body, timeout=30):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def parse_target_id_overrides(values):
    """Parse --hypothesis-target-id entries as benchmark=uuid mappings."""
    mapping = {}
    for raw in values or []:
        text = str(raw or "").strip()
        if not text:
            continue
        if "=" not in text:
            raise ValueError(f"target id override must be NAME=UUID, got {text!r}")
        name, target_id = text.split("=", 1)
        name = name.strip()
        target_id = target_id.strip()
        if not name or not target_id:
            raise ValueError(f"target id override must be NAME=UUID, got {text!r}")
        mapping[name] = target_id
    return mapping


def route_tokens(entry):
    toks = set()
    route = (entry.get("route") or "").lower().strip("/").split("?")[0]
    parts = [p for p in route.split("/") if p]
    while parts and parts[0] in ("rest", "api", "v1", "v2", "v3"):
        parts = parts[1:]
    if parts:
        full = "/".join(parts)
        if len(full) >= 4:
            toks.add(full)
        last = re.split(r"[?=&.#]", parts[-1])[0].strip("{}:- ")
        if len(last) >= 4 and last not in STOP:
            toks.add(last)
    return {t for t in toks if t}


def finding_classes(hay):
    return {c for c, kws in CLASS_KEYWORDS.items() if any(k in hay for k in kws)}


def benchmark_hypothesis_seed_payload(card, *, target_id=None, created_by="benchmark_targets.py"):
    followups = card.get("benchmark_followups") if isinstance(card.get("benchmark_followups"), list) else []
    return {
        "target_id": target_id,
        "benchmark": card.get("target") or "benchmark",
        "scorecard_id": f"{card.get('target') or 'benchmark'}:{card.get('phase') or 'scan_finish'}",
        "scorecard_scan_id": card.get("scan_id"),
        "followups": followups,
        "created_by": created_by,
    }


def seed_benchmark_hypotheses(api, card, *, target_id=None, created_by="benchmark_targets.py"):
    followups = card.get("benchmark_followups") if isinstance(card.get("benchmark_followups"), list) else []
    if not followups:
        return {
            "submitted": False,
            "reason": "no_benchmark_followups",
            "created_or_endorsed": 0,
            "skipped_count": 0,
            "execution_enabled": False,
            "findings_created": 0,
            "queued_scans": 0,
        }
    body = benchmark_hypothesis_seed_payload(card, target_id=target_id, created_by=created_by)
    result = _post(f"{api}/arsenal/hypotheses/from-benchmark", body)
    return {"submitted": True, "request": body, "response": result}


def _benchmark_miss_followup(miss, fixture, auth_workflow):
    """Translate one missed expectation into an actionable, non-claiming work item.

    This deliberately emits only Command Arsenal actions that exist today. Families
    without a focused executor stay as detector-gap records so the scorecard does
    not imply a runnable campaign where none exists.
    """
    family = str(miss.get("family") or "").lower()
    proof = str(miss.get("proof") or "deterministic").lower()
    route = miss.get("route")
    benchmark = fixture.get("name") or "benchmark"
    check_family = FOCUSED_FAMILY_FOR_BENCHMARK_MISS.get(family)
    target_url = fixture.get("target_url")
    hints = []
    if family == "nosqli":
        hints.append("json_body_operator_probes")
    if family == "sqli" and route and any(token in str(route).lower() for token in ("login", "coupon", "review")):
        hints.append("post_body_params")
    if proof == "browser":
        hints.append("browser_proof_required")
    if family == "bola":
        hints.append("cross_principal_differential_required")

    blockers = []
    if family in AUTH_REQUIRED_FAMILIES and auth_workflow.get("status") == "blocked":
        blockers.extend(auth_workflow.get("blockers") or ["missing_required_auth_context"])
    if family == "bola" and not auth_workflow.get("two_principal_observed"):
        if "missing_second_principal" not in blockers:
            blockers.append("missing_second_principal")

    base = {
        "id": f"benchmark-miss:{benchmark}:{miss.get('id')}",
        "benchmark": benchmark,
        "expectation_id": miss.get("id"),
        "family": family,
        "route": route,
        "proof_required": proof,
        "min_severity": miss.get("min_severity"),
        "status": "ready",
        "operator_hints": hints,
        "blocked_by": blockers,
        "reason": "missing_required_auth_context" if blockers else "missing_verified_benchmark_expectation",
    }

    if not check_family or not target_url:
        base["status"] = "detector_gap"
        base["next_test_action"] = None
        base["developer_note"] = (
            "No focused-family executor currently maps this benchmark family; improve the generic detector "
            "or add a registered executor before this miss can be campaign-queued."
        )
        return base

    params = {
        "target": target_url,
        "check_family": check_family,
        "scan_type": "smart",
        "budget_profile": "thorough",
        "no_early_stop": True,
    }
    if family == "bola":
        params["exploit_depth"] = True
    if blockers:
        base["status"] = "blocked"
        base["next_test_action"] = None
        base["blocked_action_template"] = {
            "command": "scan.focused_family",
            "risk_tier": "active",
            "parameters": params,
        }
    else:
        base["next_test_action"] = {
            "command": "scan.focused_family",
            "risk_tier": "active",
            "parameters": params,
        }
    return base


def mint_token(target_url, login_cfg, email, password):
    """Sign up (best-effort) + login to mint a bearer token."""
    base = target_url.rstrip("/")
    login = login_cfg.get("url", "/rest/user/login")
    ef = login_cfg.get("email_field", "email")
    pf = login_cfg.get("password_field", "password")
    # best-effort signup (ignore failures — account may exist)
    for signup in ("/api/Users/", "/identity/api/auth/signup"):
        try:
            _post(base + signup, {ef: email, pf: password, "passwordRepeat": password,
                                  "name": email.split("@")[0], "number": "9999999999",
                                  "securityQuestion": {"id": 1}, "securityAnswer": "x"})
        except Exception:
            pass
    try:
        resp = _post(base + login, {ef: email, pf: password})
        # token under common shapes
        return (resp.get("authentication", {}) or {}).get("token") or resp.get("token") or resp.get("access_token")
    except Exception:
        return None


def _report_invariants(report):
    """Run the shared report-invariant checker (§2/§10) — empty list == consistent."""
    try:
        sys.path.insert(0, os.path.join(REPO, "scanner"))
        from findings import check_report_invariants
        return check_report_invariants(report)
    except Exception as e:
        return [f"invariant-check-unavailable: {e}"]


def collect_scorecard(report, fixture):
    findings = report.get("findings") or []
    enriched = []
    for f in findings:
        hay = " ".join(str(f.get(k, "")) for k in
                       ("title", "url", "category", "type", "cwe", "description", "name")).lower()
        sev = (f.get("severity") or "").lower()
        enriched.append((f, hay, finding_classes(hay), sev, bool(f.get("verified"))))

    high_crit = [e for e in enriched if e[3] in ("high", "critical")]
    verified_hc = [e for e in high_crit if e[4]]
    suspected_hc = [e for e in high_crit if not e[4]]

    auth_states = ((report.get("smart_coverage") or {}).get("auth_states_tested") or [])
    auth_cfg = fixture.get("auth") or {}
    required_auth_states = []
    if auth_cfg.get("user1_login"):
        required_auth_states.append("user1")
    if auth_cfg.get("requires_two_users") or auth_cfg.get("user2_login"):
        required_auth_states.append("user2")
    observed_auth_states = sorted({str(item).lower() for item in auth_states if item})
    missing_auth_states = sorted(set(required_auth_states) - set(observed_auth_states))
    auth_workflow = {
        "required_auth_states": required_auth_states,
        "observed_auth_states": observed_auth_states,
        "missing_auth_states": missing_auth_states,
        "two_principal_required": "user2" in required_auth_states,
        "two_principal_observed": {"user1", "user2"}.issubset(set(observed_auth_states)),
        "status": "blocked" if missing_auth_states else ("ready" if required_auth_states else "not_required"),
        "blockers": (
            ["missing_required_auth_states"]
            + (["missing_second_principal"] if "user2" in missing_auth_states else [])
        ) if missing_auth_states else [],
    }

    expected = fixture.get("expected", [])
    found, missed = [], []
    for ent in expected:
        compat = COMPAT.get(ent["family"], {ent["family"]})
        toks = route_tokens(ent)
        minsev = SEV_RANK.get(ent.get("min_severity", "high"), 3)
        proof = ent.get("proof", "deterministic")
        hit = None
        for f, hay, classes, sev, ver in high_crit:
            if not (classes & compat):
                continue
            if toks and not any(t in hay for t in toks):
                continue
            if SEV_RANK.get(sev, 0) < minsev:
                continue
            if proof in ("verified", "browser") and not ver:
                continue  # required proof not present
            hit = f
            break
        (found if hit else missed).append({
            "id": ent["id"], "family": ent["family"], "route": ent.get("route"),
            "proof": proof, "min_severity": ent.get("min_severity", "high"),
            "evidence": (hit.get("title") if hit else None),
        })
    followups = [_benchmark_miss_followup(m, fixture, auth_workflow) for m in missed]

    cov = ((report.get("smart_coverage") or {}).get("endpoints") or {})
    active = report.get("active_checks") or {}
    return {
        "total_findings": len(findings),
        "verified_high_critical": len(verified_hc),
        "suspected_high_critical": len(suspected_hc),
        "false_positive_risk": round(len(suspected_hc) / max(1, len(high_crit)), 2),
        "coverage_percent": cov.get("coverage"),
        "endpoints_discovered": cov.get("discovered"),
        "endpoints_tested": cov.get("tested"),
        "budget_exhausted": bool(active.get("budget_exhausted")),
        "budget_exhausted_reason": active.get("budget_exhausted_reason"),
        "auth_blocked": bool(report.get("auth_blocked")) or "auth_missing" in str(report.get("status", "")),
        "auth_states_tested": auth_states,
        "auth_workflow": auth_workflow,
        "timeout": "timeout" in str(report.get("error_message", "")).lower()
                   or "max duration" in str(report.get("error_message", "")).lower(),
        "error": report.get("error_message") or None,
        "expected_found": found,
        "expected_missed": missed,
        "benchmark_followups": followups,
        "body_completion_diagnostics": collect_body_completion_diagnostics(report),
        "expected_recall": round(len(found) / max(1, len(expected)), 2),
    }


def apply_gates(card, fixture):
    gates = fixture.get("gates", {})
    results = []
    def chk(name, ok, detail):
        results.append({"gate": name, "pass": bool(ok), "detail": detail})
    invariant_violations = card.get("report_invariant_violations") or []
    chk("report_invariants_clean", not invariant_violations,
        "clean" if not invariant_violations else "; ".join(str(v) for v in invariant_violations[:5]))
    chk("grade_reliable", card.get("grade_reliable") is not False,
        f"grade_reliable={card.get('grade_reliable')}")
    chk("active_execution_ok", not bool(card.get("active_execution_failed")),
        f"active_execution_failed={bool(card.get('active_execution_failed'))}")
    chk("report_not_degraded", not bool(card.get("report_degraded")),
        f"report_degraded={bool(card.get('report_degraded'))}")
    if "retest_settled" in card:
        chk("retest_settled", card.get("retest_settled") is True,
            f"retest_settled={card.get('retest_settled')}")
    if "min_verified_high_critical" in gates:
        n = gates["min_verified_high_critical"]
        chk("min_verified_high_critical", card["verified_high_critical"] >= n,
            f"{card['verified_high_critical']} >= {n}")
    if "max_unverified_high_ratio" in gates:
        m = gates["max_unverified_high_ratio"]
        chk("max_unverified_high_ratio", card["false_positive_risk"] <= m,
            f"{card['false_positive_risk']} <= {m}")
    if gates.get("require_verified_sqli"):
        ok = any(e["family"] == "sqli" for e in card["expected_found"])
        chk("require_verified_sqli", ok, "verified SQLi present" if ok else "no verified SQLi")
    if gates.get("require_browser_proven_xss"):
        ok = any(e["family"] == "xss" and e["proof"] == "browser" for e in card["expected_found"])
        chk("require_browser_proven_xss", ok, "browser XSS present" if ok else "no browser-proven XSS")
    if gates.get("require_verified_bola"):
        ok = any(e["family"] == "bola" for e in card["expected_found"])
        chk("require_verified_bola", ok, "verified BOLA present" if ok else "no verified BOLA")
    return results


def artifact_metadata(passed: bool) -> dict:
    status = "passed_benchmark_scorecard" if passed else "failed_benchmark_scorecard"
    return {
        "artifact_type": "benchmark_scorecard_run",
        "artifact_status": status,
        "artifact_note": (
            "Tracked benchmark scorecard. A tracked file is not a success claim: "
            "passed=true means every configured gate passed; passed=false means "
            "at least one configured gate failed."
        ),
    }


def run_target(name, api, timeout, do_auth, preset_scan_id=None, rescore_after_retest=False, retest_wait=600):
    fx = yaml.safe_load(open(os.path.join(FIXTURE_DIR, f"{name}.yaml")))
    report = None
    scan_id = preset_scan_id
    two_user = False
    if not scan_id:
        opts = dict(fx.get("scan_options") or {})
        if do_auth and fx.get("auth"):
            t1 = mint_token(fx["target_url"], fx["auth"].get("user1_login", {}),
                            "bench.u1@shaker.test", "Bench!Pass1")
            if t1:
                opts["auth_header"] = f"Bearer {t1}"
            if fx["auth"].get("requires_two_users") or fx["auth"].get("user2_login"):
                t2 = mint_token(fx["target_url"], fx["auth"].get("user2_login", fx["auth"].get("user1_login", {})),
                                "bench.u2@shaker.test", "Bench!Pass2")
                if t2:
                    opts["user2_header"] = f"Bearer {t2}"
                    two_user = True
        resp = _post(f"{api}/scans", {"target": fx["target_url"], "options": opts})
        scan_id = resp.get("id") or resp.get("scan_id")
        print(f"[{name}] submitted scan {scan_id} (two_user={two_user})", flush=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = _get(f"{api}/scans/{scan_id}")
            if st.get("status") in ("completed", "failed", "cancelled"):
                break
            time.sleep(30)
    report = _get(f"{api}/scans/{scan_id}/result")

    # Scorecard #1: at scan finish (scan-time triage).
    finish_card = collect_scorecard(report, fx)
    finish_card["phase"] = "scan_finish"
    # §4 active-execution honesty + §2 report-invariant signals on the card.
    meta = report.get("scan_metadata") or {}
    result_block = report.get("result") or {}
    # §4: record the resolved budget contract the scan actually ran with, so a
    # budget change is visible in the scorecard history.
    _opts = meta.get("options") if isinstance(meta.get("options"), dict) else {}
    finish_card["resolved_budget"] = _opts.get("resolved_budget")
    finish_card["invariant_violations"] = report.get("invariant_violations")
    finish_card["active_execution_failed"] = bool(meta.get("active_execution_failed"))
    finish_card["grade_reliable"] = result_block.get("grade_reliable")
    finish_card["report_degraded"] = bool(report.get("degraded") or meta.get("degraded") or result_block.get("degraded"))
    finish_card["report_invariant_violations"] = list(report.get("invariant_violations") or []) or _report_invariants(report)
    finish_card["two_user"] = two_user

    cards_by_phase = {"scan_finish": finish_card}
    scoring_card = finish_card

    # Scorecard #2: after the deterministic auto-retest wave settles, re-read live
    # findings so the verified count reflects PROOF, not just scan-time triage (§6).
    if rescore_after_retest:
        settled = wait_for_retest_settle(api, timeout=retest_wait)
        live = fetch_live_findings(api, scan_id)
        if live is not None:
            retest_report = dict(report)
            retest_report["findings"] = live
            post_card = collect_scorecard(retest_report, fx)
            post_card["phase"] = "post_retest"
            post_card["retest_settled"] = settled
            post_card["two_user"] = two_user
            # The post-retest card is the scoring card, so carry over the report-level
            # trust signals from scan finish. A verified-count lift must not hide a
            # degraded report, active-lane failure, or invariant violation.
            post_card["resolved_budget"] = finish_card.get("resolved_budget")
            post_card["invariant_violations"] = finish_card.get("invariant_violations")
            post_card["active_execution_failed"] = finish_card.get("active_execution_failed")
            post_card["grade_reliable"] = finish_card.get("grade_reliable")
            post_card["report_degraded"] = finish_card.get("report_degraded")
            post_card["report_invariant_violations"] = finish_card.get("report_invariant_violations")
            cards_by_phase["post_retest"] = post_card
            scoring_card = post_card  # gates judged on proven state
            print(f"[{name}] post-retest re-score: verified H/C "
                  f"{finish_card['verified_high_critical']} -> {post_card['verified_high_critical']}", flush=True)

    gates = apply_gates(scoring_card, fx)
    out = dict(scoring_card)
    out["scan_id"] = scan_id
    out["target"] = name
    out["gates"] = gates
    out["passed"] = all(g["pass"] for g in gates)
    out["scorecards"] = cards_by_phase
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--api", default="http://localhost:8080")
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--auth", action="store_true", help="mint bearer tokens from fixture auth config")
    ap.add_argument("--scan-id", default=None, help="score an existing scan id instead of submitting")
    ap.add_argument("--rescore-after-retest", action="store_true",
                    help="after the scan, wait for the auto-retest wave then re-score from live verdicts (§6)")
    ap.add_argument("--retest-wait", type=int, default=900, help="max seconds to wait for the retest wave to settle")
    ap.add_argument("--allow-stale-fleet", action="store_true",
                    help="run even if the worker fleet is not uniform (NOT recommended — §10 gate)")
    ap.add_argument("--seed-hypotheses", action="store_true",
                    help="post benchmark_followups to /arsenal/hypotheses/from-benchmark after scoring")
    ap.add_argument("--hypothesis-target-id", action="append", default=[],
                    help="optional benchmark target binding as NAME=UUID; repeat for multiple targets")
    ap.add_argument("--hypothesis-created-by", default="benchmark_targets.py",
                    help="created_by value for benchmark hypothesis seeding")
    args = ap.parse_args()
    try:
        hypothesis_target_ids = parse_target_id_overrides(args.hypothesis_target_id)
    except ValueError as e:
        print(f"ABORT: {e}", file=sys.stderr)
        return 2

    # §3/§10 fleet gate: a stale/mixed fleet silently produces bad numbers. Abort
    # unless explicitly overridden, and record the fleet state in the output.
    uniform, fleet = check_fleet(args.api)
    if not uniform and not args.allow_stale_fleet:
        print(f"ABORT: worker fleet is not uniform — refusing to benchmark on a mixed/stale fleet: {fleet}",
              file=sys.stderr)
        print("       restart all workers (docker restart $(docker ps -aq --filter name=shakerscan-worker)) "
              "or pass --allow-stale-fleet.", file=sys.stderr)
        return 2
    if not uniform:
        print(f"WARN: proceeding on a non-uniform fleet (--allow-stale-fleet): {fleet}", file=sys.stderr)

    os.makedirs(OUT_DIR, exist_ok=True)
    overall_ok = True
    cards = []
    for name in args.targets:
        try:
            card = run_target(name, args.api, args.timeout, args.auth, args.scan_id,
                              rescore_after_retest=args.rescore_after_retest, retest_wait=args.retest_wait)
        except Exception as e:
            card = {"target": name, "error": str(e), "passed": False}
        if args.seed_hypotheses:
            target_id = hypothesis_target_ids.get(name) or hypothesis_target_ids.get(str(card.get("target") or ""))
            try:
                card["benchmark_hypothesis_seed"] = seed_benchmark_hypotheses(
                    args.api,
                    card,
                    target_id=target_id,
                    created_by=args.hypothesis_created_by,
                )
            except Exception as e:
                card["benchmark_hypothesis_seed"] = {
                    "submitted": False,
                    "error": str(e),
                    "created_or_endorsed": 0,
                    "skipped_count": 0,
                    "execution_enabled": False,
                    "findings_created": 0,
                    "queued_scans": 0,
                }
        cards.append(card)
        overall_ok = overall_ok and card.get("passed")
        print(f"\n=== {name} scorecard ({card.get('phase', 'scan_finish')}) ===")
        print(f"  verified H/C: {card.get('verified_high_critical')}  suspected: {card.get('suspected_high_critical')}  "
              f"FP-risk: {card.get('false_positive_risk')}  coverage: {card.get('coverage_percent')}")
        print(f"  expected recall: {card.get('expected_recall')}  "
              f"found {len(card.get('expected_found', []))}/{len(card.get('expected_found', []))+len(card.get('expected_missed', []))}")
        if card.get("active_execution_failed"):
            print("    [DEGRADED] active-execution failed: grade not reliable for active coverage")
        if card.get("report_invariant_violations"):
            print(f"    [INVARIANT] report blocks disagree: {card['report_invariant_violations']}")
        for m in card.get("expected_missed", []):
            print(f"    MISS {m['id']} ({m['family']} {m['route']})")
        for f in card.get("benchmark_followups", []):
            action = f.get("next_test_action") or f.get("blocked_action_template") or {}
            command = action.get("command") or "detector_gap"
            print(f"    FOLLOWUP {f.get('expectation_id')} [{f.get('status')}]: {command} "
                  f"{f.get('blocked_by') or ''}")
        if card.get("benchmark_hypothesis_seed"):
            seed = card["benchmark_hypothesis_seed"]
            response = seed.get("response") if isinstance(seed.get("response"), dict) else {}
            created = response.get("created_or_endorsed", seed.get("created_or_endorsed", 0))
            skipped = response.get("skipped_count", seed.get("skipped_count", 0))
            status = "submitted" if seed.get("submitted") else "not-submitted"
            detail = seed.get("error") or seed.get("reason") or ""
            print(f"    HYPOTHESES {status}: created_or_endorsed={created} skipped={skipped} {detail}")
        for g in card.get("gates", []):
            print(f"    [{'PASS' if g['pass'] else 'FAIL'}] {g['gate']}: {g['detail']}")
    run = {
        **artifact_metadata(bool(overall_ok)),
        "fleet": fleet, "fleet_uniform": uniform,
        "rescore_after_retest": args.rescore_after_retest,
        "seed_hypotheses": args.seed_hypotheses,
        "targets": cards, "passed": overall_ok,
    }
    # Latest-pointer (stable name) plus a timestamped, git-trackable record so a
    # passing/failing run is visible in history (§10 — scorecards committed).
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    latest = os.path.join(OUT_DIR, f"benchmark-{'_'.join(args.targets)}.json")
    archive = os.path.join(OUT_DIR, f"benchmark-{'_'.join(args.targets)}-{stamp}.json")
    payload = json.dumps(run, indent=2)
    open(latest, "w").write(payload)
    open(archive, "w").write(payload)
    print(f"\nwrote {latest}\nwrote {archive}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
