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


def _get(url, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _post(url, body, timeout=30):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


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
            "proof": proof, "evidence": (hit.get("title") if hit else None),
        })

    cov = ((report.get("smart_coverage") or {}).get("endpoints") or {})
    active = report.get("active_checks") or {}
    auth_states = ((report.get("smart_coverage") or {}).get("auth_states_tested") or [])
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
        "timeout": "timeout" in str(report.get("error_message", "")).lower()
                   or "max duration" in str(report.get("error_message", "")).lower(),
        "error": report.get("error_message") or None,
        "expected_found": found,
        "expected_missed": missed,
        "expected_recall": round(len(found) / max(1, len(expected)), 2),
    }


def apply_gates(card, fixture):
    gates = fixture.get("gates", {})
    results = []
    def chk(name, ok, detail):
        results.append({"gate": name, "pass": bool(ok), "detail": detail})
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


def run_target(name, api, timeout, do_auth, preset_scan_id=None):
    fx = yaml.safe_load(open(os.path.join(FIXTURE_DIR, f"{name}.yaml")))
    report = None
    scan_id = preset_scan_id
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
        resp = _post(f"{api}/scans", {"target": fx["target_url"], "options": opts})
        scan_id = resp.get("id") or resp.get("scan_id")
        print(f"[{name}] submitted scan {scan_id}", flush=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = _get(f"{api}/scans/{scan_id}")
            if st.get("status") in ("completed", "failed", "cancelled"):
                break
            time.sleep(30)
    report = _get(f"{api}/scans/{scan_id}/result")
    card = collect_scorecard(report, fx)
    gates = apply_gates(card, fx)
    card["scan_id"] = scan_id
    card["target"] = name
    card["gates"] = gates
    card["passed"] = all(g["pass"] for g in gates)
    return card


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--api", default="http://localhost:8080")
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--auth", action="store_true", help="mint bearer tokens from fixture auth config")
    ap.add_argument("--scan-id", default=None, help="score an existing scan id instead of submitting")
    args = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    overall_ok = True
    cards = []
    for name in args.targets:
        try:
            card = run_target(name, args.api, args.timeout, args.auth, args.scan_id)
        except Exception as e:
            card = {"target": name, "error": str(e), "passed": False}
        cards.append(card)
        overall_ok = overall_ok and card.get("passed")
        print(f"\n=== {name} scorecard ===")
        print(f"  verified H/C: {card.get('verified_high_critical')}  suspected: {card.get('suspected_high_critical')}  "
              f"FP-risk: {card.get('false_positive_risk')}  coverage: {card.get('coverage_percent')}")
        print(f"  expected recall: {card.get('expected_recall')}  "
              f"found {len(card.get('expected_found', []))}/{len(card.get('expected_found', []))+len(card.get('expected_missed', []))}")
        for m in card.get("expected_missed", []):
            print(f"    MISS {m['id']} ({m['family']} {m['route']})")
        for g in card.get("gates", []):
            print(f"    [{'PASS' if g['pass'] else 'FAIL'}] {g['gate']}: {g['detail']}")
    out = os.path.join(OUT_DIR, f"benchmark-{'_'.join(args.targets)}.json")
    open(out, "w").write(json.dumps(cards, indent=2))
    print(f"\nwrote {out}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
