#!/usr/bin/env python3
"""End-to-end DAST benchmark runner (proposed-next-steps.md §1).

Submits one deterministic Scan per target fixture with the benchmark's fixed V2 policy and budget,
waits for completion, fetches the report,
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
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.parse
import urllib.error
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
# No cross-family aliases: each expected class is satisfied only by its own
# first-class family now that sensitive_exposure, nosqli, and authz_surface
# exist. broken_access_control still admits bola because object-level (BOLA) and
# function-level (BFLA) findings are both broken access control — that is one
# vulnerability class, not two distinct families aliased together.
COMPAT = {
    "sqli": {"sqli"}, "nosqli": {"nosqli"}, "xss": {"xss"},
    "bola": {"bola"},
    "broken_access_control": {"broken_access_control", "bola"},
    "sensitive_exposure": {"sensitive_exposure"},
    "webhook": {"webhook"}, "approval": {"approval"},
    "path_traversal": {"path_traversal"}, "jwt": {"jwt"}, "xxe": {"xxe"},
}
STOP = {"rest", "api", "http", "https", "html", "json", "www", "v1", "v2", "v3",
        "id", "user", "users", "identity", "workshop", "community"}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Every value must be a canonical Scan family: this drives an actual focused
# rerun, so a stale mapping runs the wrong verifier against the miss. NoSQLi and
# function-level authorization are first-class families now, and "auth" never was
# one -- a broken-access-control miss asked for a family the contract rejects.
FOCUSED_FAMILY_FOR_BENCHMARK_MISS = {
    "sqli": "sqli",
    "nosqli": "nosqli",
    "xss": "xss",
    "bola": "bola",
    # Function-level access control is authz_surface; object-level is bola.
    "broken_access_control": "authz_surface",
    "sensitive_exposure": "sensitive_exposure",
    "authz_surface": "authz_surface",
}
AUTH_REQUIRED_FAMILIES = {"bola", "broken_access_control"}
PUBLIC_SCAN_OPTION_FIELDS = frozenset({
    "custom_endpoints",
    "require_current_workers",
    "placement",
    "parallel",
    "shards",
    "shard_strategy",
    "auth_state_shards",
})
BENCHMARK_CREDENTIAL_CAPABILITIES = [
    "http.request", "web.probe", "web.crawl", "web.content_discover",
    "templates.passive_scan", "templates.scan", "collections.replay_safe",
    "collections.replay_active", "xss.verify", "sqli.verify",
    "xss.request_verify", "sqli.request_verify", "authz.verify",
]


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
        "tool": f.get("tool"),
        "severity": f.get("severity"),
        # Live API rows carry `is_verified` (the derived proof projection); `verified` is not a
        # field they have, so reading only it was dead code and the whole expression depended on
        # the verdict alone. Read both so a proof-projected row counts even if the verdict is
        # absent.
        "verified": bool(f.get("is_verified") or f.get("verified")) or verdict == "exploited",
        "confidence_tier": f.get("confidence_tier"),
        "evidence": f.get("evidence"),
        "browser_proof": f.get("browser_proof"),
        "poe_result": f.get("poe_result"),
    }


def _post_retest_findings(scan_findings, live_findings):
    """Overlay live verdicts without discarding immutable scan-time proof."""
    by_exact = {}
    by_title_url = {}
    for finding in scan_findings or []:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "").strip().lower()
        url = str(finding.get("url") or "").strip()
        tool = str(finding.get("tool") or "").strip().lower()
        by_exact.setdefault((title, url, tool), finding)
        by_title_url.setdefault((title, url), finding)

    merged_findings = []
    for live in live_findings or []:
        if not isinstance(live, dict):
            continue
        title = str(live.get("title") or "").strip().lower()
        url = str(live.get("url") or "").strip()
        tool = str(live.get("tool") or "").strip().lower()
        original = by_exact.get((title, url, tool)) or by_title_url.get((title, url)) or {}
        merged = dict(original)
        merged.update(live)

        original_evidence = original.get("evidence")
        live_evidence = live.get("evidence")
        for name, value in (("original", original_evidence), ("live", live_evidence)):
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except (TypeError, ValueError):
                    value = None
            if name == "original":
                original_evidence = value
            else:
                live_evidence = value
        if isinstance(original_evidence, dict) and isinstance(live_evidence, dict):
            merged["evidence"] = {**original_evidence, **live_evidence}
        elif isinstance(original_evidence, dict) and not live_evidence:
            merged["evidence"] = original_evidence

        for proof_field in ("browser_proof", "poe_result"):
            if not merged.get(proof_field) and original.get(proof_field):
                merged[proof_field] = original[proof_field]
        merged_findings.append(merged)
    return merged_findings


def _has_browser_proof(finding):
    """Require the same structured ShakerScan browser proof as report promotion."""
    evidence = finding.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (TypeError, ValueError):
            evidence = {}
    if not isinstance(evidence, dict):
        evidence = {}
    for proof in (finding.get("browser_proof"), evidence.get("browser_proof")):
        if not isinstance(proof, dict) or proof.get("proven") is not True:
            continue
        if (
            proof.get("proof_producer") == "shakerscan"
            and str(proof.get("evidence_type") or "").strip().lower()
            in {"dom_execution", "browser_execution"}
            and str(proof.get("technique") or "").strip().lower().startswith("headless_xss_")
        ):
            return True
    return False


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


def _write_json(method, url, body, timeout=30):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8", errors="replace"))
        except (TypeError, ValueError):
            payload = {}
        detail = payload.get("detail") if isinstance(payload, dict) else None
        if isinstance(detail, list):
            safe_detail = [
                {
                    key: item.get(key)
                    for key in ("loc", "msg", "type")
                    if item.get(key) is not None
                }
                for item in detail[:20]
                if isinstance(item, dict)
            ]
        elif isinstance(detail, dict):
            safe_detail = {
                key: detail.get(key)
                for key in ("error", "message")
                if detail.get(key) is not None
            }
        else:
            safe_detail = str(detail or "request rejected")[:500]
        path = urllib.parse.urlsplit(url).path or "/"
        raise RuntimeError(
            f"HTTP {exc.code} {method} {path}: {json.dumps(safe_detail, sort_keys=True)}"
        ) from None


def _post(url, body, timeout=30):
    return _write_json("POST", url, body, timeout=timeout)


def _patch(url, body, timeout=30):
    return _write_json("PATCH", url, body, timeout=timeout)


def _canonical_benchmark_authority(api, target_url, *, credential_risk):
    """Create an exact-target scope/approval pair for one authorized benchmark."""
    target = _post(f"{api}/targets", {
        "url": target_url,
        "name": "DAST benchmark target",
    })
    target_id = str(target.get("id") or "")
    if not target_id:
        raise RuntimeError("benchmark target registration returned no target id")
    parsed = urllib.parse.urlsplit(target_url)
    host = str(parsed.hostname or "").strip()
    scope = _post(f"{api}/arsenal/scope/preview", {
        "url": target_url,
        "target_id": target_id,
        "allowed_hosts": [host] if host else [],
        "environment": "lab" if host in {"localhost", "127.0.0.1", "host.docker.internal"} else "production",
    })
    scope_receipt = scope.get("scope_receipt") or {}
    scope_id = str(scope_receipt.get("receipt_id") or scope_receipt.get("id") or "")
    if not scope_id:
        raise RuntimeError("benchmark scope preview returned no receipt id")
    if scope_receipt.get("verdict") == "blocked":
        raise RuntimeError("benchmark target scope was blocked")
    approval = _post(f"{api}/arsenal/approvals", {
        "scope_receipt_id": scope_id,
        "risk_tier": "credential" if credential_risk else "active",
        "confirmations": ["confirm_authorized", "confirm_scope_reviewed"],
        "action_name": "scan.submit",
        "approved_by": "benchmark_targets.py",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat(),
    })
    approval_id = str((approval.get("approval_receipt") or {}).get("id") or "")
    if not approval_id:
        raise RuntimeError("benchmark approval returned no receipt id")
    return target_id, approval_id


def _create_benchmark_bearer_profile(api, *, target_id, token, lane):
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
    name = f"Ephemeral benchmark {lane}"
    listing = _get(
        f"{api}/credential-profiles?{urllib.parse.urlencode({
            'target_kind': 'web',
            'target_id': target_id,
            'include_inactive': 'true',
        })}",
        timeout=30,
    )
    existing = next(
        (
            item for item in listing.get("profiles", [])
            if isinstance(item, dict) and item.get("name") == name
        ),
        None,
    )
    if existing is not None:
        if (
            existing.get("auth_kind") != "bearer_token"
            or existing.get("principal_slot") != lane
        ):
            raise RuntimeError(
                f"existing benchmark {lane} credential profile has incompatible metadata"
            )
        profile_id = str(existing.get("id") or "")
        if not profile_id:
            raise RuntimeError(f"existing benchmark {lane} credential profile has no id")
        patched = _patch(f"{api}/credential-profiles/{profile_id}", {
            "expected_record_version": existing.get("record_version"),
            "name": name,
            "principal_label": f"benchmark-{lane}",
            "principal_slot": lane,
            "expires_at": expires_at,
            "is_active": True,
            "allowed_capabilities": BENCHMARK_CREDENTIAL_CAPABILITIES,
        })
        patched_profile = patched.get("profile") or {}
        rotated = _post(f"{api}/credential-profiles/{profile_id}/rotate", {
            "expected_record_version": patched_profile.get("record_version"),
            "secret": token,
            "expires_at": expires_at,
            "created_by": "benchmark_targets.py",
        })
        rotated_id = str((rotated.get("profile") or {}).get("id") or "")
        if rotated_id != profile_id:
            raise RuntimeError(f"benchmark {lane} credential rotation returned the wrong id")
        return rotated_id

    created = _post(f"{api}/credential-profiles", {
        "target_kind": "web",
        "target_id": target_id,
        "name": name,
        "auth_kind": "bearer_token",
        "principal_label": f"benchmark-{lane}",
        "principal_slot": lane,
        "secret": token,
        "expires_at": expires_at,
        "allowed_capabilities": BENCHMARK_CREDENTIAL_CAPABILITIES,
        "created_by": "benchmark_targets.py",
    })
    profile_id = str((created.get("profile") or {}).get("id") or "")
    if not profile_id:
        raise RuntimeError(f"benchmark {lane} credential profile returned no id")
    return profile_id


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
    """Return the substrings a finding must contain to be about this expectation's route.

    A declared route ALWAYS yields at least one token. The four-character floor exists to keep a
    tiny token from matching noise, but returning an empty set was far worse than a noisy match:
    the match loop skipped the route filter entirely when the set was empty, so a short route like
    ``/ftp`` was credited by any finding of a compatible class -- whatever route it was about. The
    floor now selects the PREFERRED token; the cleaned route is kept as the fallback so the
    constraint is never silently dropped.
    """
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
        if not toks:
            # Every part was below the floor. Keep the route itself rather than no constraint.
            toks.update(token for token in (full, last) if token and token not in STOP)
    return {t for t in toks if t}


def match_expectation(entry, candidates, claimed_finding_ids):
    """Return the first candidate finding that satisfies ``entry``, or None.

    ``claimed_finding_ids`` is mutated by the caller, not here: a finding already credited to
    another expectation is skipped, because one finding satisfying several expectations inflates
    recall exactly as much as an unrelated finding satisfying one.
    """
    compat = COMPAT.get(entry["family"], {entry["family"]})
    toks = route_tokens(entry)
    minsev = SEV_RANK.get(entry.get("min_severity", "high"), 3)
    proof = entry.get("proof", "deterministic")
    for candidate in candidates:
        if str(candidate.get("finding_id")) in claimed_finding_ids:
            continue
        if not (set(candidate.get("classes") or ()) & compat):
            continue
        # A declared route is a requirement, never a hint that can evaporate.
        if toks and not any(token in str(candidate.get("hay") or "") for token in toks):
            continue
        if SEV_RANK.get(candidate.get("severity"), 0) < minsev:
            continue
        if proof in ("verified", "browser") and not candidate.get("verified"):
            continue
        if proof == "browser" and not candidate.get("browser_proven"):
            continue
        return candidate
    return None


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
    phone_suffix = int.from_bytes(hashlib.sha256(email.encode("utf-8")).digest()[:8], "big") % 1_000_000_000
    phone_number = str(9_000_000_000 + phone_suffix)
    # best-effort signup (ignore failures — account may exist)
    for signup in ("/api/Users/", "/identity/api/auth/signup"):
        try:
            _post(base + signup, {ef: email, pf: password, "passwordRepeat": password,
                                  "name": email.split("@")[0], "number": phone_number,
                                  "securityQuestion": {"id": 1}, "securityAnswer": "x"})
        except Exception:
            pass
    for attempt, delay in enumerate((0.0, 0.25, 0.5, 1.0)):
        if delay:
            time.sleep(delay)
        try:
            resp = _post(base + login, {ef: email, pf: password})
            token = (
                (resp.get("authentication", {}) or {}).get("token")
                or resp.get("token")
                or resp.get("access_token")
            )
            if token:
                return token
        except Exception:
            if attempt == 3:
                return None
    return None


def credential_bootstrap_url(target_url):
    """Translate Docker's host alias for a helper running on the host itself."""
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.hostname != "host.docker.internal":
        return target_url
    host = "127.0.0.1"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def _jwt_principal_identity(token):
    """Extract a stable principal claim from a server-issued JWT for comparison."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    for key in ("email", "user_id", "userId", "username", "sub", "id"):
        value = claims.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            normalized = str(value).strip().lower() if key in {"email", "username"} else str(value).strip()
            return f"{key}:{normalized}"
    return None


def _principal_identity_fingerprint(identity):
    """Return a bounded, non-claim fingerprint for benchmark receipts."""
    value = str(identity or "").strip()
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


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
        enriched.append((
            f,
            hay,
            finding_classes(hay),
            sev,
            bool(f.get("verified")),
            _has_browser_proof(f),
        ))

    high_crit = [e for e in enriched if e[3] in ("high", "critical")]
    verified_hc = [e for e in high_crit if e[4]]
    suspected_hc = [e for e in high_crit if not e[4]]
    verified_hc_families = sorted({family for entry in verified_hc for family in entry[2]})
    browser_proven_hc_families = sorted({
        family for entry in high_crit if entry[5] for family in entry[2]
    })

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
        "principal_contexts_scheduled": observed_auth_states,
        "missing_auth_states": missing_auth_states,
        "two_principal_required": "user2" in required_auth_states,
        "two_principal_contexts_scheduled": {"user1", "user2"}.issubset(set(observed_auth_states)),
        "two_principal_observed": {"user1", "user2"}.issubset(set(observed_auth_states)),
        "two_principal_observed_semantics": "compatibility_alias_for_contexts_scheduled",
        "principal_identities_validated": False,
        "authenticated_responses_accepted": None,
        "status": "blocked" if missing_auth_states else ("ready" if required_auth_states else "not_required"),
        "blockers": (
            ["missing_required_auth_states"]
            + (["missing_second_principal"] if "user2" in missing_auth_states else [])
        ) if missing_auth_states else [],
    }
    # SCAN-04: the distinct-principal leg must come from SERVER-OBSERVED proof, not a client-supplied
    # scan option. A verified cross_principal_replay finding is emitted only on the scanner path gated
    # by the fail-closed distinct-credential-fingerprint check (same_principal_context -> skip), so its
    # evidence `distinct_principal_control` is the authoritative distinct-principal receipt. A finding
    # label or a submitter-set benchmark option cannot satisfy this leg on its own.
    accepted_auth_replay = False
    server_observed_distinct_principals = False
    for finding, _hay, classes, _sev, verified, _browser in enriched:
        if not verified or "bola" not in classes:
            continue
        evidence = finding.get("evidence")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except (TypeError, ValueError):
                evidence = {}
        if not isinstance(evidence, dict):
            continue
        owner_status = evidence.get("owner_status", evidence.get("user1_status"))
        attacker_status = evidence.get("attacker_status", evidence.get("user2_status"))
        try:
            replay_accepted = 200 <= int(owner_status) < 300 and 200 <= int(attacker_status) < 300
        except (TypeError, ValueError):
            replay_accepted = False
        if bool(evidence.get("distinct_principal_control")) and replay_accepted:
            accepted_auth_replay = True
            server_observed_distinct_principals = True
            break
    auth_workflow["principal_identities_validated"] = server_observed_distinct_principals
    if server_observed_distinct_principals:
        auth_workflow["authenticated_responses_accepted"] = accepted_auth_replay

    expected = fixture.get("expected", [])
    found, missed = [], []
    # One finding may credit at most one expectation. Without this a single high-severity finding
    # satisfied every expectation whose class it happened to match, inflating recall silently.
    expectation_candidates = [
        {
            "finding": entry[0],
            # Findings carry an id; fall back to position so an id-less row is still distinct.
            "finding_id": str((entry[0] or {}).get("id") or f"index:{index}"),
            "hay": entry[1],
            "classes": entry[2],
            "severity": entry[3],
            "verified": entry[4],
            "browser_proven": entry[5],
        }
        for index, entry in enumerate(high_crit)
    ]
    claimed_finding_ids: set[str] = set()
    for ent in expected:
        proof = ent.get("proof", "deterministic")
        match = match_expectation(ent, expectation_candidates, claimed_finding_ids)
        if match is not None:
            claimed_finding_ids.add(str(match.get("finding_id")))
        hit = match.get("finding") if match else None
        (found if hit else missed).append({
            "id": ent["id"], "family": ent["family"], "route": ent.get("route"),
            "proof": proof, "min_severity": ent.get("min_severity", "high"),
            "evidence": (hit.get("title") if hit else None),
        })
    followups = [_benchmark_miss_followup(m, fixture, auth_workflow) for m in missed]

    cov = ((report.get("smart_coverage") or {}).get("endpoints") or {})
    active = report.get("active_checks") or {}
    # Canonical V2 truth: the per-family rollup and grade reliability the pure
    # finalizer computes, read directly instead of via legacy projections.
    canonical_coverage = report.get("coverage") or {}
    family_coverage = [
        dict(row) for row in (canonical_coverage.get("family_coverage") or [])
        if isinstance(row, dict)
    ]
    selected_family_gaps = list(canonical_coverage.get("selected_family_gaps") or [])
    canonical_grade_reliable = (report.get("result") or {}).get("grade_reliable")
    attempted_families = {
        str(row.get("family"))
        for row in family_coverage
        if int(row.get("attempted_candidates") or 0) > 0
        or str(row.get("coverage_status")) == "complete"
    }
    # Mandatory family-attempt gate (§17): a selected expected family that
    # attempted nothing is a hard failure, independent of finding matching.
    family_attempt_failures = sorted({
        row.get("family") for row in family_coverage
        if row.get("required") and str(row.get("reason")) == "zero_attempts"
    })
    return {
        "total_findings": len(findings),
        "verified_high_critical": len(verified_hc),
        "verified_high_critical_families": verified_hc_families,
        "browser_proven_high_critical_families": browser_proven_hc_families,
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
        "family_coverage": family_coverage,
        "selected_family_gaps": selected_family_gaps,
        "family_attempt_failures": family_attempt_failures,
        "attempted_families": sorted(attempted_families),
        "canonical_grade_reliable": canonical_grade_reliable,
    }


def apply_quality_bar(card, fixture):
    """Evaluate the standard this benchmark is FOR, separately from what currently ships.

    Setting the shipped numbers as the only gate makes a passing scorecard mean "no worse than the
    day we lowered it" while reading like "the engine meets its bar". Both are recorded: the
    regression gates decide `passed` and keep CI honest about drift, and the quality bar is
    evaluated and reported every run so the distance to the intended standard is never hidden. It
    deliberately does not affect `passed` -- the release decision is a human one, made with both
    numbers in view.
    """
    bar = fixture.get("quality_bar") or {}
    if not bar:
        return None
    results = []

    def chk(name, ok, detail):
        results.append({"gate": name, "pass": bool(ok), "detail": detail})

    if "min_expected_recall" in bar:
        recall = card.get("expected_recall")
        measured = isinstance(recall, (int, float)) and not isinstance(recall, bool)
        chk("quality:min_expected_recall",
            measured and float(recall) >= float(bar["min_expected_recall"]),
            f"{recall if measured else 'not measured'} >= {bar['min_expected_recall']}")
    if bar.get("require_browser_proven_xss"):
        ok = "xss" in (card.get("browser_proven_high_critical_families") or [])
        chk("quality:require_browser_proven_xss", ok,
            "browser XSS present" if ok else "no browser-proven XSS")
    if bar.get("require_reliable_grade"):
        chk("quality:grade_reliable", card.get("grade_reliable") is not False,
            f"grade_reliable={card.get('grade_reliable')}")
    if "max_known_expectation_gaps" in bar:
        declared = len((fixture.get("gates") or {}).get("known_expectation_gaps") or [])
        chk("quality:max_known_expectation_gaps",
            declared <= int(bar["max_known_expectation_gaps"]),
            f"{declared} declared gaps <= {bar['max_known_expectation_gaps']}")
    card["quality_gates"] = results
    card["quality_passed"] = all(item["pass"] for item in results)
    return results


def apply_gates(card, fixture):
    gates = fixture.get("gates", {})
    results = []
    def chk(name, ok, detail):
        results.append({"gate": name, "pass": bool(ok), "detail": detail})
    invariant_violations = card.get("report_invariant_violations") or []
    chk("report_invariants_clean", not invariant_violations,
        "clean" if not invariant_violations else "; ".join(str(v) for v in invariant_violations[:5]))
    completion_anomalies = (
        (card.get("body_completion_diagnostics") or {}).get("telemetry_anomalies") or []
    )
    chk(
        "completion_telemetry_consistent",
        not completion_anomalies,
        "clean" if not completion_anomalies else "; ".join(
            str(item.get("reason") or item) for item in completion_anomalies[:5]
        ),
    )
    # grade_reliable reports whether coverage was complete enough to trust the grade. That is a
    # real signal, but a fixture running at a budget that cannot cover its whole surface will
    # legitimately report partial, so the fixture decides whether it is a failure. Default remains
    # strict: a fixture that says nothing still requires a reliable grade.
    if gates.get("require_reliable_grade", True):
        chk("grade_reliable", card.get("grade_reliable") is not False,
            f"grade_reliable={card.get('grade_reliable')}")
    else:
        chk("grade_reliable_recorded", True,
            f"grade_reliable={card.get('grade_reliable')} (not gated by this fixture)")
    chk("active_execution_ok", not bool(card.get("active_execution_failed")),
        f"active_execution_failed={bool(card.get('active_execution_failed'))}")
    # §17 mandatory family-attempt gate: a selected family that attempted zero
    # candidates is a hard failure — no aliasing or finding can mask it.
    family_gaps = card.get("family_attempt_failures") or []
    chk("selected_families_attempted", not family_gaps,
        "all selected families attempted" if not family_gaps
        else "zero-attempt families: " + ", ".join(str(f) for f in family_gaps))
    chk("report_not_degraded", not bool(card.get("report_degraded")),
        f"report_degraded={bool(card.get('report_degraded'))}")
    if "retest_settled" in card:
        chk("retest_settled", card.get("retest_settled") is True,
            f"retest_settled={card.get('retest_settled')}")
    if "known_expectation_gaps" in gates:
        # Lowering a recall number to whatever the engine currently reaches erases the gap. Naming
        # the classes it cannot yet prove keeps the answer key intact -- it still describes what a
        # competent DAST should find -- while making the benchmark a regression detector at the
        # level actually shipped: a NEW miss fails even though the declared ones do not.
        declared = {
            str(item.get("id") or item) for item in gates["known_expectation_gaps"]
        }
        missed_ids = {str(item.get("id")) for item in (card.get("expected_missed") or [])}
        undeclared = sorted(missed_ids - declared)
        chk(
            "no_undeclared_expectation_misses",
            not undeclared,
            "only declared gaps missed" if not undeclared
            else "undeclared misses: " + ", ".join(undeclared),
        )
        # An improvement is not a failure, but it should be visible so the gap list can shrink.
        closed = sorted(declared - missed_ids)
        if closed:
            card.setdefault("closed_expectation_gaps", closed)
    if "min_expected_recall" in gates:
        # Answer-key coverage, not finding volume. min_verified_high_critical counts what the scan
        # proved; it says nothing about whether those findings are the ones the benchmark asked
        # for, so a scan could report many verified findings while matching few expectations.
        # Fail closed when no recall was measured: an absent number is not a met bar.
        threshold = gates["min_expected_recall"]
        recall = card.get("expected_recall")
        measured = isinstance(recall, (int, float)) and not isinstance(recall, bool)
        chk(
            "min_expected_recall",
            measured and float(recall) >= float(threshold),
            f"{recall if measured else 'not measured'} >= {threshold}",
        )
    if "min_verified_high_critical" in gates:
        n = gates["min_verified_high_critical"]
        chk("min_verified_high_critical", card["verified_high_critical"] >= n,
            f"{card['verified_high_critical']} >= {n}")
    if "max_unverified_high_ratio" in gates:
        m = gates["max_unverified_high_ratio"]
        chk("max_unverified_high_ratio", card["false_positive_risk"] <= m,
            f"{card['false_positive_risk']} <= {m}")
    if gates.get("require_verified_sqli"):
        ok = "sqli" in (card.get("verified_high_critical_families") or [])
        chk("require_verified_sqli", ok, "verified SQLi present" if ok else "no verified SQLi")
    if gates.get("require_browser_proven_xss"):
        ok = "xss" in (card.get("browser_proven_high_critical_families") or [])
        chk("require_browser_proven_xss", ok, "browser XSS present" if ok else "no browser-proven XSS")
    if gates.get("require_verified_bola"):
        workflow = card.get("auth_workflow") or {}
        has_bola = "bola" in (card.get("verified_high_critical_families") or [])
        principals_valid = workflow.get("principal_identities_validated") is True
        responses_accepted = workflow.get("authenticated_responses_accepted") is True
        ok = has_bola and principals_valid and responses_accepted
        chk(
            "require_verified_bola",
            ok,
            "verified control-backed BOLA with distinct accepted principals" if ok else (
                f"verified_bola={has_bola}, principal_identities_validated={principals_valid}, "
                f"authenticated_responses_accepted={responses_accepted}"
            ),
        )
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


def submit_target(name, api, do_auth):
    """Submit one benchmark scan and return a content-free queue receipt."""
    fx = yaml.safe_load(open(os.path.join(FIXTURE_DIR, f"{name}.yaml")))
    opts = dict(fx.get("scan_options") or {})
    budget_profile = str(opts.pop("budget_profile", "thorough"))
    unsupported_options = sorted(set(opts).difference(PUBLIC_SCAN_OPTION_FIELDS))
    if unsupported_options:
        raise RuntimeError(
            "benchmark fixture uses unsupported public V2 scan option(s): "
            + ", ".join(unsupported_options)
        )
    opts["require_current_workers"] = True
    two_user = False
    principal_validation = {
        "schema_version": "benchmark_principal_validation_v1",
        "contexts_configured": [],
        "distinct_identity_claims_validated": False,
        "identity_fingerprints": [],
        "validation_method": None,
        "authenticated_responses_accepted": None,
    }
    auth_cfg = fx.get("auth") if isinstance(fx.get("auth"), dict) else {}
    minted_tokens = []
    if do_auth and auth_cfg:
        principal_nonce = secrets.token_hex(6)
        auth_target_url = credential_bootstrap_url(fx["target_url"])
        t1 = mint_token(
            auth_target_url,
            auth_cfg.get("user1_login", {}),
            f"bench.u1.{principal_nonce}@shaker.test",
            "Bench!Pass1",
        )
        if not t1:
            raise RuntimeError("failed to mint required benchmark user1 credentials")
        minted_tokens.append(("primary", t1))
        principal_validation["contexts_configured"].append("user1")
        requires_two_users = bool(auth_cfg.get("requires_two_users") or auth_cfg.get("user2_login"))
        if requires_two_users:
            t2 = mint_token(
                auth_target_url,
                auth_cfg.get("user2_login", auth_cfg.get("user1_login", {})),
                f"bench.u2.{principal_nonce}@shaker.test",
                "Bench!Pass2",
            )
            if not t2:
                raise RuntimeError("failed to mint required benchmark user2 credentials")
            identity1 = _jwt_principal_identity(t1)
            identity2 = _jwt_principal_identity(t2)
            if not identity1 or not identity2:
                raise RuntimeError("cannot prove distinct benchmark principals from token identity claims")
            if identity1 == identity2:
                raise RuntimeError("benchmark user1 and user2 resolved to the same principal identity")
            minted_tokens.append(("secondary", t2))
            two_user = True
            principal_validation.update({
                "contexts_configured": ["user1", "user2"],
                "distinct_identity_claims_validated": True,
                "identity_fingerprints": [
                    _principal_identity_fingerprint(identity1),
                    _principal_identity_fingerprint(identity2),
                ],
                "validation_method": "jwt_stable_claim",
            })
    target_id, approval_id = _canonical_benchmark_authority(
        api, fx["target_url"], credential_risk=bool(minted_tokens),
    )
    credential_profile_ids = [
        _create_benchmark_bearer_profile(
            api, target_id=target_id, token=token, lane=lane,
        )
        for lane, token in minted_tokens
    ]
    # Select the canonical family set explicitly (§17) so every first-class
    # family the fixture expects actually runs — no reliance on preset defaults
    # and no alias credit. authz_surface (BFLA) is credential-gated, so add it
    # only when a primary principal was minted; nuclei_active stays off.
    include_families = [
        "recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure", "nosqli",
    ]
    # authz_surface (BFLA) is a cross-principal differential: with one principal it can only ever
    # report zero attempts, which then fails the mandatory family-attempt gate for a reason that has
    # nothing to do with the engine. Select it only when two principals actually exist.
    if len(minted_tokens) >= 2:
        include_families.append("authz_surface")
    resp = _post(f"{api}/scans", {
        "target": fx["target_url"],
        "target_kind": "web",
        "budget_profile": budget_profile,
        "policy": {
            "active_testing": True,
            # nosqli probes mutate by design, and a request-body injection candidate is a
            # state-changing request by definition. Without this the plan grants zero
            # state_changing_requests and admission rejects the whole submission with
            # "reserved_budget exceeds the plan budget" -- so the benchmark could not run at all,
            # and its own answer key's nosqli expectation was structurally unreachable. The
            # benchmark holds an approval receipt for an authorized target, which is exactly the
            # authority this represents.
            "allow_state_changing_http": True,
            "include_families": include_families,
            "exclude_families": ["nuclei_active"],
        },
        "options": opts,
        "credential_profile_ids": credential_profile_ids,
        "approval_receipt_id": approval_id,
    })
    scan_id = resp.get("id") or resp.get("scan_id")
    if not scan_id:
        raise RuntimeError("benchmark scan submission returned no scan id")
    return {
        "target": name,
        "scan_id": scan_id,
        "job_id": resp.get("job_id"),
        "status": resp.get("status"),
        "two_user": two_user,
        "principal_validation": principal_validation,
        "require_current_workers": True,
    }


def run_target(name, api, timeout, do_auth, preset_scan_id=None, rescore_after_retest=False, retest_wait=600):
    fx = yaml.safe_load(open(os.path.join(FIXTURE_DIR, f"{name}.yaml")))
    report = None
    scan_id = preset_scan_id
    two_user = False
    principal_validation = None
    if not scan_id:
        receipt = submit_target(name, api, do_auth)
        scan_id = receipt["scan_id"]
        two_user = receipt["two_user"]
        principal_validation = receipt.get("principal_validation")
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
    if principal_validation:
        # SCAN-04: the harness's client-side claim is informational provenance
        # only. The authoritative legs (principal_identities_validated,
        # authenticated_responses_accepted) live in auth_workflow, derived by
        # collect_scorecard from SERVER-observed receipts — a submitter-supplied
        # claim must never override them.
        finish_card["principal_validation_client_claim"] = principal_validation

    cards_by_phase = {"scan_finish": finish_card}
    scoring_card = finish_card

    # Scorecard #2: after the deterministic auto-retest wave settles, re-read live
    # findings so the verified count reflects PROOF, not just scan-time triage (§6).
    if rescore_after_retest:
        settled = wait_for_retest_settle(api, timeout=retest_wait)
        live = fetch_live_findings(api, scan_id)
        if live is not None:
            retest_report = dict(report)
            retest_report["findings"] = _post_retest_findings(report.get("findings"), live)
            post_card = collect_scorecard(retest_report, fx)
            post_card["phase"] = "post_retest"
            post_card["retest_settled"] = settled
            post_card["two_user"] = two_user
            if principal_validation:
                # SCAN-04: informational client claim only; the authoritative
                # auth_workflow legs come from server-observed receipts.
                post_card["principal_validation_client_claim"] = principal_validation
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

    quality = apply_quality_bar(scoring_card, fx)
    gates = apply_gates(scoring_card, fx)
    out = dict(scoring_card)
    out["scan_id"] = scan_id
    out["target"] = name
    out["gates"] = gates
    out["passed"] = all(g["pass"] for g in gates)
    if quality is not None:
        # Reported beside `passed`, never folded into it: a regression pass must never read as
        # meeting the standard the benchmark exists to measure.
        out["quality_gates"] = quality
        out["quality_passed"] = all(g["pass"] for g in quality)
    out["scorecards"] = cards_by_phase
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--api", default="http://localhost:8080")
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--auth", action="store_true", help="mint bearer tokens from fixture auth config")
    ap.add_argument("--scan-id", default=None, help="score an existing scan id instead of submitting")
    ap.add_argument("--submit-only", action="store_true",
                    help="submit exactly one benchmark and exit without polling or scoring")
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

    # Fail fast on an unknown benchmark target instead of writing a mis-named "failed" scorecard: the
    # output filename is derived from the target name (benchmark-<name>.json), so a typo such as
    # "juice-shop" (the fixture is juice_shop.yaml) would otherwise silently emit a stray file.
    missing_fixtures = [
        name for name in args.targets
        if not os.path.isfile(os.path.join(FIXTURE_DIR, f"{name}.yaml"))
    ]
    if missing_fixtures:
        available = sorted(
            os.path.splitext(f)[0] for f in os.listdir(FIXTURE_DIR) if f.endswith(".yaml")
        )
        print(f"ABORT: no benchmark fixture for {missing_fixtures}. Available targets: {available}",
              file=sys.stderr)
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

    if args.submit_only:
        if args.scan_id or args.rescore_after_retest or args.seed_hypotheses:
            print("ABORT: --submit-only cannot be combined with scoring or hypothesis options", file=sys.stderr)
            return 2
        if len(args.targets) != 1:
            print("ABORT: --submit-only requires exactly one benchmark target", file=sys.stderr)
            return 2
        try:
            receipt = submit_target(args.targets[0], args.api, args.auth)
        except Exception as e:
            print(f"ABORT: {e}", file=sys.stderr)
            return 2
        print(json.dumps(receipt, sort_keys=True))
        return 0

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
        quality = card.get("quality_gates") or []
        if quality:
            # Printed after the regression gates and clearly labelled, so a green run can never be
            # read as meeting the standard when it is only holding the line.
            verdict = "MET" if card.get("quality_passed") else "NOT MET"
            print(f"    -- quality bar ({verdict}): the standard this benchmark measures against --")
            for g in quality:
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
