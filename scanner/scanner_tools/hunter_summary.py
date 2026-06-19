"""Hunter-campaign self miss-analysis (P0 of the hunter-campaign ladder).

A backward-compatible report section, ``report["hunter_summary"]``, that explains
for *every* scan: what was discovered, how much was attempted, what was confirmed,
what proof is missing, what was *blocked* by a missing prerequisite (e.g. no second
principal for BOLA), and what to run next. It is derived purely from data the report
already carries (discovery sources, ``active_checks.endpoint_attempts``, findings,
``smart_coverage``) — no new probes, no detector changes.

Data contract:
- producer: ``scanner.build_report`` (writes ``report["hunter_summary"]``).
- consumer: benchmark harness, ``/asm/gaps``, UI.
- old rows / absent section: callers must treat a missing ``hunter_summary`` as
  "not computed" (default to ``None``); never assume presence.
- backward compatibility: additive top-level field only; no existing field changes.
- idempotency: pure function of ``report`` (+ auth options); recomputing yields the
  same value for the same report.
- redaction: only counts, family names, statuses, and titles are emitted; no
  cookies/tokens/headers/PII (auth options are reduced to booleans).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from scanner_tools.benchmark_summary import (
    _as_dict,
    _as_list,
    _collect_attempts,
    _collect_discovery_sources,
    _collect_findings,
)

# Discovery sources that mean we actually observed the live API surface (vs. static
# guessing). If none are present and few endpoints were found, the surface is
# under-discovered — the dominant reason hunter scans miss authenticated bugs.
_OBSERVED_DISCOVERY = frozenset(
    {"browser", "browser_api_endpoints", "har", "har_network_capture", "openapi", "crawl", "js"}
)


def _has_primary_auth(options: dict[str, Any]) -> bool:
    o = options or {}
    return bool(
        o.get("auth_header")
        or o.get("auth_cookies")
        or o.get("auth_headers_json")
        or (o.get("login_username") and o.get("login_password"))
    )


def _has_second_principal(options: dict[str, Any], auth_states: list[str]) -> bool:
    o = options or {}
    return bool(o.get("user2_header") or o.get("user2_cookies") or ("user2" in (auth_states or [])))


def build_hunter_summary(report: dict[str, Any], *, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the backward-compatible ``hunter_summary`` section for a scan report."""
    report = _as_dict(report)
    options = _as_dict(options) if options is not None else _as_dict(report.get("options"))
    meta = _as_dict(report.get("scan_metadata"))

    discovery_sources = _collect_discovery_sources(report)
    attempts, _params_by_location = _collect_attempts(report)
    findings_stats, proof_and_severity_gaps = _collect_findings(report)

    cov = _as_dict(report.get("smart_coverage"))
    endpoints = _as_dict(cov.get("endpoints"))
    params = _as_dict(cov.get("parameters"))
    auth_states = [str(x).lower() for x in _as_list(cov.get("auth_states_tested"))]

    findings = [f for f in _as_list(report.get("findings")) if isinstance(f, dict)]
    sev_counts = Counter(str(f.get("severity") or "info").lower() for f in findings)
    confirmed_high_critical = sum(
        n
        for key, n in _as_dict(findings_stats.get("confirmed_by_family_severity")).items()
        if str(key).split("|", 1)[-1] in {"high", "critical"}
    )

    proof_gaps = [g for g in proof_and_severity_gaps if g.get("reason") == "high_or_critical_without_deterministic_proof"]
    severity_gaps = [g for g in proof_and_severity_gaps if g.get("severity_rationale")]

    has_auth = _has_primary_auth(options)
    has_user2 = _has_second_principal(options, auth_states)

    # Blocked hypotheses: precondition-gated families we could not honestly test.
    blocked: list[dict[str, Any]] = []
    if not has_auth:
        blocked.append({
            "family": "authz", "status": "blocked", "reason": "auth_missing",
            "required_inputs": ["primary credentials"],
        })
    if not has_user2:
        blocked.append({
            "family": "bola", "status": "blocked", "reason": "missing_second_principal",
            "required_inputs": ["user2 credentials"],
        })

    observed_surface = any(s in _OBSERVED_DISCOVERY for s in discovery_sources)
    attempts_total = int(attempts.get("total") or 0)
    next_campaigns: list[str] = []
    if not has_auth:
        next_campaigns.append("supply primary credentials to reach the authenticated API surface")
    if not has_user2:
        next_campaigns.append("supply a second principal (user2) and run a focused BOLA campaign with exploit_depth")
    if not observed_surface and int(endpoints.get("discovered") or 0) <= 40:
        next_campaigns.append("enable browser/HAR/OpenAPI discovery — API surface appears under-discovered")
    if proof_gaps:
        next_campaigns.append("increase proof depth for high/critical findings lacking deterministic proof")
    if confirmed_high_critical == 0 and attempts_total > 0:
        next_campaigns.append("run focused deep passes per family (sqli, xss, bola) over the discovered surface")

    return {
        "campaign_id": meta.get("campaign_id") or options.get("campaign_id"),
        "mode": meta.get("scan_type") or options.get("scan_type"),
        "policy_preset": options.get("budget_profile") or meta.get("budget_profile"),
        "exploit_depth": bool(meta.get("exploit_depth") or options.get("exploit_depth")),
        "discovery_sources": discovery_sources,
        "app_graph_stats": {
            "endpoints_discovered": endpoints.get("discovered"),
            "endpoints_tested": endpoints.get("tested"),
            "parameters_tested": params.get("tested"),
            "auth_states_tested": auth_states,
            "principals_available": {"primary": has_auth, "second": has_user2},
        },
        # Until the hypothesis engine (P4) exists, a "hypothesis" == an attempted
        # endpoint probe; generated == tested. Stated honestly so callers aren't misled.
        "hypotheses_generated": attempts_total,
        "hypotheses_tested": attempts_total,
        "attempts_by_family": _as_dict(attempts.get("by_auth_state_family_status")),
        "findings_confirmed": dict(sorted(sev_counts.items())),
        "confirmed_high_critical": confirmed_high_critical,
        "blocked_hypotheses": blocked,
        "proof_gaps": proof_gaps,
        "severity_gaps": severity_gaps,
        "next_recommended_campaigns": next_campaigns,
    }
