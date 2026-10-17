"""How a finding retest's outcome is classified: verdict, result status and reason.

Moved out of ``worker.py`` (its size is frozen); ``worker`` re-exports every name here.
"""

from __future__ import annotations

import ipaddress
import urllib.parse

try:
    from action_scope import evaluate_runtime_destination_scope
    from retest_contract import parse_json_field
except ModuleNotFoundError:  # package import in host-side tests
    from ..action_scope import evaluate_runtime_destination_scope
    from ..retest_contract import parse_json_field


def _is_internal_target(url: str) -> bool:
    """Heuristic check for internal-only hosts."""
    if not url:
        return False

    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
    except Exception:
        host = str(url).lower()

    if not host:
        return False

    if host in {"localhost", "host.docker.internal"}:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True

    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return True
    except ValueError:
        pass

    return False


def _url_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP origin for strict source-scan inheritance."""
    try:
        parsed = urllib.parse.urlparse(str(url or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, parsed.hostname.lower().rstrip("."), port
    except (TypeError, ValueError):
        return None


def _internal_retest_scope_authorized(verification: dict, target_url: str) -> bool:
    """Inherit bounded private-target authorization from the source scan.

    A finding cannot authorize its own destination. The source scan must target
    the exact origin and carry either a lab-scoped runtime guard or explicit
    deep intent on an active scan type.
    """
    source_target = str(verification.get("source_scan_target_url") or "").strip()
    if not source_target or _url_origin(source_target) != _url_origin(target_url):
        return False

    options = parse_json_field(verification.get("source_scan_options"))
    guard = options.get("runtime_scope_guard")
    if isinstance(guard, dict):
        environment = str(guard.get("environment") or "production").strip().lower()
        if environment in {"development", "dev", "preview", "staging", "lab", "test"}:
            scope = evaluate_runtime_destination_scope(guard, target_url)
            if scope.get("status") in {"allowed", "degraded"}:
                return True
        return False

    scan_type = str(
        verification.get("source_scan_type") or options.get("scan_type") or ""
    ).strip().lower()
    return scan_type in {"smart", "full", "aggressive"} and options.get("exploit_depth") is True


def _detect_security_block_text(*parts: str | None) -> bool:
    """Best-effort detection for WAF/edge blocks from response text."""
    merged = " ".join([p for p in parts if p]).lower()
    if not merged:
        return False

    patterns = (
        "forbidden",
        "access denied",
        "request blocked",
        "blocked by",
        "blocked",
        "waf",
        "modsecurity",
        "cloudflare",
        "security policy",
        "captcha",
        "too many requests",
        "rate limit",
        "not allowed",
    )
    return any(p in merged for p in patterns)


def classify_retest_outcome(
    *,
    proof: dict | None,
    proven: bool,
    confidence: float | None,
    inputs: dict,
    error_message: str | None = None,
    internal_target_authorized: bool = False,
) -> tuple[str, str, str]:
    """
    Return (result_status, verdict, verdict_reason).

    result_status keeps backwards-compatible semantics.
    verdict introduces Shannon-style classification.
    """
    if proven:
        return (
            "still_vulnerable",
            "exploited",
            "Proof-of-exploit succeeded and impact was reproduced.",
        )

    if error_message:
        return (
            "error",
            "error",
            f"Retest execution error: {error_message}",
        )

    evidence_type = str((proof or {}).get("evidence_type") or "")
    response_snippet = str((proof or {}).get("response_snippet") or "")
    extracted_data = str((proof or {}).get("extracted_data") or "")
    target_url = str(inputs.get("original_url") or inputs.get("target_url") or "")

    if _is_internal_target(target_url) and not internal_target_authorized:
        return (
            "inconclusive",
            "out_of_scope_internal",
            "Target appears internal/private and could require internal network access.",
        )

    if _detect_security_block_text(response_snippet, extracted_data):
        return (
            "inconclusive",
            "blocked_by_security",
            "Exploit path appears blocked by security controls or edge filtering.",
        )

    if evidence_type in {"authentication_required", "target_refused"}:
        # The replay's baseline was refused (a session-less request, a sign-in redirect, a
        # 403): every payload met the refusal, so reproducing nothing proves nothing fixed.
        return (
            "inconclusive",
            "inconclusive",
            "The target refused the retest's baseline request"
            + (" and asked for credentials" if evidence_type == "authentication_required" else "")
            + "; the finding could not be retested and stays open.",
        )

    if evidence_type in {"no_url", "unsupported_vulnerability_type"}:
        # Missing replay context is "we could not verify", NOT proof the finding
        # was invalid. false_positive must be reserved for objective FP evidence.
        return (
            "inconclusive",
            "inconclusive",
            "Finding lacks replayable exploit context for this verifier; could not verify.",
        )

    if evidence_type in {"catch_all_server", "shape_match_over_catch_all", "ambiguous_200_response"}:
        return (
            "inconclusive",
            "inconclusive",
            "Retest could not distinguish the original exposure from a catch-all or ambiguous HTTP 200 response.",
        )

    if confidence is not None and confidence <= 0.2:
        # No exploit evidence reproduced, but a non-reproduction at low confidence
        # is inconclusive — it is not objective proof the original finding was a
        # false positive. Returning false_positive here mislabels timeouts and
        # weak replays as terminal FPs.
        return (
            "inconclusive",
            "inconclusive",
            "Retest reproduced no exploit evidence (low confidence); inconclusive.",
        )

    return (
        "likely_fixed",
        "likely_fixed",
        "Retest could not reproduce exploit behavior with available inputs.",
    )


def _result_status_for_verdict(verdict: str | None) -> str:
    """Map normalized verdicts to backwards-compatible result_status values."""
    v = str(verdict or "").lower()
    if v == "exploited":
        return "still_vulnerable"
    if v == "likely_fixed":
        return "likely_fixed"
    if v in {"likely_vulnerable", "false_positive", "inconclusive", "blocked_by_security", "out_of_scope_internal"}:
        return "inconclusive"
    return "error"
