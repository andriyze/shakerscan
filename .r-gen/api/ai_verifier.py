#!/usr/bin/env python3
"""
AI-driven DAST verification engine.

Uses an LLM to reason about finding exploitation in a black-box context —
no source code, only HTTP evidence. Generates exploitation plans and
executes them via HTTP (fetch_with_capture) or browser (InteractiveSession).

Opt-in via AI_VERIFY_ENABLED=true. Sits as Tier 2 behind deterministic provers.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore

from retest_contract import (
    SUPPORTED_RETEST_VERDICTS,
    auth_context_to_headers,
    parse_json_field,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Retry constants (matches ai_classifier.py patterns)
# ---------------------------------------------------------------------------
AI_RETRY_ATTEMPTS = 3
AI_RETRY_BASE_DELAY = 1.0
AI_RETRY_MAX_DELAY = 8.0
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Max steps the LLM can generate in one plan
MAX_PLAN_STEPS = 8

# Max response body bytes to feed back to the LLM
MAX_RESPONSE_SNIPPET = 4000

# Finding types we support for AI verification
AI_VERIFIABLE_TYPES = {"xss", "sqli", "ssrf", "path_traversal", "open_redirect", "cors", "2fa_bypass", "command_injection", "ssti", "xxe", "jwt", "idor", "bola", "exposed_file", "generic_http"}

# Enforce safe, same-origin HTTP replay behavior for AI-generated steps.
ALLOWED_HTTP_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
ALLOWED_STEP_SCHEMES = {"http", "https"}

_REDACT_BODY_FN = None
_REDACT_BODY_LOADED = False

SENSITIVE_QUERY_KEYS = (
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "auth",
    "session",
    "jwt",
    "cookie",
)
SENSITIVE_OBJECT_KEYS = (
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "jwt",
    "auth",
)
FALLBACK_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(api[_-]?key|apikey)[\"'=\s:]+[A-Za-z0-9_\-]{10,}", re.I), r"\1=[REDACTED]"),
    (re.compile(r"(secret|token|password|passwd|pwd)[\"'=\s:]+[^\s\"'<>]{6,}", re.I), r"\1=[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"), "[REDACTED_JWT]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[REDACTED_EMAIL]"),
)


# ---------------------------------------------------------------------------
# LLM call helper (reuses ai_classifier.py patterns)
# ---------------------------------------------------------------------------


def _load_shared_call_ai_provider():
    """Load shared provider client from scanner module if available."""
    import_errors: list[str] = []
    for module_name in ("scanner_tools.ai_classifier", "scanner.scanner_tools.ai_classifier"):
        try:
            module = importlib.import_module(module_name)
            fn = getattr(module, "call_ai_provider", None)
            if callable(fn):
                return fn, None
        except Exception as exc:
            import_errors.append(f"{module_name}: {type(exc).__name__}")
    return None, "; ".join(import_errors) if import_errors else "call_ai_provider not found"


def _load_redact_body_function():
    """Load shared response-body redactor from ai_classifier when available."""
    global _REDACT_BODY_FN, _REDACT_BODY_LOADED
    if _REDACT_BODY_LOADED:
        return _REDACT_BODY_FN
    _REDACT_BODY_LOADED = True
    for module_name in ("scanner_tools.ai_classifier", "scanner.scanner_tools.ai_classifier"):
        try:
            module = importlib.import_module(module_name)
            fn = getattr(module, "redact_response_body", None)
            if callable(fn):
                _REDACT_BODY_FN = fn
                break
        except Exception:
            continue
    return _REDACT_BODY_FN


def _fallback_redact_text(value: str) -> str:
    redacted = value
    for pattern, replacement in FALLBACK_REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _redact_text_for_ai(value: Any) -> str:
    if value is None:
        return ""
    raw = str(value)
    if not raw:
        return ""
    shared_fn = _load_redact_body_function()
    if callable(shared_fn):
        try:
            return str(shared_fn(raw))
        except Exception:
            pass
    return _fallback_redact_text(raw)


def _redact_url_for_ai(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return _redact_text_for_ai(url)
    if not parsed.query:
        return url
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    sanitized_pairs: list[tuple[str, str]] = []
    for key, val in query_pairs:
        lowered = key.lower()
        if any(s in lowered for s in SENSITIVE_QUERY_KEYS):
            sanitized_pairs.append((key, "[REDACTED]"))
        else:
            sanitized_pairs.append((key, val))
    sanitized_query = urlencode(sanitized_pairs, doseq=True)
    return urlunparse(parsed._replace(query=sanitized_query))


def _redact_object_for_ai(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            key_str = str(key)
            lowered = key_str.lower()
            if any(s in lowered for s in SENSITIVE_OBJECT_KEYS):
                out[key_str] = "[REDACTED]"
            else:
                out[key_str] = _redact_object_for_ai(value)
        return out
    if isinstance(obj, list):
        return [_redact_object_for_ai(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_object_for_ai(item) for item in obj)
    if isinstance(obj, str):
        return _redact_text_for_ai(obj)
    return obj


def _effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _resolve_and_validate_step_url(step_url: str, base_url: str) -> tuple[str | None, str | None]:
    """
    Resolve a possibly relative step URL and enforce same-origin policy.

    This prevents LLM-generated plans from sending verification traffic to
    off-target hosts or alternate schemes/ports.
    """
    base_candidate = base_url if "://" in (base_url or "") else f"https://{base_url}"
    try:
        base_parsed = urlparse(base_candidate)
    except Exception:
        return None, "Invalid base URL"

    if base_parsed.scheme not in ALLOWED_STEP_SCHEMES or not base_parsed.hostname:
        return None, "Invalid base URL for verification"

    raw_step = (step_url or "/").strip() or "/"
    if raw_step.startswith(("http://", "https://")):
        resolved = raw_step
    else:
        resolved = urljoin(base_candidate.rstrip("/") + "/", raw_step)

    try:
        parsed = urlparse(resolved)
    except Exception:
        return None, "Invalid step URL"

    if parsed.scheme not in ALLOWED_STEP_SCHEMES:
        return None, f"Disallowed step URL scheme: {parsed.scheme or 'missing'}"
    if not parsed.hostname:
        return None, "Step URL missing host"

    if parsed.hostname.lower() != base_parsed.hostname.lower():
        return None, "Blocked cross-origin step URL"

    if _effective_port(parsed) != _effective_port(base_parsed):
        return None, "Blocked cross-origin step URL (port mismatch)"

    if parsed.scheme != base_parsed.scheme:
        return None, "Blocked cross-origin step URL (scheme mismatch)"

    return urlunparse(parsed._replace(fragment="")), None


def _extract_text_chunks(value: Any) -> list[str]:
    chunks: list[str] = []
    if value is None:
        return chunks
    if isinstance(value, str):
        if value.strip():
            chunks.append(value)
        return chunks
    if isinstance(value, list):
        for item in value:
            chunks.extend(_extract_text_chunks(item))
        return chunks
    if isinstance(value, dict):
        for key in ("text", "content", "value", "output_text", "completion", "output"):
            if key in value:
                chunks.extend(_extract_text_chunks(value.get(key)))
        if not chunks:
            for nested in value.values():
                if isinstance(nested, (str, list, dict)):
                    chunks.extend(_extract_text_chunks(nested))
        return chunks
    return chunks


def _strip_markdown_fences(content: str) -> str:
    text = content.strip()
    if text.startswith("```"):
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            return match.group(1).strip()
    return text


def _extract_json_payload(content: str) -> Any | None:
    if not content:
        return None
    stripped = _strip_markdown_fences(content)
    if not stripped:
        return None

    decoder = json.JSONDecoder()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    for idx, ch in enumerate(stripped):
        if ch not in "{[":
            continue
        try:
            parsed, _ = decoder.raw_decode(stripped[idx:])
            return parsed
        except Exception:
            continue
    return None


def _extract_direct_parsed_json(response_data: dict[str, Any]) -> Any | None:
    choices = response_data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first, dict) else {}
        if isinstance(message, dict):
            parsed = message.get("parsed")
            if parsed is not None:
                return parsed
    return None


def _extract_content_from_response(response_data: dict[str, Any]) -> str:
    content_chunks: list[str] = []

    choices = response_data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first, dict) else {}
        if isinstance(message, dict):
            content_chunks.extend(_extract_text_chunks(message.get("content")))
        if isinstance(first, dict):
            delta = first.get("delta")
            if isinstance(delta, dict):
                content_chunks.extend(_extract_text_chunks(delta.get("content")))

    content_chunks.extend(_extract_text_chunks(response_data.get("content")))
    content_chunks.extend(_extract_text_chunks(response_data.get("output_text")))
    content_chunks.extend(_extract_text_chunks(response_data.get("completion")))
    content_chunks.extend(_extract_text_chunks(response_data.get("output")))

    return "\n".join(chunk for chunk in content_chunks if chunk).strip()


async def _call_llm(
    ai_url: str,
    ai_api_key: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: int = 60,
    max_tokens: int = 4000,
    temperature: float = 0.2,
    fallback_models: str | list[str] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Call OpenAI-compatible API and parse JSON response.

    Returns (parsed_json, error_message).
    """
    shared_call, _shared_err = _load_shared_call_ai_provider()
    if shared_call:
        try:
            response, error, _latency_ms = await shared_call(
                ai_url=ai_url,
                ai_api_key=ai_api_key,
                model=model,
                messages=messages,
                timeout_seconds=timeout_seconds,
                max_tokens=max_tokens,
                temperature=temperature,
                fallback_models=fallback_models,
            )
            if isinstance(response, dict):
                response.pop("_provider_meta", None)
            return response, error
        except Exception as exc:
            logger.warning(f"Shared AI provider call failed in verifier, using local fallback: {type(exc).__name__}")

    if aiohttp is None:
        return None, "aiohttp not installed"

    headers = {
        "Authorization": f"Bearer {ai_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }

    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    last_error: str | None = None

    for attempt in range(AI_RETRY_ATTEMPTS):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.post(ai_url, json=body, headers=headers) as resp:
                    if resp.status != 200:
                        error_text = (await resp.text())[:500]
                        if resp.status in RETRYABLE_STATUS_CODES and attempt < AI_RETRY_ATTEMPTS - 1:
                            delay = min(AI_RETRY_BASE_DELAY * (2 ** attempt), AI_RETRY_MAX_DELAY)
                            last_error = f"HTTP {resp.status}: {error_text}"
                            await asyncio.sleep(delay)
                            continue
                        return None, f"HTTP {resp.status}: {error_text}"

                    response_data = await resp.json(content_type=None)
                    parsed = _extract_direct_parsed_json(response_data)
                    if parsed is None:
                        content = _extract_content_from_response(response_data)
                        if not content:
                            return None, "Empty content in response"
                        parsed = _extract_json_payload(content)

                    if parsed is None:
                        return None, "Invalid JSON in response"
                    if not isinstance(parsed, dict):
                        return None, "AI response JSON is not an object"
                    return parsed, None

        except (TimeoutError, asyncio.TimeoutError):
            last_error = f"Timeout after {timeout_seconds}s"
            if attempt < AI_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(AI_RETRY_BASE_DELAY * (2 ** attempt))
                continue
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON: {e}"
        except Exception as e:
            return None, f"Unexpected error: {type(e).__name__}: {str(e)[:200]}"

    return None, last_error or "All retries exhausted"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert penetration tester performing black-box (DAST) verification.

You are given a vulnerability finding from an automated scanner. Your job is to:
1. Analyze the finding evidence (HTTP responses, parameters, payloads, tool output)
2. Generate a concrete exploitation plan with HTTP requests to verify the vulnerability
3. After seeing the results, classify whether the vulnerability is confirmed

You have NO source code access. You can only see HTTP request/response data.

RULES:
- Generate only safe, read-only verification requests (no data destruction)
- Use the exact target URL and parameters from the finding
- Each step must include the expected result that would confirm the vulnerability
- Keep plans concise (max 8 steps)
- For XSS: verify payload reflection in executable context
- For SQLi: verify error-based or union-based data extraction (no time-based delays)
- For SSRF: verify internal resource access or response differences
- For path traversal: verify file content extraction
- For open redirect: verify Location header or meta redirect
- For CORS: verify permissive origin reflection with credentials

Respond with JSON only."""


def _build_plan_prompt(finding: dict[str, Any], auth_context: dict[str, str] | None) -> str:
    """Build the user prompt for plan generation."""
    evidence = parse_json_field(finding.get("evidence"))

    parts = [
        "## Finding to Verify\n",
        f"**Title:** {finding.get('title', 'Unknown')}",
        f"**Severity:** {finding.get('severity', 'unknown')}",
        f"**Type:** {finding.get('finding_type') or finding.get('tool', 'unknown')}",
        f"**URL:** {finding.get('url') or finding.get('target_url', 'unknown')}",
    ]

    if finding.get("tool"):
        parts.append(f"**Detected by:** {finding['tool']}")

    # Evidence details
    param = evidence.get("param") or evidence.get("parameter") or finding.get("param")
    if param:
        parts.append(f"**Parameter:** {param}")

    payload = evidence.get("payload") or finding.get("payload")
    if payload:
        parts.append(f"**Original payload:** {_redact_text_for_ai(payload)}")

    method = evidence.get("method") or finding.get("method")
    if method:
        parts.append(f"**HTTP Method:** {method}")

    # Response snippet from evidence
    response_snippet = evidence.get("response_snippet") or evidence.get("response")
    if response_snippet:
        redacted_snippet = _redact_text_for_ai(response_snippet)
        parts.append(f"\n**Response snippet:**\n```\n{redacted_snippet[:2000]}\n```")

    detail = evidence.get("detail")
    if isinstance(detail, dict):
        safe_detail = _redact_object_for_ai(detail)
        parts.append(f"\n**Detail:** {json.dumps(safe_detail, indent=2)[:2000]}")

    # Auth info
    if auth_context:
        auth_types = []
        if auth_context.get("auth_header"):
            auth_types.append("Authorization header")
        if auth_context.get("auth_cookies"):
            auth_types.append("Session cookies")
        if auth_types:
            parts.append(f"\n**Authentication:** {', '.join(auth_types)} (will be included automatically)")

    parts.append("\n## Task")
    parts.append(
        "Generate a verification plan as JSON with this structure:\n"
        '```json\n'
        '{\n'
        '  "analysis": "Brief analysis of the vulnerability and verification approach",\n'
        '  "execution_mode": "http",\n'
        '  "steps": [\n'
        '    {\n'
        '      "description": "What this step verifies",\n'
        '      "method": "GET",\n'
        '      "url": "/path?param=payload",\n'
        '      "body": null,\n'
        '      "expected": {"body_contains": "expected_string"}\n'
        '    }\n'
        '  ]\n'
        '}\n'
        '```\n\n'
        'Expected check types: body_contains, status_code, header_contains, body_not_contains\n'
        'For execution_mode, use "http" (default) or "browser" (for DOM XSS, JS-rendered pages).'
    )

    return "\n".join(parts)


def _build_classify_prompt(
    finding: dict[str, Any],
    plan: dict[str, Any],
    step_results: list[dict[str, Any]],
) -> str:
    """Build the prompt for classification after execution."""
    parts = [
        f"## Original Finding\n**Title:** {finding.get('title', 'Unknown')}",
        f"**Type:** {finding.get('finding_type') or finding.get('tool', 'unknown')}",
        f"\n## Your Analysis\n{plan.get('analysis', 'N/A')}",
        "\n## Execution Results\n",
    ]

    for i, sr in enumerate(step_results):
        step = sr.get("step", {})
        result = sr.get("result", {})
        safe_step_url = _redact_url_for_ai(str(step.get("url", "?")))
        parts.append(f"### Step {i+1}: {step.get('description', 'unknown')}")
        parts.append(f"- **Request:** {step.get('method', 'GET')} {safe_step_url}")
        parts.append(f"- **Status:** {result.get('status_code', 'N/A')}")

        body = _redact_text_for_ai(result.get("body", ""))[:MAX_RESPONSE_SNIPPET]
        if body:
            parts.append(f"- **Response (truncated):**\n```\n{body}\n```")

        checks = sr.get("checks", {})
        if checks:
            parts.append(f"- **Check results:** {json.dumps(checks)}")

    parts.append(
        "\n## Task\n"
        "Based on the execution results, classify this finding.\n"
        "Respond with JSON:\n"
        '```json\n'
        '{\n'
        '  "verdict": "exploited|likely_fixed|false_positive|inconclusive|blocked_by_security",\n'
        '  "confidence": 0.0-1.0,\n'
        '  "reasoning": "Brief explanation of your classification"\n'
        '}\n'
        '```'
    )

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Step execution
# ---------------------------------------------------------------------------

async def _execute_http_step(
    step: dict[str, Any],
    base_url: str,
    auth_headers: dict[str, str],
) -> dict[str, Any]:
    """Execute a single HTTP verification step using fetch_with_capture."""
    try:
        from scanner_tools.proof_of_exploit import fetch_with_capture
    except ImportError:
        return {"error": "proof_of_exploit module not available", "status_code": 0, "body": ""}

    method = str(step.get("method", "GET")).upper()
    if method not in ALLOWED_HTTP_METHODS:
        return {
            "error": f"Disallowed HTTP method for AI verification: {method}",
            "status_code": 0,
            "body": "",
        }

    resolved_url, url_error = _resolve_and_validate_step_url(str(step.get("url", "") or "/"), base_url)
    if url_error or not resolved_url:
        return {
            "error": url_error or "Invalid step URL",
            "status_code": 0,
            "body": "",
        }

    body_data = step.get("body")
    headers = dict(auth_headers)  # copy
    content_type = step.get("content_type")
    if isinstance(body_data, (dict, list)):
        body_data = json.dumps(body_data)
        if not content_type and "Content-Type" not in headers:
            content_type = "application/json"
    elif body_data is not None and not isinstance(body_data, str):
        body_data = str(body_data)

    if content_type:
        headers["Content-Type"] = content_type
    elif body_data and "Content-Type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    result = await fetch_with_capture(
        resolved_url,
        method=method,
        data=body_data,
        headers=headers if headers else None,
        timeout=15,
    )

    return result


async def _execute_browser_step(
    step: dict[str, Any],
    session,
) -> dict[str, Any]:
    """Execute a browser action step via InteractiveSession."""
    action = step.get("action", "navigate")
    data = {}

    if action == "navigate":
        data["url"] = step.get("url", "/")
    elif action == "fill":
        data["selector"] = step.get("selector", "")
        data["value"] = step.get("value", "")
    elif action == "click":
        data["selector"] = step.get("selector", "")
    elif action == "wait":
        data["selector"] = step.get("selector", "body")
        data["timeout"] = step.get("timeout", 3000)

    result = await session.execute_action(action, data)
    return result


def _check_expected(result: dict[str, Any], expected: dict[str, Any]) -> dict[str, bool]:
    """Check whether the HTTP response matches expected conditions."""
    checks: dict[str, bool] = {}
    body = str(result.get("body", ""))
    status = result.get("status_code", 0)
    resp_headers = result.get("headers", {})

    if "body_contains" in expected:
        checks["body_contains"] = expected["body_contains"] in body

    if "body_not_contains" in expected:
        checks["body_not_contains"] = expected["body_not_contains"] not in body

    if "status_code" in expected:
        checks["status_code"] = status == expected["status_code"]

    if "header_contains" in expected:
        hdr_val = expected["header_contains"]
        header_text = json.dumps(resp_headers) if isinstance(resp_headers, dict) else str(resp_headers)
        checks["header_contains"] = hdr_val.lower() in header_text.lower()

    return checks


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def ai_verify_finding(
    finding: dict[str, Any],
    auth_context: dict[str, str] | None,
    ai_url: str,
    ai_api_key: str,
    model: str,
    target_url: str,
    fallback_models: str | list[str] | None = None,
) -> dict[str, Any]:
    """
    DAST-only AI verification.

    1. Build context from finding evidence (no source code)
    2. LLM generates exploitation plan with expected results
    3. Execute steps via HTTP (fetch_with_capture)
    4. Feed results back to LLM for classification
    5. Return verdict with confidence and evidence

    Returns dict with: verdict, confidence, reasoning, ai_plan, step_results, verification_mode
    """
    started_at = time.time()
    auth_headers = auth_context_to_headers(auth_context)

    # Step 1: Generate exploitation plan
    plan_prompt = _build_plan_prompt(finding, auth_context)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": plan_prompt},
    ]

    plan, plan_error = await _call_llm(
        ai_url,
        ai_api_key,
        model,
        messages,
        fallback_models=fallback_models,
    )

    if plan_error or not plan:
        return {
            "verdict": "inconclusive",
            "confidence": None,
            "reasoning": f"AI plan generation failed: {plan_error}",
            "ai_plan": None,
            "step_results": [],
            "verification_mode": "ai_driven",
            "error": plan_error,
        }

    # Validate plan structure
    steps = plan.get("steps", [])
    if not steps or not isinstance(steps, list):
        return {
            "verdict": "inconclusive",
            "confidence": None,
            "reasoning": "AI generated empty or invalid plan",
            "ai_plan": plan,
            "step_results": [],
            "verification_mode": "ai_driven",
            "error": "No steps in plan",
        }

    # Cap steps
    steps = steps[:MAX_PLAN_STEPS]
    execution_mode = plan.get("execution_mode", "http")

    # Step 2: Execute plan steps
    step_results: list[dict[str, Any]] = []

    if execution_mode == "browser":
        # Try browser execution via InteractiveSession
        try:
            from session_manager import InteractiveSession

            session = InteractiveSession(
                session_id=f"ai-verify-{int(time.time())}",
                target_url=target_url,
            )
            start_result = await session.start()
            if not start_result.get("success"):
                # Fall back to HTTP mode
                execution_mode = "http"
            else:
                try:
                    for step in steps:
                        result = await _execute_browser_step(step, session)
                        checks = _check_expected(result, step.get("expected", {}))
                        step_results.append({"step": step, "result": result, "checks": checks})
                finally:
                    await session.close()
        except ImportError:
            execution_mode = "http"

    if execution_mode == "http":
        for step in steps:
            result = await _execute_http_step(step, target_url, auth_headers)
            checks = _check_expected(result, step.get("expected", {}))
            step_results.append({"step": step, "result": result, "checks": checks})

    # Step 3: Feed results back to LLM for classification
    classify_prompt = _build_classify_prompt(finding, plan, step_results)
    classify_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": classify_prompt},
    ]

    classification, classify_error = await _call_llm(
        ai_url, ai_api_key, model, classify_messages,
        max_tokens=1000,
        fallback_models=fallback_models,
    )

    if classify_error or not classification:
        # Fall back: check if any steps had all checks pass
        any_confirmed = any(
            sr.get("checks") and all(sr["checks"].values())
            for sr in step_results
            if sr.get("checks")
        )
        return {
            "verdict": "exploited" if any_confirmed else "inconclusive",
            "confidence": 0.6 if any_confirmed else None,
            "reasoning": f"AI classification failed ({classify_error}), used check-based fallback",
            "ai_plan": plan,
            "step_results": _sanitize_step_results(step_results),
            "verification_mode": "ai_driven",
            "error": classify_error,
        }

    verdict = classification.get("verdict", "inconclusive")
    # Normalize verdict to supported values
    if verdict not in SUPPORTED_RETEST_VERDICTS:
        verdict = "inconclusive"

    confidence = classification.get("confidence")
    if isinstance(confidence, (int, float)):
        confidence = max(0.0, min(1.0, float(confidence)))
    else:
        confidence = None

    elapsed_ms = int((time.time() - started_at) * 1000)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": classification.get("reasoning", ""),
        "ai_plan": plan,
        "step_results": _sanitize_step_results(step_results),
        "verification_mode": "ai_driven",
        "elapsed_ms": elapsed_ms,
        "error": None,
    }


def _sanitize_step_results(step_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Truncate large response bodies to keep storage reasonable."""
    sanitized = []
    for sr in step_results:
        clean = {
            "step": sr.get("step", {}),
            "checks": sr.get("checks", {}),
            "result": {},
        }
        result = sr.get("result", {})
        clean["result"]["status_code"] = result.get("status_code")
        clean["result"]["elapsed_ms"] = result.get("elapsed_ms")
        clean["result"]["error"] = _redact_text_for_ai(result.get("error"))
        body = _redact_text_for_ai(result.get("body", ""))
        clean["result"]["body_preview"] = body[:MAX_RESPONSE_SNIPPET] if body else ""
        sanitized.append(clean)
    return sanitized
