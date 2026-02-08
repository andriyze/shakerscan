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
import json
import logging
import re
import time
from typing import Any

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
AI_VERIFIABLE_TYPES = {"xss", "sqli", "ssrf", "path_traversal", "open_redirect", "cors"}


# ---------------------------------------------------------------------------
# LLM call helper (reuses ai_classifier.py patterns)
# ---------------------------------------------------------------------------
async def _call_llm(
    ai_url: str,
    ai_api_key: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: int = 60,
    max_tokens: int = 4000,
    temperature: float = 0.2,
) -> tuple[dict[str, Any] | None, str | None]:
    """Call OpenAI-compatible API and parse JSON response.

    Returns (parsed_json, error_message).
    """
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

                    response_data = await resp.json()
                    choices = response_data.get("choices", [])
                    if not choices:
                        return None, "No choices in response"

                    content = choices[0].get("message", {}).get("content", "")
                    if not content:
                        return None, "Empty content in response"

                    # Strip markdown fences
                    if content.strip().startswith("```"):
                        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", content)
                        if match:
                            content = match.group(1)

                    parsed = json.loads(content.strip())
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
        parts.append(f"**Original payload:** {payload}")

    method = evidence.get("method") or finding.get("method")
    if method:
        parts.append(f"**HTTP Method:** {method}")

    # Response snippet from evidence
    response_snippet = evidence.get("response_snippet") or evidence.get("response")
    if response_snippet:
        parts.append(f"\n**Response snippet:**\n```\n{str(response_snippet)[:2000]}\n```")

    detail = evidence.get("detail")
    if isinstance(detail, dict):
        parts.append(f"\n**Detail:** {json.dumps(detail, indent=2)[:2000]}")

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
        parts.append(f"### Step {i+1}: {step.get('description', 'unknown')}")
        parts.append(f"- **Request:** {step.get('method', 'GET')} {step.get('url', '?')}")
        parts.append(f"- **Status:** {result.get('status_code', 'N/A')}")

        body = str(result.get("body", ""))[:MAX_RESPONSE_SNIPPET]
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

    method = step.get("method", "GET").upper()
    step_url = step.get("url", "")

    # Resolve relative URLs against base
    if step_url.startswith("/"):
        from urllib.parse import urlparse, urlunparse
        parsed_base = urlparse(base_url)
        step_url = urlunparse(parsed_base._replace(path=step_url.split("?")[0], query=step_url.split("?")[1] if "?" in step_url else ""))
    elif not step_url.startswith("http"):
        step_url = base_url.rstrip("/") + "/" + step_url.lstrip("/")

    body_data = step.get("body")
    headers = dict(auth_headers)  # copy
    content_type = step.get("content_type")
    if content_type:
        headers["Content-Type"] = content_type
    elif body_data and "Content-Type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    result = await fetch_with_capture(
        step_url,
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

    plan, plan_error = await _call_llm(ai_url, ai_api_key, model, messages)

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
        clean["result"]["error"] = result.get("error")
        body = str(result.get("body", ""))
        clean["result"]["body_preview"] = body[:MAX_RESPONSE_SNIPPET] if body else ""
        sanitized.append(clean)
    return sanitized
