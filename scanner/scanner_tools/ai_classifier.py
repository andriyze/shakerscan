"""
AI-powered finding classification and analysis module.

Supports OpenAI-compatible APIs (OpenAI, OpenRouter, Claude-via-gateway, etc.).
"""

import asyncio
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Retry Configuration for AI Provider Calls
# ---------------------------------------------------------------------------
AI_RETRY_ATTEMPTS = 3
AI_RETRY_BASE_DELAY = 1.0  # seconds
AI_RETRY_MAX_DELAY = 8.0   # seconds
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
DEFAULT_MAX_FINDINGS_PER_BATCH = max(1, int(os.environ.get("AI_CLASSIFY_MAX_FINDINGS_PER_BATCH", "12")))
DEFAULT_MAX_PROMPT_CHARS = max(4000, int(os.environ.get("AI_CLASSIFY_MAX_PROMPT_CHARS", "24000")))
MAX_REASONING_RETRY_TOKENS = max(4000, int(os.environ.get("AI_REASONING_RETRY_MAX_TOKENS", "12000")))
AI_CLASSIFY_CHAIN_BUDGET_SECONDS = max(0, int(os.environ.get("AI_CLASSIFY_CHAIN_BUDGET_SECONDS", "120")))
AI_CLASSIFY_CIRCUIT_WINDOW_SECONDS = max(30, int(os.environ.get("AI_CLASSIFY_CIRCUIT_WINDOW_SECONDS", "300")))
AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD = max(1, int(os.environ.get("AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD", "5")))
AI_CLASSIFY_CIRCUIT_COOLDOWN_SECONDS = max(30, int(os.environ.get("AI_CLASSIFY_CIRCUIT_COOLDOWN_SECONDS", "180")))

RESPONSE_FORMAT_UNSUPPORTED_PATTERNS = (
    "response_format",
    "json_schema",
    "json_object",
    "unsupported",
    "not support",
    "invalid_request_error",
)

RETRYABLE_PROVIDER_ERROR_PATTERNS = (
    "network error",
    "connection",
    "connection closed",
    "connection reset",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "rate limit",
    "429",
    "500",
    "502",
    "503",
    "504",
    "budget exceeded",
)

_AI_CLASSIFY_CIRCUIT_STATE: dict[str, Any] = {
    "error_count": 0,
    "window_started_monotonic": None,
    "open_until_monotonic": None,
    "last_error": None,
}
_AI_CLASSIFY_CIRCUIT_LOCK = threading.Lock()

# Models that support strict structured outputs (json_schema mode)
STRUCTURED_OUTPUT_MODELS = frozenset([
    "gpt-4o", "gpt-4o-mini", "gpt-4o-2024-08-06", "gpt-4o-2024-11-20",
    "gpt-4o-mini-2024-07-18", "o1", "o1-mini", "o1-preview",
])

# JSON Schema for classification responses (OpenAI structured outputs)
CLASSIFICATION_JSON_SCHEMA = {
    "name": "findings_classification",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "unclear"]},
                        "confidence": {"type": "number"},
                        "rationale": {"type": "string"},
                        "verification_steps": {"type": "array", "items": {"type": "string"}},
                        "remediation": {"type": "array", "items": {"type": "string"}},
                        "attack_narrative": {"type": ["string", "null"]},
                        "severity_adjustment": {"type": ["string", "null"]}
                    },
                    "required": ["finding_id", "verdict", "confidence", "rationale"],
                    "additionalProperties": False
                }
            }
        },
        "required": ["findings"],
        "additionalProperties": False
    }
}

# JSON Schema for executive summary
EXECUTIVE_SUMMARY_JSON_SCHEMA = {
    "name": "executive_summary",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "executive_summary": {"type": "string"},
            "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low", "minimal"]},
            "key_findings": {"type": "array", "items": {"type": "string"}},
            "immediate_actions": {"type": "array", "items": {"type": "string"}},
            "business_impact": {"type": "string"}
        },
        "required": ["executive_summary", "risk_level", "key_findings", "immediate_actions", "business_impact"],
        "additionalProperties": False
    }
}

# ---------------------------------------------------------------------------
# Sensitive Data Redaction (Privacy Protection)
# ---------------------------------------------------------------------------

# Headers that may contain secrets/credentials - always redact values
SENSITIVE_HEADERS = frozenset([
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "proxy-authorization",
    "www-authenticate",
    "x-amz-security-token",
    "x-aws-access-key-id",
])

# Patterns for secrets in response bodies
BODY_REDACTION_PATTERNS = [
    # API keys and tokens
    (re.compile(r'(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.I), r'\1="[REDACTED]"'),
    (re.compile(r'(secret|token|password|passwd|pwd)["\s:=]+["\']?([^\s"\'<>&]{8,})["\']?', re.I), r'\1="[REDACTED]"'),
    # AWS keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])'), '[REDACTED_SECRET]'),
    # JWT tokens
    (re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'), '[REDACTED_JWT]'),
    # Session IDs (generic patterns)
    (re.compile(r'(session[_-]?id|sess|sid)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.I), r'\1="[REDACTED]"'),
    # Email addresses (PII)
    (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), '[REDACTED_EMAIL]'),
]


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """
    Redact sensitive header values before sending to AI provider.

    Preserves header names but replaces sensitive values with [REDACTED].
    """
    if not headers:
        return {}

    redacted = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in SENSITIVE_HEADERS:
            redacted[key] = "[REDACTED]"
        elif "token" in key_lower or "auth" in key_lower or "key" in key_lower:
            # Catch custom auth headers
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def redact_response_body(body: str) -> str:
    """
    Redact potential secrets and PII from response body before sending to AI.

    Applies pattern-based redaction for common secret formats.
    """
    if not body:
        return ""

    redacted = body
    for pattern, replacement in BODY_REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    return redacted


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class AIClassificationResult:
    """Result of AI classification for a single finding."""
    verdict: str  # "true_positive", "false_positive", "unclear"
    confidence: float  # 0.0-1.0
    rationale: str
    verification_steps: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    attack_narrative: str | None = None
    severity_adjustment: str | None = None  # "upgrade", "downgrade", None
    classification_source: str = "provider"  # provider | heuristic_fallback


# ---------------------------------------------------------------------------
# System Prompts
# ---------------------------------------------------------------------------

SECURITY_ANALYST_SYSTEM_PROMPT = """You are an expert application security analyst performing vulnerability triage. You have deep expertise in:
- OWASP Top 10 (2021)
- CWE/SANS Top 25
- CVSSv3.1 scoring
- Web application security patterns
- Cloud security misconfigurations
- Cryptographic best practices

CLASSIFICATION GUIDELINES:
- true_positive: Finding represents a real, exploitable vulnerability or confirmed misconfiguration
- false_positive: Finding is a non-issue (honeypot, WAF test response, HTML 404 page, etc.)
- unclear: Insufficient evidence to determine; requires manual verification

CONFIDENCE CALIBRATION:
- 0.95+: Definitive evidence (actual exploitation, confirmed response differences)
- 0.80-0.94: Strong evidence (specialized tool confirmed, consistent attack patterns)
- 0.60-0.79: Moderate evidence (heuristic detection, partial confirmation)
- 0.40-0.59: Weak evidence (keyword matching, possible false positive)
- <0.40: Insufficient evidence (lean toward unclear)

IMPORTANT RULES:
1. Static misconfigurations (missing headers, DNS issues) are always true_positive if confirmed
2. Consider honeypot indicators (405 responses, "enterprise security testing" text, intentional traps)
3. Check for HTML wrappers in exposed files (often custom 404 pages)
4. Cross-reference findings (weak TLS + sensitive data = higher risk)
5. Be skeptical of automated tool output without corroborating evidence
6. Never suggest invasive testing in verification steps (only GET/HEAD/OPTIONS)

RESPONSE FORMAT (strict JSON):
{
  "findings": [
    {
      "finding_id": "string - the id from input",
      "verdict": "true_positive|false_positive|unclear",
      "confidence": 0.0-1.0,
      "rationale": "Brief explanation of classification logic",
      "attack_narrative": "For true_positives: how an attacker would exploit this (null for FP/unclear)",
      "verification_steps": ["Safe commands to verify (curl/GET/HEAD only)"],
      "remediation": ["Prioritized fix steps"],
      "false_positive_indicators": ["Signs this might be FP (null if TP)"],
      "severity_adjustment": null | "upgrade" | "downgrade",
      "severity_adjustment_reason": "If adjusted, explain why (null otherwise)"
    }
  ],
  "cross_finding_correlations": ["Findings that indicate attack chains or compounding risk"],
  "overall_risk_assessment": "1-2 sentence risk summary"
}"""

EXECUTIVE_SUMMARY_SYSTEM_PROMPT = """You are a senior security consultant preparing an executive briefing for C-level stakeholders. Your audience is NOT technical - they need to understand:

1. BUSINESS RISK: What could go wrong? What's the financial/reputational impact?
2. URGENCY: What needs immediate attention vs. planned remediation?
3. COMPLIANCE: How does this affect audits (PCI DSS, SOC 2, HIPAA, GDPR)?
4. POSITIVE NEWS: What security controls are working well?
5. ACTION PLAN: Clear, prioritized next steps with effort estimates

WRITING STYLE:
- No technical jargon (translate CVEs/CWEs to business impact)
- Use analogies when helpful ("This is like leaving the front door unlocked")
- Be specific about impact ("Customer data could be exposed" not just "data breach risk")
- Provide timeline recommendations ("Address within 24 hours" / "Plan for next sprint")

RESPONSE FORMAT (strict JSON):
{
  "risk_overview": "2-3 sentence summary of overall security posture",
  "risk_score_interpretation": "What the grade/score means in plain terms",
  "critical_issues": [
    {
      "title": "Business-friendly title",
      "business_impact": "What could happen to the business",
      "urgency": "immediate|this_week|this_month|planned",
      "affected_assets": "What systems/data are at risk"
    }
  ],
  "attack_surface_summary": "What an attacker could target (plain language)",
  "recommended_actions": [
    {
      "priority": 1,
      "action": "What to do",
      "owner": "Suggested responsible team (DevOps/Security/Dev)",
      "effort": "hours|days|weeks",
      "impact": "What this fixes"
    }
  ],
  "compliance_impact": {
    "frameworks_affected": ["PCI DSS", "SOC 2", "HIPAA", "GDPR"],
    "summary": "Plain language compliance implications"
  },
  "positive_findings": ["Security controls that are working well"],
  "timeline_recommendation": "Overall remediation timeline suggestion"
}"""


# ---------------------------------------------------------------------------
# Test/Honeypot Target Detection
# ---------------------------------------------------------------------------

# Hostname patterns that indicate test/honeypot/staging environments
TEST_TARGET_INDICATORS = frozenset([
    "honey", "honeypot", "test", "testing", "staging", "stage", "dev", "development",
    "sandbox", "demo", "preview", "qa", "uat", "preprod", "pre-prod", "canary",
    "localhost", "127.0.0.1", ".local", ".test", ".example", ".invalid"
])


def is_test_honeypot_target(hostname: str) -> bool:
    """Detect if the target appears to be a test/honeypot/staging environment.

    This is used to provide appropriate context to AI analysis and avoid
    generating inappropriate compliance warnings for non-production targets.

    Args:
        hostname: The target hostname (e.g., "honey.example.com", "staging.app.io")

    Returns:
        True if the hostname appears to be a test/honeypot target
    """
    if not hostname:
        return False

    hostname_lower = hostname.lower()

    # Check direct matches and subdomain patterns
    for indicator in TEST_TARGET_INDICATORS:
        # Check if indicator is a subdomain component or hostname suffix
        if (indicator in hostname_lower.split('.') or
            hostname_lower.startswith(indicator + '.') or
            hostname_lower.startswith(indicator + '-') or
            '-' + indicator + '.' in hostname_lower or
            '-' + indicator + '-' in hostname_lower):
            return True

    return False


# ---------------------------------------------------------------------------
# Finding-Type Context Templates
# ---------------------------------------------------------------------------

FINDING_CONTEXT_TEMPLATES = {
    "xss": """XSS FINDING ANALYSIS:
Consider: Is the reflection in an executable context? Does CSP block execution?
Check for: DOM-based vs reflected, encoding bypass, WAF evasion indicators.""",

    "sqli": """SQL INJECTION ANALYSIS:
Consider: Are responses consistent with SQL execution? Could this be a honeypot?
Check for: Error-based indicators, blind injection patterns, database fingerprints.""",

    "exposed_files": """EXPOSED FILE ANALYSIS:
Consider: Is the content authentic or an HTML wrapper (custom 404)?
Check for: File signatures (BEGIN PRIVATE KEY), consistent content types, realistic file sizes.""",

    "tls_config": """TLS CONFIGURATION ANALYSIS:
This is a static configuration finding - always true_positive if evidence confirms.
Check for: Protocol versions, cipher strength, certificate validity.""",

    "api_security": """API SECURITY ANALYSIS:
Consider: Is auth truly bypassed or just missing on intentionally public endpoints?
Check for: Inconsistent auth enforcement, sensitive data exposure, swagger/openapi access.""",

    "csrf": """CSRF ANALYSIS:
Consider: Is this a state-changing form? Is there other CSRF protection (SameSite, custom headers)?
Check for: Token presence, cookie attributes, origin validation.""",

    "cors_scanner": """CORS ANALYSIS:
Consider: Does the CORS policy allow credential exposure? Is the origin truly dangerous?
Check for: Wildcard origins with credentials, null origin reflection, subdomain patterns.""",

    "http_headers": """HTTP HEADERS ANALYSIS:
This is a static configuration finding - always true_positive if header is missing/misconfigured.
Check for: HSTS, CSP, X-Frame-Options, X-Content-Type-Options presence and strength.""",

    "dns_policy": """DNS POLICY ANALYSIS:
This is a static configuration finding - always true_positive if DNS record is missing/misconfigured.
Check for: SPF, DMARC, DKIM, DNSSEC presence and correct configuration.""",

    "graphql_vulnerability": """GRAPHQL ANALYSIS:
Consider: Is introspection enabled? Are there sensitive queries accessible?
Check for: Introspection availability, batch query abuse, authorization on resolvers.""",

    "subdomain_takeover": """SUBDOMAIN TAKEOVER ANALYSIS:
Consider: Is the DNS pointing to a claimable service?
Check for: CNAME to deprovisioned services (S3, Azure, Heroku, GitHub Pages).""",

    "nuclei": """NUCLEI SCAN RESULT:
Nuclei uses well-maintained templates. Confidence is typically high.
Check for: Template ID, matcher type, response evidence.""",

    "dalfox": """DALFOX XSS RESULT:
Dalfox is a specialized XSS scanner. Cross-reference with CSP policy.
Check for: Injection point, payload type, reflection context.""",

    "sqlmap": """SQLMAP RESULT:
SQLmap is a specialized SQL injection tool. High confidence for confirmed injections.
Check for: Injection type, database type, exploitation level.""",
}


# ---------------------------------------------------------------------------
# JSON Repair for Truncated Responses
# ---------------------------------------------------------------------------

def _repair_truncated_json(content: str) -> str | None:
    """
    Attempt to repair truncated JSON responses from AI models.

    Common truncation scenarios:
    - Unterminated strings: {"key": "value...  -> {"key": "value"}
    - Missing closing braces: {"a": {"b": 1}  -> {"a": {"b": 1}}
    - Missing closing brackets: [1, 2, 3  -> [1, 2, 3]
    - Trailing comma: {"a": 1,}  -> {"a": 1}

    Returns repaired JSON string or None if repair failed.
    """
    if not content:
        return None

    # Track open braces/brackets
    brace_count = 0
    bracket_count = 0
    in_string = False
    escape_next = False
    last_char = ''

    for i, char in enumerate(content):
        if escape_next:
            escape_next = False
            continue

        if char == '\\' and in_string:
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            elif char == '[':
                bracket_count += 1
            elif char == ']':
                bracket_count -= 1

        last_char = char

    # If we're still in a string, it was truncated - close it
    if in_string:
        content = content + '"'

    # Remove trailing commas before closing
    content = re.sub(r',\s*$', '', content)
    content = re.sub(r',\s*}', '}', content)
    content = re.sub(r',\s*]', ']', content)

    # Add missing closing braces/brackets
    while brace_count > 0:
        content = content + '}'
        brace_count -= 1

    while bracket_count > 0:
        content = content + ']'
        bracket_count -= 1

    # Final validation - try parsing
    try:
        json.loads(content)
        return content
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# AI Provider Communication
# ---------------------------------------------------------------------------


def _clone_messages(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    return [{"role": str(msg.get("role", "user")), "content": str(msg.get("content", ""))} for msg in messages]


def _append_strict_json_instruction(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Append a strict JSON reminder without mutating caller-provided messages."""
    cloned = _clone_messages(messages)
    strict_hint = "IMPORTANT: Respond with ONLY valid JSON. No markdown, no explanations."
    if cloned and cloned[-1].get("role") == "user":
        content = cloned[-1].get("content", "")
        if strict_hint not in content:
            cloned[-1]["content"] = f"{content}\n\n{strict_hint}"
    else:
        cloned.append({"role": "user", "content": strict_hint})
    return cloned


def _parse_model_chain(model: str, fallback_models: str | list[str] | None = None) -> list[str]:
    """Parse primary model + optional fallbacks from strings/lists."""
    chain: list[str] = []

    def _extend(raw: str | None) -> None:
        if not raw:
            return
        for part in str(raw).split(","):
            candidate = part.strip()
            if candidate and candidate not in chain:
                chain.append(candidate)

    _extend(model)
    if isinstance(fallback_models, str):
        _extend(fallback_models)
    elif isinstance(fallback_models, list):
        for item in fallback_models:
            _extend(str(item))

    return chain


def _provider_kind_from_url(ai_url: str) -> str:
    """Infer request format from URL path."""
    try:
        parsed = urlparse(ai_url)
        path = (parsed.path or "").rstrip("/").lower()
    except Exception:
        path = ai_url.lower()
    if path.endswith("/v1/messages"):
        return "anthropic_messages"
    return "chat_completions"


def _supports_structured_outputs(model: str) -> bool:
    model_base = model.split("/")[-1].lower()
    return any(m in model_base for m in STRUCTURED_OUTPUT_MODELS)


def _build_response_format_candidates(
    model: str,
    json_schema: dict[str, Any] | None,
) -> list[tuple[str, dict[str, Any] | None]]:
    modes: list[tuple[str, dict[str, Any] | None]] = []
    if json_schema and _supports_structured_outputs(model):
        modes.append(("json_schema", {"type": "json_schema", "json_schema": json_schema}))
    modes.append(("json_object", {"type": "json_object"}))
    modes.append(("none", None))
    return modes


def _build_request_headers(ai_api_key: str, provider_kind: str) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Title": "scanner-ai-review",
    }
    if provider_kind == "anthropic_messages":
        headers["x-api-key"] = ai_api_key
        headers["anthropic-version"] = "2023-06-01"
    else:
        headers["Authorization"] = f"Bearer {ai_api_key}"
    return headers


def _build_request_body(
    provider_kind: str,
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    temperature: float,
    response_format: dict[str, Any] | None,
) -> dict[str, Any]:
    if provider_kind == "anthropic_messages":
        system_parts: list[str] = []
        anthropic_messages: list[dict[str, str]] = []
        for msg in messages:
            role = str(msg.get("role", "user"))
            content = str(msg.get("content", ""))
            if role == "system":
                if content:
                    system_parts.append(content)
                continue
            if role not in {"user", "assistant"}:
                role = "user"
            anthropic_messages.append({"role": role, "content": content})
        if not anthropic_messages:
            anthropic_messages = [{"role": "user", "content": "Respond with JSON."}]
        body: dict[str, Any] = {
            "model": model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_parts:
            body["system"] = "\n\n".join(system_parts)
        return body

    body = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if response_format:
        body["response_format"] = response_format
    return body


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
        for key in ("text", "content", "value", "output_text", "reasoning_content", "reasoning"):
            if key in value:
                chunks.extend(_extract_text_chunks(value.get(key)))
        # Some providers nest text parts under output/message blocks.
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
    """Parse JSON payload from raw text, fenced blocks, or embedded snippets."""
    if not content:
        return None
    stripped = _strip_markdown_fences(content)
    if not stripped:
        return None

    decoder = json.JSONDecoder()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        repaired = _repair_truncated_json(stripped)
        if repaired:
            try:
                return json.loads(repaired)
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
    """Extract already-parsed JSON from provider-specific fields if present."""
    choices = response_data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first, dict) else {}
        if isinstance(message, dict):
            parsed = message.get("parsed")
            if parsed is not None:
                return parsed
    return None


def _extract_content_and_reasoning(response_data: dict[str, Any]) -> tuple[str, str]:
    content_chunks: list[str] = []
    reasoning_chunks: list[str] = []

    choices = response_data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first, dict) else {}
        if isinstance(message, dict):
            content_chunks.extend(_extract_text_chunks(message.get("content")))
            reasoning_chunks.extend(_extract_text_chunks(message.get("reasoning_content")))
            reasoning_chunks.extend(_extract_text_chunks(message.get("reasoning")))
        if isinstance(first, dict):
            delta = first.get("delta")
            if isinstance(delta, dict):
                content_chunks.extend(_extract_text_chunks(delta.get("content")))

    content_chunks.extend(_extract_text_chunks(response_data.get("content")))
    content_chunks.extend(_extract_text_chunks(response_data.get("output_text")))
    content_chunks.extend(_extract_text_chunks(response_data.get("completion")))
    content_chunks.extend(_extract_text_chunks(response_data.get("output")))
    reasoning_chunks.extend(_extract_text_chunks(response_data.get("reasoning")))

    content = "\n".join(chunk for chunk in content_chunks if chunk).strip()
    reasoning = "\n".join(chunk for chunk in reasoning_chunks if chunk).strip()
    return content, reasoning


def _error_mentions_response_format(error_text: str) -> bool:
    text = (error_text or "").lower()
    return any(pat in text for pat in RESPONSE_FORMAT_UNSUPPORTED_PATTERNS)


def _is_retryable_provider_error(error_text: str | None) -> bool:
    text = str(error_text or "").strip().lower()
    if not text:
        return False
    return any(pattern in text for pattern in RETRYABLE_PROVIDER_ERROR_PATTERNS)


def _should_open_provider_circuit(error_count: int) -> bool:
    return int(error_count) >= AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD


def _is_provider_circuit_open(open_until_monotonic: float | None, now_monotonic: float) -> bool:
    return bool(open_until_monotonic and open_until_monotonic > now_monotonic)


def _refresh_provider_circuit_locked(now_monotonic: float) -> None:
    open_until = _AI_CLASSIFY_CIRCUIT_STATE.get("open_until_monotonic")
    if isinstance(open_until, (int, float)) and open_until <= now_monotonic:
        _AI_CLASSIFY_CIRCUIT_STATE["open_until_monotonic"] = None

    window_started = _AI_CLASSIFY_CIRCUIT_STATE.get("window_started_monotonic")
    if not isinstance(window_started, (int, float)):
        _AI_CLASSIFY_CIRCUIT_STATE["window_started_monotonic"] = now_monotonic
        _AI_CLASSIFY_CIRCUIT_STATE["error_count"] = 0
        return

    if now_monotonic - float(window_started) > AI_CLASSIFY_CIRCUIT_WINDOW_SECONDS:
        _AI_CLASSIFY_CIRCUIT_STATE["window_started_monotonic"] = now_monotonic
        _AI_CLASSIFY_CIRCUIT_STATE["error_count"] = 0


def _get_provider_circuit_state(now_monotonic: float | None = None) -> dict[str, Any]:
    now_value = now_monotonic if isinstance(now_monotonic, (int, float)) else time.monotonic()
    with _AI_CLASSIFY_CIRCUIT_LOCK:
        _refresh_provider_circuit_locked(now_value)
        open_until = _AI_CLASSIFY_CIRCUIT_STATE.get("open_until_monotonic")
        is_open = _is_provider_circuit_open(
            float(open_until) if isinstance(open_until, (int, float)) else None,
            now_value,
        )
        remaining = 0
        if is_open and isinstance(open_until, (int, float)):
            remaining = max(0, int(open_until - now_value))
        return {
            "error_count": max(0, int(_AI_CLASSIFY_CIRCUIT_STATE.get("error_count") or 0)),
            "is_open": is_open,
            "open_until_monotonic": open_until if isinstance(open_until, (int, float)) else None,
            "cooldown_remaining_seconds": remaining,
            "last_error": _AI_CLASSIFY_CIRCUIT_STATE.get("last_error"),
        }


def _register_provider_circuit_failure(error_text: str, now_monotonic: float | None = None) -> tuple[bool, int]:
    if not _is_retryable_provider_error(error_text):
        return False, 0
    now_value = now_monotonic if isinstance(now_monotonic, (int, float)) else time.monotonic()
    with _AI_CLASSIFY_CIRCUIT_LOCK:
        _refresh_provider_circuit_locked(now_value)
        error_count = max(0, int(_AI_CLASSIFY_CIRCUIT_STATE.get("error_count") or 0)) + 1
        _AI_CLASSIFY_CIRCUIT_STATE["error_count"] = error_count
        _AI_CLASSIFY_CIRCUIT_STATE["last_error"] = str(error_text)[:400]
        if _should_open_provider_circuit(error_count):
            _AI_CLASSIFY_CIRCUIT_STATE["open_until_monotonic"] = now_value + AI_CLASSIFY_CIRCUIT_COOLDOWN_SECONDS
            return True, error_count
        return False, error_count


def _clear_provider_circuit_state() -> None:
    with _AI_CLASSIFY_CIRCUIT_LOCK:
        _AI_CLASSIFY_CIRCUIT_STATE["error_count"] = 0
        _AI_CLASSIFY_CIRCUIT_STATE["window_started_monotonic"] = time.monotonic()
        _AI_CLASSIFY_CIRCUIT_STATE["open_until_monotonic"] = None
        _AI_CLASSIFY_CIRCUIT_STATE["last_error"] = None


def _remaining_budget_seconds(deadline_monotonic: float | None) -> float | None:
    if deadline_monotonic is None:
        return None
    return max(0.0, float(deadline_monotonic) - time.monotonic())


def _is_budget_exhausted(deadline_monotonic: float | None) -> bool:
    remaining = _remaining_budget_seconds(deadline_monotonic)
    return bool(remaining is not None and remaining <= 0.0)


async def _sleep_with_budget(delay_seconds: float, deadline_monotonic: float | None) -> bool:
    sleep_for = max(0.0, float(delay_seconds))
    if sleep_for <= 0.0:
        return True

    remaining = _remaining_budget_seconds(deadline_monotonic)
    if remaining is not None:
        if remaining <= 0.0:
            return False
        sleep_for = min(sleep_for, remaining)
        if sleep_for <= 0.0:
            return False

    await asyncio.sleep(sleep_for)
    return True


async def call_ai_provider(
    ai_url: str,
    ai_api_key: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: int = 45,
    max_tokens: int = 4000,
    temperature: float = 0.3,
    json_schema: dict[str, Any] | None = None,
    fallback_models: str | list[str] | None = None,
    overall_budget_seconds: int | None = None,
    use_circuit_breaker: bool = True,
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """
    Call AI provider and parse JSON response with model/mode fallback.

    Includes automatic retry with exponential backoff for transient errors
    and JSON parse failures.

    Args:
        json_schema: Optional strict JSON schema for structured outputs.
                    Only used for compatible chat-completions models.
        fallback_models: Optional comma-separated string or list of fallback model IDs.
        overall_budget_seconds: Optional hard cap for the entire model/mode fallback chain.
        use_circuit_breaker: When true, fail fast while transient provider failures are cooling down.

    Returns:
        Tuple of (parsed_response, error_message, latency_ms)
    """
    if aiohttp is None:
        logger.error("AI validation failed: aiohttp not installed")
        return None, "aiohttp not installed", None

    if not ai_url or not ai_api_key:
        return None, "AI provider URL/API key not configured", None

    model_chain = _parse_model_chain(model, fallback_models)
    if not model_chain:
        return None, "AI model not configured", None

    effective_budget_seconds = (
        AI_CLASSIFY_CHAIN_BUDGET_SECONDS
        if overall_budget_seconds is None
        else max(0, int(overall_budget_seconds))
    )
    budget_deadline_monotonic = (
        time.monotonic() + effective_budget_seconds
        if effective_budget_seconds > 0
        else None
    )

    if use_circuit_breaker:
        circuit_state = _get_provider_circuit_state()
        if circuit_state.get("is_open"):
            cooldown = int(circuit_state.get("cooldown_remaining_seconds") or 0)
            error = (
                f"AI provider circuit open ({cooldown}s remaining) "
                "after repeated transient failures"
            )
            logger.warning(error)
            return None, error, 0

    provider_kind = _provider_kind_from_url(ai_url)
    headers = _build_request_headers(ai_api_key, provider_kind)
    total_start = time.time()
    cumulative_latency_ms = 0
    attempt_errors: list[str] = []
    budget_error: str | None = None

    for model_name in model_chain:
        if _is_budget_exhausted(budget_deadline_monotonic):
            budget_error = f"AI provider budget exceeded {effective_budget_seconds}s"
            break

        if provider_kind == "anthropic_messages":
            mode_candidates = [("none", None)]
        else:
            mode_candidates = _build_response_format_candidates(model_name, json_schema)

        for mode_name, response_format in mode_candidates:
            if _is_budget_exhausted(budget_deadline_monotonic):
                budget_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                break

            mode_error: str | None = None
            strict_retry = False

            for attempt in range(AI_RETRY_ATTEMPTS):
                if _is_budget_exhausted(budget_deadline_monotonic):
                    mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                    budget_error = mode_error
                    break

                start = time.time()
                messages_for_attempt = _clone_messages(messages)
                max_tokens_for_attempt = max_tokens
                if strict_retry:
                    messages_for_attempt = _append_strict_json_instruction(messages_for_attempt)
                    max_tokens_for_attempt = min(
                        MAX_REASONING_RETRY_TOKENS,
                        max(max_tokens_for_attempt + 1000, max_tokens_for_attempt * 2),
                    )

                body = _build_request_body(
                    provider_kind=provider_kind,
                    model=model_name,
                    messages=messages_for_attempt,
                    max_tokens=max_tokens_for_attempt,
                    temperature=temperature,
                    response_format=response_format,
                )

                try:
                    remaining_budget = _remaining_budget_seconds(budget_deadline_monotonic)
                    if remaining_budget is not None and remaining_budget <= 0.0:
                        mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                        budget_error = mode_error
                        break

                    request_timeout_seconds = float(timeout_seconds)
                    if remaining_budget is not None:
                        request_timeout_seconds = max(1.0, min(request_timeout_seconds, remaining_budget))

                    timeout = aiohttp.ClientTimeout(total=request_timeout_seconds)
                    async with aiohttp.ClientSession(timeout=timeout) as sess:
                        async with sess.post(ai_url, json=body, headers=headers) as resp:
                            latency_ms = int((time.time() - start) * 1000)
                            cumulative_latency_ms += latency_ms

                            if resp.status != 200:
                                error_text = (await resp.text())[:500]
                                mode_error = f"HTTP {resp.status}: {error_text}"

                                if resp.status in RETRYABLE_STATUS_CODES and attempt < AI_RETRY_ATTEMPTS - 1:
                                    delay = min(AI_RETRY_BASE_DELAY * (2 ** attempt), AI_RETRY_MAX_DELAY)
                                    logger.warning(
                                        f"AI provider HTTP {resp.status}, retrying in {delay:.1f}s "
                                        f"(model={model_name}, mode={mode_name}, attempt {attempt + 1}/{AI_RETRY_ATTEMPTS})"
                                    )
                                    if not await _sleep_with_budget(delay, budget_deadline_monotonic):
                                        mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                                        budget_error = mode_error
                                        break
                                    continue

                                # Auth errors are definitive; no point rotating models.
                                if resp.status in {401, 403}:
                                    return None, mode_error, cumulative_latency_ms

                                # If response_format is rejected, try less strict mode.
                                if response_format and resp.status in {400, 422} and _error_mentions_response_format(error_text):
                                    logger.debug(
                                        "AI provider rejected response_format; downgrading mode "
                                        f"(model={model_name}, mode={mode_name})"
                                    )
                                break

                            try:
                                response_data = await resp.json(content_type=None)
                            except Exception:
                                raw_text = (await resp.text())[:500]
                                mode_error = f"Invalid JSON response envelope: {raw_text}"
                                if attempt < AI_RETRY_ATTEMPTS - 1:
                                    delay = min(AI_RETRY_BASE_DELAY * (2 ** attempt), AI_RETRY_MAX_DELAY)
                                    if not await _sleep_with_budget(delay, budget_deadline_monotonic):
                                        mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                                        budget_error = mode_error
                                        break
                                    continue
                                break

                            parsed = _extract_direct_parsed_json(response_data)
                            content_text, reasoning_text = _extract_content_and_reasoning(response_data)
                            if parsed is None and content_text:
                                parsed = _extract_json_payload(content_text)

                            if parsed is None:
                                mode_error = "Empty content in response" if not content_text else "Invalid JSON in response"
                                if attempt < AI_RETRY_ATTEMPTS - 1 and not strict_retry:
                                    strict_retry = True
                                    delay = AI_RETRY_BASE_DELAY
                                    logger.warning(
                                        "AI response parse failed, retrying with stricter JSON prompt "
                                        f"(model={model_name}, mode={mode_name})"
                                    )
                                    if not await _sleep_with_budget(delay, budget_deadline_monotonic):
                                        mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                                        budget_error = mode_error
                                        break
                                    continue
                                break

                            if not isinstance(parsed, dict):
                                mode_error = "AI response JSON is not an object"
                                break

                            parsed["_provider_meta"] = {
                                "model_used": model_name,
                                "mode_used": mode_name,
                                "provider_kind": provider_kind,
                                "latency_ms": latency_ms,
                                "reasoning_present": bool(reasoning_text),
                            }
                            if use_circuit_breaker:
                                _clear_provider_circuit_state()
                            return parsed, None, cumulative_latency_ms

                except (TimeoutError, asyncio.TimeoutError):
                    latency_ms = int((time.time() - start) * 1000)
                    cumulative_latency_ms += latency_ms
                    mode_error = f"AI provider timeout after {timeout_seconds}s"
                    if attempt < AI_RETRY_ATTEMPTS - 1:
                        delay = min(AI_RETRY_BASE_DELAY * (2 ** attempt), AI_RETRY_MAX_DELAY)
                        logger.warning(
                            f"AI provider timeout, retrying in {delay:.1f}s "
                            f"(model={model_name}, mode={mode_name}, attempt {attempt + 1}/{AI_RETRY_ATTEMPTS})"
                        )
                        if not await _sleep_with_budget(delay, budget_deadline_monotonic):
                            mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                            budget_error = mode_error
                            break
                        continue
                    break

                except aiohttp.ClientError as e:
                    latency_ms = int((time.time() - start) * 1000)
                    cumulative_latency_ms += latency_ms
                    mode_error = f"Network error: {type(e).__name__}: {str(e)[:100]}"
                    if attempt < AI_RETRY_ATTEMPTS - 1:
                        delay = min(AI_RETRY_BASE_DELAY * (2 ** attempt), AI_RETRY_MAX_DELAY)
                        logger.warning(
                            f"AI provider network error ({type(e).__name__}), retrying in {delay:.1f}s "
                            f"(model={model_name}, mode={mode_name}, attempt {attempt + 1}/{AI_RETRY_ATTEMPTS})"
                        )
                        if not await _sleep_with_budget(delay, budget_deadline_monotonic):
                            mode_error = f"AI provider budget exceeded {effective_budget_seconds}s"
                            budget_error = mode_error
                            break
                        continue
                    break

                except Exception as e:
                    latency_ms = int((time.time() - start) * 1000)
                    cumulative_latency_ms += latency_ms
                    mode_error = f"Unexpected error: {type(e).__name__}: {str(e)[:120]}"
                    break

            if mode_error:
                attempt_errors.append(f"{model_name} [{mode_name}]: {mode_error}")
            if budget_error:
                break
        if budget_error:
            break

    total_latency = int((time.time() - total_start) * 1000)
    unique_errors: list[str] = []
    for err in attempt_errors:
        if err not in unique_errors:
            unique_errors.append(err)
    if budget_error and budget_error not in unique_errors:
        unique_errors.append(budget_error)
    if unique_errors:
        compact_error = "; ".join(unique_errors[:3])
        if len(unique_errors) > 3:
            compact_error += f"; +{len(unique_errors) - 3} more"
    else:
        compact_error = "All retries exhausted"

    if use_circuit_breaker:
        circuit_opened, error_count = _register_provider_circuit_failure(compact_error)
        if circuit_opened:
            logger.warning(
                "AI provider circuit opened for %ss after %s transient errors",
                AI_CLASSIFY_CIRCUIT_COOLDOWN_SECONDS,
                error_count,
            )

    logger.warning(f"AI provider call failed after model/mode fallback chain: {compact_error}")
    return None, compact_error, cumulative_latency_ms or total_latency


async def probe_ai_provider(
    ai_url: str,
    ai_api_key: str,
    model: str,
    fallback_models: str | list[str] | None = None,
    timeout_seconds: int = 25,
) -> dict[str, Any]:
    """Run a lightweight provider probe used by settings API/UI."""
    messages = [
        {"role": "system", "content": "Respond only with valid JSON object."},
        {"role": "user", "content": 'Return {"ok": true, "probe": "shakerscan"} as JSON.'},
    ]
    response, error, latency_ms = await call_ai_provider(
        ai_url=ai_url,
        ai_api_key=ai_api_key,
        model=model,
        messages=messages,
        timeout_seconds=timeout_seconds,
        max_tokens=300,
        temperature=0.0,
        fallback_models=fallback_models,
        overall_budget_seconds=max(10, timeout_seconds),
        use_circuit_breaker=False,
    )
    provider_meta = {}
    parsed_response: dict[str, Any] | None = None
    if isinstance(response, dict):
        provider_meta = response.pop("_provider_meta", {}) if isinstance(response.get("_provider_meta"), dict) else {}
        parsed_response = response
    return {
        "ok": error is None and isinstance(parsed_response, dict),
        "error": error,
        "latency_ms": latency_ms,
        "provider_meta": provider_meta,
        "response": parsed_response,
    }


# ---------------------------------------------------------------------------
# Prompt Building
# ---------------------------------------------------------------------------

def get_finding_context(finding: dict[str, Any]) -> str:
    """Get finding-type-specific analysis context."""
    tool = (finding.get("tool") or "").lower()
    title = (finding.get("title") or "").lower()

    # Match by tool first
    if tool in FINDING_CONTEXT_TEMPLATES:
        return FINDING_CONTEXT_TEMPLATES[tool]

    # Match by keywords in title
    for key, template in FINDING_CONTEXT_TEMPLATES.items():
        if key in title or key in tool:
            return template

    return ""


def build_classification_prompt(
    findings: list[dict[str, Any]],
    scan_context: dict[str, Any],
    mask_host: str
) -> str:
    """
    Build a comprehensive user prompt with full scan context.
    """
    # Build context summary
    http_info = scan_context.get("http", {})
    dns_info = scan_context.get("dns", {})
    tls_info = scan_context.get("tls", {})
    discovery_info = scan_context.get("discovery", {})

    context_summary = {
        "target": mask_host,
        "http_status": http_info.get("status"),
        "security_headers_present": {
            "hsts": bool(http_info.get("security_headers", {}).get("hsts")),
            "csp": bool(http_info.get("security_headers", {}).get("csp")),
            "x_frame_options": bool(http_info.get("security_headers", {}).get("x_frame_options")),
            "x_content_type_options": bool(http_info.get("security_headers", {}).get("x_content_type_options")),
        },
        "tls_info": {
            "protocols": list(tls_info.get("cipher_suites", {}).keys()) if tls_info.get("cipher_suites") else [],
            "cert_days_remaining": tls_info.get("certificate", {}).get("days_remaining"),
        },
        "dns_info": {
            "spf_present": bool(dns_info.get("spf")),
            "dmarc_present": bool(dns_info.get("dmarc", {}).get("record")),
            "dnssec_status": dns_info.get("dnssec", {}).get("status"),
        },
        "tech_stack": discovery_info.get("technologies", [])[:10],  # Limit to 10
        "waf_detected": discovery_info.get("waf_detected", False),
    }

    # Prepare findings with context hints
    findings_for_ai = []
    for f in findings:
        finding_data = {
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "tool": f.get("tool"),
            "cvss_score": f.get("cvss_score"),
            "cwe": f.get("cwe"),
            "owasp": f.get("owasp"),
        }

        # Include evidence, but limit size
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            # Serialize and truncate if too large
            ev_str = json.dumps(evidence, default=str)
            if len(ev_str) > 1000:
                finding_data["evidence"] = {"_truncated": True, "summary": ev_str[:1000]}
            else:
                finding_data["evidence"] = evidence

        # Add analysis context hint
        context_hint = get_finding_context(f)
        if context_hint:
            finding_data["_analysis_hint"] = context_hint

        findings_for_ai.append(finding_data)

    return json.dumps({
        "instruction": "Classify each finding as true_positive, false_positive, or unclear. Provide confidence scores and remediation guidance.",
        "scan_context": context_summary,
        "findings": findings_for_ai,
        "total_findings": len(findings_for_ai)
    }, indent=2)


def build_executive_summary_prompt(report: dict[str, Any], mask_host: str) -> str:
    """Build prompt for executive summary generation."""
    result = report.get("result", {})
    findings = report.get("findings", [])

    # Categorize findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Get top findings (critical and high only)
    top_findings = [
        {"title": f.get("title"), "severity": f.get("severity"), "cwe": f.get("cwe")}
        for f in findings
        if f.get("severity", "").lower() in ("critical", "high")
    ][:10]  # Limit to 10

    # If no critical/high, include medium findings instead
    if not top_findings:
        top_findings = [
            {"title": f.get("title"), "severity": f.get("severity"), "cwe": f.get("cwe")}
            for f in findings
            if f.get("severity", "").lower() == "medium"
        ][:10]

    # Extract TLS info to prevent AI from hallucinating encryption issues
    tls_info = report.get("tls", {})
    tls_summary = {}
    if tls_info:
        cert = tls_info.get("certificate", {})
        cipher_suites = tls_info.get("cipher_suites", {})
        # Check if all ciphers are secure
        all_secure = True
        tls_versions = []
        for proto, ciphers in cipher_suites.items():
            tls_versions.append(proto)
            if isinstance(ciphers, list):
                for c in ciphers:
                    if isinstance(c, dict) and (c.get("weak") or c.get("insecure")):
                        all_secure = False
        # Check endpoints for TLS 1.3
        endpoints = tls_info.get("endpoints", [])
        supports_tls13 = any(ep.get("tlsversion") == "tls13" for ep in endpoints if isinstance(ep, dict))

        tls_summary = {
            "encryption_status": "strong" if all_secure else "weak_ciphers_present",
            "supports_tls13": supports_tls13,
            "protocols_found": tls_versions,
            "certificate_valid": cert.get("days_remaining", 0) > 0,
            "certificate_days_remaining": cert.get("days_remaining"),
        }

    # Build instruction with explicit guidance
    instruction_parts = [
        "Generate an executive summary for non-technical stakeholders.",
        "Focus on business impact, urgency, and actionable recommendations.",
    ]

    # Add explicit guidance based on findings
    if severity_counts["critical"] == 0 and severity_counts["high"] == 0:
        instruction_parts.append(
            "IMPORTANT: There are NO critical or high severity vulnerabilities. "
            "Do NOT invent or exaggerate issues. Focus on the medium/low findings that exist. "
            "The critical_issues section should only contain ACTUAL findings from the scan, not hypothetical scenarios."
        )

    if tls_summary.get("encryption_status") == "strong":
        instruction_parts.append(
            "NOTE: TLS/encryption is properly configured with secure ciphers. "
            "Do NOT report 'weak encryption' issues - the encryption is strong."
        )

    # Check if target appears to be a test/honeypot environment
    is_test_target = is_test_honeypot_target(mask_host)
    if is_test_target:
        instruction_parts.append(
            "IMPORTANT: This target appears to be a test/honeypot/staging environment "
            f"(hostname: {mask_host}). DO NOT include compliance framework analysis "
            "(PCI DSS, HIPAA, GDPR, SOC 2) - these are not applicable to test environments. "
            "Set compliance_impact.frameworks_affected to an empty array []. "
            "Focus the summary on technical findings only, not business impact or regulatory risk. "
            "Vulnerabilities found may be intentional honeypot artifacts."
        )

    summary_data = {
        "target": mask_host,
        "overall_score": result.get("score"),
        "overall_grade": result.get("grade"),
        "severity_breakdown": severity_counts,
        "total_findings": len(findings),
        "top_findings": top_findings,
        "no_critical_or_high": severity_counts["critical"] == 0 and severity_counts["high"] == 0,
        "compliance_frameworks": result.get("compliance", {}).get("owasp_top10", []),
        "cvss_metrics": result.get("cvss_metrics", {}),
        "tls_summary": tls_summary,
        "is_test_target": is_test_target,  # Signal to skip compliance analysis
    }

    return json.dumps({
        "instruction": " ".join(instruction_parts),
        "scan_summary": summary_data
    }, indent=2)


# ---------------------------------------------------------------------------
# Hybrid Confidence Scoring
# ---------------------------------------------------------------------------

def calculate_hybrid_confidence(
    heuristic_verdict: str,
    heuristic_confidence: float,
    heuristic_rationale: str,
    ai_result: AIClassificationResult | None
) -> tuple[str, float, str]:
    """
    Combine heuristic and AI verdicts with weighted confidence.

    Strategy:
    - If both agree: boost confidence
    - If disagree: use confidence-weighted decision, flag for review
    - If AI unavailable: use heuristics with slight confidence penalty

    Returns:
        Tuple of (final_verdict, final_confidence, combined_rationale)
    """
    if ai_result is None:
        # AI unavailable - use heuristics with 10% confidence penalty
        adj_conf = max(0.4, heuristic_confidence * 0.9)
        return (heuristic_verdict, adj_conf, f"{heuristic_rationale} [AI unavailable]")

    a_verdict = ai_result.verdict
    a_conf = ai_result.confidence
    a_rationale = ai_result.rationale

    # Both agree
    if heuristic_verdict == a_verdict:
        # Boost confidence by averaging and adding agreement bonus
        combined_conf = min(0.99, (heuristic_confidence + a_conf) / 2 + 0.1)
        return (
            heuristic_verdict,
            round(combined_conf, 2),
            f"Heuristic+AI agree: {heuristic_rationale}; AI: {a_rationale}"
        )

    # Disagreement handling
    if heuristic_confidence > a_conf + 0.2:
        # Heuristic is significantly more confident - trust heuristic
        final_conf = heuristic_confidence * 0.85
        return (
            heuristic_verdict,
            round(final_conf, 2),
            f"Heuristic ({heuristic_confidence:.0%}): {heuristic_rationale}; AI disagreed as {a_verdict} ({a_conf:.0%})"
        )
    elif a_conf > heuristic_confidence + 0.2:
        # AI is significantly more confident - trust AI
        final_conf = a_conf * 0.85
        return (
            a_verdict,
            round(final_conf, 2),
            f"AI ({a_conf:.0%}): {a_rationale}; Heuristic disagreed as {heuristic_verdict} ({heuristic_confidence:.0%})"
        )
    else:
        # Close confidence levels with differing verdicts
        # Instead of always marking unclear, use the higher-confidence verdict with penalty
        # Only mark as "unclear" if BOTH have low confidence (< 0.5)
        avg_conf = (heuristic_confidence + a_conf) / 2

        if heuristic_confidence < 0.5 and a_conf < 0.5:
            # Both sources have low confidence - genuinely unclear
            return (
                "unclear",
                round(avg_conf * 0.7, 2),
                f"CONFLICT: Low confidence from both. Heuristic says {heuristic_verdict} ({heuristic_confidence:.0%}), AI says {a_verdict} ({a_conf:.0%}). Manual review recommended."
            )

        # At least one has decent confidence - use the higher one with penalty
        if heuristic_confidence >= a_conf:
            final_verdict = heuristic_verdict
            final_conf = heuristic_confidence * 0.75
            rationale = f"Heuristic ({heuristic_confidence:.0%}) slightly preferred over AI ({a_conf:.0%}): {heuristic_rationale}"
        else:
            final_verdict = a_verdict
            final_conf = a_conf * 0.75
            rationale = f"AI ({a_conf:.0%}) slightly preferred over heuristic ({heuristic_confidence:.0%}): {a_rationale}"

        return (
            final_verdict,
            round(final_conf, 2),
            f"CONFLICT (resolved): {rationale}"
        )


# ---------------------------------------------------------------------------
# Fallback Classification (when AI unavailable)
# ---------------------------------------------------------------------------

# Tools with high-confidence outputs (well-tested, low false positive rate)
HIGH_CONFIDENCE_TOOLS = frozenset([
    "sqlmap", "dalfox", "nuclei", "testssl", "sslyze",
    "nmap", "subfinder", "katana", "httpx"
])

# Severity-based default confidence (used for fallback)
SEVERITY_CONFIDENCE_MAP = {
    "critical": 0.7,
    "high": 0.6,
    "medium": 0.5,
    "low": 0.4,
    "info": 0.3,
}


def fallback_classify_finding(finding: dict[str, Any]) -> AIClassificationResult:
    """
    Rule-based classification when AI is unavailable.

    Uses heuristics based on tool reputation and finding characteristics.
    Always marks findings as needing AI review.
    """
    tool = finding.get("tool", "").lower()
    severity = finding.get("severity", "medium").lower()
    title = finding.get("title", "").lower()

    # High-confidence tools get true_positive verdict
    if tool in HIGH_CONFIDENCE_TOOLS:
        verdict = "true_positive"
        confidence = SEVERITY_CONFIDENCE_MAP.get(severity, 0.5)
        rationale = f"Classified by heuristics (AI unavailable). Tool '{tool}' has high reliability."
    # Info-level findings are typically true positives (they're informational)
    elif severity == "info":
        verdict = "true_positive"
        confidence = 0.6
        rationale = "Informational finding - typically accurate. Classified by heuristics (AI unavailable)."
    # "Potential" or "Possible" in title indicates uncertainty
    elif any(word in title for word in ["potential", "possible", "suspected", "may be"]):
        verdict = "unclear"
        confidence = 0.4
        rationale = "Title indicates uncertainty. Requires manual verification. Classified by heuristics (AI unavailable)."
    else:
        verdict = "unclear"
        confidence = SEVERITY_CONFIDENCE_MAP.get(severity, 0.5) * 0.8
        rationale = f"No AI classification available. Manual review recommended for {severity}-severity finding."

    # Generate basic verification steps based on finding type
    verification_steps = _generate_fallback_verification_steps(finding)

    return AIClassificationResult(
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        verification_steps=verification_steps,
        remediation=[],
        attack_narrative=None,
        severity_adjustment=None,
        classification_source="heuristic_fallback",
    )


def _generate_fallback_verification_steps(finding: dict[str, Any]) -> list[str]:
    """Generate basic verification steps for a finding when AI is unavailable."""
    tool = finding.get("tool", "").lower()
    evidence = finding.get("evidence", {})

    steps = []

    # URL-based verification
    url = evidence.get("url") or evidence.get("matched_at")
    if url:
        steps.append(f"Verify the issue at: {url}")

    # Reproduction command if available
    repro = evidence.get("reproduction")
    if repro:
        steps.append(f"Run reproduction command: {repro}")

    # Tool-specific suggestions
    if "sql" in tool or "sqli" in finding.get("title", "").lower():
        steps.append("Test with manual SQL injection payloads")
        steps.append("Check if error messages reveal database information")
    elif "xss" in tool or "xss" in finding.get("title", "").lower():
        steps.append("Test with manual XSS payloads in a browser")
        steps.append("Check if payload is reflected without encoding")
    elif "cors" in tool:
        steps.append("Test CORS with: curl -H 'Origin: https://evil.com' -I <url>")
    elif "tls" in tool or "ssl" in tool:
        steps.append("Verify with: testssl.sh or sslyze")

    if not steps:
        steps.append("Review the finding evidence manually")
        steps.append("Attempt to reproduce the issue in a controlled environment")

    return steps


# ---------------------------------------------------------------------------
# Batch Classification
# ---------------------------------------------------------------------------


def _chunk_findings_for_classification(
    findings: list[dict[str, Any]],
    scan_context: dict[str, Any],
    mask_host: str,
    max_findings_per_batch: int = DEFAULT_MAX_FINDINGS_PER_BATCH,
    max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS,
) -> list[list[dict[str, Any]]]:
    """Split findings into prompt-safe chunks for providers with tighter limits."""
    if not findings:
        return []

    chunks: list[list[dict[str, Any]]] = []
    start = 0
    total = len(findings)
    max_findings = max(1, max_findings_per_batch)
    max_chars = max(4000, max_prompt_chars)

    while start < total:
        end = min(total, start + max_findings)
        chosen_end = end

        while chosen_end > start:
            candidate = findings[start:chosen_end]
            prompt = build_classification_prompt(candidate, scan_context, mask_host)
            if len(prompt) <= max_chars or chosen_end == start + 1:
                break
            chosen_end -= 1

        if chosen_end <= start:
            chosen_end = min(total, start + 1)

        chunks.append(findings[start:chosen_end])
        start = chosen_end

    return chunks


def _parse_ai_classification_results(response: dict[str, Any]) -> dict[str, AIClassificationResult]:
    parsed: dict[str, AIClassificationResult] = {}
    for ai_finding in response.get("findings", []) or []:
        if not isinstance(ai_finding, dict):
            continue
        finding_id = ai_finding.get("finding_id")
        if not finding_id:
            continue

        verdict = ai_finding.get("verdict", "unclear")
        if verdict not in ("true_positive", "false_positive", "unclear"):
            verdict = "unclear"

        confidence = ai_finding.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)):
            confidence = 0.5
        confidence = max(0.0, min(1.0, float(confidence)))

        parsed[str(finding_id)] = AIClassificationResult(
            verdict=verdict,
            confidence=confidence,
            rationale=ai_finding.get("rationale", ""),
            verification_steps=ai_finding.get("verification_steps", []),
            remediation=ai_finding.get("remediation", []),
            attack_narrative=ai_finding.get("attack_narrative"),
            severity_adjustment=ai_finding.get("severity_adjustment"),
            classification_source="provider",
        )

    return parsed


async def classify_findings_batch(
    findings: list[dict[str, Any]],
    scan_context: dict[str, Any],
    ai_url: str,
    ai_api_key: str,
    model: str,
    mask_host: str = "example.com",
    fallback_models: str | list[str] | None = None,
) -> tuple[dict[str, AIClassificationResult], str | None, int | None, dict[str, Any] | None]:
    """
    Classify findings in one or more AI calls with chunking/fallback.

    Falls back to heuristic-based classification when AI fails for any chunk.

    Returns:
        Tuple of (results_dict, error_message, latency_ms, meta)
        results_dict maps finding_id -> AIClassificationResult
    """
    if not findings:
        return {}, None, None, None

    results: dict[str, AIClassificationResult] = {}
    chunk_errors: list[str] = []
    used_models: list[str] = []
    provider_used = False
    ai_chunks = 0
    total_latency_ms = 0
    cross_finding_correlations: list[str] = []
    overall_risk_assessment: str | None = None
    provider_finding_ids: set[str] = set()
    fallback_finding_ids: set[str] = set()

    finding_chunks = _chunk_findings_for_classification(findings, scan_context, mask_host)
    for chunk_idx, chunk in enumerate(finding_chunks, start=1):
        user_prompt = build_classification_prompt(chunk, scan_context, mask_host)
        messages = [
            {"role": "system", "content": SECURITY_ANALYST_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        response, error, latency_ms = await call_ai_provider(
            ai_url,
            ai_api_key,
            model,
            messages,
            timeout_seconds=60,
            max_tokens=4000,
            json_schema=CLASSIFICATION_JSON_SCHEMA,
            fallback_models=fallback_models,
        )
        if latency_ms:
            total_latency_ms += latency_ms

        if error or not response:
            chunk_errors.append(f"chunk {chunk_idx}/{len(finding_chunks)}: {error or 'empty response'}")
            for finding in chunk:
                finding_id = finding.get("id")
                if finding_id and finding_id not in results:
                    fid = str(finding_id)
                    results[fid] = fallback_classify_finding(finding)
                    fallback_finding_ids.add(fid)
            continue

        chunk_results = _parse_ai_classification_results(response)
        provider_meta = response.get("_provider_meta", {}) if isinstance(response, dict) else {}
        used_model = provider_meta.get("model_used") if isinstance(provider_meta, dict) else None
        if isinstance(used_model, str) and used_model and used_model not in used_models:
            used_models.append(used_model)
        if chunk_results:
            provider_used = True
            ai_chunks += 1

        for finding in chunk:
            finding_id = finding.get("id")
            if not finding_id:
                continue
            fid = str(finding_id)
            if fid in chunk_results:
                results[fid] = chunk_results[fid]
                provider_finding_ids.add(fid)
            else:
                results[fid] = fallback_classify_finding(finding)
                fallback_finding_ids.add(fid)
                chunk_errors.append(f"chunk {chunk_idx}/{len(finding_chunks)}: missing AI verdict for finding {fid}")

        corr = response.get("cross_finding_correlations", [])
        if isinstance(corr, list):
            for item in corr:
                if isinstance(item, str) and item and item not in cross_finding_correlations:
                    cross_finding_correlations.append(item)

        risk = response.get("overall_risk_assessment")
        if isinstance(risk, str) and risk and not overall_risk_assessment:
            overall_risk_assessment = risk

    # Safety net in case some records lacked IDs during chunk processing.
    for finding in findings:
        finding_id = finding.get("id")
        if finding_id and str(finding_id) not in results:
            fid = str(finding_id)
            results[fid] = fallback_classify_finding(finding)
            fallback_finding_ids.add(fid)

    latency_out = total_latency_ms or None
    if not provider_used:
        err = chunk_errors[0] if chunk_errors else "AI classification unavailable"
        return results, f"AI unavailable, used heuristics: {err}", latency_out, {
            "provider_used": False,
            "used_models": used_models,
            "chunks_total": len(finding_chunks),
            "chunks_with_ai": 0,
            "chunks_fallback": len(finding_chunks),
            "provider_finding_ids": [],
            "fallback_finding_ids": sorted(fallback_finding_ids),
            "errors": chunk_errors[:5],
            "cross_finding_correlations": cross_finding_correlations,
            "overall_risk_assessment": overall_risk_assessment,
        }

    partial_error: str | None = None
    if chunk_errors:
        partial_error = f"AI partially unavailable: {'; '.join(chunk_errors[:3])}"
        if len(chunk_errors) > 3:
            partial_error += f"; +{len(chunk_errors) - 3} more"

    meta = {
        "provider_used": True,
        "used_models": used_models,
        "chunks_total": len(finding_chunks),
        "chunks_with_ai": ai_chunks,
        "chunks_fallback": len(finding_chunks) - ai_chunks,
        "provider_finding_ids": sorted(provider_finding_ids),
        "fallback_finding_ids": sorted(fallback_finding_ids),
        "errors": chunk_errors[:5],
        "cross_finding_correlations": cross_finding_correlations,
        "overall_risk_assessment": overall_risk_assessment,
    }
    return results, partial_error, latency_out, meta


# ---------------------------------------------------------------------------
# Executive Summary Generation
# ---------------------------------------------------------------------------

def _unmask_domain_in_structure(obj: Any, mask_host: str, real_host: str) -> Any:
    """Recursively replace mask_host with real_host in all strings within a structure."""
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj.replace(mask_host, real_host)
    if isinstance(obj, dict):
        return {k: _unmask_domain_in_structure(v, mask_host, real_host) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_unmask_domain_in_structure(item, mask_host, real_host) for item in obj]
    return obj


async def generate_executive_summary(
    report: dict[str, Any],
    ai_url: str,
    ai_api_key: str,
    model: str,
    mask_host: str = "example.com",
    real_host: str | None = None,
    fallback_models: str | list[str] | None = None,
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """
    Generate an AI-powered executive summary for non-technical stakeholders.

    Args:
        report: The scan report dict
        ai_url: AI provider URL
        ai_api_key: AI provider API key
        model: Model identifier
        mask_host: The placeholder domain sent to AI (default: example.com)
        real_host: The actual target domain to replace mask_host with in output

    Returns:
        Tuple of (summary_dict, error_message, latency_ms)
    """
    user_prompt = build_executive_summary_prompt(report, mask_host)

    messages = [
        {"role": "system", "content": EXECUTIVE_SUMMARY_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    response, error, latency_ms = await call_ai_provider(
        ai_url, ai_api_key, model, messages,
        timeout_seconds=45,  # Increased timeout for larger responses
        max_tokens=3000,  # Increased from 2000 to handle longer summaries
        json_schema=EXECUTIVE_SUMMARY_JSON_SCHEMA,  # Use strict structured outputs
        fallback_models=fallback_models,
    )

    if error:
        logger.warning(f"AI executive summary generation failed: {error}")
        return None, error, latency_ms

    # Remove internal provider metadata before persisting report output.
    if response:
        response.pop("_provider_meta", None)

    # Unmask domain in the response if real_host is provided
    if response and real_host and mask_host != real_host:
        response = _unmask_domain_in_structure(response, mask_host, real_host)

    return response, None, latency_ms


# ---------------------------------------------------------------------------
# Response-Based AI Validation (for hard cases only)
# ---------------------------------------------------------------------------

RESPONSE_VALIDATION_PROMPT = """You are analyzing an HTTP response to determine if a detected vulnerability is real or a false positive.

You will receive:
1. The vulnerability finding (type, severity, where it was detected)
2. The actual HTTP response content (or relevant portion)
3. Context about how the vulnerability was detected

Your job is to analyze the response and determine:
1. Is this a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (not exploitable)?
2. What is your confidence level?

COMMON FALSE POSITIVE PATTERNS:
- XSS: Payload reflected but in non-executable context (JSON, comments, attribute values with proper encoding)
- XSS: Response has CSP that blocks inline scripts
- SQLi: Error message is a generic 500 error, not a database error
- SQLi: "SQL syntax" appears in page content unrelated to the injection
- Path Traversal: Response is a custom 404 page, not the actual file
- SSRF: Internal IP in response but it's hardcoded in the application
- Exposed files: HTML wrapper around the content (custom 404)
- API endpoints: "Unauthorized" or "403" means auth is working, not bypassed

TRUE POSITIVE INDICATORS:
- XSS: Payload in <script> tag, event handler, or javascript: URL that would execute
- SQLi: Database-specific error messages (MySQL, PostgreSQL, MSSQL, Oracle syntax errors)
- SQLi: Boolean-based response differences (true condition shows data, false doesn't)
- Path Traversal: Actual file contents visible (root:x:0:0, [boot loader], etc.)
- SSRF: Response contains content from internal services
- Exposed files: Raw file content without HTML wrappers

RESPONSE FORMAT (strict JSON):
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of why you reached this conclusion",
  "evidence_in_response": "Quote the specific part of the response that proves your verdict",
  "recommended_action": "What should be done (report as-is, downgrade severity, filter out)"
}"""


@dataclass
class ResponseValidationResult:
    """Result of AI-based response validation."""
    verdict: str  # "true_positive", "false_positive", "uncertain"
    confidence: float
    reasoning: str
    evidence: str | None = None
    recommended_action: str = "report"


async def validate_finding_with_response(
    finding: dict[str, Any],
    response_body: str,
    response_headers: dict[str, str] | None = None,
    ai_url: str = "",
    ai_api_key: str = "",
    model: str = "gpt-4o-mini"
) -> ResponseValidationResult | None:
    """
    Use AI to validate a finding by analyzing the actual HTTP response.

    This is for HARD CASES ONLY - when pattern matching is inconclusive.
    Do NOT call this for every finding (expensive, slow).

    Args:
        finding: The vulnerability finding
        response_body: The HTTP response body
        response_headers: Optional response headers
        ai_url: AI provider URL (OpenAI-compatible)
        ai_api_key: AI API key
        model: Model to use (default: gpt-4o-mini for speed/cost)

    Returns:
        ResponseValidationResult or None if AI unavailable/failed
    """
    if not ai_url or not ai_api_key:
        return None

    # SECURITY: Redact sensitive data before sending to AI provider
    # This prevents leaking cookies, tokens, API keys, PII to external services
    redacted_body = redact_response_body(response_body)
    redacted_headers = redact_headers(response_headers)

    # Truncate response to avoid token limits (after redaction)
    max_response_len = 3000
    truncated_body = redacted_body[:max_response_len]
    if len(redacted_body) > max_response_len:
        truncated_body += f"\n... [truncated, {len(redacted_body)} total chars]"

    # Build user prompt with redacted data
    user_prompt = json.dumps({
        "finding": {
            "type": finding.get("title", "Unknown"),
            "severity": finding.get("severity", "unknown"),
            "tool": finding.get("tool", "unknown"),
            "evidence_summary": str(finding.get("evidence", {}))[:500]
        },
        "response": {
            "body": truncated_body,
            "headers": redacted_headers,
            "content_type": redacted_headers.get("content-type", "unknown")
        },
        "question": "Is this finding a true positive or false positive based on the response?"
    }, indent=2)

    messages = [
        {"role": "system", "content": RESPONSE_VALIDATION_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    response, error, _ = await call_ai_provider(
        ai_url, ai_api_key, model, messages,
        timeout_seconds=20,
        max_tokens=500,
        temperature=0.2  # Low temperature for more consistent verdicts
    )

    if error:
        logger.warning(f"AI response validation failed: {error}")
        return None

    if not response:
        logger.warning("AI response validation returned empty response")
        return None

    verdict = response.get("verdict", "uncertain")
    if verdict not in ("true_positive", "false_positive", "uncertain"):
        verdict = "uncertain"

    confidence = response.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    confidence = max(0.0, min(1.0, float(confidence)))

    return ResponseValidationResult(
        verdict=verdict,
        confidence=confidence,
        reasoning=response.get("reasoning", ""),
        evidence=response.get("evidence_in_response"),
        recommended_action=response.get("recommended_action", "report")
    )


# ---------------------------------------------------------------------------
# Smart AI Trigger Logic
# ---------------------------------------------------------------------------

# Finding types where AI validation is most valuable (expanded list)
AI_VALIDATION_VALUABLE_FOR = frozenset([
    # Injection vulnerabilities
    "xss", "sqli", "ssrf", "xxe", "ssti", "rce", "lfi", "rfi",
    "nosql", "ldap", "xpath", "command_injection", "code_injection",
    # Access control
    "idor", "bola", "bfla", "auth_bypass", "csrf", "open_redirect",
    "privilege_escalation", "broken_access",
    # Exposure/Disclosure
    "exposed_file", "exposed_secret", "exposed_credential", "api_security",
    "sensitive_data", "information_disclosure", "default_credential",
    # Configuration
    "cors", "security_header", "misconfiguration", "subdomain_takeover",
    # Path traversal variants
    "path_traversal", "directory_traversal", "file_inclusion",
])

# Confidence range where AI adds value (widened for better coverage)
# Lower bound: 0.30 catches more uncertain findings
# Upper bound: 0.90 allows AI review of high-confidence criticals
AI_CONFIDENCE_RANGE = (0.30, 0.90)


def should_use_ai_validation(
    finding: dict[str, Any],
    current_confidence: float,
    ai_enabled: bool = False
) -> bool:
    """
    Determine if AI validation should be used for this finding.

    AI validation is expensive, so only use it when:
    1. AI is enabled by user
    2. Finding type benefits from semantic analysis
    3. Current confidence is in the uncertain range
    4. Severity warrants the cost

    IMPORTANT: Always validate critical findings regardless of confidence
    to prevent false positive criticals from destroying the score.

    Returns:
        True if AI validation should be attempted
    """
    if not ai_enabled:
        return False

    severity = finding.get("severity", "").lower()

    # ALWAYS validate critical findings - false positive criticals are very damaging
    if severity == "critical":
        return True

    # Skip info findings (too many, low value)
    if severity == "info":
        return False

    # For high severity, use wider confidence range
    if severity == "high":
        if 0.20 <= current_confidence <= 0.95:
            return True

    # For medium/low, check confidence is in standard uncertain range
    if current_confidence < AI_CONFIDENCE_RANGE[0] or current_confidence > AI_CONFIDENCE_RANGE[1]:
        return False

    # Check finding type matches valuable categories
    title_lower = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()
    cwe = finding.get("cwe", "").lower()

    for vuln_type in AI_VALIDATION_VALUABLE_FOR:
        if vuln_type in title_lower or vuln_type in tool:
            return True

    # Also check CWE-based matching for common vulnerability classes
    cwe_valuable = {
        "cwe-79": True,   # XSS
        "cwe-89": True,   # SQLi
        "cwe-918": True,  # SSRF
        "cwe-611": True,  # XXE
        "cwe-22": True,   # Path Traversal
        "cwe-639": True,  # IDOR
        "cwe-352": True,  # CSRF
        "cwe-601": True,  # Open Redirect
        "cwe-78": True,   # OS Command Injection
        "cwe-94": True,   # Code Injection
        "cwe-287": True,  # Auth Bypass
        "cwe-200": True,  # Information Disclosure
        "cwe-942": True,  # CORS
    }
    if cwe in cwe_valuable:
        return True

    return False


async def enhance_finding_with_ai(
    finding: dict[str, Any],
    response_body: str | None,
    response_headers: dict[str, str] | None,
    ai_url: str,
    ai_api_key: str,
    model: str = "gpt-4o-mini"
) -> dict[str, Any]:
    """
    Enhance a finding with AI analysis when appropriate.

    Only runs AI validation for hard cases where it adds value.
    Modifies the finding in place with AI results.

    Returns:
        The finding (modified in place)
    """
    current_confidence = finding.get("confidence", 0.5)

    # Check if AI validation would help
    if not should_use_ai_validation(finding, current_confidence, ai_enabled=bool(ai_api_key)):
        return finding

    if not response_body:
        return finding

    # Run AI validation
    result = await validate_finding_with_response(
        finding=finding,
        response_body=response_body,
        response_headers=response_headers,
        ai_url=ai_url,
        ai_api_key=ai_api_key,
        model=model
    )

    if result is None:
        logger.debug(f"AI validation returned no result for finding {finding.get('id', 'unknown')}")
        return finding

    # Apply AI results to finding
    finding["ai_validation"] = {
        "verdict": result.verdict,
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "evidence": result.evidence
    }

    # Adjust finding based on AI verdict
    if result.verdict == "false_positive" and result.confidence >= 0.75:
        # High-confidence FP - mark for filtering
        finding["ai_verdict"] = "false_positive"
        finding["confidence"] = min(finding.get("confidence", 0.5), 0.25)
        finding["filter_reason"] = f"AI FP detection: {result.reasoning}"

    elif result.verdict == "true_positive" and result.confidence >= 0.80:
        # High-confidence TP - boost confidence
        finding["ai_verdict"] = "true_positive"
        finding["confidence"] = max(finding.get("confidence", 0.5), result.confidence)

    elif result.verdict == "uncertain":
        # AI couldn't decide - flag for manual review
        finding["ai_verdict"] = "uncertain"
        finding["needs_manual_review"] = True

    return finding
