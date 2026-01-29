"""
Race Condition Testing Module

Tests for TOCTOU (Time-of-Check-Time-of-Use) and concurrency vulnerabilities
in web applications and APIs.

OWASP: Race Conditions
CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

All functions follow async patterns and return structured dictionaries.
"""

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp

from .common import run, get_auth_curl_args, AdaptiveRateLimiter


# =============================================================================
# CONFIGURATION
# =============================================================================

# Default number of concurrent requests for race condition testing
DEFAULT_CONCURRENT_REQUESTS = 10

# Maximum concurrent requests to avoid overwhelming targets
MAX_CONCURRENT_REQUESTS = 50

# Timeout for individual requests during race testing
RACE_REQUEST_TIMEOUT = 10

# Delay between race test batches to allow state recovery
BATCH_DELAY_SECONDS = 1.0


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class RaceTestResult:
    """Result from a single race condition test."""
    endpoint: str
    method: str
    concurrent_requests: int
    successful_responses: int
    failed_responses: int
    response_codes: dict[int, int]  # status_code -> count
    unique_responses: int
    timing_spread_ms: float  # Difference between fastest and slowest response
    potential_race: bool
    evidence: str
    confidence: float
    responses: list[dict] = field(default_factory=list)


@dataclass
class RaceConditionFinding:
    """A confirmed or suspected race condition vulnerability."""
    type: str
    severity: str
    endpoint: str
    method: str
    evidence: str
    confidence: float
    cwe: str = "CWE-362"
    details: dict = field(default_factory=dict)


# =============================================================================
# RACE CONDITION ENDPOINT PATTERNS
# =============================================================================

# Endpoints commonly vulnerable to race conditions
RACE_PRONE_PATTERNS = [
    # Financial/transactional
    (r"/checkout", "checkout_race", "high"),
    (r"/pay", "payment_race", "high"),
    (r"/transfer", "transfer_race", "critical"),
    (r"/withdraw", "withdrawal_race", "critical"),
    (r"/deposit", "deposit_race", "high"),
    (r"/purchase", "purchase_race", "high"),
    (r"/order", "order_race", "high"),
    (r"/buy", "purchase_race", "high"),

    # Coupon/discount
    (r"/coupon", "coupon_race", "high"),
    (r"/promo", "promo_race", "high"),
    (r"/discount", "discount_race", "high"),
    (r"/redeem", "redeem_race", "high"),
    (r"/voucher", "voucher_race", "high"),
    (r"/gift[-_]?card", "giftcard_race", "high"),

    # Inventory/stock
    (r"/cart", "cart_race", "medium"),
    (r"/add[-_]?to[-_]?cart", "cart_race", "medium"),
    (r"/inventory", "inventory_race", "high"),
    (r"/stock", "stock_race", "high"),
    (r"/reserve", "reservation_race", "high"),
    (r"/book", "booking_race", "high"),

    # Account/points
    (r"/points", "points_race", "high"),
    (r"/credits", "credits_race", "high"),
    (r"/balance", "balance_race", "high"),
    (r"/reward", "reward_race", "high"),
    (r"/bonus", "bonus_race", "high"),

    # Like/vote/rating
    (r"/like", "like_race", "low"),
    (r"/upvote", "vote_race", "low"),
    (r"/downvote", "vote_race", "low"),
    (r"/vote", "vote_race", "low"),
    (r"/rate", "rating_race", "low"),
    (r"/follow", "follow_race", "low"),

    # Invitation/referral
    (r"/invite", "invite_race", "medium"),
    (r"/referral", "referral_race", "medium"),
    (r"/signup[-_]?bonus", "signup_race", "high"),

    # File operations
    (r"/upload", "upload_race", "medium"),
    (r"/delete", "delete_race", "medium"),

    # API tokens/keys
    (r"/api[-_]?key", "apikey_race", "high"),
    (r"/token", "token_race", "high"),
    (r"/refresh", "refresh_race", "medium"),
]

# Parameters that indicate race-prone operations
RACE_PRONE_PARAMS = [
    "quantity", "qty", "amount", "count", "num",
    "coupon", "promo", "code", "voucher",
    "price", "total", "discount",
    "points", "credits", "balance",
    "limit", "max", "available",
]


# =============================================================================
# CORE RACE CONDITION TESTING
# =============================================================================

async def send_concurrent_requests(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: dict | str | None = None,
    concurrent_count: int = DEFAULT_CONCURRENT_REQUESTS,
    timeout: float = RACE_REQUEST_TIMEOUT,
) -> list[dict]:
    """
    Send multiple identical requests concurrently to test for race conditions.

    Uses asyncio.gather() to fire all requests as simultaneously as possible.

    Args:
        url: Target URL
        method: HTTP method
        headers: Request headers including auth
        body: Request body (dict for JSON, str for form data)
        concurrent_count: Number of concurrent requests
        timeout: Timeout per request in seconds

    Returns:
        List of response dictionaries with timing info
    """
    results = []

    async def single_request(request_id: int) -> dict:
        """Execute a single request and capture timing."""
        start_time = time.monotonic()
        result = {
            "request_id": request_id,
            "status_code": None,
            "body": None,
            "headers": {},
            "elapsed_ms": 0,
            "error": None,
            "start_time": start_time,
        }

        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                request_kwargs = {
                    "headers": headers or {},
                    "ssl": False,  # Allow self-signed certs for internal testing
                }

                if body:
                    if isinstance(body, dict):
                        request_kwargs["json"] = body
                    else:
                        request_kwargs["data"] = body

                async with session.request(method, url, **request_kwargs) as response:
                    result["status_code"] = response.status
                    result["headers"] = dict(response.headers)
                    try:
                        result["body"] = await response.text()
                    except Exception:
                        result["body"] = ""

        except asyncio.TimeoutError:
            result["error"] = "timeout"
        except aiohttp.ClientError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = f"unexpected: {str(e)}"

        result["elapsed_ms"] = (time.monotonic() - start_time) * 1000
        return result

    # Fire all requests concurrently
    tasks = [single_request(i) for i in range(concurrent_count)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle any exceptions that were raised
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append({
                "request_id": i,
                "status_code": None,
                "body": None,
                "headers": {},
                "elapsed_ms": 0,
                "error": str(result),
            })
        else:
            processed_results.append(result)

    return processed_results


def analyze_race_responses(
    responses: list[dict],
    expected_single_success: bool = True,
) -> RaceTestResult:
    """
    Analyze responses from concurrent requests to detect race conditions.

    Detection heuristics:
    1. Multiple successful responses when only one should succeed
    2. Response inconsistency (different data for same request)
    3. Timing anomalies suggesting lock contention

    Args:
        responses: List of response dicts from send_concurrent_requests
        expected_single_success: Whether only one request should succeed

    Returns:
        RaceTestResult with analysis
    """
    # Count response codes
    status_counts: dict[int, int] = {}
    for resp in responses:
        code = resp.get("status_code")
        if code:
            status_counts[code] = status_counts.get(code, 0) + 1

    # Count successes (2xx responses)
    successful = sum(count for code, count in status_counts.items() if code and 200 <= code < 300)
    failed = len(responses) - successful

    # Calculate timing spread
    valid_times = [r["elapsed_ms"] for r in responses if r.get("elapsed_ms", 0) > 0]
    timing_spread = max(valid_times) - min(valid_times) if valid_times else 0

    # Check for response uniqueness (hash response bodies)
    body_hashes = set()
    for resp in responses:
        body = resp.get("body", "")
        if body:
            body_hashes.add(hashlib.md5(body.encode()).hexdigest())

    unique_responses = len(body_hashes)

    # Determine if race condition likely exists
    potential_race = False
    evidence = ""
    confidence = 0.0

    if expected_single_success and successful > 1:
        # Multiple successes when only one expected - strong indicator
        potential_race = True
        evidence = f"Expected 1 success, got {successful} successful responses"
        confidence = min(0.95, 0.5 + (successful - 1) * 0.15)

    elif unique_responses > 1 and successful > 1:
        # Different response bodies suggest state inconsistency
        potential_race = True
        evidence = f"Got {unique_responses} unique responses, indicating state inconsistency"
        confidence = 0.7

    elif timing_spread > 2000 and successful > 1:
        # Large timing spread with multiple successes suggests lock contention
        potential_race = True
        evidence = f"Timing spread of {timing_spread:.0f}ms suggests lock contention"
        confidence = 0.5

    return RaceTestResult(
        endpoint="",  # To be filled by caller
        method="",
        concurrent_requests=len(responses),
        successful_responses=successful,
        failed_responses=failed,
        response_codes=status_counts,
        unique_responses=unique_responses,
        timing_spread_ms=timing_spread,
        potential_race=potential_race,
        evidence=evidence,
        confidence=confidence,
        responses=responses,
    )


# =============================================================================
# SPECIFIC RACE CONDITION TESTS
# =============================================================================

async def test_race_condition(
    url: str,
    method: str = "POST",
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    concurrent_requests: int = DEFAULT_CONCURRENT_REQUESTS,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Generic race condition test for any endpoint.

    Sends N identical requests simultaneously and analyzes responses
    for signs of race conditions.

    Args:
        url: Target endpoint URL
        method: HTTP method (usually POST for state changes)
        body: Request body
        headers: Additional headers
        concurrent_requests: Number of concurrent requests (default 10)
        auth_session: AuthSession for authenticated testing

    Returns:
        Dict with test results and any findings
    """
    # Build headers with auth
    request_headers = headers.copy() if headers else {}
    if auth_session:
        exported = auth_session.export_session()
        for key, value in exported.get("headers", {}).items():
            request_headers[key] = value
        cookies = exported.get("cookies", {})
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            request_headers["Cookie"] = cookie_str

    # Add content-type for JSON body
    if body and isinstance(body, dict):
        request_headers.setdefault("Content-Type", "application/json")

    # Send concurrent requests
    responses = await send_concurrent_requests(
        url=url,
        method=method,
        headers=request_headers,
        body=body,
        concurrent_count=min(concurrent_requests, MAX_CONCURRENT_REQUESTS),
    )

    # Analyze results
    result = analyze_race_responses(responses, expected_single_success=True)
    result.endpoint = url
    result.method = method

    findings = []
    if result.potential_race:
        findings.append(RaceConditionFinding(
            type="race_condition",
            severity="high" if result.confidence > 0.7 else "medium",
            endpoint=url,
            method=method,
            evidence=result.evidence,
            confidence=result.confidence,
            details={
                "concurrent_requests": result.concurrent_requests,
                "successful_responses": result.successful_responses,
                "response_codes": result.response_codes,
                "timing_spread_ms": result.timing_spread_ms,
            }
        ))

    return {
        "tested": True,
        "endpoint": url,
        "method": method,
        "concurrent_requests": result.concurrent_requests,
        "successful_responses": result.successful_responses,
        "failed_responses": result.failed_responses,
        "response_codes": result.response_codes,
        "timing_spread_ms": result.timing_spread_ms,
        "potential_race": result.potential_race,
        "evidence": result.evidence,
        "confidence": result.confidence,
        "findings": [f.__dict__ for f in findings],
    }


async def test_checkout_race(
    checkout_url: str,
    body: dict | None = None,
    quantity_param: str = "quantity",
    auth_session: Any = None,
    concurrent_requests: int = 10,
) -> dict[str, Any]:
    """
    Test for e-commerce checkout race conditions.

    Attempts to exploit race conditions in purchase flows by sending
    multiple simultaneous checkout requests.

    Common vulnerabilities:
    - Purchasing more items than in stock
    - Double-charging or under-charging
    - Applying discounts multiple times

    Args:
        checkout_url: Checkout/purchase endpoint
        body: Checkout request body
        quantity_param: Parameter name for quantity (for analysis)
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent checkout attempts

    Returns:
        Dict with test results
    """
    if body is None:
        body = {}

    result = await test_race_condition(
        url=checkout_url,
        method="POST",
        body=body,
        concurrent_requests=concurrent_requests,
        auth_session=auth_session,
    )

    # Additional checkout-specific analysis
    if result["successful_responses"] > 1:
        result["evidence"] = f"Multiple checkout requests succeeded ({result['successful_responses']}). " \
                            f"Potential for inventory overselling or duplicate orders."
        result["potential_race"] = True
        result["confidence"] = max(result["confidence"], 0.85)

        # Check response bodies for order confirmations
        order_ids = set()
        for resp in result.get("responses", []):
            body_text = resp.get("body", "")
            # Look for order IDs in responses
            order_matches = re.findall(r'"order[_-]?id"[:\s]*"?(\w+)"?', body_text, re.I)
            order_ids.update(order_matches)

        if len(order_ids) > 1:
            result["evidence"] += f" Created {len(order_ids)} separate orders."
            result["details"]["order_ids"] = list(order_ids)

    result["test_type"] = "checkout_race"
    return result


async def test_coupon_race(
    apply_coupon_url: str,
    coupon_code: str,
    body_template: dict | None = None,
    coupon_param: str = "code",
    auth_session: Any = None,
    concurrent_requests: int = 10,
) -> dict[str, Any]:
    """
    Test for coupon/promo code race conditions.

    Attempts to redeem a single-use coupon multiple times simultaneously.

    Args:
        apply_coupon_url: Coupon application endpoint
        coupon_code: The coupon code to test
        body_template: Base request body (coupon code will be added)
        coupon_param: Parameter name for coupon code
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent redemption attempts

    Returns:
        Dict with test results
    """
    body = body_template.copy() if body_template else {}
    body[coupon_param] = coupon_code

    result = await test_race_condition(
        url=apply_coupon_url,
        method="POST",
        body=body,
        concurrent_requests=concurrent_requests,
        auth_session=auth_session,
    )

    # Coupon-specific analysis
    successful = result["successful_responses"]
    if successful > 1:
        result["evidence"] = f"Coupon '{coupon_code}' was successfully applied {successful} times. " \
                            f"Single-use coupon race condition likely exists."
        result["potential_race"] = True
        result["confidence"] = max(result["confidence"], 0.9)

        # Look for discount amounts in responses
        discounts = []
        for resp in result.get("responses", []):
            body_text = resp.get("body", "")
            discount_matches = re.findall(r'"discount"[:\s]*(\d+(?:\.\d+)?)', body_text)
            discounts.extend(float(d) for d in discount_matches)

        if discounts:
            total_discount = sum(discounts)
            result["details"]["total_discount_applied"] = total_discount
            result["details"]["discount_applications"] = len(discounts)

    result["test_type"] = "coupon_race"
    result["coupon_code"] = coupon_code
    return result


async def test_balance_race(
    transfer_url: str,
    amount: float | int,
    body_template: dict | None = None,
    amount_param: str = "amount",
    auth_session: Any = None,
    concurrent_requests: int = 10,
) -> dict[str, Any]:
    """
    Test for balance/funds transfer race conditions.

    Attempts to transfer/withdraw more funds than available by
    exploiting race conditions in balance checks.

    Args:
        transfer_url: Transfer/withdrawal endpoint
        amount: Amount to transfer per request
        body_template: Base request body
        amount_param: Parameter name for amount
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent transfer attempts

    Returns:
        Dict with test results
    """
    body = body_template.copy() if body_template else {}
    body[amount_param] = amount

    result = await test_race_condition(
        url=transfer_url,
        method="POST",
        body=body,
        concurrent_requests=concurrent_requests,
        auth_session=auth_session,
    )

    # Balance-specific analysis
    successful = result["successful_responses"]
    if successful > 1:
        potential_total = amount * successful
        result["evidence"] = f"Transfer of {amount} succeeded {successful} times. " \
                            f"Potential total transferred: {potential_total}. " \
                            f"Balance race condition likely exists."
        result["potential_race"] = True
        result["confidence"] = max(result["confidence"], 0.9)
        result["details"]["amount_per_request"] = amount
        result["details"]["potential_total_transferred"] = potential_total

    result["test_type"] = "balance_race"
    return result


async def test_like_vote_race(
    vote_url: str,
    body: dict | None = None,
    auth_session: Any = None,
    concurrent_requests: int = 20,
) -> dict[str, Any]:
    """
    Test for like/vote/rating race conditions.

    Attempts to register multiple votes simultaneously, bypassing
    single-vote restrictions.

    Args:
        vote_url: Vote/like endpoint
        body: Request body
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent vote attempts

    Returns:
        Dict with test results
    """
    result = await test_race_condition(
        url=vote_url,
        method="POST",
        body=body,
        concurrent_requests=concurrent_requests,
        auth_session=auth_session,
    )

    successful = result["successful_responses"]
    if successful > 1:
        result["evidence"] = f"Vote/like registered {successful} times from same user. " \
                            f"Vote manipulation via race condition possible."
        result["potential_race"] = True
        result["confidence"] = max(result["confidence"], 0.8)

    result["test_type"] = "vote_race"
    return result


async def test_invitation_race(
    invite_url: str,
    invite_code: str | None = None,
    body_template: dict | None = None,
    auth_session: Any = None,
    concurrent_requests: int = 10,
) -> dict[str, Any]:
    """
    Test for invitation/referral bonus race conditions.

    Attempts to claim referral bonuses multiple times.

    Args:
        invite_url: Invitation/referral endpoint
        invite_code: Invitation code if required
        body_template: Base request body
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent claims

    Returns:
        Dict with test results
    """
    body = body_template.copy() if body_template else {}
    if invite_code:
        body["code"] = invite_code

    result = await test_race_condition(
        url=invite_url,
        method="POST",
        body=body,
        concurrent_requests=concurrent_requests,
        auth_session=auth_session,
    )

    successful = result["successful_responses"]
    if successful > 1:
        result["evidence"] = f"Invitation/referral bonus claimed {successful} times. " \
                            f"Referral abuse via race condition possible."
        result["potential_race"] = True
        result["confidence"] = max(result["confidence"], 0.85)

    result["test_type"] = "invitation_race"
    return result


# =============================================================================
# ENDPOINT DISCOVERY AND AUTOMATED TESTING
# =============================================================================

def identify_race_prone_endpoints(
    endpoints: list[dict],
) -> list[dict]:
    """
    Identify endpoints that are likely vulnerable to race conditions.

    Analyzes endpoint URLs and parameters to find candidates for race testing.

    Args:
        endpoints: List of discovered endpoints with url, method, params

    Returns:
        List of endpoints marked as race-prone with risk assessment
    """
    race_candidates = []

    for endpoint in endpoints:
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", [])

        # Skip GET requests (usually idempotent)
        if method == "GET":
            continue

        # Check URL against race-prone patterns
        url_lower = url.lower()
        for pattern, race_type, severity in RACE_PRONE_PATTERNS:
            if re.search(pattern, url_lower):
                race_candidates.append({
                    **endpoint,
                    "race_type": race_type,
                    "race_severity": severity,
                    "detection_method": "url_pattern",
                })
                break
        else:
            # Check parameters for race-prone indicators
            param_names = [p.get("name", "").lower() for p in params] if isinstance(params, list) else []
            for prone_param in RACE_PRONE_PARAMS:
                if any(prone_param in p for p in param_names):
                    race_candidates.append({
                        **endpoint,
                        "race_type": "parameter_based",
                        "race_severity": "medium",
                        "detection_method": "param_pattern",
                        "prone_param": prone_param,
                    })
                    break

    return race_candidates


async def run_race_condition_tests(
    endpoints: list[dict],
    auth_session: Any = None,
    concurrent_requests: int = DEFAULT_CONCURRENT_REQUESTS,
    test_all: bool = False,
) -> dict[str, Any]:
    """
    Run race condition tests on identified endpoints.

    Args:
        endpoints: List of endpoints to test (from identify_race_prone_endpoints)
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent requests per test
        test_all: If True, test all endpoints; otherwise only high-risk ones

    Returns:
        Dict with all test results and findings
    """
    results = {
        "tested_endpoints": 0,
        "vulnerable_endpoints": 0,
        "findings": [],
        "details": [],
    }

    # Filter to high-risk endpoints unless test_all is True
    if not test_all:
        endpoints = [e for e in endpoints if e.get("race_severity") in ("high", "critical")]

    for endpoint in endpoints:
        url = endpoint.get("url", "")
        method = endpoint.get("method", "POST")
        body = endpoint.get("body")
        race_type = endpoint.get("race_type", "generic")

        # Select appropriate test function based on race type
        if race_type == "checkout_race" or race_type == "purchase_race":
            test_result = await test_checkout_race(
                checkout_url=url,
                body=body,
                auth_session=auth_session,
                concurrent_requests=concurrent_requests,
            )
        elif race_type == "coupon_race" or race_type == "promo_race":
            # Need a coupon code - skip if not available
            coupon_code = endpoint.get("coupon_code", "TEST")
            test_result = await test_coupon_race(
                apply_coupon_url=url,
                coupon_code=coupon_code,
                body_template=body,
                auth_session=auth_session,
                concurrent_requests=concurrent_requests,
            )
        elif race_type in ("transfer_race", "withdrawal_race", "balance_race"):
            amount = endpoint.get("amount", 1)
            test_result = await test_balance_race(
                transfer_url=url,
                amount=amount,
                body_template=body,
                auth_session=auth_session,
                concurrent_requests=concurrent_requests,
            )
        elif race_type == "vote_race" or race_type == "like_race":
            test_result = await test_like_vote_race(
                vote_url=url,
                body=body,
                auth_session=auth_session,
                concurrent_requests=concurrent_requests,
            )
        else:
            # Generic race test
            test_result = await test_race_condition(
                url=url,
                method=method,
                body=body,
                auth_session=auth_session,
                concurrent_requests=concurrent_requests,
            )

        results["tested_endpoints"] += 1
        results["details"].append(test_result)

        if test_result.get("potential_race"):
            results["vulnerable_endpoints"] += 1
            results["findings"].extend(test_result.get("findings", []))

        # Small delay between tests to avoid overwhelming target
        await asyncio.sleep(BATCH_DELAY_SECONDS)

    return results


# =============================================================================
# CSRF DOUBLE-SUBMIT TESTING
# =============================================================================

async def test_csrf_token_reuse(
    form_url: str,
    submit_url: str,
    csrf_token: str,
    form_data: dict,
    csrf_param: str = "csrf_token",
    auth_session: Any = None,
    concurrent_requests: int = 5,
) -> dict[str, Any]:
    """
    Test if CSRF tokens can be reused in concurrent requests.

    Some applications don't properly invalidate CSRF tokens after use,
    allowing them to be reused in a race condition window.

    Args:
        form_url: URL of the form page (for reference)
        submit_url: Form submission endpoint
        csrf_token: The CSRF token to test
        form_data: Form data to submit
        csrf_param: Parameter name for CSRF token
        auth_session: AuthSession for authenticated testing
        concurrent_requests: Number of concurrent submissions

    Returns:
        Dict with test results
    """
    # Add CSRF token to form data
    body = form_data.copy()
    body[csrf_param] = csrf_token

    result = await test_race_condition(
        url=submit_url,
        method="POST",
        body=body,
        auth_session=auth_session,
        concurrent_requests=concurrent_requests,
    )

    successful = result["successful_responses"]
    if successful > 1:
        result["evidence"] = f"CSRF token reused successfully {successful} times. " \
                            f"Token not invalidated after first use."
        result["potential_race"] = True
        result["confidence"] = 0.9
        result["findings"].append({
            "type": "csrf_token_reuse",
            "severity": "medium",
            "endpoint": submit_url,
            "evidence": result["evidence"],
            "cwe": "CWE-352",
        })

    result["test_type"] = "csrf_token_reuse"
    return result


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def test_race_conditions(
    url: str,
    endpoints: list[dict] | None = None,
    auth_session: Any = None,
    scan_type: str = "standard",
) -> dict[str, Any]:
    """
    Main entry point for race condition testing.

    Discovers race-prone endpoints and runs appropriate tests.

    Args:
        url: Base URL of the target
        endpoints: Pre-discovered endpoints (optional)
        auth_session: AuthSession for authenticated testing
        scan_type: Scan intensity (quick, standard, deep, full)

    Returns:
        Dict with all test results
    """
    results = {
        "tested": True,
        "base_url": url,
        "race_prone_endpoints": 0,
        "findings": [],
        "details": {},
    }

    # Configure based on scan type
    if scan_type == "quick":
        concurrent_requests = 5
        test_all = False
    elif scan_type == "standard":
        concurrent_requests = 10
        test_all = False
    elif scan_type == "deep":
        concurrent_requests = 15
        test_all = True
    else:  # full or aggressive
        concurrent_requests = 20
        test_all = True

    # Identify race-prone endpoints
    if endpoints:
        race_prone = identify_race_prone_endpoints(endpoints)
        results["race_prone_endpoints"] = len(race_prone)

        if race_prone:
            # Run race condition tests
            test_results = await run_race_condition_tests(
                endpoints=race_prone,
                auth_session=auth_session,
                concurrent_requests=concurrent_requests,
                test_all=test_all,
            )

            results["findings"] = test_results["findings"]
            results["details"] = {
                "tested_endpoints": test_results["tested_endpoints"],
                "vulnerable_endpoints": test_results["vulnerable_endpoints"],
                "test_details": test_results["details"],
            }

    return results
