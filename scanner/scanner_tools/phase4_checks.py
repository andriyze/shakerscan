"""
Phase 4 Security Checks - P1 Priority Implementation

This module contains high-priority security checks for:
- File Upload Vulnerabilities (CWE-434)
- Open Redirect (CWE-601)
- Host Header Injection (CWE-644)
- Business Logic Vulnerabilities (CWE-840)
- API Security / Mass Assignment (CWE-915)

All functions follow async patterns and return structured dictionaries.
All checks run in safe_mode by default (detection only, no exploitation).
"""

import asyncio
import hashlib
import re
import urllib.parse
from typing import Any

from .common import get_auth_curl_args, run

# ============================================================================
# Check 1: File Upload Vulnerabilities (CWE-434)
# ============================================================================

async def test_file_upload(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for file upload vulnerabilities.

    Checks performed:
    1. Detect upload endpoints via form scanning (input type=file)
    2. Identify dangerous file type acceptance
    3. Check for missing content-type validation (detection only)

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs to check for upload forms
        auth_session: AuthSession for authenticated requests (optional)
        safe_mode: If True, only detect upload endpoints without testing

    Returns:
        Dict containing:
        - vulnerable: bool
        - upload_endpoints: list of detected upload forms
        - dangerous_extensions_allowed: list of risky extensions
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "upload_endpoints": [],
        "dangerous_extensions_allowed": [],
        "missing_validation_indicators": [],
        "tested_endpoints": 0,
        "evidence": []
    }

    urls_to_test = [url]
    if discovered_urls:
        urls_to_test.extend(discovered_urls[:20])  # Limit to 20 URLs

    # Dangerous file extensions to look for
    dangerous_extensions = [
        '.php', '.phtml', '.php3', '.php4', '.php5', '.phps',
        '.jsp', '.jspx', '.asp', '.aspx', '.ascx',
        '.exe', '.dll', '.bat', '.cmd', '.sh',
        '.cgi', '.pl', '.py', '.rb',
        '.htaccess', '.config'
    ]

    auth_args = get_auth_curl_args(auth_session)

    for test_url in urls_to_test:
        results["tested_endpoints"] += 1

        # Fetch page content
        html_out, html_err, html_rc = await run(
            ["curl", "-sS", "-L", "-k", "--max-time", "10",
             "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [test_url],
            timeout=15
        )

        if html_rc != 0 or not html_out:
            continue

        # Find file upload inputs
        file_inputs = re.findall(
            r'<input[^>]*type=["\']file["\'][^>]*>',
            html_out,
            re.IGNORECASE | re.DOTALL
        )

        # Also check for forms containing file inputs
        forms_with_files = re.findall(
            r'<form[^>]*>(.*?)</form>',
            html_out,
            re.IGNORECASE | re.DOTALL
        )

        for form_content in forms_with_files:
            if re.search(r'type=["\']file["\']', form_content, re.IGNORECASE):
                # Extract form action
                action_match = re.search(
                    r'<form[^>]*action=["\']([^"\']*)["\']',
                    html_out,
                    re.IGNORECASE
                )
                action = action_match.group(1) if action_match else test_url

                # Check for accept attribute (file type restrictions)
                accept_match = re.search(
                    r'accept=["\']([^"\']*)["\']',
                    form_content,
                    re.IGNORECASE
                )

                # Check for enctype
                enctype_match = re.search(
                    r'enctype=["\']multipart/form-data["\']',
                    form_content,
                    re.IGNORECASE
                )

                endpoint_info = {
                    "page_url": test_url,
                    "action": urllib.parse.urljoin(test_url, action),
                    "has_file_type_restriction": accept_match is not None,
                    "accepted_types": accept_match.group(1) if accept_match else "any",
                    "has_enctype": enctype_match is not None
                }

                results["upload_endpoints"].append(endpoint_info)

                # Check if dangerous extensions might be allowed
                if not accept_match:
                    # No accept attribute = potentially dangerous
                    results["missing_validation_indicators"].append({
                        "endpoint": endpoint_info["action"],
                        "issue": "No file type restriction (accept attribute missing)",
                        "risk": "high"
                    })
                    results["vulnerable"] = True
                else:
                    # Check if accept is too permissive
                    accept_value = accept_match.group(1).lower()
                    if '*/*' in accept_value or 'application/octet-stream' in accept_value:
                        results["missing_validation_indicators"].append({
                            "endpoint": endpoint_info["action"],
                            "issue": f"Permissive accept attribute: {accept_value}",
                            "risk": "medium"
                        })
                        results["vulnerable"] = True

        # Rate limit
        await asyncio.sleep(0.05)

    # Build evidence
    if results["upload_endpoints"]:
        results["evidence"].append({
            "type": "upload_endpoints_found",
            "count": len(results["upload_endpoints"]),
            "endpoints": [e["action"] for e in results["upload_endpoints"][:5]]
        })

    if results["missing_validation_indicators"]:
        results["evidence"].append({
            "type": "missing_validation",
            "issues": results["missing_validation_indicators"][:5]
        })

    return results


# ============================================================================
# Check 2: Open Redirect (CWE-601)
# ============================================================================

async def test_open_redirect(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for open redirect vulnerabilities.

    Checks performed:
    1. Scan URL parameters for redirect-related names
    2. Test common redirect parameter payloads
    3. Check for JavaScript-based redirects in source

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs to analyze
        auth_session: AuthSession for authenticated requests (optional)
        safe_mode: If True, only test with safe domains

    Returns:
        Dict containing:
        - vulnerable: bool
        - redirect_params_found: list of potential redirect parameters
        - confirmed_redirects: list of confirmed open redirects
        - javascript_redirects: JS redirect patterns found
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "redirect_params_found": [],
        "confirmed_redirects": [],
        "javascript_redirects": [],
        "tested_urls": 0,
        "evidence": []
    }

    # Common redirect parameter names
    redirect_params = [
        'redirect', 'redirect_uri', 'redirect_url', 'redirectUrl', 'redirectUri',
        'url', 'uri', 'next', 'nextUrl', 'next_url',
        'return', 'returnUrl', 'return_url', 'returnTo', 'return_to',
        'continue', 'continueTo', 'continue_url',
        'dest', 'destination', 'destUrl', 'dest_url',
        'goto', 'go', 'target', 'link', 'to',
        'callback', 'callback_url', 'callbackUrl',
        'redir', 'out', 'view', 'ref', 'site'
    ]

    # Test payloads (safe - pointing to example.com which we control the test for)
    test_payloads = [
        'https://evil.example.com',
        '//evil.example.com',
        '\\/\\/evil.example.com',
        '/\\evil.example.com',
        'https:evil.example.com',
        '///evil.example.com',
        'javascript:alert(1)',  # Detection only
        'data:text/html,<script>alert(1)</script>'  # Detection only
    ]

    urls_to_test = [url]
    if discovered_urls:
        urls_to_test.extend(discovered_urls[:15])

    auth_args = get_auth_curl_args(auth_session)

    for test_url in urls_to_test:
        results["tested_urls"] += 1
        parsed = urllib.parse.urlparse(test_url)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Check if URL has any redirect-like parameters
        for param_name in query_params:
            if param_name.lower() in [p.lower() for p in redirect_params]:
                results["redirect_params_found"].append({
                    "url": test_url,
                    "param": param_name,
                    "current_value": query_params[param_name][0][:100]
                })

        # Test for open redirect - use safe payloads in safe_mode
        payloads_to_test = test_payloads[:3] if safe_mode else test_payloads
        base_url_parsed = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        def _normalize_host(netloc: str) -> str:
            """Normalize host by removing default ports for comparison."""
            netloc = netloc.lower()
            # Remove default ports
            if netloc.endswith(':80'):
                return netloc[:-3]
            if netloc.endswith(':443'):
                return netloc[:-4]
            return netloc

        def _is_external_redirect(location: str, original_host: str) -> bool:
            """
            Validate that redirect goes to an EXTERNAL domain, not same-origin.

            Key distinction: A Location header like '/page?redirect=https://evil.com'
            redirects to '/page' (same origin), NOT to evil.com.
            The payload appearing in the query string is NOT an open redirect.
            """
            location = location.strip()

            # Relative paths starting with / are same-origin (NOT open redirects)
            # Exception: // is protocol-relative and IS an open redirect
            if location.startswith('/') and not location.startswith('//'):
                return False

            # Check for dangerous schemes
            if location.lower().startswith('javascript:') or location.lower().startswith('data:'):
                return True

            # Normalize original host (remove port for comparison)
            original_host_normalized = _normalize_host(original_host)
            # Also extract just the hostname without any port
            original_hostname = original_host.lower().split(':')[0]

            # Protocol-relative URLs (//) redirect to external domain
            if location.startswith('//'):
                target_host = location.lstrip('/').split('/')[0].split('?')[0]
                target_hostname = target_host.lower().split(':')[0]
                return target_hostname != original_hostname

            # Absolute URLs - parse and compare hosts
            try:
                parsed_loc = urllib.parse.urlparse(location)
                if parsed_loc.netloc:
                    # Has a host - compare hostnames (ignore port differences on same host)
                    target_hostname = parsed_loc.netloc.lower().split(':')[0]
                    return target_hostname != original_hostname
            except Exception:
                pass

            # If we can't determine, assume not vulnerable (avoid false positives)
            return False

        for param in redirect_params[:10]:  # Test top 10 param names
            for payload in payloads_to_test:
                test_target = f"{base_url_parsed}?{param}={urllib.parse.quote(payload)}"

                # Use curl with -I to check redirect without following
                out, err, rc = await run(
                    ["curl", "-sS", "-I", "-k", "--max-time", "5",
                     "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [test_target],
                    timeout=10
                )

                if rc == 0 and out:
                    # Check for redirect headers
                    location_match = re.search(
                        r'Location:\s*(.+)',
                        out,
                        re.IGNORECASE
                    )
                    if location_match:
                        location = location_match.group(1).strip()
                        # Check if redirect goes to an EXTERNAL domain
                        if _is_external_redirect(location, parsed.netloc):
                            results["vulnerable"] = True
                            results["confirmed_redirects"].append({
                                "url": test_target,
                                "param": param,
                                "payload": payload,
                                "redirect_to": location[:200]
                            })
                            break  # Found vulnerable, move to next URL

                await asyncio.sleep(0.05)  # Rate limit

            if results["confirmed_redirects"]:
                break  # Found one, don't test more params

        # Check for JavaScript redirects in page source
        html_out, html_err, html_rc = await run(
            ["curl", "-sS", "-L", "-k", "--max-time", "10",
             "-H", "User-Agent: Mozilla/5.0"] + auth_args + [test_url],
            timeout=15
        )

        if html_rc == 0 and html_out:
            js_redirect_patterns = [
                r'window\.location\s*=\s*["\']?\s*\+?\s*(?:document|location|params)',
                r'location\.href\s*=\s*["\']?\s*\+?\s*(?:document|location|params)',
                r'window\.location\.replace\s*\([^)]*(?:params|query|search)',
                r'window\.location\.assign\s*\([^)]*(?:params|query|search)',
            ]

            for pattern in js_redirect_patterns:
                matches = re.findall(pattern, html_out, re.IGNORECASE)
                for match in matches:
                    results["javascript_redirects"].append({
                        "url": test_url,
                        "pattern": match[:100]
                    })
                    results["vulnerable"] = True

        await asyncio.sleep(0.05)

    # Build evidence
    if results["redirect_params_found"]:
        results["evidence"].append({
            "type": "redirect_parameters",
            "count": len(results["redirect_params_found"]),
            "params": results["redirect_params_found"][:5]
        })

    if results["confirmed_redirects"]:
        results["evidence"].append({
            "type": "confirmed_open_redirect",
            "redirects": results["confirmed_redirects"][:5]
        })

    return results


# ============================================================================
# Check 3: Host Header Injection (CWE-644)
# ============================================================================

async def test_host_header_injection(
    url: str,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for host header injection vulnerabilities.

    Checks performed:
    1. Test X-Forwarded-Host header reflection
    2. Test Host header manipulation
    3. Check for password reset poisoning indicators

    Args:
        url: Base URL to test
        auth_session: AuthSession for authenticated requests (optional)
        safe_mode: If True, use benign test values

    Returns:
        Dict containing:
        - vulnerable: bool
        - header_reflection: list of headers that are reflected
        - password_reset_endpoints: detected reset endpoints
        - cache_key_indicators: cache poisoning indicators
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "header_reflection": [],
        "password_reset_endpoints": [],
        "cache_key_indicators": [],
        "tested_headers": 0,
        "evidence": []
    }

    parsed = urllib.parse.urlparse(url)
    base_host = parsed.netloc
    auth_args = get_auth_curl_args(auth_session)

    # Headers to test
    injection_headers = [
        ("X-Forwarded-Host", "attacker.example.com"),
        ("X-Host", "attacker.example.com"),
        ("X-Original-Host", "attacker.example.com"),
        ("X-Forwarded-Server", "attacker.example.com"),
        ("X-HTTP-Host-Override", "attacker.example.com"),
        ("Forwarded", "host=attacker.example.com"),
    ]

    # Test main URL for header reflection
    for header_name, header_value in injection_headers:
        results["tested_headers"] += 1

        out, err, rc = await run(
            ["curl", "-sS", "-k", "--max-time", "10",
             "-H", "User-Agent: Mozilla/5.0 (Security Scanner)",
             "-H", f"{header_name}: {header_value}"] + auth_args + [url],
            timeout=15
        )

        if rc == 0 and out:
            # Check if injected host appears in response
            if header_value in out:
                results["vulnerable"] = True
                results["header_reflection"].append({
                    "header": header_name,
                    "value": header_value,
                    "url": url,
                    "reflected_in": "response_body"
                })

            # Check response headers for reflection
            header_out, _, _ = await run(
                ["curl", "-sS", "-I", "-k", "--max-time", "5",
                 "-H", f"{header_name}: {header_value}"] + auth_args + [url],
                timeout=10
            )

            if header_out and header_value in header_out:
                results["vulnerable"] = True
                results["header_reflection"].append({
                    "header": header_name,
                    "value": header_value,
                    "url": url,
                    "reflected_in": "response_headers"
                })

        await asyncio.sleep(0.05)

    # Look for password reset endpoints
    password_reset_paths = [
        '/password/reset', '/password-reset', '/reset-password',
        '/forgot-password', '/forgot', '/account/recover',
        '/auth/reset', '/user/reset', '/resetpassword'
    ]

    for path in password_reset_paths:
        test_url = f"{parsed.scheme}://{base_host}{path}"

        out, err, rc = await run(
            ["curl", "-sS", "-I", "-k", "--max-time", "5"] + auth_args + [test_url],
            timeout=10
        )

        if rc == 0 and out:
            # Check for 200/302 indicating endpoint exists
            status_match = re.search(r'HTTP/\d\.?\d?\s+(\d+)', out)
            if status_match:
                status = int(status_match.group(1))
                if status in [200, 301, 302, 303, 307, 308]:
                    results["password_reset_endpoints"].append({
                        "url": test_url,
                        "status": status,
                        "risk": "Test with X-Forwarded-Host for password reset poisoning"
                    })

        await asyncio.sleep(0.05)

    # Check for cache-related headers
    out, err, rc = await run(
        ["curl", "-sS", "-I", "-k", "--max-time", "10"] + auth_args + [url],
        timeout=15
    )

    if rc == 0 and out:
        cache_headers = ['X-Cache', 'CF-Cache-Status', 'Age', 'Cache-Control', 'Vary']
        for header in cache_headers:
            if re.search(rf'{header}:', out, re.IGNORECASE):
                results["cache_key_indicators"].append(header)

        if results["cache_key_indicators"] and results["header_reflection"]:
            results["evidence"].append({
                "type": "cache_poisoning_risk",
                "message": "Caching detected + host header reflection = potential cache poisoning",
                "cache_headers": results["cache_key_indicators"],
                "reflected_headers": [r["header"] for r in results["header_reflection"]]
            })

    # Build evidence
    if results["header_reflection"]:
        results["evidence"].append({
            "type": "host_header_injection",
            "reflections": results["header_reflection"][:5]
        })

    if results["password_reset_endpoints"]:
        results["evidence"].append({
            "type": "password_reset_endpoints",
            "endpoints": results["password_reset_endpoints"][:5]
        })

    return results


# ============================================================================
# Check 4: Business Logic Vulnerabilities (CWE-840)
# ============================================================================

async def test_business_logic(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for business logic vulnerabilities (detection only).

    Checks performed:
    1. Detect price/quantity fields in forms
    2. Identify checkout/payment endpoints
    3. Look for race condition candidates

    Note: This check only DETECTS potential issues, it does NOT exploit them.

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs to analyze
        auth_session: AuthSession for authenticated requests (optional)
        safe_mode: Always True - detection only mode

    Returns:
        Dict containing:
        - potential_issues: list of detected business logic risks
        - price_fields: detected price manipulation points
        - quantity_fields: detected quantity fields
        - race_condition_endpoints: potential race condition targets
        - evidence: detailed findings
    """
    results = {
        "potential_issues": [],
        "price_fields": [],
        "quantity_fields": [],
        "race_condition_endpoints": [],
        "tested_endpoints": 0,
        "evidence": []
    }

    urls_to_test = [url]
    if discovered_urls:
        urls_to_test.extend(discovered_urls[:20])

    # Patterns for business-critical fields
    price_patterns = [
        r'name=["\'](?:price|amount|total|cost|fee|charge|subtotal)["\']',
        r'id=["\'](?:price|amount|total|cost|fee)["\']',
        r'data-price',
        r'data-amount',
    ]

    quantity_patterns = [
        r'name=["\'](?:qty|quantity|count|num|number|items)["\']',
        r'id=["\'](?:qty|quantity|count)["\']',
        r'type=["\']number["\'][^>]*(?:qty|quantity|count)',
    ]

    # Checkout/payment endpoint patterns
    checkout_patterns = [
        r'/checkout', r'/cart', r'/payment', r'/pay',
        r'/order', r'/purchase', r'/buy', r'/billing',
        r'/subscribe', r'/upgrade', r'/transfer'
    ]

    auth_args = get_auth_curl_args(auth_session)

    for test_url in urls_to_test:
        results["tested_endpoints"] += 1

        # Fetch page
        html_out, html_err, html_rc = await run(
            ["curl", "-sS", "-L", "-k", "--max-time", "10",
             "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [test_url],
            timeout=15
        )

        if html_rc != 0 or not html_out:
            continue

        # Check for price fields
        for pattern in price_patterns:
            matches = re.findall(pattern, html_out, re.IGNORECASE)
            for match in matches:
                results["price_fields"].append({
                    "url": test_url,
                    "field": match,
                    "risk": "Price field detected - verify server-side validation"
                })

        # Check for quantity fields
        for pattern in quantity_patterns:
            matches = re.findall(pattern, html_out, re.IGNORECASE)
            for match in matches:
                results["quantity_fields"].append({
                    "url": test_url,
                    "field": match,
                    "risk": "Quantity field detected - check for negative value handling"
                })

        # Check for checkout/payment endpoints
        for pattern in checkout_patterns:
            if re.search(pattern, test_url, re.IGNORECASE):
                results["race_condition_endpoints"].append({
                    "url": test_url,
                    "type": pattern.strip('/'),
                    "risk": "Financial endpoint - potential race condition target"
                })

        # Look for coupon/discount fields
        coupon_patterns = [
            r'name=["\'](?:coupon|discount|promo|voucher|code)["\']',
            r'id=["\'](?:coupon|discount|promo)["\']',
        ]

        for pattern in coupon_patterns:
            if re.search(pattern, html_out, re.IGNORECASE):
                results["potential_issues"].append({
                    "url": test_url,
                    "type": "coupon_field",
                    "risk": "Coupon/discount field - verify single-use enforcement"
                })

        # Look for transfer/balance fields
        transfer_patterns = [
            r'name=["\'](?:balance|transfer|credit|points|reward)["\']',
            r'/transfer', r'/send', r'/withdraw'
        ]

        for pattern in transfer_patterns:
            if re.search(pattern, html_out, re.IGNORECASE) or \
               re.search(pattern, test_url, re.IGNORECASE):
                results["potential_issues"].append({
                    "url": test_url,
                    "type": "transfer_field",
                    "risk": "Transfer/balance field - check for race conditions and negative values"
                })

        await asyncio.sleep(0.05)

    # Build evidence
    if results["price_fields"]:
        results["evidence"].append({
            "type": "price_manipulation_risk",
            "count": len(results["price_fields"]),
            "fields": results["price_fields"][:5]
        })

    if results["quantity_fields"]:
        results["evidence"].append({
            "type": "quantity_manipulation_risk",
            "count": len(results["quantity_fields"]),
            "fields": results["quantity_fields"][:5]
        })

    if results["race_condition_endpoints"]:
        results["evidence"].append({
            "type": "race_condition_risk",
            "endpoints": results["race_condition_endpoints"][:5]
        })

    return results


# ============================================================================
# Check 5: API Security / Mass Assignment (CWE-915)
# ============================================================================

async def test_api_security(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for API security vulnerabilities (OWASP API Top 10).

    Checks performed:
    1. Mass assignment indicators (hidden fields, API structure)
    2. Broken Function Level Authorization (BFLA) - admin endpoints
    3. Excessive data exposure indicators

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs to analyze
        auth_session: AuthSession for authenticated requests (optional)
        safe_mode: If True, only detection mode

    Returns:
        Dict containing:
        - vulnerable: bool
        - mass_assignment_risks: potential mass assignment targets
        - bfla_endpoints: admin/internal endpoints found
        - excessive_data_exposure: detected data exposure risks
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "mass_assignment_risks": [],
        "bfla_endpoints": [],
        "excessive_data_exposure": [],
        "api_endpoints_found": [],
        "tested_endpoints": 0,
        "evidence": []
    }

    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    auth_args = get_auth_curl_args(auth_session)

    # Admin/internal endpoints to check (BFLA)
    bfla_paths = [
        '/admin', '/admin/', '/administrator', '/admin/dashboard',
        '/internal', '/internal/', '/api/admin', '/api/internal',
        '/management', '/manager', '/console', '/backend',
        '/api/v1/admin', '/api/v2/admin', '/api/users',
        '/api/users/all', '/api/config', '/api/settings',
        '/graphql', '/graphiql', '/api/graphql'
    ]

    # Get homepage content for SPA detection (SPAs return same HTML for all routes)
    homepage_out, _, homepage_rc = await run(
        ["curl", "-sS", "-L", "-k", "--max-time", "5",
         "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [base_url],
        timeout=10
    )
    homepage_content = homepage_out if homepage_rc == 0 else ""
    # Extract key SPA indicators from homepage
    homepage_is_spa = bool(
        homepage_content and (
            '<div id="root">' in homepage_content or
            '<div id="app">' in homepage_content or
            '<div id="__next">' in homepage_content or
            'ng-app=' in homepage_content or
            re.search(r'<script[^>]*type=["\']module["\']', homepage_content)
        )
    )
    # Create a simple fingerprint of the homepage (first 2000 chars stripped of dynamic content)
    def content_fingerprint(html: str) -> str:
        if not html:
            return ""
        # Remove dynamic elements (nonces, timestamps, etc)
        cleaned = re.sub(r'nonce="[^"]*"', '', html[:2000])
        cleaned = re.sub(r'data-[a-z-]+="[^"]*"', '', cleaned)
        cleaned = re.sub(r'/_next/static/[^"\']+', '/_next/static/...', cleaned)
        cleaned = re.sub(r'\b[0-9a-f]{8,}\b', '<hash>', cleaned, flags=re.I)
        return cleaned.strip()

    def _looks_like_spa_shell(html: str) -> bool:
        sample = (html or "")[:5000].lower()
        indicators = (
            "<!doctype html",
            "<html",
            "/_next/static/",
            "__next",
            "webpackchunk",
            "data-nextjs",
            '<script type="module"',
            '<div id="root"',
            '<div id="app"',
        )
        return sum(1 for indicator in indicators if indicator in sample) >= 2

    def _has_privileged_content(path: str, html: str) -> bool:
        sample = (html or "")[:12000].lower()
        path_lower = path.lower()
        if path_lower.startswith(("/api/", "/graphql", "/graphiql")):
            return True
        privileged_markers = (
            "admin dashboard",
            "user management",
            "system settings",
            "audit log",
            "api keys",
            "role management",
            "delete user",
            "impersonate",
            "privileged",
        )
        return any(marker in sample for marker in privileged_markers)

    homepage_fingerprint = content_fingerprint(homepage_content)

    # Test BFLA endpoints
    for path in bfla_paths:
        test_url = f"{base_url}{path}"
        results["tested_endpoints"] += 1

        out, err, rc = await run(
            ["curl", "-sS", "-I", "-k", "--max-time", "5",
             "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [test_url],
            timeout=10
        )

        if rc == 0 and out:
            status_match = re.search(r'HTTP/\d\.?\d?\s+(\d+)', out)
            if status_match:
                status = int(status_match.group(1))
                # 200 = accessible, 403 = exists but forbidden, 401 = needs auth
                if status in [200, 403, 401]:
                    is_accessible = status == 200
                    is_spa_false_positive = False

                    validation_reason = None
                    body_out = ""
                    # For 200 responses, validate it's not just a frontend shell.
                    # Modern Next/App Router pages often return a 200 HTML shell for
                    # unknown or client-gated routes without exposing privileged data.
                    if is_accessible:
                        # Fetch actual content to compare
                        body_out, _, body_rc = await run(
                            ["curl", "-sS", "-L", "-k", "--max-time", "5",
                             "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [test_url],
                            timeout=10
                        )
                        if body_rc == 0 and body_out:
                            body_fingerprint = content_fingerprint(body_out)
                            # If content is same as homepage, it's SPA routing (false positive)
                            if body_fingerprint and homepage_fingerprint:
                                if body_fingerprint == homepage_fingerprint:
                                    is_spa_false_positive = True
                                    validation_reason = "same_as_homepage_shell"
                                # Also check if it has the same SPA shell markers
                                elif (
                                    '<div id="root"></div>' in body_out or
                                    '<div id="app"></div>' in body_out or
                                    '<div id="__next">' in body_out
                                ):
                                    # SPA shell without actual admin content
                                    if not re.search(r'admin|dashboard|management|console', body_out[500:], re.I):
                                        is_spa_false_positive = True
                                        validation_reason = "spa_shell_without_privileged_content"
                            if (
                                not is_spa_false_positive
                                and _looks_like_spa_shell(body_out)
                                and not _has_privileged_content(path, body_out)
                            ):
                                is_spa_false_positive = True
                                validation_reason = "generic_html_shell"

                    # Only report as accessible if not a SPA false positive
                    if not is_spa_false_positive:
                        results["bfla_endpoints"].append({
                            "url": test_url,
                            "path": path,
                            "status": status,
                            "status_code": status,
                            "accessible": is_accessible,
                            "risk": "high" if is_accessible else "medium"
                        })
                        if is_accessible:
                            results["vulnerable"] = True
                    elif is_accessible:
                        results["bfla_endpoints"].append({
                            "url": test_url,
                            "path": path,
                            "status": status,
                            "status_code": status,
                            "accessible": False,
                            "risk": "info",
                            "false_positive_detected": True,
                            "validation_reason": validation_reason or "frontend_shell",
                        })

        await asyncio.sleep(0.05)

    # Analyze discovered URLs for API patterns
    urls_to_analyze = [url]
    if discovered_urls:
        urls_to_analyze.extend(discovered_urls[:30])

    api_patterns = [r'/api/', r'/v1/', r'/v2/', r'/graphql', r'/rest/']

    for test_url in urls_to_analyze:
        for pattern in api_patterns:
            if re.search(pattern, test_url, re.IGNORECASE):
                results["api_endpoints_found"].append(test_url)
                break

    def _is_api_candidate(candidate_url: str) -> bool:
        candidate_l = candidate_url.lower()
        if not any(re.search(pattern, candidate_l, re.IGNORECASE) for pattern in api_patterns):
            return False
        return not any(
            marker in candidate_l
            for marker in (
                "socket.io",
                ".js",
                ".css",
                ".png",
                ".jpg",
                ".jpeg",
                ".svg",
                ".ico",
                "openapi.json",
                "swagger.json",
            )
        )

    def _json_sensitive_markers(body: str) -> list[str]:
        marker_patterns = {
            "password": r'"password"\s*:',
            "api_key": r'"(?:api[_-]?key|apikey)"\s*:',
            "secret": r'"(?:secret|totpSecret|mfa_secret)"\s*:',
            "token": r'"(?:token|auth_token|access_token|refresh_token|deluxeToken)"\s*:',
            "admin_role": r'"role"\s*:\s*"admin"',
            "email": r'"email"\s*:\s*"[^"]+@[^"]+\.[^"]+"',
        }
        return [
            name
            for name, pattern in marker_patterns.items()
            if re.search(pattern, body, re.IGNORECASE)
        ]

    # Verify sensitive data leaks from actual machine-readable API responses.
    api_candidates = []
    for candidate in results["api_endpoints_found"]:
        if isinstance(candidate, str) and _is_api_candidate(candidate):
            api_candidates.append(candidate)
    api_candidates = list(dict.fromkeys(api_candidates))[:15]

    for api_url in api_candidates:
        out, _, rc = await run(
            ["curl", "-sS", "-i", "-L", "-k", "--max-time", "6",
             "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [api_url],
            timeout=10,
        )
        if rc != 0 or not out:
            continue
        status_match = re.search(r'HTTP/\d\.?\d?\s+(\d+)', out)
        if not status_match or int(status_match.group(1)) != 200:
            continue
        header_text, _, body = out.partition("\r\n\r\n")
        if not body:
            header_text, _, body = out.partition("\n\n")
        content_type_match = re.search(r"content-type:\s*([^\r\n]+)", header_text, re.IGNORECASE)
        content_type = (content_type_match.group(1).lower() if content_type_match else "")
        body_lstrip = body.lstrip()
        is_machine_readable = (
            "application/json" in content_type
            or "application/problem+json" in content_type
            or body_lstrip.startswith("{")
            or body_lstrip.startswith("[")
        )
        if not is_machine_readable:
            continue
        markers = _json_sensitive_markers(body)
        strong_markers = [m for m in markers if m not in {"email", "admin_role"}]
        if not strong_markers:
            continue
        response_hash = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]
        results["vulnerable"] = True
        results["excessive_data_exposure"].append({
            "url": api_url,
            "type": "api_sensitive_data",
            "risk": "Sensitive data exposed in API response",
            "verified": True,
            "sensitive_markers": markers[:8],
            "response_hash16": response_hash,
            "response_sample": body[:300],
        })

    # Check for mass assignment indicators in forms
    html_out, html_err, html_rc = await run(
        ["curl", "-sS", "-L", "-k", "--max-time", "10",
         "-H", "User-Agent: Mozilla/5.0 (Security Scanner)"] + auth_args + [url],
        timeout=15
    )

    if html_rc == 0 and html_out:
        # Look for hidden fields that might indicate mass assignment risks
        dangerous_hidden_fields = [
            r'name=["\'](?:role|isAdmin|is_admin|admin|privilege|permission)["\']',
            r'name=["\'](?:user_type|userType|account_type|accountType)["\']',
            r'name=["\'](?:credit|balance|points|discount)["\']',
            r'name=["\'](?:verified|active|enabled|status)["\']',
        ]

        for pattern in dangerous_hidden_fields:
            matches = re.findall(pattern, html_out, re.IGNORECASE)
            for match in matches:
                results["mass_assignment_risks"].append({
                    "url": url,
                    "field": match,
                    "risk": "Hidden privileged field - potential mass assignment"
                })
                results["vulnerable"] = True

        # Check for excessive data in responses (look for email, phone patterns)
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
            (r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', 'phone'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn_pattern'),
            (r'"password"\s*:', 'password_field'),
            (r'"apiKey"\s*:', 'api_key_field'),
            (r'"secret"\s*:', 'secret_field'),
        ]

        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, html_out)
            if len(matches) > 5:  # More than 5 = likely excessive exposure
                results["excessive_data_exposure"].append({
                    "url": url,
                    "type": data_type,
                    "count": len(matches),
                    "risk": "Excessive data exposure detected"
                })

    # Build evidence
    if results["bfla_endpoints"]:
        accessible = [e for e in results["bfla_endpoints"] if e["accessible"]]
        results["evidence"].append({
            "type": "bfla_endpoints",
            "accessible_count": len(accessible),
            "total_found": len(results["bfla_endpoints"]),
            "endpoints": results["bfla_endpoints"][:5]
        })

    if results["mass_assignment_risks"]:
        results["evidence"].append({
            "type": "mass_assignment_risk",
            "fields": results["mass_assignment_risks"][:5]
        })

    if results["excessive_data_exposure"]:
        results["evidence"].append({
            "type": "excessive_data_exposure",
            "exposures": results["excessive_data_exposure"][:5]
        })

    return results
