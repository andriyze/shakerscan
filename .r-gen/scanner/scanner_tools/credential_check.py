"""
Default Credential Testing Module

Tests for default/weak credentials on detected login forms and admin panels.
Only runs on full/aggressive scans to avoid excessive requests.
"""

import asyncio
import json
import re
import sys
import urllib.parse
from typing import Any

from .common import run


# =============================================================================
# DEFAULT CREDENTIALS DATABASE
# =============================================================================

# Generic credentials (try on any login form)
GENERIC_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("demo", "demo"),
]

# Technology-specific default credentials
TECH_CREDENTIALS = {
    "tomcat": [
        ("tomcat", "tomcat"),
        ("admin", "tomcat"),
        ("manager", "manager"),
        ("admin", "s3cret"),
        ("tomcat", "s3cret"),
    ],
    "jenkins": [
        ("admin", "admin"),
        ("jenkins", "jenkins"),
        ("admin", "password"),
    ],
    "wordpress": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "wordpress"),
        ("wp-admin", "wp-admin"),
    ],
    "joomla": [
        ("admin", "admin"),
        ("administrator", "administrator"),
    ],
    "drupal": [
        ("admin", "admin"),
        ("drupal", "drupal"),
    ],
    "phpmyadmin": [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("pma", ""),
        ("admin", "admin"),
    ],
    "mongodb": [
        ("admin", "admin"),
        ("admin", "password"),
        ("mongo", "mongo"),
        ("", ""),  # No auth
    ],
    "redis": [
        ("", ""),  # No auth by default
    ],
    "grafana": [
        ("admin", "admin"),
        ("admin", "grafana"),
    ],
    "rabbitmq": [
        ("guest", "guest"),
        ("admin", "admin"),
    ],
    "elasticsearch": [
        ("elastic", "changeme"),
        ("elastic", "elastic"),
    ],
    "gitlab": [
        ("root", "5iveL!fe"),
        ("admin", "admin"),
    ],
    "jupyter": [
        ("", "jupyter"),
        ("", "password"),
    ],
    "router": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("user", "user"),
    ],
}

# Common login form field names
LOGIN_FIELD_PATTERNS = {
    "username": ["username", "user", "email", "login", "userid", "user_id", "uname", "name", "account"],
    "password": ["password", "pass", "passwd", "pwd", "secret", "credential"],
}

# Success indicators (login worked)
SUCCESS_INDICATORS = [
    r"dashboard",
    r"welcome",
    r"logout",
    r"sign\s*out",
    r"my\s*account",
    r"profile",
    r"settings",
    r"admin\s*panel",
    r"control\s*panel",
    r'"authenticated"\s*:\s*true',
    r'"success"\s*:\s*true',
    r'"status"\s*:\s*"ok"',
    r'"loggedIn"\s*:\s*true',
    r'"token"\s*:',
    r'"access_token"\s*:',
    r'"jwt"\s*:',
]

# Failure indicators (login failed - helps reduce false positives)
FAILURE_INDICATORS = [
    r"invalid\s*(username|password|credentials)",
    r"login\s*failed",
    r"authentication\s*failed",
    r"incorrect\s*(username|password)",
    r"wrong\s*(username|password)",
    r"access\s*denied",
    r'"authenticated"\s*:\s*false',
    r'"success"\s*:\s*false',
    r'"error"\s*:',
    r"unauthorized",
    # 404/error page patterns (reduce false positives from Next.js routing state, etc.)
    r"not\s*found",
    r"\b404\b",
    r"page\s*(not\s*found|does\s*not\s*exist)",
    r"resource\s*not\s*found",
    r"bad\s*request",
    r"forbidden",
]


async def detect_login_form(url: str) -> dict[str, Any] | None:
    """
    Detect login form on a page and extract form details.

    Returns:
        Dict with form action, method, and field names, or None if no form found
    """
    out, _, rc = await run([
        "curl", "-sS", "-L", "-k", "--max-time", "10",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        url
    ], timeout=15)

    if rc != 0 or not out:
        return None

    # Look for form with password field
    form_match = re.search(
        r'<form[^>]*action=["\']?([^"\'\s>]*)["\']?[^>]*>(.*?)</form>',
        out,
        re.IGNORECASE | re.DOTALL
    )

    if not form_match:
        # Try to find any password input (might be AJAX-based login)
        if 'type="password"' in out.lower() or "type='password'" in out.lower():
            # Look for nearby inputs
            pass
        else:
            return None

    form_action = form_match.group(1) if form_match else url
    form_content = form_match.group(2) if form_match else out

    # Resolve relative action URL
    if form_action and not form_action.startswith("http"):
        form_action = urllib.parse.urljoin(url, form_action)

    # Detect form method
    method = "POST"
    if form_match:
        method_match = re.search(r'method=["\']?(GET|POST)["\']?', form_match.group(0), re.IGNORECASE)
        if method_match:
            method = method_match.group(1).upper()

    # Find username and password field names
    username_field = None
    password_field = None

    # Find all input fields
    inputs = re.findall(
        r'<input[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*type=["\']?([^"\'\s>]+)["\']?|'
        r'<input[^>]*type=["\']?([^"\'\s>]+)["\']?[^>]*name=["\']?([^"\'\s>]+)["\']?',
        form_content,
        re.IGNORECASE
    )

    for match in inputs:
        name = match[0] or match[3]
        input_type = match[1] or match[2]

        if not name:
            continue

        name_lower = name.lower()

        if input_type and input_type.lower() == "password":
            password_field = name
        elif any(pattern in name_lower for pattern in LOGIN_FIELD_PATTERNS["username"]):
            username_field = name

    # If no username field found, look for common names
    if not username_field:
        for pattern in LOGIN_FIELD_PATTERNS["username"]:
            if f'name="{pattern}"' in out.lower() or f"name='{pattern}'" in out.lower():
                username_field = pattern
                break

    if not password_field:
        return None

    return {
        "action": form_action or url,
        "method": method,
        "username_field": username_field or "username",
        "password_field": password_field,
        "original_url": url,
    }


async def test_credential(
    form_info: dict[str, Any],
    username: str,
    password: str,
    baseline_response: str | None = None
) -> dict[str, Any] | None:
    """
    Test a single credential pair against a login form.

    Returns:
        Finding dict if successful, None otherwise
    """
    action = form_info["action"]
    method = form_info["method"]
    username_field = form_info["username_field"]
    password_field = form_info["password_field"]

    # Build POST data
    post_data = f"{username_field}={urllib.parse.quote(username)}&{password_field}={urllib.parse.quote(password)}"

    # Add common additional fields that might be required
    extra_fields = ["submit=Login", "login=1", "action=login"]
    post_data += "&" + "&".join(extra_fields)

    # Don't use -L (follow redirects) so we can capture Location headers for success detection
    # Use -i to include headers in output for redirect detection
    if method == "POST":
        cmd = [
            "curl", "-sS", "-i", "-k", "--max-time", "10",
            "-X", "POST",
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "-d", post_data,
            "-w", "\n---RESPONSE_CODE:%{http_code}---",
            action
        ]
    else:
        # GET request
        separator = "&" if "?" in action else "?"
        get_url = f"{action}{separator}{post_data}"
        cmd = [
            "curl", "-sS", "-i", "-k", "--max-time", "10",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "-w", "\n---RESPONSE_CODE:%{http_code}---",
            get_url
        ]

    out, _, rc = await run(cmd, timeout=15)

    if rc != 0 or not out:
        return None

    # Parse response
    response_code = "000"
    if "---RESPONSE_CODE:" in out:
        try:
            response_code = out.split("---RESPONSE_CODE:")[1].split("---")[0]
            out = out.split("---RESPONSE_CODE:")[0]
        except IndexError:
            pass

    # Reject 4xx/5xx status codes immediately (reduces false positives from error pages)
    if response_code and response_code.isdigit():
        if int(response_code) >= 400:
            return None

    # Check for success indicators
    success_detected = False
    success_evidence = []

    for indicator in SUCCESS_INDICATORS:
        if re.search(indicator, out, re.IGNORECASE):
            success_detected = True
            success_evidence.append(f"Found: {indicator}")
            break

    # Check that failure indicators are NOT present (reduces false positives)
    failure_detected = False
    for indicator in FAILURE_INDICATORS:
        if re.search(indicator, out, re.IGNORECASE):
            failure_detected = True
            break

    # Also check for redirect to dashboard/admin (common success pattern)
    if not success_detected and not failure_detected:
        if response_code in ["301", "302", "303", "307", "308"]:
            # Redirect might indicate success
            location_match = re.search(r'location:\s*([^\r\n]+)', out, re.IGNORECASE)
            if location_match:
                redirect_url = location_match.group(1).lower()
                if any(word in redirect_url for word in ["dashboard", "admin", "panel", "home", "welcome"]):
                    success_detected = True
                    success_evidence.append(f"Redirect to: {location_match.group(1)}")

    # Response significantly different from baseline (might indicate success)
    if baseline_response and not success_detected and not failure_detected:
        baseline_len = len(baseline_response)
        response_len = len(out)
        if abs(response_len - baseline_len) > 500:
            # Significant change - might be logged in
            # But don't flag as definite success without other indicators
            pass

    if success_detected and not failure_detected:
        return {
            "type": "Default Credentials",
            "url": form_info["original_url"],
            "form_action": action,
            "username": username,
            "password": password if len(password) < 20 else password[:10] + "...",
            "evidence": success_evidence,
            "severity": "critical",
            "response_code": response_code,
        }

    return None


async def test_default_credentials(
    url: str,
    detected_tech: list[str] | None = None,
    max_attempts: int = 10,
    delay_ms: int = 500
) -> dict[str, Any]:
    """
    Test default credentials on detected login forms.

    Args:
        url: Base URL or specific login endpoint
        detected_tech: List of detected technologies (for tech-specific creds)
        max_attempts: Maximum credential pairs to test (default 10)
        delay_ms: Delay between attempts to avoid lockouts (default 500ms)

    Returns:
        Dict with findings and test statistics
    """
    import sys

    results: dict[str, Any] = {
        "findings": [],
        "tested": 0,
        "forms_found": 0,
        "scan_completed": False,
    }

    print(f"[cred_check] Starting credential testing for {url}", file=sys.stderr)

    # Common login paths to check
    login_paths = [
        "/login", "/admin", "/admin/login", "/wp-login.php", "/wp-admin",
        "/user/login", "/users/sign_in", "/account/login", "/signin",
        "/auth/login", "/administrator", "/manager/html", "/console",
    ]

    # Build list of URLs to test
    urls_to_test = [url]
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    for path in login_paths:
        test_url = urllib.parse.urljoin(base_url, path)
        if test_url not in urls_to_test:
            urls_to_test.append(test_url)

    # Find login forms
    forms_found = []
    for test_url in urls_to_test[:10]:  # Limit URL checks
        form_info = await detect_login_form(test_url)
        if form_info:
            forms_found.append(form_info)
            print(f"[cred_check] Found login form at {test_url}", file=sys.stderr)

    results["forms_found"] = len(forms_found)

    if not forms_found:
        print("[cred_check] No login forms detected", file=sys.stderr)
        results["scan_completed"] = True
        return results

    # Build credential list based on detected tech
    credentials_to_test = list(GENERIC_CREDENTIALS)

    if detected_tech:
        for tech in detected_tech:
            tech_lower = tech.lower()
            for tech_name, tech_creds in TECH_CREDENTIALS.items():
                if tech_name in tech_lower or tech_lower in tech_name:
                    # Add tech-specific creds at the beginning (higher priority)
                    for cred in tech_creds:
                        if cred not in credentials_to_test:
                            credentials_to_test.insert(0, cred)

    # Limit attempts
    credentials_to_test = credentials_to_test[:max_attempts]

    print(f"[cred_check] Testing {len(credentials_to_test)} credential pairs on {len(forms_found)} forms", file=sys.stderr)

    # Test credentials
    for form_info in forms_found:
        # Get baseline response for failed login
        baseline_cred = ("invalid_user_12345", "invalid_pass_12345")
        baseline_result = await test_credential(form_info, baseline_cred[0], baseline_cred[1])
        baseline_response = None  # We don't have the raw response in current impl

        for username, password in credentials_to_test:
            results["tested"] += 1

            # Rate limiting (async to avoid blocking event loop)
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000)

            finding = await test_credential(form_info, username, password, baseline_response)
            if finding:
                results["findings"].append(finding)
                print(f"[cred_check] FOUND: {username}:{password} at {form_info['original_url']}", file=sys.stderr)
                # Stop testing this form after first success
                break

    results["scan_completed"] = True
    print(f"[cred_check] Complete: {len(results['findings'])} credentials found", file=sys.stderr)

    return results
