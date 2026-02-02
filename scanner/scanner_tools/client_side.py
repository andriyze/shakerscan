"""
Client-Side Security Checks

This module provides security checks for client-side vulnerabilities:
1. JavaScript Dependency Scanning (Retire.js methodology)
2. Secret Leaks in JavaScript Bundles (API keys, credentials)

CWE Coverage:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-798: Use of Hard-coded Credentials

OWASP Coverage:
- A06:2021: Vulnerable and Outdated Components
- A05:2021: Security Misconfiguration

All checks are read-only with low false positive rates (<5%).
"""

import asyncio
import json
import logging
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Any
from urllib.parse import urljoin

# ============================================================================
# HTTP HELPER FUNCTIONS (using urllib)
# ============================================================================

# Create SSL context that doesn't verify certificates (for scanning)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Set global socket timeout to prevent DNS hangs (critical fix)
socket.setdefaulttimeout(10)


async def _fetch_url(url: str, timeout: int = 10, headers: dict[str, str] | None = None) -> str:
    """
    Fetch URL content using urllib (async wrapper).

    Args:
        url: URL to fetch
        timeout: Timeout in seconds
        headers: Optional HTTP headers

    Returns:
        Response text content
    """
    def _sync_fetch():
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception:
            return ""

    # Run in thread pool to keep async interface
    return await asyncio.to_thread(_sync_fetch)


# ============================================================================
# CDN URL PATTERN EXTRACTION
# ============================================================================

# CDN URL patterns for library version extraction
CDN_PATTERNS = [
    # jsdelivr: cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js
    (r'cdn\.jsdelivr\.net/npm/([^@/]+)@(\d+\.\d+(?:\.\d+)?)', 'jsdelivr'),
    # cdnjs: cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js
    (r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/(\d+\.\d+(?:\.\d+)?)', 'cdnjs'),
    # unpkg: unpkg.com/react@18.2.0/umd/react.production.min.js
    (r'unpkg\.com/([^@/]+)@(\d+\.\d+(?:\.\d+)?)', 'unpkg'),
    # Google CDN: ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js
    (r'ajax\.googleapis\.com/ajax/libs/([^/]+)/(\d+\.\d+(?:\.\d+)?)', 'google'),
    # jQuery CDN: code.jquery.com/jquery-3.6.0.min.js
    (r'code\.jquery\.com/jquery-(\d+\.\d+(?:\.\d+)?)', 'jquery_cdn'),
    # Bootstrap CDN
    (r'stackpath\.bootstrapcdn\.com/bootstrap/(\d+\.\d+(?:\.\d+)?)', 'bootstrap_cdn'),
    # Generic versioned JS filename pattern
    (r'/([a-z][a-z0-9._-]+)[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'filename'),
]


def extract_versions_from_cdn_urls(urls: list[str]) -> dict[str, dict[str, str]]:
    """
    Extract library names and versions from CDN URLs.

    Args:
        urls: List of JavaScript file URLs

    Returns:
        Dict mapping library names to version info with source and confidence
    """
    detected = {}
    for url in urls:
        url_lower = url.lower()
        for pattern, cdn_name in CDN_PATTERNS:
            match = re.search(pattern, url_lower)
            if match:
                groups = match.groups()
                if cdn_name == 'jquery_cdn':
                    lib_name = 'jquery'
                    version = groups[0]
                elif cdn_name == 'bootstrap_cdn':
                    lib_name = 'bootstrap'
                    version = groups[0]
                elif cdn_name == 'filename':
                    # For generic filename pattern, normalize library name
                    lib_name = groups[0].replace('.js', '').replace('-', '_').replace('.', '_')
                    version = groups[1]
                    # Skip very generic names
                    if lib_name in ('app', 'main', 'bundle', 'index', 'script', 'vendor', 'chunk'):
                        continue
                else:
                    lib_name = groups[0].replace('.js', '').replace('-', '_')
                    version = groups[1]

                if lib_name not in detected:
                    detected[lib_name] = {
                        'version': version,
                        'source': cdn_name,
                        'url': url,
                        'confidence': 'high' if cdn_name != 'filename' else 'medium'
                    }
                break
    return detected


# ============================================================================
# RETIRE.JS DATABASE LOADER
# ============================================================================

RETIREJS_DB_PATH = '/app/data/jsrepository.json'


@lru_cache(maxsize=1)
def load_retirejs_database() -> dict[str, Any]:
    """
    Load the bundled Retire.js vulnerability database.

    Returns:
        Dict mapping library names (lowercase) to vulnerability info.
        Returns empty dict if file not found or parsing fails.
    """
    if not os.path.exists(RETIREJS_DB_PATH):
        return {}

    try:
        with open(RETIREJS_DB_PATH) as f:
            raw_db = json.load(f)

        transformed = {}
        for lib_name, lib_data in raw_db.items():
            # Skip metadata keys that start with $
            if lib_name.startswith('$'):
                continue

            vulnerabilities = []
            for vuln in lib_data.get('vulnerabilities', []):
                severity = vuln.get('severity', 'medium')
                # Normalize severity to our format
                if severity not in ['critical', 'high', 'medium', 'low']:
                    severity = 'medium'

                identifiers = vuln.get('identifiers', {})
                cve_list = identifiers.get('CVE', [])

                # Get summary from identifiers or info array
                summary = identifiers.get('summary', '')
                if not summary:
                    info_list = vuln.get('info', [])
                    summary = info_list[0] if info_list else 'Unknown vulnerability'

                vuln_entry = {
                    'below': vuln.get('below'),
                    'above': vuln.get('atOrAbove'),  # Retire.js uses atOrAbove
                    'severity': severity,
                    'cve': cve_list[0] if cve_list else None,
                    'summary': summary
                }

                # Only add if there's a "below" threshold
                if vuln_entry['below']:
                    vulnerabilities.append(vuln_entry)

            if vulnerabilities:
                transformed[lib_name.lower()] = {
                    'vulnerabilities': vulnerabilities,
                    'extractors': lib_data.get('extractors', {}),
                }

        return transformed
    except Exception:
        return {}


def get_combined_vulnerability_database() -> dict[str, Any]:
    """
    Combine built-in VULNERABLE_JS_LIBRARIES with Retire.js database.

    Built-in entries take precedence (more curated).

    Returns:
        Combined vulnerability database
    """
    # Import here to avoid circular reference since VULNERABLE_JS_LIBRARIES is defined later
    combined = dict(VULNERABLE_JS_LIBRARIES)

    retirejs_db = load_retirejs_database()
    for lib_name, lib_data in retirejs_db.items():
        if lib_name not in combined:
            # Add new library from Retire.js
            combined[lib_name] = lib_data
        else:
            # Merge vulnerabilities, avoiding duplicates by CVE
            existing_cves = {v.get('cve') for v in combined[lib_name].get('vulnerabilities', []) if v.get('cve')}
            for vuln in lib_data.get('vulnerabilities', []):
                if vuln.get('cve') and vuln['cve'] not in existing_cves:
                    combined[lib_name]['vulnerabilities'].append(vuln)
                elif not vuln.get('cve'):
                    # For vulns without CVE, check by summary
                    existing_summaries = {v.get('summary', '').lower() for v in combined[lib_name].get('vulnerabilities', [])}
                    if vuln.get('summary', '').lower() not in existing_summaries:
                        combined[lib_name]['vulnerabilities'].append(vuln)

    return combined


# ============================================================================
# VULNERABLE JAVASCRIPT LIBRARY DATABASE (Retire.js subset)
# ============================================================================

VULNERABLE_JS_LIBRARIES = {
    "jquery": {
        "vulnerabilities": [
            {
                "below": "3.5.0",
                "severity": "medium",
                "cve": "CVE-2020-11022",
                "summary": "XSS vulnerability via $.htmlPrefilter"
            },
            {
                "below": "3.4.0",
                "severity": "medium",
                "cve": "CVE-2019-11358",
                "summary": "Prototype pollution vulnerability"
            },
            {
                "below": "1.12.0",
                "severity": "medium",
                "cve": "CVE-2015-9251",
                "summary": "XSS vulnerability in jQuery.extend"
            },
            {
                "below": "1.9.0",
                "severity": "high",
                "cve": "CVE-2012-6708",
                "summary": "XSS vulnerability in selector parsing"
            },
        ],
        "detection_patterns": [
            r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'jQuery\s+v(\d+\.\d+\.\d+)',
            r'/\*!\s*jQuery\s+v(\d+\.\d+\.\d+)',
        ]
    },
    "bootstrap": {
        "vulnerabilities": [
            {
                "below": "4.3.1",
                "severity": "medium",
                "cve": "CVE-2019-8331",
                "summary": "XSS vulnerability in tooltip and popover plugins"
            },
            {
                "below": "3.4.0",
                "severity": "medium",
                "cve": "CVE-2018-14042",
                "summary": "XSS vulnerability in collapse plugin"
            },
            {
                "below": "3.4.0",
                "severity": "medium",
                "cve": "CVE-2018-14041",
                "summary": "XSS vulnerability in data-target attribute"
            },
        ],
        "detection_patterns": [
            r'bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'Bootstrap\s+v(\d+\.\d+\.\d+)',
        ]
    },
    "angular": {
        "vulnerabilities": [
            {
                "below": "1.5.0",
                "severity": "high",
                "cve": "CVE-2016-9533",
                "summary": "XSS vulnerability in $sanitize service"
            },
            {
                "below": "1.6.0",
                "severity": "medium",
                "cve": "CVE-2017-1000007",
                "summary": "CORS bypass vulnerability"
            },
            {
                "below": "1.6.5",
                "severity": "medium",
                "cve": "CVE-2017-1000208",
                "summary": "Template injection vulnerability"
            },
        ],
        "detection_patterns": [
            r'angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'AngularJS\s+v(\d+\.\d+\.\d+)',
        ]
    },
    "lodash": {
        "vulnerabilities": [
            {
                "below": "4.17.12",
                "severity": "high",
                "cve": "CVE-2019-10744",
                "summary": "Prototype pollution in defaultsDeep function"
            },
            {
                "below": "4.17.11",
                "severity": "critical",
                "cve": "CVE-2018-16487",
                "summary": "Prototype pollution in merge/mergeWith/defaultsDeep"
            },
            {
                "below": "4.17.5",
                "severity": "high",
                "cve": "CVE-2018-3721",
                "summary": "Prototype pollution via defaultsDeep"
            },
        ],
        "detection_patterns": [
            r'lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'lodash\s+(\d+\.\d+\.\d+)',
        ]
    },
    "moment": {
        "vulnerabilities": [
            {
                "below": "2.29.2",
                "severity": "high",
                "cve": "CVE-2022-24785",
                "summary": "ReDoS vulnerability in preprocessRFC2822 function"
            },
            {
                "below": "2.29.4",
                "severity": "high",
                "cve": "CVE-2022-31129",
                "summary": "ReDoS vulnerability in preprocessRFC2822"
            },
            {
                "below": "2.19.3",
                "severity": "medium",
                "cve": "CVE-2017-18214",
                "summary": "ReDoS vulnerability in duration parsing"
            },
        ],
        "detection_patterns": [
            r'moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'Moment\.js\s+(\d+\.\d+\.\d+)',
        ]
    },
    "react": {
        "vulnerabilities": [
            {
                "below": "16.4.2",
                "severity": "high",
                "cve": "CVE-2018-6341",
                "summary": "XSS vulnerability in react-dom server renderer"
            },
        ],
        "detection_patterns": [
            r'react[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'React\s+(\d+\.\d+\.\d+)',
            r'"react":\s*"[~^]?(\d+\.\d+\.\d+)"',  # package.json format
        ]
    },
    "vue": {
        "vulnerabilities": [
            {
                "below": "2.6.11",
                "severity": "medium",
                "cve": "CVE-2020-8987",
                "summary": "XSS vulnerability in asset injection"
            },
        ],
        "detection_patterns": [
            r'vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'Vue\.js\s+v(\d+\.\d+\.\d+)',
        ]
    },
    "next": {
        "vulnerabilities": [
            # Authorization bypass in middleware (July 2024)
            {
                "below": "14.2.10",
                "severity": "critical",
                "cve": "CVE-2024-51479",
                "summary": "Authorization bypass via x-middleware-subrequest header"
            },
            # SSRF in Server Actions (May 2024)
            {
                "below": "14.1.1",
                "above": "14.0.0",
                "severity": "high",
                "cve": "CVE-2024-34351",
                "summary": "Server-Side Request Forgery (SSRF) in Server Actions"
            },
            # HTTP Request Smuggling (May 2024)
            {
                "below": "14.1.1",
                "above": "13.4.0",
                "severity": "high",
                "cve": "CVE-2024-34350",
                "summary": "HTTP Request/Response Smuggling leading to response queue poisoning"
            },
            # Authorization bypass (July 2024)
            {
                "below": "14.2.4",
                "severity": "high",
                "cve": "CVE-2024-39693",
                "summary": "Authorization bypass in middleware"
            },
            # DoS via malformed URL (October 2023)
            {
                "below": "13.5.1",
                "severity": "medium",
                "cve": "CVE-2023-46298",
                "summary": "Denial of Service via malformed URL in App Router"
            },
            # XSS in image optimization (February 2022)
            {
                "below": "12.1.0",
                "severity": "medium",
                "cve": "CVE-2022-23646",
                "summary": "XSS vulnerability in next/image component"
            },
        ],
        "detection_patterns": [
            r'"next":\s*"[~^]?(\d+\.\d+\.\d+)"',  # package.json format
            r'Next\.js\s+v?(\d+\.\d+\.\d+)',
        ]
    },
    # ========================================================================
    # EXPANDED LIBRARY COVERAGE
    # ========================================================================
    "axios": {
        "vulnerabilities": [
            {
                "below": "1.6.0",
                "severity": "high",
                "cve": "CVE-2023-45857",
                "summary": "CSRF token exposure via Cross-Site Request Forgery"
            },
            {
                "below": "0.21.1",
                "severity": "medium",
                "cve": "CVE-2020-28168",
                "summary": "Server-Side Request Forgery (SSRF) vulnerability"
            },
        ],
        "detection_patterns": [
            r'axios[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"axios":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "handlebars": {
        "vulnerabilities": [
            {
                "below": "4.7.7",
                "severity": "critical",
                "cve": "CVE-2021-23369",
                "summary": "Remote code execution via template compilation"
            },
            {
                "below": "4.7.6",
                "severity": "high",
                "cve": "CVE-2019-19919",
                "summary": "Prototype pollution vulnerability"
            },
            {
                "below": "4.4.5",
                "severity": "high",
                "cve": "CVE-2019-20920",
                "summary": "Arbitrary code execution via lookupProperty"
            },
        ],
        "detection_patterns": [
            r'handlebars[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"handlebars":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "dompurify": {
        "vulnerabilities": [
            {
                "below": "2.4.1",
                "severity": "high",
                "cve": "CVE-2022-41720",
                "summary": "mXSS bypass vulnerability"
            },
            {
                "below": "2.3.3",
                "severity": "medium",
                "cve": "CVE-2021-23770",
                "summary": "XSS bypass via mutation XSS"
            },
            {
                "below": "2.0.17",
                "severity": "medium",
                "cve": "CVE-2020-26870",
                "summary": "XSS vulnerability via svg/math tags"
            },
        ],
        "detection_patterns": [
            r'dompurify[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'DOMPurify\s+(\d+\.\d+\.\d+)',
            r'"dompurify":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "marked": {
        "vulnerabilities": [
            {
                "below": "4.0.10",
                "severity": "high",
                "cve": "CVE-2022-21680",
                "summary": "ReDoS vulnerability in block.def regex"
            },
            {
                "below": "2.0.0",
                "severity": "medium",
                "cve": "CVE-2021-21306",
                "summary": "ReDoS in heading regex"
            },
            {
                "below": "0.3.9",
                "severity": "high",
                "cve": "CVE-2017-17461",
                "summary": "XSS vulnerability via malicious markdown"
            },
        ],
        "detection_patterns": [
            r'marked[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"marked":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "highlight.js": {
        "vulnerabilities": [
            {
                "below": "10.4.1",
                "severity": "high",
                "cve": "CVE-2020-26237",
                "summary": "ReDoS vulnerability in language definition"
            },
            {
                "below": "9.18.2",
                "severity": "medium",
                "cve": "CVE-2020-8244",
                "summary": "Prototype pollution vulnerability"
            },
        ],
        "detection_patterns": [
            r'highlight[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"highlight\.js":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "serialize-javascript": {
        "vulnerabilities": [
            {
                "below": "3.1.0",
                "severity": "critical",
                "cve": "CVE-2020-7660",
                "summary": "Remote code execution via crafted input"
            },
            {
                "below": "2.1.1",
                "severity": "high",
                "cve": "CVE-2019-16769",
                "summary": "Arbitrary code execution via object injection"
            },
        ],
        "detection_patterns": [
            r'"serialize-javascript":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "node-forge": {
        "vulnerabilities": [
            {
                "below": "1.3.0",
                "severity": "high",
                "cve": "CVE-2022-24771",
                "summary": "Signature verification bypass via RSA PKCS#1 v1.5"
            },
            {
                "below": "1.0.0",
                "severity": "medium",
                "cve": "CVE-2020-7720",
                "summary": "Prototype pollution in util.setPath"
            },
        ],
        "detection_patterns": [
            r'node-forge[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"node-forge":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "ejs": {
        "vulnerabilities": [
            {
                "below": "3.1.7",
                "severity": "critical",
                "cve": "CVE-2022-29078",
                "summary": "Server-side template injection (SSTI)"
            },
            {
                "below": "2.7.4",
                "severity": "high",
                "cve": "CVE-2020-26256",
                "summary": "Remote code execution via delimiter option"
            },
        ],
        "detection_patterns": [
            r'ejs[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"ejs":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "underscore": {
        "vulnerabilities": [
            {
                "below": "1.13.6",
                "severity": "high",
                "cve": "CVE-2021-23358",
                "summary": "Arbitrary code execution via template function"
            },
            {
                "below": "1.12.1",
                "severity": "medium",
                "cve": "CVE-2021-23424",
                "summary": "ReDoS vulnerability in escape function"
            },
        ],
        "detection_patterns": [
            r'underscore[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"underscore":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "socket.io": {
        "vulnerabilities": [
            {
                "below": "4.5.4",
                "severity": "medium",
                "cve": "CVE-2022-44690",
                "summary": "Memory exhaustion via crafted request"
            },
            {
                "below": "2.4.0",
                "severity": "high",
                "cve": "CVE-2020-28481",
                "summary": "Unauthorized access via resource exhaustion"
            },
        ],
        "detection_patterns": [
            r'socket\.io[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"socket\.io":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "crypto-js": {
        "vulnerabilities": [
            {
                "below": "4.2.0",
                "severity": "critical",
                "cve": "CVE-2023-46233",
                "summary": "PBKDF2 weak key derivation (1 iteration default)"
            },
        ],
        "detection_patterns": [
            r'crypto-js[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"crypto-js":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "express": {
        "vulnerabilities": [
            {
                "below": "4.19.2",
                "severity": "medium",
                "cve": "CVE-2024-29041",
                "summary": "Open redirect vulnerability"
            },
            {
                "below": "4.17.3",
                "severity": "medium",
                "cve": "CVE-2022-24999",
                "summary": "Prototype pollution via qs module"
            },
        ],
        "detection_patterns": [
            r'"express":\s*"[~^]?(\d+\.\d+\.\d+)"',
            r'X-Powered-By:\s*Express',
        ]
    },
    "jsonwebtoken": {
        "vulnerabilities": [
            {
                "below": "9.0.0",
                "severity": "high",
                "cve": "CVE-2022-23529",
                "summary": "Insecure key retrieval via secretOrPublicKey"
            },
            {
                "below": "8.5.1",
                "severity": "critical",
                "cve": "CVE-2022-23539",
                "summary": "Algorithm confusion via public key as secret"
            },
        ],
        "detection_patterns": [
            r'"jsonwebtoken":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "minimist": {
        "vulnerabilities": [
            {
                "below": "1.2.6",
                "severity": "critical",
                "cve": "CVE-2021-44906",
                "summary": "Prototype pollution via setKey function"
            },
            {
                "below": "1.2.3",
                "severity": "low",
                "cve": "CVE-2020-7598",
                "summary": "Prototype pollution vulnerability"
            },
        ],
        "detection_patterns": [
            r'"minimist":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "path-to-regexp": {
        "vulnerabilities": [
            {
                "below": "6.2.2",
                "severity": "high",
                "cve": "CVE-2024-45296",
                "summary": "ReDoS via unbounded backtracking"
            },
            {
                "below": "0.1.10",
                "severity": "high",
                "cve": "CVE-2024-52798",
                "summary": "Catastrophic backtracking in pattern matching"
            },
        ],
        "detection_patterns": [
            r'"path-to-regexp":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "semver": {
        "vulnerabilities": [
            {
                "below": "7.5.2",
                "severity": "high",
                "cve": "CVE-2022-25883",
                "summary": "ReDoS vulnerability in range parsing"
            },
        ],
        "detection_patterns": [
            r'"semver":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "tough-cookie": {
        "vulnerabilities": [
            {
                "below": "4.1.3",
                "severity": "medium",
                "cve": "CVE-2023-26136",
                "summary": "Prototype pollution vulnerability"
            },
        ],
        "detection_patterns": [
            r'"tough-cookie":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "word-wrap": {
        "vulnerabilities": [
            {
                "below": "1.2.4",
                "severity": "medium",
                "cve": "CVE-2023-26115",
                "summary": "ReDoS vulnerability"
            },
        ],
        "detection_patterns": [
            r'"word-wrap":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "sanitize-html": {
        "vulnerabilities": [
            {
                "below": "2.7.1",
                "severity": "medium",
                "cve": "CVE-2022-25887",
                "summary": "Improper sanitization of certain attributes"
            },
            {
                "below": "1.27.5",
                "severity": "medium",
                "cve": "CVE-2021-26539",
                "summary": "XSS bypass via SVG attributes"
            },
        ],
        "detection_patterns": [
            r'"sanitize-html":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "js-yaml": {
        "vulnerabilities": [
            {
                "below": "3.13.1",
                "severity": "high",
                "cve": "CVE-2019-7164",
                "summary": "Code execution via !!js/function"
            },
        ],
        "detection_patterns": [
            r'js-yaml[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            r'"js-yaml":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "shelljs": {
        "vulnerabilities": [
            {
                "below": "0.8.5",
                "severity": "high",
                "cve": "CVE-2022-0144",
                "summary": "Improper privilege management"
            },
        ],
        "detection_patterns": [
            r'"shelljs":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "tar": {
        "vulnerabilities": [
            {
                "below": "6.1.11",
                "severity": "high",
                "cve": "CVE-2021-37701",
                "summary": "Arbitrary file creation via symlink"
            },
            {
                "below": "6.1.9",
                "severity": "high",
                "cve": "CVE-2021-37712",
                "summary": "Path traversal via symlink following"
            },
        ],
        "detection_patterns": [
            r'"tar":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "async": {
        "vulnerabilities": [
            {
                "below": "3.2.2",
                "severity": "high",
                "cve": "CVE-2021-43138",
                "summary": "Prototype pollution in mapValues"
            },
        ],
        "detection_patterns": [
            r'"async":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
    "json5": {
        "vulnerabilities": [
            {
                "below": "2.2.2",
                "severity": "high",
                "cve": "CVE-2022-46175",
                "summary": "Prototype pollution via __proto__ key"
            },
        ],
        "detection_patterns": [
            r'"json5":\s*"[~^]?(\d+\.\d+\.\d+)"',
        ]
    },
}


# ============================================================================
# API KEY PATTERNS (High-Precision Regexes)
# ============================================================================

API_KEY_PATTERNS = {
    "aws_access_key": {
        "pattern": r'(?:AWS|aws)_?(?:ACCESS|access)_?(?:KEY|key)_?(?:ID|id)?["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})',
        "severity": "critical",
        "description": "AWS Access Key ID",
        "risk": "Full AWS account access if secret key also leaked"
    },
    "aws_secret_key": {
        "pattern": r'(?:AWS|aws)_?(?:SECRET|secret)_?(?:ACCESS|access)?_?(?:KEY|key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
        "severity": "critical",
        "description": "AWS Secret Access Key",
        "risk": "Full AWS account access"
    },
    "stripe_live_key": {
        "pattern": r'sk_live_[A-Za-z0-9]{24,}',
        "severity": "critical",
        "description": "Stripe Live Secret Key",
        "risk": "Full access to Stripe account, can charge customers"
    },
    "stripe_test_key": {
        "pattern": r'sk_test_[A-Za-z0-9]{24,}',
        "severity": "medium",
        "description": "Stripe Test Secret Key",
        "risk": "Access to Stripe test environment"
    },
    "github_token": {
        "pattern": r'ghp_[A-Za-z0-9]{36}',
        "severity": "high",
        "description": "GitHub Personal Access Token",
        "risk": "Access to private GitHub repositories and code"
    },
    "slack_token": {
        "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
        "severity": "high",
        "description": "Slack API Token",
        "risk": "Access to Slack workspace messages and data"
    },
    "firebase_api_key": {
        "pattern": r'AIza[A-Za-z0-9_-]{35}',
        "severity": "info",
        "description": "Firebase/Google API Key (Public by Design)",
        "risk": "Firebase API keys are designed to be public in frontend code. Security is enforced via Firebase Security Rules, not key secrecy. Verify security rules are properly configured.",
        "false_positive_note": "This is typically NOT a vulnerability - Firebase keys are meant to be exposed in client-side code."
    },
    "sendgrid_api_key": {
        "pattern": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
        "severity": "high",
        "description": "SendGrid API Key",
        "risk": "Can send emails on behalf of the account"
    },
    "twilio_account_sid": {
        "pattern": r'AC[a-f0-9]{32}',
        "severity": "medium",
        "description": "Twilio Account SID",
        "risk": "Account identification (low risk alone)"
    },
    "twilio_auth_token": {
        "pattern": r'(?:TWILIO|twilio)_?(?:AUTH|auth)_?(?:TOKEN|token)["\']?\s*[:=]\s*["\']?([a-f0-9]{32})',
        "severity": "high",
        "description": "Twilio Auth Token",
        "risk": "Can send SMS and make calls on behalf of the account"
    },
    "mailgun_api_key": {
        "pattern": r'key-[A-Za-z0-9]{32}',
        "severity": "high",
        "description": "Mailgun API Key",
        "risk": "Can send emails on behalf of the account"
    },
    "generic_api_key": {
        "pattern": r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32,})["\']',
        "severity": "low",
        "description": "Generic API Key",
        "risk": "Varies by service"
    },
}


# ============================================================================
# 1. JAVASCRIPT DEPENDENCY SCANNING (Retire.js)
# ============================================================================

async def test_js_dependencies(
    url: str,
    discovered_urls: list[str] | None = None,
    safe_mode: bool = True,
    browser_versions: dict[str, str] | None = None,
    package_json_content: str | None = None,
    html_content: str | None = None,
    response_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Scan JavaScript dependencies for known vulnerabilities (Retire.js methodology).

    Enhanced with React/Next.js detection via:
    - Browser JavaScript inspection (passed from http_scanner.py)
    - Exposed package.json parsing
    - __NEXT_DATA__ script tag analysis
    - Bundle content analysis

    Detection Strategy:
    1. Extract all <script src="..."> tags from HTML
    2. Download JavaScript files from discovered URLs
    3. Match version patterns against known vulnerable libraries
    4. Report CVE, severity, and upgrade recommendations

    Why This Works:
    - Most sites load libraries from CDNs or local paths with version numbers
    - jQuery example: jquery-3.4.1.min.js -> Extract "3.4.1" -> Match against CVE database
    - Low false positive rate (version matching is deterministic)

    Args:
        url: Base URL to scan
        discovered_urls: List of discovered URLs (from crawling phase)
        safe_mode: If True, only scan first 20 JS files (performance)
        browser_versions: Versions extracted from Playwright (e.g., {"react": "18.2.0"})
        package_json_content: Content of package.json if exposed
        html_content: HTML content of the page (optional, will be fetched if not provided)

    Returns:
        {
            "vulnerable": bool,
            "vulnerable_libraries": [
                {
                    "library": "jquery",
                    "version": "3.4.1",
                    "url": "https://example.com/static/jquery-3.4.1.min.js",
                    "vulnerabilities": [
                        {
                            "cve": "CVE-2019-11358",
                            "severity": "medium",
                            "summary": "Prototype pollution",
                            "fixed_in": "3.5.0"
                        }
                    ]
                }
            ],
            "libraries_scanned": int,
            "total_js_files": int,
            "framework_detection": {...},  # React/Next.js detection results
            "cwe": "CWE-829",
            "owasp": "A06:2021 - Vulnerable and Outdated Components"
        }
    """
    results = {
        "vulnerable": False,
        "vulnerable_libraries": [],
        "libraries_scanned": 0,
        "total_js_files": 0,
        "framework_detection": {},
        "cdn_detected": {},  # Libraries detected from CDN URLs
        "detection_sources": {  # Track where versions were found
            "browser": [],
            "cdn": [],
            "static_patterns": [],
        },
        "cwe": "CWE-829",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "severity": "varies",
        "recommendation": "Update vulnerable JavaScript libraries to latest versions"
    }

    # Get combined vulnerability database (built-in + Retire.js)
    vuln_db = get_combined_vulnerability_database()

    js_files = []

    # Step 1: Extract JavaScript files from HTML
    try:
        # Use provided HTML content or fetch it
        html = html_content if html_content else await _fetch_url(url, timeout=10)

        # Extract <script src="...">
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        script_urls = re.findall(script_pattern, html, re.IGNORECASE)

        # Build absolute URLs - detect JS files including modern bundled assets
        def is_js_url(u: str) -> bool:
            """Check if URL is a JavaScript file, including modern bundled assets"""
            return (u.endswith('.js') or
                    '/js/' in u or
                    '.js?' in u or
                    '/_next/' in u or           # Next.js bundles
                    '/static/chunks/' in u or   # Common chunk path
                    '/webpack/' in u or         # Webpack bundles
                    '/_nuxt/' in u or           # Nuxt.js bundles
                    ('/assets/' in u and '.js' in u))  # Vite/other bundlers

        for script_url in script_urls:
            absolute_url = urljoin(url, script_url)
            if is_js_url(absolute_url):
                js_files.append(absolute_url)

        # Also check discovered URLs for .js files
        if discovered_urls:
            for disc_url in discovered_urls:
                if is_js_url(disc_url):
                    js_files.append(disc_url)

    except Exception:
        pass

    # Remove duplicates
    js_files = list(set(js_files))
    results["total_js_files"] = len(js_files)

    # Step 1.5: Extract library versions from CDN URLs
    cdn_detected = extract_versions_from_cdn_urls(js_files)
    results["cdn_detected"] = cdn_detected
    results["detection_sources"]["cdn"] = list(cdn_detected.keys())

    # Track browser-detected versions and include the actual data for UI display
    if browser_versions:
        results["detection_sources"]["browser"] = list(browser_versions.keys())
    results["browser_versions"] = browser_versions or {}

    # Limit to first 20 files in safe mode
    if safe_mode and len(js_files) > 20:
        js_files = js_files[:20]

    # Step 2: Download and analyze each JS file
    for js_url in js_files:
        results["libraries_scanned"] += 1

        try:
            # Download JS file (first 100KB only by using Range header)
            js_content = await _fetch_url(js_url, timeout=10, headers={'Range': 'bytes=0-102400'})

            # Step 3: Match against vulnerable library patterns
            for lib_name, lib_data in vuln_db.items():
                # Skip libraries without detection patterns
                if "detection_patterns" not in lib_data:
                    continue
                for pattern in lib_data["detection_patterns"]:
                    match = re.search(pattern, js_content, re.IGNORECASE)
                    if match:
                        detected_version = match.group(1)

                        # Track detection source
                        if lib_name not in results["detection_sources"]["static_patterns"]:
                            results["detection_sources"]["static_patterns"].append(lib_name)

                        # Check if version is vulnerable
                        for vuln in lib_data["vulnerabilities"]:
                            if _is_version_vulnerable(detected_version, vuln["below"]):
                                results["vulnerable"] = True

                                # Check if already reported (avoid duplicates)
                                existing = next(
                                    (v for v in results["vulnerable_libraries"]
                                     if v["library"] == lib_name and v["version"] == detected_version),
                                    None
                                )

                                if existing:
                                    # Add vulnerability to existing entry
                                    existing["vulnerabilities"].append({
                                        "cve": vuln["cve"],
                                        "severity": vuln["severity"],
                                        "summary": vuln["summary"],
                                        "fixed_in": vuln["below"]
                                    })
                                else:
                                    # New vulnerable library entry
                                    results["vulnerable_libraries"].append({
                                        "library": lib_name,
                                        "version": detected_version,
                                        "url": js_url,
                                        "vulnerabilities": [{
                                            "cve": vuln["cve"],
                                            "severity": vuln["severity"],
                                            "summary": vuln["summary"],
                                            "fixed_in": vuln["below"]
                                        }]
                                    })

        except Exception:
            continue

        await asyncio.sleep(0.2)  # Rate limiting

    # Step 3: Enhanced React/Next.js detection
    try:
        framework_versions = await detect_react_nextjs_versions(
            url=url,
            browser_versions=browser_versions,
            package_json_content=package_json_content,
            html_content=html,
            discovered_urls=discovered_urls,
            response_headers=response_headers
        )
    except Exception as e:
        logging.warning(f"[js_deps] Error in detect_react_nextjs_versions: {e}")
        framework_versions = {
            "react": {"detected": False, "version": None, "detection_method": None, "confidence": None},
            "nextjs": {"detected": False, "version": None, "detection_method": None, "confidence": None}
        }
    results["framework_detection"] = framework_versions

    # Check React version for vulnerabilities
    if framework_versions["react"]["detected"] and framework_versions["react"]["version"]:
        detected_version = framework_versions["react"]["version"]
        react_vulns = []
        react_lib = vuln_db.get("react", {})
        for vuln in react_lib.get("vulnerabilities", []):
            if _is_version_vulnerable_range(detected_version, vuln):
                react_vulns.append({
                    "cve": vuln.get("cve"),
                    "severity": vuln.get("severity", "medium"),
                    "summary": vuln.get("summary", "Unknown vulnerability"),
                    "fixed_in": vuln.get("below")
                })

        if react_vulns:
            results["vulnerable"] = True
            results["vulnerable_libraries"].append({
                "library": "react",
                "version": detected_version,
                "url": url,
                "detection_method": framework_versions["react"]["detection_method"],
                "confidence": framework_versions["react"]["confidence"],
                "vulnerabilities": react_vulns
            })

    # Check Next.js version for vulnerabilities
    if framework_versions["nextjs"]["detected"] and framework_versions["nextjs"]["version"]:
        detected_version = framework_versions["nextjs"]["version"]
        next_vulns = []
        next_lib = vuln_db.get("next", {})
        for vuln in next_lib.get("vulnerabilities", []):
            if _is_version_vulnerable_range(detected_version, vuln):
                next_vulns.append({
                    "cve": vuln.get("cve"),
                    "severity": vuln.get("severity", "medium"),
                    "summary": vuln.get("summary", "Unknown vulnerability"),
                    "fixed_in": vuln.get("below")
                })

        if next_vulns:
            results["vulnerable"] = True
            results["vulnerable_libraries"].append({
                "library": "next",
                "version": detected_version,
                "url": url,
                "detection_method": framework_versions["nextjs"]["detection_method"],
                "confidence": framework_versions["nextjs"]["confidence"],
                "vulnerabilities": next_vulns
            })

    return results


def _normalize_version(version: str) -> str:
    """
    Normalize version string by stripping prefixes and suffixes.

    Examples:
        v18.2.0 -> 18.2.0
        18.2.0-canary -> 18.2.0
        3.4.1-beta.1 -> 3.4.1
        1.0.0-rc1 -> 1.0.0
    """
    # Strip leading 'v' or 'V'
    version = version.lstrip('vV')
    # Split on common pre-release separators and take first part
    for sep in ['-', '+', '_', ' ']:
        if sep in version:
            version = version.split(sep)[0]
    return version


def _is_version_vulnerable(detected_version: str, vulnerable_below: str) -> bool:
    """
    Compare semantic versions (e.g., "3.4.1" < "3.5.0").
    Returns True if detected_version is vulnerable (below threshold).

    Handles pre-release versions like "18.2.0-canary" by stripping suffixes.
    """
    try:
        # Normalize versions to handle v-prefix and pre-release suffixes
        detected_clean = _normalize_version(detected_version)
        threshold_clean = _normalize_version(vulnerable_below)

        # Parse numeric parts, filtering out non-numeric segments
        detected_parts = []
        for x in detected_clean.split('.'):
            # Extract leading digits from each part
            digits = ''
            for c in x:
                if c.isdigit():
                    digits += c
                else:
                    break
            if digits:
                detected_parts.append(int(digits))

        threshold_parts = []
        for x in threshold_clean.split('.'):
            digits = ''
            for c in x:
                if c.isdigit():
                    digits += c
                else:
                    break
            if digits:
                threshold_parts.append(int(digits))

        if not detected_parts or not threshold_parts:
            return False

        # Pad to same length
        max_len = max(len(detected_parts), len(threshold_parts))
        detected_parts += [0] * (max_len - len(detected_parts))
        threshold_parts += [0] * (max_len - len(threshold_parts))

        # Compare
        for d, t in zip(detected_parts, threshold_parts, strict=False):
            if d < t:
                return True  # Vulnerable
            elif d > t:
                return False  # Not vulnerable

        return False  # Equal version, not vulnerable (threshold is exclusive)
    except Exception:
        return False


def _is_version_vulnerable_range(detected_version: str, vuln_spec: dict) -> bool:
    """
    Check if version falls within a vulnerable range.

    Supports both simple "below" checks and ranged vulnerabilities with "above".

    Args:
        detected_version: The detected version string (e.g., "19.1.0")
        vuln_spec: Vulnerability specification with "below" and optional "above" keys

    Returns:
        True if the detected version is vulnerable
    """
    try:
        below = vuln_spec.get("below")
        above = vuln_spec.get("above")  # Optional: only vulnerable if version >= above

        # Must be below the fix threshold
        if below and not _is_version_vulnerable(detected_version, below):
            return False  # Version is >= fixed version, not vulnerable

        # If "above" is specified, version must be >= above to be in the vulnerable range
        if above:
            # Check if detected version is >= above (i.e., NOT below above)
            if _is_version_vulnerable(detected_version, above):
                return False  # Version is below the affected range

        return True
    except Exception:
        return False


def _extract_semver(version_string: str) -> str | None:
    """
    Extract semantic version from npm version string (handles ^, ~, >=, etc.)

    Handles common formats:
    - Full semver: "^18.2.0", "~14.1.0", ">=1.0.0", "1.2.3"
    - Two-part: "14.1", "^14.0"
    - Pre-release: "14.1.0-canary.1", "18.2.0-rc.1"
    - X-ranges: "14.x", "14.1.x"

    Args:
        version_string: Version string from package.json (e.g., "^18.2.0", "~14.1.0")

    Returns:
        Clean version string (e.g., "18.2.0") or None if not parseable
    """
    if not version_string:
        return None

    # Strip common prefixes and suffixes first
    clean = version_string.strip().lstrip('^~>=<vV ')

    # Try full semver first (x.y.z), allowing pre-release suffix
    match = re.search(r'^(\d+\.\d+\.\d+)', clean)
    if match:
        return match.group(1)

    # Try two-part version (x.y) - normalize to x.y.0
    match = re.search(r'^(\d+)\.(\d+)', clean)
    if match:
        return f"{match.group(1)}.{match.group(2)}.0"

    # Try single major version (e.g., "14", "14.x")
    match = re.search(r'^(\d+)(?:\.x)?$', clean)
    if match:
        return f"{match.group(1)}.0.0"

    return None


def _parse_next_data(html_content: str) -> dict[str, Any] | None:
    """
    Extract and parse __NEXT_DATA__ script tag content from HTML.

    This tag is injected by Next.js and contains build metadata.

    Args:
        html_content: Raw HTML content of the page

    Returns:
        Parsed JSON object from __NEXT_DATA__ or None if not found/invalid
    """
    import json
    # More flexible patterns to handle attribute reordering
    # Pattern 1: id first (most common)
    # Pattern 2: type first, then id
    # Pattern 3: Any attribute order with id="__NEXT_DATA__" somewhere
    patterns = [
        r'<script\s+id="__NEXT_DATA__"[^>]*>([^<]+)</script>',
        r'<script\s+type="application/json"\s+id="__NEXT_DATA__"[^>]*>([^<]+)</script>',
        r'<script[^>]+id="__NEXT_DATA__"[^>]*>([^<]+)</script>',
        r'<script[^>]+id=\'__NEXT_DATA__\'[^>]*>([^<]+)</script>',
    ]
    # Increase limit to 500KB for large pages (SPAs can have large initial HTML)
    search_content = html_content[:500000]

    for pattern in patterns:
        match = re.search(pattern, search_content, re.IGNORECASE | re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                continue
    return None


# ============================================================================
# REACT/NEXT.JS ENHANCED VERSION DETECTION
# ============================================================================

async def detect_react_nextjs_versions(
    url: str,
    browser_versions: dict[str, str] | None = None,
    package_json_content: str | None = None,
    html_content: str | None = None,
    discovered_urls: list[str] | None = None,
    response_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Enhanced detection for React and Next.js versions using multiple methods.

    Detection Methods (in priority order):
    1. Browser JavaScript inspection (window.React.version, window.next.version)
    2. Exposed package.json parsing
    3. X-Powered-By / X-Next-Version headers
    4. __NEXT_DATA__ script tag analysis
    5. Build manifest parsing
    6. _next/static/ URL pattern detection (presence only)

    Args:
        url: Base URL being scanned
        browser_versions: Versions extracted from Playwright (e.g., {"react": "18.2.0"})
        package_json_content: Content of package.json if exposed
        html_content: HTML content of the page
        discovered_urls: List of discovered URLs from crawling
        response_headers: HTTP response headers

    Returns:
        {
            "react": {
                "detected": bool,
                "version": str or None,
                "detection_method": str,
                "confidence": "high" | "medium" | "low"
            },
            "nextjs": {
                "detected": bool,
                "version": str or None,
                "detection_method": str,
                "confidence": "high" | "medium" | "low"
            }
        }
    """
    import json
    import re

    results = {
        "react": {"detected": False, "version": None, "detection_method": None, "confidence": None},
        "nextjs": {"detected": False, "version": None, "detection_method": None, "confidence": None}
    }

    def _is_valid_semver(version: str) -> bool:
        """Check if version string is a valid semver (not 'detected', '18+', etc.)."""
        if not version:
            return False
        # Must start with a digit and contain at least one dot
        return bool(re.match(r'^\d+\.\d+', version))

    # Method 1: Browser JavaScript inspection (highest confidence)
    if browser_versions:
        react_version = browser_versions.get("react")
        if react_version:
            # Only use version if it's a valid semver, otherwise mark as detected only
            results["react"] = {
                "detected": True,
                "version": react_version if _is_valid_semver(react_version) else None,
                "detection_method": "browser_js_inspection",
                "confidence": "high" if _is_valid_semver(react_version) else "low",
                "presence_marker": react_version if not _is_valid_semver(react_version) else None
            }
        # Check both "next" and "nextjs" keys (http_scanner uses "nextjs")
        next_version = browser_versions.get("next") or browser_versions.get("nextjs")
        if next_version:
            results["nextjs"] = {
                "detected": True,
                "version": next_version if _is_valid_semver(next_version) else None,
                "detection_method": "browser_js_inspection",
                "confidence": "high" if _is_valid_semver(next_version) else "low",
                "presence_marker": next_version if not _is_valid_semver(next_version) else None
            }

    # Method 2: Parse exposed package.json
    if package_json_content and not (results["react"]["version"] and results["nextjs"]["version"]):
        try:
            pkg = json.loads(package_json_content)
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

            if not results["react"]["version"] and "react" in deps:
                version = _extract_semver(deps["react"])
                if version:
                    results["react"] = {
                        "detected": True,
                        "version": version,
                        "detection_method": "package_json",
                        "confidence": "high"
                    }

            if not results["nextjs"]["version"] and "next" in deps:
                version = _extract_semver(deps["next"])
                if version:
                    results["nextjs"] = {
                        "detected": True,
                        "version": version,
                        "detection_method": "package_json",
                        "confidence": "high"
                    }
        except Exception:
            pass

    # Method 3: Check X-Powered-By and other headers for Next.js version/presence
    if response_headers:
        # Check X-Powered-By: Next.js
        # Handle both Dict[str, str] (Playwright) and Dict[str, List[str]] (curl) formats
        powered_by_raw = response_headers.get("x-powered-by", "")
        powered_by = powered_by_raw[0] if isinstance(powered_by_raw, list) and powered_by_raw else (powered_by_raw if not isinstance(powered_by_raw, list) else "")
        if powered_by and ("Next.js" in powered_by or "next.js" in powered_by.lower()):
            results["nextjs"]["detected"] = True
            # Try to extract version from "Next.js 14.0.0" format
            version_match = re.search(r'Next\.js[/ ]?(\d+\.\d+(?:\.\d+)?)', powered_by, re.IGNORECASE)
            if version_match:
                results["nextjs"]["version"] = version_match.group(1)
                results["nextjs"]["detection_method"] = "x-powered-by"
                results["nextjs"]["confidence"] = "high"
            elif not results["nextjs"]["detection_method"]:
                results["nextjs"]["detection_method"] = "x-powered-by"
                results["nextjs"]["confidence"] = "low"

        # Additional Next.js header presence signals (no version, but confirms Next.js)
        nextjs_headers = ["x-nextjs-cache", "x-nextjs-page", "x-nextjs-matched-path", "x-middleware-rewrite"]
        for header in nextjs_headers:
            if response_headers.get(header) and not results["nextjs"]["detected"]:
                results["nextjs"]["detected"] = True
                results["nextjs"]["detection_method"] = f"header:{header}"
                results["nextjs"]["confidence"] = "medium"
                break

    # Method 4: __NEXT_DATA__ script tag analysis
    next_build_id = None
    if html_content:
        next_data = _parse_next_data(html_content)
        if next_data:
            results["nextjs"]["detected"] = True
            if not results["nextjs"]["detection_method"]:
                results["nextjs"]["detection_method"] = "__NEXT_DATA__"
            # Extract buildId for manifest fetching
            next_build_id = next_data.get("buildId")
            # Check if version is available in __NEXT_DATA__ (rare but possible)
            if next_data.get("nextVersion"):
                results["nextjs"]["version"] = next_data["nextVersion"]
                results["nextjs"]["confidence"] = "high"
            elif not results["nextjs"]["version"]:
                results["nextjs"]["confidence"] = "low"  # Detected but no version

    # Method 5: Try to fetch and parse Next.js build manifest for version hints
    # Pass buildId if available for more targeted manifest fetching
    if results["nextjs"]["detected"] and not results["nextjs"]["version"]:
        version = await _detect_nextjs_version_from_manifest(
            url,
            discovered_urls or [],
            build_id=next_build_id
        )
        if version:
            results["nextjs"]["version"] = version
            results["nextjs"]["detection_method"] = "build_manifest"
            results["nextjs"]["confidence"] = "medium"

    # Method 6: _next/static/ URL pattern detection (Next.js presence only)
    if discovered_urls and not results["nextjs"]["detected"]:
        for disc_url in (discovered_urls or []):
            if "/_next/static/" in disc_url or "/_next/data/" in disc_url:
                results["nextjs"]["detected"] = True
                results["nextjs"]["detection_method"] = "_next_url_pattern"
                results["nextjs"]["confidence"] = "low"
                break

    # Method 6b: Check HTML content for _next patterns
    if html_content and not results["nextjs"]["detected"]:
        if "/_next/static/" in html_content or "__NEXT_DATA__" in html_content:
            results["nextjs"]["detected"] = True
            results["nextjs"]["detection_method"] = "html_pattern"
            results["nextjs"]["confidence"] = "low"

    # Method 6c: Check HTML for React patterns (createElement, ReactDOM)
    if html_content and not results["react"]["detected"]:
        if "React.createElement" in html_content or "ReactDOM" in html_content or "__REACT_DEVTOOLS" in html_content:
            results["react"]["detected"] = True
            results["react"]["detection_method"] = "html_pattern"
            results["react"]["confidence"] = "low"

    # Method 7: Try to extract React version from JS bundles
    if discovered_urls and results["react"]["detected"] and not results["react"]["version"]:
        version = await _detect_react_version_from_bundles(url, discovered_urls)
        if version:
            results["react"]["version"] = version
            results["react"]["detection_method"] = "js_bundle_analysis"
            results["react"]["confidence"] = "medium"

    return results


async def _detect_nextjs_version_from_manifest(
    url: str,
    discovered_urls: list[str],
    build_id: str | None = None
) -> str | None:
    """
    Try to detect Next.js version from build manifest or chunk files.

    Enhanced detection methods:
    1. If buildId available, fetch /_next/static/<buildId>/_buildManifest.js
    2. Check main-app.js, framework.js chunks (App Router)
    3. Check main-*.js, webpack-*.js chunks (Pages Router)
    4. Look for __NEXT_VERSION__ or process.env.__NEXT_VERSION__ patterns
    """
    import re

    import aiohttp

    # Version patterns to search for in bundle content
    version_patterns = [
        r'"Next\.js[/ ](\d+\.\d+(?:\.\d+)?)"',  # "Next.js 14.0.0"
        r'__NEXT_VERSION__["\s:=]+["\'](\d+\.\d+(?:\.\d+)?)["\']',  # __NEXT_VERSION__
        r'process\.env\.__NEXT_VERSION__["\s:=]+["\'](\d+\.\d+(?:\.\d+)?)["\']',
        r'version["\s:]+["\'](\d+\.\d+\.\d+)["\']',  # version:"14.0.0"
        r'"version":\s*"(\d+\.\d+\.\d+)"',  # JSON version field
        r'next@(\d+\.\d+\.\d+)',  # next@14.0.0 in comments/source maps
    ]

    target_files = []

    # Method 1: Use buildId to construct manifest URL directly
    if build_id:
        base_url = url.rstrip('/')
        manifest_urls = [
            f"{base_url}/_next/static/{build_id}/_buildManifest.js",
            f"{base_url}/_next/static/{build_id}/_ssgManifest.js",
        ]
        target_files.extend(manifest_urls)

    # Method 2: Look for chunk files in discovered URLs (expanded patterns)
    chunk_patterns = [
        "/_next/static/chunks/main-app",  # App Router main chunk
        "/_next/static/chunks/main.",      # Pages Router main chunk
        "/_next/static/chunks/framework",  # Framework chunk (common)
        "/_next/static/chunks/webpack",    # Webpack runtime
        "/_next/static/chunks/pages/_app", # Pages Router _app
        "/chunks/polyfills",               # Polyfills (sometimes has version)
    ]

    for disc_url in discovered_urls:
        for pattern in chunk_patterns:
            if pattern in disc_url and disc_url not in target_files:
                target_files.append(disc_url)
                break
        if len(target_files) >= 6:  # Check up to 6 files
            break

    if not target_files:
        return None

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            for chunk_url in target_files[:6]:
                try:
                    async with session.get(chunk_url) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            # Check first 100KB of content for version patterns
                            search_content = content[:100000]

                            for pattern in version_patterns:
                                match = re.search(pattern, search_content)
                                if match:
                                    version = match.group(1)
                                    # Normalize to x.y.z format
                                    if version.count('.') == 1:
                                        version += '.0'
                                    return version
                except Exception:
                    continue
    except Exception:
        pass

    return None


async def _detect_react_version_from_bundles(url: str, discovered_urls: list[str]) -> str | None:
    """
    Try to detect React version from JS bundle files.

    React embeds version info in:
    - react.production.min.js (contains React.version)
    - Main bundle chunks
    """
    import re

    import aiohttp

    # Look for react-related JS files
    target_files = []
    for disc_url in discovered_urls:
        if ("react" in disc_url.lower() and disc_url.endswith(".js")) or ("/_next/static/chunks/" in disc_url and disc_url.endswith(".js")):
            target_files.append(disc_url)
        if len(target_files) >= 3:
            break

    if not target_files:
        return None

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            for js_url in target_files[:3]:
                try:
                    async with session.get(js_url) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            # React version patterns
                            # Pattern 1: React.version = "18.2.0"
                            match = re.search(r'React\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', content)
                            if match:
                                return match.group(1)
                            # Pattern 2: "react":"18.2.0" in package info
                            match = re.search(r'"react"\s*:\s*["\'][\^~]?(\d+\.\d+\.\d+)["\']', content)
                            if match:
                                return match.group(1)
                            # Pattern 3: version:"18.2.0" near "react" context
                            if "react" in content.lower()[:1000]:
                                match = re.search(r'version:\s*["\'](\d+\.\d+\.\d+)["\']', content[:5000])
                                if match:
                                    return match.group(1)
                except Exception:
                    continue
    except Exception:
        pass

    return None


def detect_server_versions(response_headers: dict[str, Any]) -> dict[str, Any]:
    """
    Detect server software versions from HTTP response headers.

    Detects:
    - nginx, Apache, IIS, LiteSpeed (Server header)
    - Node.js, PHP, Python (X-Powered-By header)
    - Various CDN/platforms (Vercel, Cloudflare, AWS, etc.)

    Args:
        response_headers: HTTP response headers (case-insensitive dict)

    Returns:
        {
            "server": {"name": str, "version": str or None, "confidence": str},
            "runtime": {"name": str, "version": str or None, "confidence": str},
            "platform": {"name": str, "version": str or None},
            "cdn": {"name": str},
            "additional": [...]  # Other detected technologies
        }
    """
    import re

    results = {
        "server": None,
        "runtime": None,
        "platform": None,
        "cdn": None,
        "additional": []
    }

    # Normalize headers to lowercase keys
    headers = {k.lower(): v for k, v in response_headers.items()}

    # Helper to safely get header as string (headers can be lists)
    def _get_str(value):
        if isinstance(value, list):
            return value[0] if value else ""
        return value or ""

    # === Server Header Analysis ===
    server_header = _get_str(headers.get("server", ""))
    if server_header:
        # nginx
        if "nginx" in server_header.lower():
            version_match = re.search(r'nginx[/\s]*([\d.]+)', server_header, re.IGNORECASE)
            results["server"] = {
                "name": "nginx",
                "version": version_match.group(1) if version_match else None,
                "confidence": "high" if version_match else "medium"
            }
        # Apache
        elif "apache" in server_header.lower():
            version_match = re.search(r'Apache[/\s]*([\d.]+)', server_header, re.IGNORECASE)
            results["server"] = {
                "name": "Apache",
                "version": version_match.group(1) if version_match else None,
                "confidence": "high" if version_match else "medium"
            }
        # Microsoft IIS
        elif "microsoft-iis" in server_header.lower() or "iis" in server_header.lower():
            version_match = re.search(r'IIS[/\s]*([\d.]+)', server_header, re.IGNORECASE)
            results["server"] = {
                "name": "Microsoft-IIS",
                "version": version_match.group(1) if version_match else None,
                "confidence": "high" if version_match else "medium"
            }
        # LiteSpeed
        elif "litespeed" in server_header.lower():
            version_match = re.search(r'LiteSpeed[/\s]*([\d.]+)', server_header, re.IGNORECASE)
            results["server"] = {
                "name": "LiteSpeed",
                "version": version_match.group(1) if version_match else None,
                "confidence": "high" if version_match else "medium"
            }
        # Cloudflare
        elif "cloudflare" in server_header.lower():
            results["server"] = {"name": "Cloudflare", "version": None, "confidence": "high"}
            results["cdn"] = {"name": "Cloudflare"}
        # Vercel
        elif "vercel" in server_header.lower():
            results["platform"] = {"name": "Vercel", "version": None}
        # Generic
        else:
            results["server"] = {"name": server_header.split("/")[0].strip(), "version": None, "confidence": "low"}

    # === X-Powered-By Header Analysis ===
    powered_by = _get_str(headers.get("x-powered-by", ""))
    if powered_by:
        # PHP
        if "php" in powered_by.lower():
            version_match = re.search(r'PHP[/\s]*([\d.]+)', powered_by, re.IGNORECASE)
            results["runtime"] = {
                "name": "PHP",
                "version": version_match.group(1) if version_match else None,
                "confidence": "high" if version_match else "medium"
            }
        # ASP.NET
        elif "asp.net" in powered_by.lower():
            version_match = re.search(r'ASP\.NET[/\s]*([\d.]+)?', powered_by, re.IGNORECASE)
            results["runtime"] = {
                "name": "ASP.NET",
                "version": version_match.group(1) if version_match and version_match.group(1) else None,
                "confidence": "high"
            }
        # Express (Node.js)
        elif "express" in powered_by.lower():
            results["runtime"] = {"name": "Express/Node.js", "version": None, "confidence": "medium"}
        # Next.js
        elif "next.js" in powered_by.lower():
            version_match = re.search(r'Next\.js[/\s]*([\d.]+)', powered_by, re.IGNORECASE)
            results["runtime"] = {
                "name": "Next.js",
                "version": version_match.group(1) if version_match else None,
                "confidence": "high" if version_match else "medium"
            }
        # Vercel
        elif powered_by.lower() == "vercel":
            results["platform"] = {"name": "Vercel", "version": None}

    # === CDN Detection ===
    # Cloudflare
    if headers.get("cf-ray") or headers.get("cf-cache-status"):
        results["cdn"] = {"name": "Cloudflare"}
        if not results["server"]:
            results["server"] = {"name": "Cloudflare", "version": None, "confidence": "high"}

    # Fastly
    elif headers.get("x-served-by") and "cache" in _get_str(headers.get("x-served-by", "")).lower():
        results["cdn"] = {"name": "Fastly"}

    # AWS CloudFront
    elif headers.get("x-amz-cf-id") or headers.get("x-amz-cf-pop"):
        results["cdn"] = {"name": "AWS CloudFront"}

    # Akamai
    elif headers.get("x-akamai-transformed"):
        results["cdn"] = {"name": "Akamai"}

    # === Platform Detection ===
    # Vercel
    if headers.get("x-vercel-id") or headers.get("x-vercel-cache"):
        results["platform"] = {"name": "Vercel", "version": None}

    # Netlify
    elif headers.get("x-nf-request-id"):
        results["platform"] = {"name": "Netlify", "version": None}

    # Heroku
    elif headers.get("via") and "vegur" in _get_str(headers.get("via", "")).lower():
        results["platform"] = {"name": "Heroku", "version": None}

    # AWS (various)
    elif headers.get("x-amzn-requestid") or headers.get("x-amz-apigw-id"):
        results["platform"] = {"name": "AWS", "version": None}

    # === Additional Technology Detection ===
    # HSTS
    if headers.get("strict-transport-security"):
        results["additional"].append({"name": "HSTS", "type": "security"})

    # X-Frame-Options
    if headers.get("x-frame-options"):
        results["additional"].append({"name": "X-Frame-Options", "type": "security", "value": _get_str(headers.get("x-frame-options"))})

    # Content-Security-Policy
    if headers.get("content-security-policy"):
        results["additional"].append({"name": "CSP", "type": "security"})

    return results


# ============================================================================
# 2. SECRET LEAKS IN JAVASCRIPT BUNDLES
# ============================================================================

async def test_js_secrets(
    url: str,
    discovered_urls: list[str] | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Scan JavaScript files for hardcoded API keys and credentials.

    Common Leak Scenarios:
    - React/Vue/Angular apps with API keys in environment configs
    - Developers commit .env values directly into frontend code
    - Build process inlines secrets into JS bundles

    Detection Strategy:
    1. Download all JavaScript files
    2. Scan for API key patterns (AWS, Stripe, GitHub, Slack, Firebase, etc.)
    3. Report matches with severity and recommendations

    Args:
        url: Base URL to scan
        discovered_urls: List of discovered URLs
        safe_mode: If True, limit to first 20 JS files

    Returns:
        {
            "vulnerable": bool,
            "secrets_found": [
                {
                    "type": "aws_access_key",
                    "severity": "critical",
                    "description": "AWS Access Key ID",
                    "file": "https://example.com/static/app.js",
                    "value_preview": "AKIA...7XYZ",  # First 4 + last 4 chars
                    "line_number": 42,
                    "context": "... const AWS_ACCESS_KEY_ID = 'AKIA...' ...",
                    "risk": "Full AWS account access if secret key also leaked"
                }
            ],
            "files_scanned": int,
            "cwe": "CWE-798",
            "owasp": "A05:2021 - Security Misconfiguration"
        }
    """
    results = {
        "vulnerable": False,
        "secrets_found": [],
        "files_scanned": 0,
        "cwe": "CWE-798",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "varies",
        "recommendation": "Remove hardcoded secrets, use environment variables and secret management"
    }

    # Collect JavaScript files (same logic as test_js_dependencies)
    js_files = await _collect_js_files(url, discovered_urls)

    if safe_mode and len(js_files) > 20:
        js_files = js_files[:20]

    for js_url in js_files:
        results["files_scanned"] += 1

        try:
            # Download JS file
            js_content = await _fetch_url(js_url, timeout=10)

            # Skip if response is too large (>500KB) or empty
            if not js_content or len(js_content) > 512000:
                continue

            # Scan for API key patterns
            for key_type, key_data in API_KEY_PATTERNS.items():
                pattern = key_data["pattern"]
                matches = re.finditer(pattern, js_content, re.IGNORECASE)

                for match in matches:
                    results["vulnerable"] = True

                    # Find line number
                    line_num = js_content[:match.start()].count('\n') + 1

                    # Extract context (50 chars before/after)
                    start = max(0, match.start() - 50)
                    end = min(len(js_content), match.end() + 50)
                    context = js_content[start:end].replace('\n', ' ')

                    # Mask sensitive value (show first 4 + last 4 chars)
                    full_value = match.group(0) if not match.groups() else (match.group(1) if len(match.groups()) > 0 else match.group(0))
                    if len(full_value) > 8:
                        masked_value = f"{full_value[:4]}...{full_value[-4:]}"
                    else:
                        masked_value = "***"

                    results["secrets_found"].append({
                        "type": key_type,
                        "description": key_data["description"],
                        "severity": key_data["severity"],
                        "file": js_url,
                        "value_preview": masked_value,
                        "line_number": line_num,
                        "context": context[:100],  # Limit context length
                        "risk": key_data.get("risk", "Unknown risk level")
                    })

        except Exception:
            continue

        await asyncio.sleep(0.2)  # Rate limiting

    return results


async def _collect_js_files(url: str, discovered_urls: list[str] | None) -> list[str]:
    """Collect all JavaScript files from base URL and discovered URLs"""
    js_files = []

    try:
        html = await _fetch_url(url, timeout=10)

        # Extract <script src="...">
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        script_urls = re.findall(script_pattern, html, re.IGNORECASE)

        for script_url in script_urls:
            absolute_url = urljoin(url, script_url)
            if (absolute_url.endswith('.js') or '/js/' in absolute_url or '.js?' in absolute_url or
                (('/_next/' in absolute_url or '/static/chunks/' in absolute_url or
                  '/webpack/' in absolute_url or '/_nuxt/' in absolute_url) and
                 ('.js' in absolute_url or absolute_url.endswith('.mjs'))) or
                ('/assets/' in absolute_url and '.js' in absolute_url)):
                js_files.append(absolute_url)

        # Also check discovered URLs
        if discovered_urls:
            for disc_url in discovered_urls:
                if (disc_url.endswith('.js') or '/js/' in disc_url or '.js?' in disc_url or
                    (('/_next/' in disc_url or '/static/chunks/' in disc_url or
                      '/webpack/' in disc_url or '/_nuxt/' in disc_url) and
                     ('.js' in disc_url or disc_url.endswith('.mjs'))) or
                    ('/assets/' in disc_url and '.js' in disc_url)):
                    js_files.append(disc_url)

    except Exception:
        pass

    return list(set(js_files))  # Remove duplicates


# ============================================================================
# 3. CLIENT-SIDE VULNERABILITY HEURISTICS
# ============================================================================

async def test_client_side_vulns(
    url: str,
    discovered_urls: list[str] | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Heuristic checks for client-side issues:
    - postMessage handlers without obvious origin validation
    - Prototype pollution sink patterns in JS bundles
    """
    results = {
        "vulnerable": False,
        "findings": [],
        "files_scanned": 0,
        "cwe": ["CWE-345", "CWE-1321"],
        "owasp": "A03:2021 - Injection"
    }

    js_files = await _collect_js_files(url, discovered_urls)
    if safe_mode and len(js_files) > 20:
        js_files = js_files[:20]

    postmessage_patterns = [
        r'addEventListener\(\s*[\'"]message[\'"]',
        r'\.onmessage\s*='
    ]
    origin_validation_patterns = [
        r'\.origin\s*[=!]==',
        r'origin\s*[=!]==',
        r'origin\s*\.includes\s*\(',
        r'origin\s*\.indexOf\s*\(',
        r'allowedOrigins',
        r'trustedOrigins',
        r'originWhitelist',
    ]

    proto_indicators = [
        r'__proto__',
        r'constructor\.prototype',
        r'prototype\[',
    ]
    merge_indicators = [
        r'Object\.assign',
        r'\.extend\(',
        r'\.merge\(',
        r'\.set\(',
    ]
    untrusted_sources = [
        r'location\.search',
        r'location\.hash',
        r'URLSearchParams',
        r'querystring\.parse',
        r'qs\.parse',
    ]

    def extract_handler_segment(content: str, start_index: int) -> str:
        brace_index = content.find("{", start_index)
        if brace_index == -1:
            end_index = content.find(";", start_index)
            if end_index == -1:
                end_index = min(start_index + 800, len(content))
            return content[start_index:end_index]
        depth = 0
        end_index = min(brace_index + 2000, len(content))
        for i in range(brace_index, min(brace_index + 2000, len(content))):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    end_index = i + 1
                    break
        return content[start_index:end_index]

    def has_origin_validation(segment: str) -> bool:
        if not re.search(r'event\.origin|\borigin\b', segment, re.IGNORECASE):
            return False
        return any(re.search(pat, segment, re.IGNORECASE) for pat in origin_validation_patterns)

    for js_url in js_files:
        results["files_scanned"] += 1
        try:
            js_content = await _fetch_url(js_url, timeout=10)
            if not js_content or len(js_content) > 512000:
                continue

            # postMessage origin validation heuristic
            for pattern in postmessage_patterns:
                for match in re.finditer(pattern, js_content, re.IGNORECASE):
                    segment = extract_handler_segment(js_content, match.start())
                    if not has_origin_validation(segment):
                        line_num = js_content[:match.start()].count('\n') + 1
                        results["vulnerable"] = True
                        results["findings"].append({
                            "type": "postmessage_origin_check_missing",
                            "severity": "low",
                            "file": js_url,
                            "line_number": line_num,
                            "evidence": segment[:160].replace('\n', ' ')
                        })
                    if len(results["findings"]) > 5:
                        break
                if len(results["findings"]) > 5:
                    break

            # Prototype pollution heuristic
            if any(re.search(p, js_content, re.IGNORECASE) for p in proto_indicators):
                if any(re.search(p, js_content, re.IGNORECASE) for p in merge_indicators) and \
                   any(re.search(p, js_content, re.IGNORECASE) for p in untrusted_sources):
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "prototype_pollution_sink",
                        "severity": "low",
                        "file": js_url,
                        "evidence": "Prototype keys + merge from URL parameters detected"
                    })

        except Exception:
            continue

        await asyncio.sleep(0.2)

    return results
