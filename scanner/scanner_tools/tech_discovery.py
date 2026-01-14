"""
Wappalyzer-style Technology Discovery Engine

Unified signature-based technology detection with:
- Centralized pattern database (JSON)
- Multi-signal matching (headers, HTML, JS, DOM, cookies, DNS, TLS)
- Confidence scoring with weighted sources
- Implied/excluded tech relationships
- Structured evidence for audit trail
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Evidence:
    """Evidence of a technology detection."""
    signal_type: str          # "header", "js", "dom", "html", "cookie", "meta", "scriptSrc", etc.
    pattern_id: str           # Key in signature (e.g., "x-powered-by", "React.version")
    matched_value: str        # What matched (truncated for large values)
    version_extracted: str | None = None
    confidence: int = 50      # 0-100


@dataclass
class TechMatch:
    """A detected technology with evidence."""
    name: str
    version: str | None = None
    confidence: int = 0       # 0-100, computed from evidence
    confidence_label: str = "hint"  # confirmed/likely/possible/hint
    category: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    implied_by: str | None = None
    cves: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "category": self.category,
            "evidence": [
                {
                    "source": e.signal_type,
                    "pattern": e.pattern_id,
                    "matched": e.matched_value[:100] if e.matched_value else None,
                    "version_extracted": e.version_extracted
                }
                for e in self.evidence
            ],
            "implied_by": self.implied_by,
            "cves": self.cves
        }


@dataclass
class TechSignals:
    """Collected signals from a page for technology detection."""
    url: str
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)        # Normalized lowercase keys
    cookies: dict[str, str] = field(default_factory=dict)        # Name -> value
    html: str = ""                                                # First 100KB of HTML
    meta_tags: dict[str, str] = field(default_factory=dict)      # name -> content
    script_srcs: list[str] = field(default_factory=list)         # All <script src="...">
    link_hrefs: list[str] = field(default_factory=list)          # All <link href="...">
    js_globals: dict[str, Any] = field(default_factory=dict)     # window.* from Playwright
    dom_markers: list[str] = field(default_factory=list)         # Matched CSS selectors
    dns_cname: str | None = None                              # CNAME record
    cert_issuer: str | None = None                            # TLS cert issuer CN


# ============================================================================
# CONFIDENCE SCORING
# ============================================================================

# Weight matrix for signal types
SIGNAL_WEIGHTS = {
    "js": 100,        # Highest - direct runtime access
    "headers": 95,    # Very reliable
    "dom": 90,        # Production markers
    "meta": 85,       # Generator tags
    "scriptSrc": 80,  # CDN/bundle URLs
    "linkHref": 80,   # CSS CDN URLs
    "html": 70,       # Content patterns
    "cookies": 60,    # Can be ambiguous
    "url": 55,        # URL patterns
    "dns": 50,        # Hosting indicators
    "certIssuer": 50, # Certificate hints
    "httpx": 75,      # External tool detection
}


def get_confidence_label(score: int) -> str:
    """Convert confidence score to human-readable label."""
    if score >= 90:
        return "confirmed"
    elif score >= 70:
        return "likely"
    elif score >= 50:
        return "possible"
    else:
        return "hint"


def calculate_final_confidence(evidence: list[Evidence]) -> int:
    """Calculate final confidence from all evidence sources."""
    if not evidence:
        return 0

    # Use highest confidence evidence
    max_conf = max(e.confidence for e in evidence)

    # Bonus for multiple source types
    source_types = len(set(e.signal_type for e in evidence))
    bonus = min(15, (source_types - 1) * 5)  # +5 per additional source, max +15

    return min(100, max_conf + bonus)


# ============================================================================
# TECH MATCHER ENGINE
# ============================================================================

class TechMatcher:
    """Signature-based technology detection engine."""

    def __init__(self, signatures_path: str | None = None):
        if signatures_path is None:
            # Default path relative to this file
            signatures_path = os.path.join(
                os.path.dirname(__file__),
                "data",
                "tech_signatures.json"
            )
        self.signatures = self._load_signatures(signatures_path)
        self._compiled_patterns: dict[str, dict[str, re.Pattern]] = {}
        self._compile_patterns()

    def _load_signatures(self, path: str) -> dict[str, Any]:
        """Load signature database from JSON file."""
        try:
            with open(path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load tech signatures from {path}: {e}")
            return {"technologies": {}, "categories": {}}

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for tech_name, tech_def in self.signatures.get("technologies", {}).items():
            self._compiled_patterns[tech_name] = {}

            for signal_type in ["headers", "html", "scriptSrc", "linkHref", "url", "dns", "certIssuer", "cookies"]:
                if signal_type in tech_def:
                    for pattern_key, pattern_def in tech_def[signal_type].items():
                        if isinstance(pattern_def, dict) and "pattern" in pattern_def:
                            try:
                                regex = re.compile(pattern_def["pattern"], re.IGNORECASE)
                                self._compiled_patterns[tech_name][f"{signal_type}:{pattern_key}"] = regex
                            except re.error:
                                pass
                        else:
                            # Simple string match - compile as literal pattern
                            try:
                                regex = re.compile(re.escape(pattern_key), re.IGNORECASE)
                                self._compiled_patterns[tech_name][f"{signal_type}:{pattern_key}"] = regex
                            except re.error:
                                pass

    def _get_category(self, tech_def: dict) -> str:
        """Get category name from tech definition."""
        cats = tech_def.get("cats", [])
        if cats and len(cats) > 0:
            cat_id = str(cats[0])
            return self.signatures.get("categories", {}).get(cat_id, {}).get("name", "")
        return ""

    def _check_headers(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check header patterns against signals."""
        evidence = []
        header_patterns = tech_def.get("headers", {})

        for header_name, pattern_def in header_patterns.items():
            header_value = signals.headers.get(header_name.lower(), "")
            if not header_value:
                continue

            if isinstance(pattern_def, dict):
                pattern = pattern_def.get("pattern", "")
                confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["headers"])

                if pattern:
                    try:
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        if match:
                            version = None
                            version_group = pattern_def.get("version", "")
                            if version_group and match.groups():
                                # Extract version from capture group
                                group_num = int(version_group.replace("\\", "")) if version_group.replace("\\", "").isdigit() else 1
                                if group_num <= len(match.groups()) and match.group(group_num):
                                    version = match.group(group_num)

                            evidence.append(Evidence(
                                signal_type="headers",
                                pattern_id=header_name,
                                matched_value=header_value[:100],
                                version_extracted=version,
                                confidence=confidence
                            ))
                    except re.error:
                        pass
                else:
                    # Just presence check
                    evidence.append(Evidence(
                        signal_type="headers",
                        pattern_id=header_name,
                        matched_value=header_value[:100],
                        confidence=confidence
                    ))
            else:
                # Simple string value - just presence
                evidence.append(Evidence(
                    signal_type="headers",
                    pattern_id=header_name,
                    matched_value=header_value[:100],
                    confidence=SIGNAL_WEIGHTS["headers"]
                ))

        return evidence

    def _check_js_globals(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check JavaScript global variables against signals."""
        evidence = []
        js_patterns = tech_def.get("js", {})

        for global_name, pattern_def in js_patterns.items():
            # Check if this global exists in js_globals
            # Handle nested paths like "React.version"
            parts = global_name.split(".")
            value = signals.js_globals

            found = True
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    found = False
                    break

            if not found:
                # Also check flat keys (browser detection sends flat)
                flat_key = global_name.lower().replace(".", "_")
                alt_keys = [flat_key, global_name.lower(), global_name.split(".")[0].lower()]
                for key in alt_keys:
                    if key in signals.js_globals:
                        value = signals.js_globals[key]
                        found = True
                        break

            if not found:
                continue

            if isinstance(pattern_def, dict):
                confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["js"])
                pattern = pattern_def.get("pattern", "")

                version = None
                if pattern and isinstance(value, str):
                    try:
                        match = re.search(pattern, value)
                        if match:
                            version_group = pattern_def.get("version", "")
                            if version_group and match.groups():
                                group_num = int(version_group.replace("\\", "")) if version_group.replace("\\", "").isdigit() else 1
                                if group_num <= len(match.groups()) and match.group(group_num):
                                    version = match.group(group_num)
                    except (re.error, TypeError):
                        pass
                elif isinstance(value, str) and value and value != "detected":
                    # Value is the version directly
                    version = value

                evidence.append(Evidence(
                    signal_type="js",
                    pattern_id=global_name,
                    matched_value=str(value)[:100] if value else "present",
                    version_extracted=version,
                    confidence=confidence
                ))
            else:
                # Simple presence check
                evidence.append(Evidence(
                    signal_type="js",
                    pattern_id=global_name,
                    matched_value="present",
                    confidence=SIGNAL_WEIGHTS["js"]
                ))

        return evidence

    def _check_html(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check HTML content patterns against signals."""
        evidence = []
        html_patterns = tech_def.get("html", {})

        if not signals.html:
            return evidence

        # Limit search area for performance
        search_html = signals.html[:100000]

        for pattern_key, pattern_def in html_patterns.items():
            if isinstance(pattern_def, dict):
                pattern = pattern_def.get("pattern", pattern_key)
                confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["html"])
            else:
                pattern = pattern_key
                confidence = SIGNAL_WEIGHTS["html"] if isinstance(pattern_def, bool) else pattern_def

            try:
                match = re.search(pattern, search_html, re.IGNORECASE)
                if match:
                    version = None
                    if isinstance(pattern_def, dict):
                        version_group = pattern_def.get("version", "")
                        if version_group and match.groups():
                            group_num = int(version_group.replace("\\", "")) if version_group.replace("\\", "").isdigit() else 1
                            if group_num <= len(match.groups()) and match.group(group_num):
                                version = match.group(group_num)

                    evidence.append(Evidence(
                        signal_type="html",
                        pattern_id=pattern_key,
                        matched_value=match.group(0)[:100],
                        version_extracted=version,
                        confidence=confidence
                    ))
            except re.error:
                pass

        return evidence

    def _check_dom(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check DOM selector patterns against signals."""
        evidence = []
        dom_patterns = tech_def.get("dom", {})

        for selector, pattern_def in dom_patterns.items():
            # Check if selector was matched (passed from Playwright)
            if selector in signals.dom_markers:
                if isinstance(pattern_def, dict):
                    confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["dom"])
                else:
                    confidence = SIGNAL_WEIGHTS["dom"]

                evidence.append(Evidence(
                    signal_type="dom",
                    pattern_id=selector,
                    matched_value="selector matched",
                    confidence=confidence
                ))

        return evidence

    def _check_meta(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check meta tag patterns against signals."""
        evidence = []
        meta_patterns = tech_def.get("meta", {})

        for meta_name, pattern_def in meta_patterns.items():
            meta_value = signals.meta_tags.get(meta_name.lower(), "")
            if not meta_value:
                continue

            if isinstance(pattern_def, dict):
                pattern = pattern_def.get("pattern", "")
                confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["meta"])

                if pattern:
                    try:
                        match = re.search(pattern, meta_value, re.IGNORECASE)
                        if match:
                            version = None
                            version_group = pattern_def.get("version", "")
                            if version_group and match.groups():
                                group_num = int(version_group.replace("\\", "")) if version_group.replace("\\", "").isdigit() else 1
                                if group_num <= len(match.groups()) and match.group(group_num):
                                    version = match.group(group_num)

                            evidence.append(Evidence(
                                signal_type="meta",
                                pattern_id=meta_name,
                                matched_value=meta_value[:100],
                                version_extracted=version,
                                confidence=confidence
                            ))
                    except re.error:
                        pass
                else:
                    evidence.append(Evidence(
                        signal_type="meta",
                        pattern_id=meta_name,
                        matched_value=meta_value[:100],
                        confidence=confidence
                    ))

        return evidence

    def _check_script_srcs(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check script src URL patterns against signals."""
        evidence = []
        src_patterns = tech_def.get("scriptSrc", {})

        for pattern_key, pattern_def in src_patterns.items():
            if isinstance(pattern_def, dict):
                pattern = pattern_def.get("pattern", pattern_key)
                confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["scriptSrc"])
            else:
                pattern = pattern_key
                confidence = SIGNAL_WEIGHTS["scriptSrc"]

            for src in signals.script_srcs:
                try:
                    match = re.search(pattern, src, re.IGNORECASE)
                    if match:
                        version = None
                        if isinstance(pattern_def, dict):
                            version_group = pattern_def.get("version", "")
                            if version_group and match.groups():
                                group_num = int(version_group.replace("\\", "")) if version_group.replace("\\", "").isdigit() else 1
                                if group_num <= len(match.groups()) and match.group(group_num):
                                    version = match.group(group_num)

                        evidence.append(Evidence(
                            signal_type="scriptSrc",
                            pattern_id=pattern_key,
                            matched_value=src[:100],
                            version_extracted=version,
                            confidence=confidence
                        ))
                        break  # One match per pattern is enough
                except re.error:
                    pass

        return evidence

    def _check_cookies(self, tech_def: dict, signals: TechSignals) -> list[Evidence]:
        """Check cookie patterns against signals."""
        evidence = []
        cookie_patterns = tech_def.get("cookies", {})

        for cookie_name, pattern_def in cookie_patterns.items():
            cookie_value = signals.cookies.get(cookie_name, "")

            if cookie_value or cookie_name in signals.cookies:
                if isinstance(pattern_def, dict):
                    confidence = pattern_def.get("confidence", SIGNAL_WEIGHTS["cookies"])
                else:
                    confidence = SIGNAL_WEIGHTS["cookies"]

                evidence.append(Evidence(
                    signal_type="cookies",
                    pattern_id=cookie_name,
                    matched_value=cookie_value[:50] if cookie_value else "present",
                    confidence=confidence
                ))

        return evidence

    def _match_tech(self, name: str, definition: dict, signals: TechSignals) -> TechMatch | None:
        """Match a single technology definition against signals."""
        evidence = []

        # Check each signal type
        evidence.extend(self._check_headers(definition, signals))
        evidence.extend(self._check_js_globals(definition, signals))
        evidence.extend(self._check_html(definition, signals))
        evidence.extend(self._check_dom(definition, signals))
        evidence.extend(self._check_meta(definition, signals))
        evidence.extend(self._check_script_srcs(definition, signals))
        evidence.extend(self._check_cookies(definition, signals))

        if not evidence:
            return None

        min_evidence = definition.get("min_evidence")
        if isinstance(min_evidence, int) and min_evidence > 1 and len(evidence) < min_evidence:
            return None

        # Calculate confidence
        confidence = calculate_final_confidence(evidence)

        # Extract best version
        version = None
        for e in sorted(evidence, key=lambda x: x.confidence, reverse=True):
            if e.version_extracted:
                version = e.version_extracted
                break

        # Get CVEs if version is known
        cves = []
        if version:
            cve_check = definition.get("cve_check", {})
            if cve_check:
                below = cve_check.get("below", "")
                if below and self._version_below(version, below):
                    cves = cve_check.get("cves", [])

        return TechMatch(
            name=name,
            version=version,
            confidence=confidence,
            confidence_label=get_confidence_label(confidence),
            category=self._get_category(definition),
            evidence=evidence,
            cves=cves
        )

    def _version_below(self, version: str, threshold: str) -> bool:
        """Check if version is below threshold (simple comparison)."""
        try:
            v_parts = [int(p) for p in version.split(".")[:3]]
            t_parts = [int(p) for p in threshold.split(".")[:3]]

            # Pad to same length
            while len(v_parts) < 3:
                v_parts.append(0)
            while len(t_parts) < 3:
                t_parts.append(0)

            return v_parts < t_parts
        except (ValueError, AttributeError):
            return False

    def match(self, signals: TechSignals) -> list[TechMatch]:
        """Match all signatures against collected signals."""
        matches = []

        for tech_name, tech_def in self.signatures.get("technologies", {}).items():
            match = self._match_tech(tech_name, tech_def, signals)
            if match:
                matches.append(match)

        return matches

    def apply_implications(self, matches: list[TechMatch]) -> list[TechMatch]:
        """Add implied technologies and remove excluded ones."""
        result = list(matches)
        detected_names = {m.name for m in matches}

        # Add implied technologies
        for match in matches:
            tech_def = self.signatures.get("technologies", {}).get(match.name, {})
            for implied in tech_def.get("implies", []):
                if implied not in detected_names:
                    # Check if implied tech exists in signatures
                    implied_def = self.signatures.get("technologies", {}).get(implied, {})
                    result.append(TechMatch(
                        name=implied,
                        version=None,
                        confidence=max(50, match.confidence - 10),
                        confidence_label=get_confidence_label(max(50, match.confidence - 10)),
                        category=self._get_category(implied_def) if implied_def else "",
                        evidence=[],
                        implied_by=match.name
                    ))
                    detected_names.add(implied)

        # Remove excluded technologies
        excluded: set[str] = set()
        for match in matches:
            tech_def = self.signatures.get("technologies", {}).get(match.name, {})
            excluded.update(tech_def.get("excludes", []))

        return [m for m in result if m.name not in excluded]


# ============================================================================
# SIGNAL COLLECTION
# ============================================================================

def extract_meta_tags(html: str) -> dict[str, str]:
    """Extract meta tag name->content pairs from HTML."""
    meta_tags = {}
    # Match <meta name="..." content="..."> or <meta property="..." content="...">
    pattern = r'<meta\s+(?:name|property)=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']'
    for match in re.finditer(pattern, html[:50000], re.IGNORECASE):
        meta_tags[match.group(1).lower()] = match.group(2)

    # Also match reverse order: content first, then name
    pattern2 = r'<meta\s+content=["\']([^"\']*)["\'][^>]*(?:name|property)=["\']([^"\']+)["\']'
    for match in re.finditer(pattern2, html[:50000], re.IGNORECASE):
        meta_tags[match.group(2).lower()] = match.group(1)

    return meta_tags


def extract_script_srcs(html: str) -> list[str]:
    """Extract all script src URLs from HTML."""
    pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    return re.findall(pattern, html[:100000], re.IGNORECASE)


def extract_link_hrefs(html: str) -> list[str]:
    """Extract all link href URLs from HTML."""
    pattern = r'<link[^>]+href=["\']([^"\']+)["\']'
    return re.findall(pattern, html[:100000], re.IGNORECASE)


async def collect_signals(
    url: str,
    browser_res: dict[str, Any],
    headers: dict[str, Any],
    html_content: str | None,
    dns_result: dict[str, Any] | None = None,
    tls_result: dict[str, Any] | None = None,
    status_code: int = 200
) -> TechSignals:
    """Aggregate signals from all sources into unified structure."""

    # Normalize headers to lowercase keys, single values
    normalized_headers = {}
    for key, value in headers.items():
        lower_key = key.lower()
        if isinstance(value, list):
            normalized_headers[lower_key] = value[0] if value else ""
        else:
            normalized_headers[lower_key] = str(value) if value else ""

    # Extract browser data
    browser_versions = browser_res.get("browser_versions", {})
    tech_stack = browser_res.get("tech_stack", [])

    # Build js_globals from browser_versions
    js_globals = dict(browser_versions)

    # Add tech_stack items as presence markers
    for tech in tech_stack:
        key = tech.lower().replace(" ", "_").replace(".", "_")
        if key not in js_globals:
            js_globals[key] = "detected"

    # Extract from HTML
    html = html_content[:100000] if html_content else ""
    meta_tags = extract_meta_tags(html) if html else {}
    script_srcs = extract_script_srcs(html) if html else []
    link_hrefs = extract_link_hrefs(html) if html else []

    # Extract DNS CNAME
    dns_cname = None
    if dns_result:
        cname = dns_result.get("cname") or dns_result.get("CNAME")
        if isinstance(cname, list) and cname:
            dns_cname = cname[0]
        elif isinstance(cname, str):
            dns_cname = cname

    # Extract TLS cert issuer
    cert_issuer = None
    if tls_result and "certificate" in tls_result:
        cert = tls_result["certificate"]
        if isinstance(cert, dict):
            issuer = cert.get("issuer", "")
            if issuer:
                cert_issuer = issuer

    return TechSignals(
        url=url,
        status_code=status_code,
        headers=normalized_headers,
        cookies={},  # TODO: Extract from browser_res if available
        html=html,
        meta_tags=meta_tags,
        script_srcs=script_srcs,
        link_hrefs=link_hrefs,
        js_globals=js_globals,
        dom_markers=[],  # TODO: Pass from Playwright if available
        dns_cname=dns_cname,
        cert_issuer=cert_issuer
    )


# ============================================================================
# LEGACY MERGER
# ============================================================================

# Mapping from browser_versions keys to canonical tech names
TECH_NAME_MAP = {
    "react": "React",
    "nextjs": "Next.js",
    "next": "Next.js",
    "vue": "Vue.js",
    "angular": "Angular",
    "angularjs": "AngularJS",
    "jquery": "jQuery",
    "lodash": "Lodash",
    "moment": "Moment.js",
    "axios": "Axios",
    "bootstrap": "Bootstrap",
    "d3": "D3.js",
    "chartjs": "Chart.js",
    "threejs": "Three.js",
    "firebase": "Firebase",
    "socketio": "Socket.io",
    "svelte": "Svelte",
    "gatsby": "Gatsby",
    "nuxt": "Nuxt.js",
    "htmx": "htmx",
    "alpine": "Alpine.js",
}


def normalize_tech_name(key: str) -> str:
    """Normalize browser_versions key to canonical tech name."""
    return TECH_NAME_MAP.get(key.lower(), key)


def merge_with_legacy(
    engine_matches: list[TechMatch],
    httpx_techs: list[str],
    browser_versions: dict[str, str],
    server_versions: dict[str, Any] | None = None
) -> list[TechMatch]:
    """Merge signature engine results with legacy detection sources."""

    by_name: dict[str, TechMatch] = {m.name: m for m in engine_matches}

    # Add httpx techs not already matched
    for tech in httpx_techs:
        if tech not in by_name:
            by_name[tech] = TechMatch(
                name=tech,
                version=None,
                confidence=75,
                confidence_label="likely",
                category="",
                evidence=[Evidence(
                    signal_type="httpx",
                    pattern_id="tech_detect",
                    matched_value=tech,
                    confidence=75
                )]
            )

    # Upgrade versions from browser detection
    for tech_key, version in browser_versions.items():
        tech_name = normalize_tech_name(tech_key)
        if tech_name in by_name:
            match = by_name[tech_name]
            if version and version != "detected" and (not match.version or match.version == "detected"):
                match.version = version
                match.evidence.append(Evidence(
                    signal_type="js",
                    pattern_id="window.*",
                    matched_value=version,
                    version_extracted=version,
                    confidence=100
                ))
                # Recalculate confidence
                match.confidence = calculate_final_confidence(match.evidence)
                match.confidence_label = get_confidence_label(match.confidence)
        else:
            # Add new tech from browser detection
            by_name[tech_name] = TechMatch(
                name=tech_name,
                version=version if version != "detected" else None,
                confidence=95,
                confidence_label="confirmed",
                category="",
                evidence=[Evidence(
                    signal_type="js",
                    pattern_id="window.*",
                    matched_value=version if version else "detected",
                    version_extracted=version if version != "detected" else None,
                    confidence=95
                )]
            )

    # Merge server versions
    if server_versions:
        for category, info in server_versions.items():
            if info and isinstance(info, dict) and info.get("name"):
                name = info["name"]
                if name not in by_name:
                    by_name[name] = TechMatch(
                        name=name,
                        version=info.get("version"),
                        confidence=90,
                        confidence_label="confirmed",
                        category=category,
                        evidence=[Evidence(
                            signal_type="headers",
                            pattern_id=category,
                            matched_value=info.get("raw", name),
                            version_extracted=info.get("version"),
                            confidence=90
                        )]
                    )

    return list(by_name.values())


# ============================================================================
# FALSE-POSITIVE GUARDRAILS
# ============================================================================

def should_skip_page(status_code: int, content: str) -> bool:
    """Check if page should be skipped for pattern matching (error pages)."""
    if status_code >= 400:
        return True

    # Check for common error page indicators
    error_patterns = [
        r"<title>\s*404",
        r"<title>\s*Page Not Found",
        r"<title>\s*Error",
        r"<h1>\s*404",
        r"<h1>\s*Not Found",
    ]

    for pattern in error_patterns:
        if re.search(pattern, content[:5000], re.IGNORECASE):
            return True

    return False


def validate_matches(matches: list[TechMatch], signals: TechSignals) -> list[TechMatch]:
    """Apply false-positive guardrails to matches."""
    result = []

    for match in matches:
        # Downgrade confidence on error pages
        if signals.status_code >= 400:
            match.confidence = min(match.confidence, 30)
            match.confidence_label = "hint"

        # Require multiple evidence sources for "confirmed" status
        if match.confidence >= 90 and len(match.evidence) < 2 and not match.implied_by:
            match.confidence = min(match.confidence, 85)
            match.confidence_label = "likely"

        result.append(match)

    return result


# ============================================================================
# MAIN API
# ============================================================================

async def discover_technologies(
    url: str,
    browser_res: dict[str, Any],
    headers: dict[str, Any],
    html_content: str | None,
    dns_result: dict[str, Any] | None = None,
    tls_result: dict[str, Any] | None = None,
    httpx_techs: list[str] | None = None,
    server_versions: dict[str, Any] | None = None,
    status_code: int = 200
) -> dict[str, Any]:
    """
    Main entry point for technology discovery.

    Returns:
        {
            "items": [TechMatch.to_dict(), ...],
            "total": int,
            "by_category": {"category": ["tech1", "tech2"], ...}
        }
    """

    # Skip if error page
    if should_skip_page(status_code, html_content or ""):
        return {
            "items": [],
            "total": 0,
            "by_category": {},
            "skipped": True,
            "skip_reason": "Error page detected"
        }

    # Collect signals
    signals = await collect_signals(
        url=url,
        browser_res=browser_res,
        headers=headers,
        html_content=html_content,
        dns_result=dns_result,
        tls_result=tls_result,
        status_code=status_code
    )

    # Initialize matcher
    matcher = TechMatcher()

    # Match technologies
    matches = matcher.match(signals)

    # Apply implications
    matches = matcher.apply_implications(matches)

    # Merge with legacy sources
    matches = merge_with_legacy(
        engine_matches=matches,
        httpx_techs=httpx_techs or [],
        browser_versions=browser_res.get("browser_versions", {}),
        server_versions=server_versions
    )

    # Validate and apply guardrails
    matches = validate_matches(matches, signals)

    # Sort by confidence (highest first)
    matches.sort(key=lambda m: (-m.confidence, m.name))

    # Build category index
    by_category: dict[str, list[str]] = {}
    for match in matches:
        if match.category:
            if match.category not in by_category:
                by_category[match.category] = []
            by_category[match.category].append(match.name)

    return {
        "items": [m.to_dict() for m in matches],
        "total": len(matches),
        "by_category": by_category
    }
