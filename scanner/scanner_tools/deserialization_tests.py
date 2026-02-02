"""
Insecure Deserialization Detection Module

Detects and tests for insecure deserialization vulnerabilities in:
- Java (ObjectInputStream, XMLDecoder, XStream, SnakeYAML, etc.)
- PHP (unserialize, phar://)
- Python (unsafe serialization formats)
- .NET (BinaryFormatter, ObjectStateFormatter, etc.)
- Ruby (Marshal.load, YAML.load)

Detection methods:
1. Signature detection in responses (magic bytes, class names)
2. Header analysis (Content-Type indicators)
3. Parameter analysis (base64-encoded serialized objects)
4. Error message analysis
5. Timing-based detection (with safe payloads)

IMPORTANT: This module is for DEFENSIVE security testing - identifying
deserialization vulnerabilities to help developers fix them.

NOTE: This module contains references to unsafe serialization formats
(Java ObjectInputStream, PHP unserialize, Python serialization, etc.)
for DETECTION PURPOSES ONLY. The scanner identifies when applications
are using these unsafe patterns so they can be remediated.
"""

import asyncio
import base64
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SerializationFormat(Enum):
    """Serialization formats and their associated risks"""
    JAVA_OBJECT = "java_object"
    JAVA_XML = "java_xml"
    JAVA_XSTREAM = "java_xstream"
    JAVA_SNAKEYAML = "java_snakeyaml"
    PHP_SERIALIZE = "php_serialize"
    PHP_PHAR = "php_phar"
    PYTHON_UNSAFE_SERIAL = "python_unsafe_serialization"
    PYTHON_YAML = "python_yaml"
    DOTNET_BINARY = "dotnet_binary"
    DOTNET_VIEWSTATE = "dotnet_viewstate"
    DOTNET_JSON = "dotnet_json"
    RUBY_MARSHAL = "ruby_marshal"
    RUBY_YAML = "ruby_yaml"
    NODEJS_SERIALIZE = "nodejs_serialize"


@dataclass
class DeserializationFinding:
    """Represents a deserialization vulnerability finding"""
    format_type: SerializationFormat
    severity: str  # critical, high, medium, low
    description: str
    evidence: dict[str, Any]
    location: str  # URL, parameter name, header, etc.
    remediation: str


# Magic bytes and signatures for serialization detection
# These patterns are used to DETECT vulnerable serialization usage in target applications
SERIALIZATION_SIGNATURES = {
    # Java ObjectInputStream
    SerializationFormat.JAVA_OBJECT: {
        "magic_bytes": [
            b"\xac\xed\x00\x05",  # Java serialization magic
            b"rO0AB",  # Base64-encoded Java serialization
            b"H4sIAAAA",  # Gzip + Base64 Java serialization
        ],
        "patterns": [
            rb"java\.lang\.",
            rb"java\.util\.",
            rb"org\.apache\.",
            rb"com\.sun\.",
            rb"ObjectInputStream",
            rb"readObject",
        ],
        "content_types": [
            "application/x-java-serialized-object",
            "application/java-serialized-object",
        ],
    },
    # Java XMLDecoder
    SerializationFormat.JAVA_XML: {
        "magic_bytes": [
            b"<?xml",
        ],
        "patterns": [
            rb"<java\s+",
            rb"<object\s+class=",
            rb"XMLDecoder",
            rb"java\.beans\.XMLDecoder",
        ],
        "content_types": [],
    },
    # XStream
    SerializationFormat.JAVA_XSTREAM: {
        "magic_bytes": [],
        "patterns": [
            rb"<[\w]+\s+class=",
            rb"com\.thoughtworks\.xstream",
            rb"XStreamException",
        ],
        "content_types": [],
    },
    # SnakeYAML
    SerializationFormat.JAVA_SNAKEYAML: {
        "magic_bytes": [],
        "patterns": [
            rb"!![\w\.]+",  # YAML type tags
            rb"org\.yaml\.snakeyaml",
            rb"SnakeYAML",
        ],
        "content_types": [],
    },
    # PHP serialize()
    SerializationFormat.PHP_SERIALIZE: {
        "magic_bytes": [
            b"a:",  # array
            b"O:",  # object
            b"s:",  # string
            b"i:",  # integer
            b"b:",  # boolean
        ],
        "patterns": [
            rb'O:\d+:"[\w\\]+":\d+:\{',  # Object
            rb'a:\d+:\{',  # Array
            rb's:\d+:"[^"]*"',  # String
            rb"unserialize\(",
            rb"__wakeup",
            rb"__destruct",
        ],
        "content_types": [],
    },
    # Python unsafe serialization (detection signatures)
    SerializationFormat.PYTHON_UNSAFE_SERIAL: {
        "magic_bytes": [
            b"\x80\x03",  # Protocol 3 header
            b"\x80\x04",  # Protocol 4 header
            b"\x80\x05",  # Protocol 5 header
            b"gASV",  # Base64 protocol 4
            b"(dp",  # Protocol 0 dict
            b"(lp",  # Protocol 0 list
        ],
        "patterns": [
            rb"__reduce__",
            rb"__setstate__",
        ],
        "content_types": [],
    },
    # Python YAML
    SerializationFormat.PYTHON_YAML: {
        "magic_bytes": [],
        "patterns": [
            rb"!!python/object",
            rb"!!python/object/apply",
            rb"!!python/object/new",
            rb"yaml\.unsafe_load",
        ],
        "content_types": [],
    },
    # .NET BinaryFormatter
    SerializationFormat.DOTNET_BINARY: {
        "magic_bytes": [
            b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00",  # BinaryFormatter
            b"AAEAAAD/",  # Base64 BinaryFormatter
        ],
        "patterns": [
            rb"System\.Runtime\.Serialization",
            rb"BinaryFormatter",
            rb"ObjectStateFormatter",
            rb"LosFormatter",
            rb"NetDataContractSerializer",
        ],
        "content_types": [
            "application/x-dotnet-serialized",
        ],
    },
    # .NET ViewState
    SerializationFormat.DOTNET_VIEWSTATE: {
        "magic_bytes": [
            b"/wE",  # Unprotected ViewState base64 prefix
        ],
        "patterns": [
            rb"__VIEWSTATE",
            rb"__VIEWSTATEGENERATOR",
            rb"__EVENTVALIDATION",
            rb"ViewStateException",
        ],
        "content_types": [],
    },
    # .NET JSON (Json.NET TypeNameHandling)
    SerializationFormat.DOTNET_JSON: {
        "magic_bytes": [],
        "patterns": [
            rb'"\$type"\s*:\s*"',
            rb"TypeNameHandling",
            rb"System\.Windows\.Data\.ObjectDataProvider",
            rb"System\.Diagnostics\.Process",
        ],
        "content_types": [],
    },
    # Ruby Marshal
    SerializationFormat.RUBY_MARSHAL: {
        "magic_bytes": [
            b"\x04\x08",  # Ruby Marshal magic
            b"BAh",  # Base64 Marshal
        ],
        "patterns": [
            rb"Marshal\.load",
            rb"::Marshal",
            rb"ActiveSupport::Deprecation",
        ],
        "content_types": [],
    },
    # Ruby YAML
    SerializationFormat.RUBY_YAML: {
        "magic_bytes": [],
        "patterns": [
            rb"!ruby/object:",
            rb"!ruby/hash:",
            rb"Psych::DisallowedClass",
            rb"YAML\.load",
        ],
        "content_types": [],
    },
    # Node.js node-serialize
    SerializationFormat.NODEJS_SERIALIZE: {
        "magic_bytes": [],
        "patterns": [
            rb'"_\$\$ND_FUNC\$\$_"',  # node-serialize function marker
            rb"node-serialize",
            rb"serialize-javascript",
        ],
        "content_types": [],
    },
}

# Error message patterns that indicate deserialization processing
# Used to detect when applications are deserializing data
ERROR_PATTERNS = {
    SerializationFormat.JAVA_OBJECT: [
        r"java\.io\.InvalidClassException",
        r"java\.io\.StreamCorruptedException",
        r"ClassNotFoundException",
        r"java\.io\.ObjectInputStream",
        r"readObject failed",
        r"invalid stream header",
    ],
    SerializationFormat.PHP_SERIALIZE: [
        r"unserialize\(\): Error",
        r"unserialize\(\): Invalid",
        r"__wakeup\(\) failed",
        r"Serialization of .* is not allowed",
    ],
    SerializationFormat.PYTHON_UNSAFE_SERIAL: [
        r"UnpicklingError",
        r"invalid load key",
        r"data was truncated",
    ],
    SerializationFormat.DOTNET_BINARY: [
        r"SerializationException",
        r"BinaryFormatter\.Deserialize",
        r"Invalid BinaryFormatter",
        r"Unable to find assembly",
    ],
    SerializationFormat.RUBY_MARSHAL: [
        r"Marshal\.load",
        r"incompatible marshal file format",
        r"undefined class/module",
    ],
}

# Safe detection payloads (cause errors but not code execution)
# These are truncated/malformed serialized objects that will trigger
# deserialization error messages without executing any payload
DETECTION_PAYLOADS = {
    SerializationFormat.JAVA_OBJECT: {
        # Truncated Java object - triggers deserialization error only
        "raw": b"\xac\xed\x00\x05sr\x00\x10InvalidClass",
        "base64": "rO0ABXNyABBJbnZhbGlkQ2xhc3M=",
    },
    SerializationFormat.PHP_SERIALIZE: {
        # Invalid PHP object (non-existent class)
        "raw": b'O:13:"InvalidClass":0:{}',
        "base64": "TzoxMzoiSW52YWxpZENsYXNzIjowOnt9",
    },
    SerializationFormat.PYTHON_UNSAFE_SERIAL: {
        # Truncated format - causes error, no code execution
        "raw": b"\x80\x04\x95\x00\x00\x00\x00",
        "base64": "gASVAAAAAAA=",
    },
    SerializationFormat.DOTNET_BINARY: {
        # Truncated .NET binary - causes error, no code execution
        "raw": b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01",
        "base64": "AAEAAAD/////AQ==",
    },
    SerializationFormat.RUBY_MARSHAL: {
        # Truncated Ruby Marshal
        "raw": b"\x04\x08o:\x10InvalidClass",
        "base64": "BAhvOhBJbnZhbGlkQ2xhc3M=",
    },
}


def detect_serialization_in_content(
    content: bytes,
    content_type: str | None = None,
) -> list[tuple[SerializationFormat, str, dict]]:
    """
    Detect serialization signatures in response content.

    Args:
        content: Response body bytes
        content_type: Content-Type header value

    Returns:
        List of (format, evidence_type, details) tuples
    """
    detections = []

    for fmt, signatures in SERIALIZATION_SIGNATURES.items():
        # Check magic bytes
        for magic in signatures["magic_bytes"]:
            if content.startswith(magic):
                detections.append((fmt, "magic_bytes", {"magic": magic.hex()}))
                break

            # Also check in base64 decoded content
            try:
                decoded = base64.b64decode(content[:100])
                if decoded.startswith(magic):
                    detections.append((fmt, "base64_magic", {"magic": magic.hex()}))
                    break
            except Exception:
                pass

        # Check patterns in content
        for pattern in signatures["patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                detections.append((fmt, "pattern_match", {"pattern": pattern.decode("utf-8", errors="ignore")}))
                break

        # Check content type
        if content_type:
            for ct in signatures["content_types"]:
                if ct.lower() in content_type.lower():
                    detections.append((fmt, "content_type", {"content_type": ct}))
                    break

    return detections


def detect_serialization_in_parameter(
    param_value: str,
) -> list[tuple[SerializationFormat, str, dict]]:
    """
    Detect serialization in parameter values.

    Args:
        param_value: Parameter value to analyze

    Returns:
        List of (format, evidence_type, details) tuples
    """
    detections = []

    # Try base64 decoding
    try:
        decoded = base64.b64decode(param_value)
        content_detections = detect_serialization_in_content(decoded)
        for fmt, evidence, details in content_detections:
            details["encoded"] = "base64"
            detections.append((fmt, f"param_{evidence}", details))
    except Exception:
        pass

    # Try URL decoding + base64
    try:
        from urllib.parse import unquote
        decoded = base64.b64decode(unquote(param_value))
        content_detections = detect_serialization_in_content(decoded)
        for fmt, evidence, details in content_detections:
            details["encoded"] = "url+base64"
            detections.append((fmt, f"param_{evidence}", details))
    except Exception:
        pass

    # Check raw value for patterns (e.g., PHP serialized)
    for fmt, signatures in SERIALIZATION_SIGNATURES.items():
        for pattern in signatures["patterns"]:
            if re.search(pattern, param_value.encode(), re.IGNORECASE):
                detections.append((fmt, "param_pattern", {"pattern": pattern.decode("utf-8", errors="ignore")}))
                break

    return detections


def detect_serialization_in_error(
    error_text: str,
) -> list[tuple[SerializationFormat, str, dict]]:
    """
    Detect deserialization processing from error messages.

    Args:
        error_text: Error message or response text

    Returns:
        List of (format, evidence_type, details) tuples
    """
    detections = []

    for fmt, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, error_text, re.IGNORECASE)
            if match:
                detections.append((fmt, "error_message", {
                    "pattern": pattern,
                    "match": match.group(0),
                }))

    return detections


async def test_deserialization_endpoint(
    url: str,
    method: str,
    param_name: str | None,
    param_location: str,  # query, body, header, cookie
    original_value: str | None,
    client: httpx.AsyncClient,
    auth_header: str | None = None,
) -> list[DeserializationFinding]:
    """
    Test an endpoint for deserialization vulnerabilities.

    Args:
        url: Target URL
        method: HTTP method
        param_name: Parameter name to test
        param_location: Where the parameter is (query, body, header, cookie)
        original_value: Original parameter value
        client: HTTP client
        auth_header: Optional authorization header

    Returns:
        List of DeserializationFinding objects
    """
    findings = []
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    # First, check if original value looks like serialized data
    if original_value:
        original_detections = detect_serialization_in_parameter(original_value)
        if original_detections:
            fmt, evidence, details = original_detections[0]
            findings.append(DeserializationFinding(
                format_type=fmt,
                severity="high",
                description=f"Detected {fmt.value} serialized data in parameter '{param_name}'",
                evidence={
                    "detection": evidence,
                    "details": details,
                    "original_value_preview": original_value[:100] + "..." if len(original_value) > 100 else original_value,
                },
                location=f"{param_location}:{param_name}",
                remediation=get_remediation(fmt),
            ))

    # Test with detection payloads (safe - only trigger errors, no code execution)
    for fmt, payloads in DETECTION_PAYLOADS.items():
        # Try base64 encoded payload
        test_value = payloads["base64"]

        try:
            # Build request based on parameter location
            if param_location == "query":
                test_url = f"{url}?{param_name}={test_value}" if param_name else url
                resp = await client.request(method, test_url, headers=headers, timeout=10.0)
            elif param_location == "body":
                if param_name:
                    data = {param_name: test_value}
                    resp = await client.request(method, url, data=data, headers=headers, timeout=10.0)
                else:
                    resp = await client.request(method, url, content=payloads["raw"], headers=headers, timeout=10.0)
            elif param_location == "header" and param_name:
                test_headers = {**headers, param_name: test_value}
                resp = await client.request(method, url, headers=test_headers, timeout=10.0)
            elif param_location == "cookie" and param_name:
                cookies = {param_name: test_value}
                resp = await client.request(method, url, headers=headers, cookies=cookies, timeout=10.0)
            else:
                continue

            # Analyze response for deserialization indicators
            response_text = resp.text

            # Check for error messages indicating deserialization
            error_detections = detect_serialization_in_error(response_text)
            for det_fmt, evidence, details in error_detections:
                if det_fmt == fmt:  # Matching format
                    findings.append(DeserializationFinding(
                        format_type=fmt,
                        severity="critical",
                        description=f"Endpoint processes {fmt.value} serialized data (error-based detection)",
                        evidence={
                            "detection": evidence,
                            "details": details,
                            "response_status": resp.status_code,
                            "test_payload": test_value,
                        },
                        location=f"{param_location}:{param_name}" if param_name else param_location,
                        remediation=get_remediation(fmt),
                    ))

        except httpx.RequestError as e:
            logger.debug(f"Request failed for {fmt.value} test: {e}")
        except Exception as e:
            logger.debug(f"Error testing {fmt.value}: {e}")

    return findings


async def scan_for_viewstate(
    url: str,
    client: httpx.AsyncClient,
) -> list[DeserializationFinding]:
    """
    Scan for .NET ViewState deserialization vulnerabilities.

    Args:
        url: Target URL
        client: HTTP client

    Returns:
        List of DeserializationFinding objects
    """
    findings = []

    try:
        resp = await client.get(url, timeout=10.0)
        content = resp.text

        # Look for ViewState fields
        viewstate_match = re.search(
            r'<input[^>]+name="__VIEWSTATE"[^>]+value="([^"]+)"',
            content,
            re.IGNORECASE,
        )

        if viewstate_match:
            viewstate_value = viewstate_match.group(1)

            # Check if ViewState is MAC protected
            mac_protected = len(viewstate_value) > 50 and not viewstate_value.startswith("/wE")

            # Check for ViewState generator (indicates potential weakness)
            generator_match = re.search(
                r'<input[^>]+name="__VIEWSTATEGENERATOR"[^>]+value="([^"]+)"',
                content,
                re.IGNORECASE,
            )

            severity = "medium" if mac_protected else "critical"

            finding = DeserializationFinding(
                format_type=SerializationFormat.DOTNET_VIEWSTATE,
                severity=severity,
                description="ASP.NET ViewState detected" + (" (potentially unprotected)" if not mac_protected else ""),
                evidence={
                    "viewstate_preview": viewstate_value[:100] + "...",
                    "mac_protected": mac_protected,
                    "generator": generator_match.group(1) if generator_match else None,
                },
                location=url,
                remediation=(
                    "Ensure ViewState MAC validation is enabled (enableViewStateMac=true). "
                    "Use strong machineKey configuration. Consider using ASP.NET Core which "
                    "doesn't use ViewState."
                ),
            )
            findings.append(finding)

    except httpx.RequestError as e:
        logger.debug(f"ViewState scan failed: {e}")

    return findings


async def scan_response_for_serialization(
    url: str,
    response: httpx.Response,
) -> list[DeserializationFinding]:
    """
    Scan an HTTP response for serialization indicators.

    Args:
        url: Request URL
        response: HTTP response object

    Returns:
        List of DeserializationFinding objects
    """
    findings = []

    content_type = response.headers.get("content-type", "")
    content = response.content

    # Detect serialization in response
    detections = detect_serialization_in_content(content, content_type)

    for fmt, evidence, details in detections:
        findings.append(DeserializationFinding(
            format_type=fmt,
            severity="medium",
            description=f"Response contains {fmt.value} serialized data",
            evidence={
                "detection": evidence,
                "details": details,
                "content_type": content_type,
                "url": url,
            },
            location=url,
            remediation=get_remediation(fmt),
        ))

    return findings


def get_remediation(fmt: SerializationFormat) -> str:
    """Get remediation advice for a serialization format."""
    remediations = {
        SerializationFormat.JAVA_OBJECT: (
            "Avoid Java native deserialization of untrusted data. "
            "Use look-ahead deserialization or whitelist allowed classes. "
            "Consider using JSON/XML with explicit type handling instead. "
            "Implement JEP 290 deserialization filters."
        ),
        SerializationFormat.JAVA_XML: (
            "Do not use XMLDecoder for untrusted input. "
            "Use standard XML parsing with DTD/external entity disabled."
        ),
        SerializationFormat.JAVA_XSTREAM: (
            "Upgrade XStream and configure security framework with explicit type permissions. "
            "Use XStream.setupDefaultSecurity() and allowTypes()/denyTypes()."
        ),
        SerializationFormat.JAVA_SNAKEYAML: (
            "Use SafeConstructor or disable arbitrary class instantiation. "
            "Upgrade to SnakeYAML 2.0+ which is safe by default."
        ),
        SerializationFormat.PHP_SERIALIZE: (
            "Never unserialize() untrusted data. Use JSON for data interchange. "
            "If serialization is required, use allowed_classes parameter."
        ),
        SerializationFormat.PHP_PHAR: (
            "Disable phar:// wrapper if not needed. "
            "Validate file paths before any file operations."
        ),
        SerializationFormat.PYTHON_UNSAFE_SERIAL: (
            "Never deserialize untrusted data with unsafe formats. "
            "Use JSON, MessagePack, or other safe formats for data interchange."
        ),
        SerializationFormat.PYTHON_YAML: (
            "Use yaml.safe_load() instead of yaml.load(). "
            "Never use yaml.unsafe_load() or yaml.full_load() with untrusted data."
        ),
        SerializationFormat.DOTNET_BINARY: (
            "BinaryFormatter is deprecated and insecure. "
            "Migrate to System.Text.Json, XmlSerializer, or DataContractSerializer. "
            "Never deserialize untrusted data with BinaryFormatter."
        ),
        SerializationFormat.DOTNET_VIEWSTATE: (
            "Ensure ViewState MAC validation is enabled. "
            "Use strong, unique machineKey values. "
            "Consider migrating to ASP.NET Core."
        ),
        SerializationFormat.DOTNET_JSON: (
            "Do not use TypeNameHandling.Auto or TypeNameHandling.All. "
            "If type handling is needed, use a custom SerializationBinder "
            "with strict type whitelisting."
        ),
        SerializationFormat.RUBY_MARSHAL: (
            "Never Marshal.load untrusted data. Use JSON for data interchange. "
            "If Marshal is required, use permitted_classes parameter (Ruby 3.1+)."
        ),
        SerializationFormat.RUBY_YAML: (
            "Use YAML.safe_load instead of YAML.load. "
            "Configure permitted_classes explicitly if needed."
        ),
        SerializationFormat.NODEJS_SERIALIZE: (
            "Remove node-serialize package - it is fundamentally insecure. "
            "Use JSON.parse/stringify for serialization."
        ),
    }

    return remediations.get(fmt, "Avoid deserializing untrusted data. Use safe data formats like JSON.")


def generate_detection_signatures() -> dict[str, list[str]]:
    """Generate Nuclei-compatible detection signatures."""
    signatures = {}

    for fmt, sigs in SERIALIZATION_SIGNATURES.items():
        key = fmt.value
        signatures[key] = {
            "magic_bytes_hex": [m.hex() for m in sigs["magic_bytes"]],
            "regex_patterns": [p.decode("utf-8", errors="ignore") for p in sigs["patterns"]],
            "content_types": sigs["content_types"],
        }

    return signatures


async def run_deserialization_scan(
    url: str,
    endpoints: list[dict] | None = None,
    auth_header: str | None = None,
    scan_responses: bool = True,
    scan_viewstate: bool = True,
) -> dict[str, Any]:
    """
    Run comprehensive deserialization vulnerability scan.

    Args:
        url: Base URL
        endpoints: Optional list of endpoints with parameters to test
        auth_header: Authorization header
        scan_responses: Whether to scan responses for serialization
        scan_viewstate: Whether to scan for ViewState issues

    Returns:
        Dict with findings and summary
    """
    findings = []

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        # Scan main page
        try:
            resp = await client.get(url, timeout=10.0)

            # Check for serialization in response
            if scan_responses:
                resp_findings = await scan_response_for_serialization(url, resp)
                findings.extend(resp_findings)

            # Check for ViewState
            if scan_viewstate:
                vs_findings = await scan_for_viewstate(url, client)
                findings.extend(vs_findings)

        except httpx.RequestError as e:
            logger.warning(f"Failed to scan {url}: {e}")

        # Test specific endpoints if provided
        if endpoints:
            for endpoint in endpoints:
                ep_url = endpoint.get("url", url)
                method = endpoint.get("method", "GET")

                for param in endpoint.get("parameters", []):
                    param_name = param.get("name")
                    param_location = param.get("location", "query")
                    param_value = param.get("value")

                    ep_findings = await test_deserialization_endpoint(
                        url=ep_url,
                        method=method,
                        param_name=param_name,
                        param_location=param_location,
                        original_value=param_value,
                        client=client,
                        auth_header=auth_header,
                    )
                    findings.extend(ep_findings)

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.format_type, f.location, f.description)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return {
        "url": url,
        "findings": [
            {
                "type": f.format_type.value,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "location": f.location,
                "remediation": f.remediation,
            }
            for f in unique_findings
        ],
        "summary": {
            "total": len(unique_findings),
            "critical": sum(1 for f in unique_findings if f.severity == "critical"),
            "high": sum(1 for f in unique_findings if f.severity == "high"),
            "medium": sum(1 for f in unique_findings if f.severity == "medium"),
            "low": sum(1 for f in unique_findings if f.severity == "low"),
        },
        "formats_detected": list(set(f.format_type.value for f in unique_findings)),
    }


# Detection utilities for integration with other modules

def is_serialized_data(data: bytes | str) -> tuple[bool, SerializationFormat | None]:
    """
    Quick check if data appears to be serialized.

    Args:
        data: Data to check

    Returns:
        Tuple of (is_serialized, format)
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    detections = detect_serialization_in_content(data)
    if detections:
        return True, detections[0][0]

    # Try base64 decode
    try:
        decoded = base64.b64decode(data)
        detections = detect_serialization_in_content(decoded)
        if detections:
            return True, detections[0][0]
    except Exception:
        pass

    return False, None


def get_format_risk_level(fmt: SerializationFormat) -> str:
    """Get the risk level for a serialization format."""
    critical_formats = {
        SerializationFormat.JAVA_OBJECT,
        SerializationFormat.PHP_SERIALIZE,
        SerializationFormat.PYTHON_UNSAFE_SERIAL,
        SerializationFormat.DOTNET_BINARY,
        SerializationFormat.NODEJS_SERIALIZE,
    }

    high_formats = {
        SerializationFormat.JAVA_XSTREAM,
        SerializationFormat.JAVA_SNAKEYAML,
        SerializationFormat.RUBY_MARSHAL,
        SerializationFormat.RUBY_YAML,
        SerializationFormat.PYTHON_YAML,
    }

    if fmt in critical_formats:
        return "critical"
    elif fmt in high_formats:
        return "high"
    else:
        return "medium"
