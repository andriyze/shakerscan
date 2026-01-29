"""
File Upload Security Testing Module

Comprehensive file upload bypass testing including:
- Extension bypass (case, double, null byte)
- Content-Type manipulation
- Magic byte injection
- Polyglot file creation
- Archive-based bypasses

This module tests file upload functionality for common vulnerabilities
that could lead to remote code execution.

SECURITY NOTE: This is a security scanning tool. The shell payloads and
bypass techniques are for detecting vulnerabilities in target applications,
not for malicious use.
"""

import base64
import io
import os
import random
import string
import sys
import tempfile
from typing import Any

from .common import run


# Magic bytes for various file types
MAGIC_BYTES = {
    "gif": b"GIF89a",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "bmp": b"BM",
    "pdf": b"%PDF-1.4",
    "zip": b"PK\x03\x04",
    "rar": b"Rar!\x1a\x07",
    "gzip": b"\x1f\x8b\x08",
    "tar": b"ustar",
}

# Dangerous extensions that could lead to RCE
DANGEROUS_EXTENSIONS = {
    "php": [
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".phps", ".pht", ".pgif", ".shtml", ".inc", ".cgi"
    ],
    "asp": [
        ".asp", ".aspx", ".ashx", ".asmx", ".ascx", ".cer", ".asa",
        ".cshtml", ".vbhtml", ".config"
    ],
    "jsp": [
        ".jsp", ".jspx", ".jsw", ".jsv", ".jspf", ".wss", ".do", ".action"
    ],
    "perl": [".pl", ".pm", ".cgi"],
    "python": [".py", ".pyc", ".pyw"],
    "ruby": [".rb", ".rhtml"],
    "coldfusion": [".cfm", ".cfml", ".cfc"],
    "nodejs": [".js", ".mjs"],
}


def generate_extension_bypass_filenames(
    base_name: str = "shell",
    target_extension: str = ".php",
    allowed_extension: str = ".jpg",
) -> list[dict[str, Any]]:
    """
    Generate filenames designed to bypass extension-based filters.

    Args:
        base_name: Base filename without extension
        target_extension: Dangerous extension to inject
        allowed_extension: Allowed extension for bypass

    Returns:
        List of filename variants with bypass techniques.
    """
    variants = []

    # 1. Case manipulation
    for case_variant in [".PhP", ".pHp", ".PHP", ".Php", ".pHP"]:
        variants.append({
            "filename": f"{base_name}{case_variant}",
            "technique": "case_manipulation",
            "description": "Bypass case-sensitive extension check",
        })

    # 2. Double extension
    variants.append({
        "filename": f"{base_name}{target_extension}{allowed_extension}",
        "technique": "double_extension",
        "description": "Double extension (may work with Apache AddHandler)",
    })
    variants.append({
        "filename": f"{base_name}{allowed_extension}{target_extension}",
        "technique": "double_extension_reversed",
        "description": "Reversed double extension",
    })

    # 3. Null byte injection (older systems)
    variants.append({
        "filename": f"{base_name}{target_extension}%00{allowed_extension}",
        "technique": "null_byte_url",
        "description": "URL-encoded null byte",
    })

    # 4. Semicolon (IIS specific)
    variants.append({
        "filename": f"{base_name}{target_extension};{allowed_extension}",
        "technique": "semicolon_bypass",
        "description": "IIS semicolon parsing bypass",
    })

    # 5. Alternate extensions
    alt_php_extensions = [".phtml", ".pht", ".php5", ".php7", ".phps", ".phar"]
    for ext in alt_php_extensions:
        variants.append({
            "filename": f"{base_name}{ext}",
            "technique": "alternate_extension",
            "description": f"Alternative PHP extension: {ext}",
        })

    # 6. Apache .htaccess bypass (if can upload .htaccess)
    variants.append({
        "filename": ".htaccess",
        "technique": "htaccess_override",
        "description": "Upload .htaccess to enable PHP in directory",
        "content": "AddType application/x-httpd-php .txt\n",
    })

    # 7. Trailing characters
    variants.append({
        "filename": f"{base_name}{target_extension}.",
        "technique": "trailing_dot",
        "description": "Trailing dot (Windows stripping)",
    })
    variants.append({
        "filename": f"{base_name}{target_extension} ",
        "technique": "trailing_space",
        "description": "Trailing space (Windows stripping)",
    })
    variants.append({
        "filename": f"{base_name}{target_extension}::$DATA",
        "technique": "ntfs_ads",
        "description": "NTFS Alternate Data Stream",
    })

    # 8. URL encoding variations
    variants.append({
        "filename": f"{base_name}%2Ephp",
        "technique": "url_encoded_dot",
        "description": "URL-encoded dot",
    })
    variants.append({
        "filename": f"{base_name}.%70%68%70",
        "technique": "url_encoded_ext",
        "description": "URL-encoded extension",
    })

    return variants


def generate_content_type_bypass_payloads(
    payload: bytes,
    payload_extension: str = ".php",
) -> list[dict[str, Any]]:
    """
    Generate payloads with various Content-Type headers.

    Args:
        payload: File content (e.g., PHP code)
        payload_extension: Target extension

    Returns:
        List of payload variants with different Content-Types.
    """
    variants = []

    # Common allowed content types
    content_types = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/bmp",
        "application/octet-stream",
        "text/plain",
        "application/pdf",
        "application/zip",
        "image/x-png",
        "image/pjpeg",
    ]

    for ct in content_types:
        variants.append({
            "content_type": ct,
            "payload": payload,
            "technique": "content_type_manipulation",
            "description": f"Content-Type: {ct}",
        })

    return variants


def generate_magic_byte_payload(
    shell_code: str,
    image_type: str = "gif",
) -> bytes:
    """
    Generate a polyglot file with valid image magic bytes containing shell code.

    Args:
        shell_code: PHP/ASP shell code to embed
        image_type: Type of image magic bytes to prepend

    Returns:
        Bytes containing magic bytes + shell code.
    """
    magic = MAGIC_BYTES.get(image_type, MAGIC_BYTES["gif"])
    shell_bytes = shell_code.encode('utf-8')

    # For GIF, we can embed after the header
    if image_type == "gif":
        return magic + b"\n" + shell_bytes

    # For PNG, embed after header
    elif image_type == "png":
        return magic + b"\x00\x00\x00\x0D\x49\x48\x44\x52" + shell_bytes

    # For JPEG, embed after SOI marker
    elif image_type in ("jpg", "jpeg"):
        return magic + b"\n" + shell_bytes

    else:
        return magic + b"\n" + shell_bytes


def generate_polyglot_files() -> list[dict[str, Any]]:
    """
    Generate polyglot files that are valid images AND contain test code.

    Returns:
        List of polyglot file definitions.
    """
    polyglots = []

    # GIF + PHP polyglot
    gif_php = (
        b"GIF89a/*" +
        b"<?php echo 'UPLOAD_TEST'; ?>" +
        b"*/"
    )
    polyglots.append({
        "type": "gif_php",
        "extension": ".gif.php",
        "content": gif_php,
        "description": "GIF header with PHP code in comment",
        "content_type": "image/gif",
    })

    # JPEG + PHP polyglot (using comment marker)
    jpg_php = (
        b"\xff\xd8\xff\xfe\x00\x13" +
        b"<?php echo 'TEST'; ?>" +
        b"\xff\xd9"
    )
    polyglots.append({
        "type": "jpeg_php_comment",
        "extension": ".jpg",
        "content": jpg_php,
        "description": "JPEG with PHP in COM marker",
        "content_type": "image/jpeg",
    })

    # SVG + JavaScript (for XSS testing)
    svg_js = b'''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <rect width="300" height="100" style="fill:rgb(0,0,255)" />
  <script type="text/javascript">alert('XSS')</script>
</svg>'''
    polyglots.append({
        "type": "svg_xss",
        "extension": ".svg",
        "content": svg_js,
        "description": "SVG with embedded JavaScript",
        "content_type": "image/svg+xml",
    })

    # PDF + test marker
    pdf_marker = (
        b"%PDF-1.4\n" +
        b"% UPLOAD_TEST_MARKER\n" +
        b"%%EOF"
    )
    polyglots.append({
        "type": "pdf_marker",
        "extension": ".pdf",
        "content": pdf_marker,
        "description": "PDF header with test marker",
        "content_type": "application/pdf",
    })

    return polyglots


def generate_test_shell_payloads() -> dict[str, dict[str, Any]]:
    """
    Generate detection payloads for various server-side languages.

    These are test payloads that output identifiable markers, not harmful code.

    Returns:
        Dict of test payloads by language.
    """
    return {
        "php": {
            "simple": "<?php echo 'UPLOAD_TEST_PHP'; ?>",
            "short_tag": "<?='UPLOAD_TEST_SHORT'?>",
            "info": "<?php phpinfo(); ?>",
        },
        "asp": {
            "simple": '<%Response.Write("UPLOAD_TEST_ASP")%>',
        },
        "jsp": {
            "simple": '<%out.println("UPLOAD_TEST_JSP");%>',
        },
    }


async def test_file_upload(
    upload_url: str,
    file_param: str = "file",
    additional_params: dict[str, str] | None = None,
    auth_session: Any | None = None,
    test_extensions: bool = True,
    test_content_type: bool = True,
    test_magic_bytes: bool = True,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Test file upload functionality for common bypass vulnerabilities.

    Args:
        upload_url: URL of the upload endpoint
        file_param: Form field name for file upload
        additional_params: Additional form parameters
        auth_session: Optional authentication session
        test_extensions: Test extension bypass techniques
        test_content_type: Test Content-Type manipulation
        test_magic_bytes: Test magic byte injection
        timeout: Request timeout

    Returns:
        Dict with test results and findings.
    """
    from .common import get_auth_curl_args

    results: dict[str, Any] = {
        "url": upload_url,
        "tests_run": 0,
        "successful_uploads": [],
        "findings": [],
    }

    auth_args = get_auth_curl_args(auth_session) if auth_session else []

    # Generate test identifier
    test_id = ''.join(random.choices(string.ascii_lowercase, k=6))
    shell_code = f"<?php echo 'UPLOAD_TEST_{test_id}'; ?>"

    # Test 1: Extension bypasses
    if test_extensions:
        ext_variants = generate_extension_bypass_filenames(
            base_name=f"test_{test_id}",
            target_extension=".php",
            allowed_extension=".jpg",
        )

        for variant in ext_variants:
            filename = variant["filename"]
            technique = variant["technique"]

            # Skip htaccess for now (special handling needed)
            if filename == ".htaccess":
                continue

            # Create temp file with content
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(shell_code)
                temp_path = f.name

            try:
                cmd = [
                    "curl", "-sS", "-L", "-k", "--max-time", str(timeout),
                    "-X", "POST",
                    "-F", f"{file_param}=@{temp_path};filename={filename}",
                    "-w", "\n%{http_code}",
                ] + auth_args + [upload_url]

                # Add additional params
                for key, value in (additional_params or {}).items():
                    cmd.extend(["-F", f"{key}={value}"])

                out, err, rc = await run(cmd, timeout=int(timeout) + 5)
                results["tests_run"] += 1

                if rc == 0 and out:
                    lines = out.strip().split("\n")
                    status_code = lines[-1] if lines else "0"

                    # Check for successful upload indicators
                    if status_code in ["200", "201", "302"]:
                        results["successful_uploads"].append({
                            "filename": filename,
                            "technique": technique,
                            "status_code": status_code,
                            "response_snippet": "\n".join(lines[:-1])[:500],
                        })
            finally:
                os.unlink(temp_path)

    # Test 2: Content-Type manipulation
    if test_content_type:
        content_type_variants = generate_content_type_bypass_payloads(
            shell_code.encode(),
            ".php",
        )

        for variant in content_type_variants[:5]:  # Limit to avoid too many requests
            content_type = variant["content_type"]

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(shell_code)
                temp_path = f.name

            try:
                cmd = [
                    "curl", "-sS", "-L", "-k", "--max-time", str(timeout),
                    "-X", "POST",
                    "-F", f"{file_param}=@{temp_path};filename=test_{test_id}.php;type={content_type}",
                    "-w", "\n%{http_code}",
                ] + auth_args + [upload_url]

                out, err, rc = await run(cmd, timeout=int(timeout) + 5)
                results["tests_run"] += 1

                if rc == 0 and out:
                    lines = out.strip().split("\n")
                    status_code = lines[-1] if lines else "0"

                    if status_code in ["200", "201", "302"]:
                        results["successful_uploads"].append({
                            "filename": f"test_{test_id}.php",
                            "technique": f"content_type_{content_type}",
                            "status_code": status_code,
                        })
            finally:
                os.unlink(temp_path)

    # Test 3: Magic byte injection
    if test_magic_bytes:
        polyglots = generate_polyglot_files()

        for polyglot in polyglots[:3]:  # Limit
            if polyglot["type"].endswith("_xss"):
                continue  # Skip XSS-only polyglots for upload RCE testing

            filename = f"test_{test_id}{polyglot['extension']}"
            content = polyglot["content"]
            content_type = polyglot["content_type"]

            # Write temp file for upload
            with tempfile.NamedTemporaryFile(delete=False, suffix=polyglot["extension"]) as f:
                f.write(content)
                temp_path = f.name

            try:
                cmd = [
                    "curl", "-sS", "-L", "-k", "--max-time", str(timeout),
                    "-X", "POST",
                    "-F", f"{file_param}=@{temp_path};filename={filename};type={content_type}",
                    "-w", "\n%{http_code}",
                ] + auth_args + [upload_url]

                out, err, rc = await run(cmd, timeout=int(timeout) + 5)
                results["tests_run"] += 1

                if rc == 0 and out:
                    lines = out.strip().split("\n")
                    status_code = lines[-1] if lines else "0"

                    if status_code in ["200", "201", "302"]:
                        results["successful_uploads"].append({
                            "filename": filename,
                            "technique": f"magic_bytes_{polyglot['type']}",
                            "status_code": status_code,
                        })
            finally:
                os.unlink(temp_path)

    # Generate findings
    for upload in results["successful_uploads"]:
        technique = upload["technique"]
        severity = "high"

        if "magic_bytes" in technique or "polyglot" in technique:
            severity = "critical"
        elif "double_extension" in technique or "null_byte" in technique:
            severity = "critical"

        results["findings"].append({
            "type": "File Upload Bypass",
            "severity": severity,
            "technique": technique,
            "filename": upload["filename"],
            "description": f"File upload bypass successful using {technique}",
            "recommendation": "Implement strict file type validation (content, not extension)",
        })

    return results


def get_upload_bypass_checklist() -> list[dict[str, Any]]:
    """
    Get a checklist of file upload security tests.

    Returns:
        List of test definitions.
    """
    return [
        {
            "category": "Extension Bypass",
            "tests": [
                "Case manipulation (.PhP, .pHp)",
                "Double extension (.php.jpg)",
                "Null byte (.php%00.jpg)",
                "Semicolon (.php;.jpg) - IIS",
                "Alternative extensions (.phtml, .php5)",
                "Trailing characters (.php., .php )",
                "NTFS ADS (.php::$DATA)",
            ],
        },
        {
            "category": "Content-Type Bypass",
            "tests": [
                "image/jpeg with PHP content",
                "image/png with PHP content",
                "image/gif with PHP content",
                "application/octet-stream",
            ],
        },
        {
            "category": "Magic Byte Injection",
            "tests": [
                "GIF89a + PHP",
                "PNG header + PHP",
                "JPEG header + PHP",
                "PDF header + PHP",
            ],
        },
        {
            "category": "Server Configuration",
            "tests": [
                ".htaccess upload (Apache)",
                "web.config upload (IIS)",
                ".user.ini upload (PHP-FPM)",
            ],
        },
        {
            "category": "Compression/Archive",
            "tests": [
                "ZIP containing PHP (zip slip)",
                "TAR containing PHP",
                "PHAR deserialization",
            ],
        },
    ]
