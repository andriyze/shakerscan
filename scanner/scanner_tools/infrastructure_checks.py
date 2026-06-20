#!/usr/bin/env python3
"""
Infrastructure & Configuration Leak Detection (Phase 3b)

This module detects exposed infrastructure files and misconfigured cloud resources:
1. CI/CD configuration files (GitHub Actions, GitLab CI, Jenkins, etc.)
2. Package manager files (package.json, requirements.txt, pom.xml, etc.)
3. Cloud storage buckets (AWS S3, Azure Blob, GCP Storage)
4. Backup files (database dumps, archives, editor backups)

All checks are read-only and safe for production scanning.

OWASP Mapping:
- A05:2021 - Security Misconfiguration

CWE Mapping:
- CWE-540: Inclusion of Sensitive Information in Source Code
- CWE-219: Storage of File with Sensitive Data Under Web Root
- CWE-552: Files or Directories Accessible to External Parties

MITRE ATT&CK:
- T1213: Data from Information Repositories
"""

import asyncio
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from xml.etree import ElementTree as ET

# Disable SSL verification for testing (corporate proxies, self-signed certs)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Set global socket timeout to prevent DNS hangs (critical fix)
socket.setdefaulttimeout(10)

# ============================================================================
# HTTP HELPER (using urllib for zero external dependencies)
# ============================================================================

async def _fetch_url(url: str, method: str = "GET", timeout: int = 10, headers: dict[str, str] | None = None) -> tuple[int, str, dict[str, str]]:
    """
    Fetch URL using urllib (async wrapper).

    Returns:
        (status_code, body, headers)
    """
    def _sync_fetch():
        try:
            req = urllib.request.Request(url, method=method, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                status_code = response.getcode()
                body = response.read().decode('utf-8', errors='ignore')
                response_headers = dict(response.headers)
                return (status_code, body, response_headers)
        except urllib.error.HTTPError as e:
            return (e.code, "", {})
        except Exception:
            return (0, "", {})

    return await asyncio.to_thread(_sync_fetch)


async def _head_url(url: str, timeout: int = 10) -> tuple[int, dict[str, str]]:
    """
    Send HEAD request using urllib (async wrapper).

    Returns:
        (status_code, headers)
    """
    def _sync_head():
        try:
            req = urllib.request.Request(url, method='HEAD')
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                return (response.getcode(), dict(response.headers))
        except urllib.error.HTTPError as e:
            return (e.code, {})
        except Exception:
            return (0, {})

    return await asyncio.to_thread(_sync_head)


# ============================================================================
# 1. CI/CD FILE EXPOSURE
# ============================================================================

CI_CD_FILES = [
    # GitHub Actions
    '.github/workflows/ci.yml',
    '.github/workflows/deploy.yml',
    '.github/workflows/build.yml',
    '.github/workflows/test.yml',
    '.github/workflows/main.yml',

    # GitLab CI
    '.gitlab-ci.yml',

    # Jenkins
    'Jenkinsfile',
    'jenkins.yml',
    '.jenkins/config.xml',

    # CircleCI
    '.circleci/config.yml',

    # Azure Pipelines
    'azure-pipelines.yml',
    '.azure/pipelines.yml',

    # Travis CI
    '.travis.yml',

    # Drone CI
    '.drone.yml',

    # Bitbucket Pipelines
    'bitbucket-pipelines.yml',

    # Docker & Kubernetes
    'docker-compose.yml',
    'docker-compose.yaml',
    'k8s.yaml',
    'k8s.yml',
    'kubernetes.yaml',
    'deployment.yaml',
]

# Secret patterns to scan for in CI/CD files
CI_CD_SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})', 'password'),
    (r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']{16,})', 'api_key'),
    (r'(?:secret|token)["\']?\s*[:=]\s*["\']([^"\']{16,})', 'secret'),
    (r'(?:AWS|aws)_?(?:ACCESS|access)_?(?:KEY|key)_?(?:ID|id)?["\']?\s*[:=]\s*["\']([A-Z0-9]{20})', 'aws_access_key'),
    (r'ghp_[A-Za-z0-9]{36}', 'github_token'),
    (r'sk_live_[A-Za-z0-9]{24,}', 'stripe_live_key'),
]


async def test_cicd_exposure(
    url: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for exposed CI/CD configuration files.

    Why This Matters:
    - CI/CD files often contain deployment credentials
    - Infrastructure details reveal attack surface
    - Build scripts may contain hardcoded secrets

    Detection Strategy:
    1. Test common CI/CD file paths (/.github/workflows/*, /.gitlab-ci.yml, etc.)
    2. Check if files are publicly accessible (HTTP 200)
    3. Download and parse YAML/JSON for sensitive patterns
    4. Report findings with severity based on content

    Args:
        url: Base URL to test
        safe_mode: Not used (read-only check)

    Returns:
        {
            "vulnerable": bool,
            "exposed_files": [
                {
                    "file": ".gitlab-ci.yml",
                    "url": "https://example.com/.gitlab-ci.yml",
                    "size_bytes": 2048,
                    "secrets_found": ["API_KEY", "PASSWORD"]
                }
            ],
            "total_files_tested": int,
            "cwe": "CWE-540",
            "owasp": "A05:2021 - Security Misconfiguration"
        }
    """
    results = {
        "vulnerable": False,
        "exposed_files": [],
        "total_files_tested": len(CI_CD_FILES),
        "cwe": "CWE-540",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "high",
        "recommendation": "Remove CI/CD files from web root, restrict access with .htaccess or server config"
    }

    for file_path in CI_CD_FILES:
        # Build full URL
        test_url = f"{url.rstrip('/')}/{file_path}"

        status_code, body, headers = await _fetch_url(test_url, timeout=10)

        if status_code == 200 and body:
            # CONTENT VALIDATION: Check if response is actually a CI/CD file
            # Many SPAs return HTTP 200 with HTML for all paths (false positive)
            body_lower = body.lower()[:3000]

            # Reject if response looks like HTML (not a CI/CD file)
            html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<div>"]
            html_matches = sum(1 for ind in html_indicators if ind in body_lower)
            if html_matches >= 2:
                continue  # Skip - this is HTML, not a CI/CD file

            # Check for CI/CD file content patterns
            cicd_patterns = [
                "jobs:", "steps:", "runs-on:", "stage:", "script:",
                "pipeline:", "stages:", "services:", "image:", "build:",
                "deploy:", "version:", "workflow_dispatch:", "on:", "env:"
            ]
            cicd_matches = sum(1 for p in cicd_patterns if p in body_lower)

            # Require at least 1 CI/CD pattern OR it's a known structured format
            is_yaml = body.strip().startswith(("---", "name:", "version:", "#"))
            is_json = body.strip().startswith("{") and "script" in body_lower

            if cicd_matches < 1 and not is_yaml and not is_json:
                continue  # Skip - doesn't look like a CI/CD config

            # File is actually exposed!
            results["vulnerable"] = True

            # Check content for secrets
            secrets_found = []
            for pattern, secret_type in CI_CD_SECRET_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    secrets_found.append(secret_type)

            results["exposed_files"].append({
                "file": file_path,
                "url": test_url,
                "size_bytes": len(body),
                "secrets_found": list(set(secrets_found)),  # Remove duplicates
                "preview": body[:200] if not secrets_found else "[REDACTED - contains secrets]"
            })

        await asyncio.sleep(0.1)  # Rate limiting

    return results


# ============================================================================
# 2. PACKAGE MANAGER FILE EXPOSURE
# ============================================================================

PACKAGE_FILES = [
    # JavaScript/Node.js
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'npm-shrinkwrap.json',

    # Python
    'requirements.txt',
    'Pipfile',
    'Pipfile.lock',
    'setup.py',
    'poetry.lock',

    # Java
    'pom.xml',
    'build.gradle',
    'gradle.properties',

    # Ruby
    'Gemfile',
    'Gemfile.lock',

    # PHP
    'composer.json',
    'composer.lock',

    # .NET
    'packages.config',
    'Project.csproj',

    # Go
    'go.mod',
    'go.sum',
]


async def test_package_exposure(
    url: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for exposed package manager files revealing dependencies.

    Why This Matters:
    - Reveals full dependency tree (attacker knows exact versions)
    - Enables targeted exploitation of known CVEs
    - May contain internal package repository URLs

    Returns:
        {
            "vulnerable": bool,
            "exposed_files": [...],
            "cwe": "CWE-219",
            "owasp": "A05:2021 - Security Misconfiguration"
        }
    """
    results = {
        "vulnerable": False,
        "exposed_files": [],
        "total_files_tested": len(PACKAGE_FILES),
        "cwe": "CWE-219",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "medium",
        "recommendation": "Remove package files from web root"
    }

    # Content validation patterns for different package file types
    package_patterns = {
        "package.json": (['"name":', '"version":', '"dependencies":', '"scripts":'], 1),
        "package-lock.json": (['"lockfileVersion":', '"packages":', '"requires":'], 1),
        "yarn.lock": (["resolved ", "integrity ", "version "], 1),
        "npm-shrinkwrap.json": (['"lockfileVersion":', '"dependencies":'], 1),
        "requirements.txt": (["==", ">=", "<=", "~="], 1),
        "Pipfile": (["[packages]", "[dev-packages]", "[[source]]"], 1),
        "Pipfile.lock": (['"_meta":', '"default":', '"develop":'], 1),
        "setup.py": (["setup(", "install_requires", "from setuptools"], 1),
        "poetry.lock": (["[[package]]", "name =", "version ="], 1),
        "pom.xml": (["<project", "<groupId>", "<artifactId>", "<dependency>"], 2),
        "build.gradle": (["dependencies {", "plugins {", "repositories {"], 1),
        "gradle.properties": (["org.gradle", "android.", "kotlin."], 1),
        "Gemfile": (["source ", "gem ", "group :"], 1),
        "Gemfile.lock": (["GEM", "PLATFORMS", "DEPENDENCIES", "specs:"], 1),
        "composer.json": (['"require":', '"autoload":', '"name":'], 1),
        "composer.lock": (['"packages":', '"_readme":', '"content-hash":'], 1),
        "packages.config": (["<packages", "<package id="], 1),
        "Project.csproj": (["<Project", "<PackageReference", "<ItemGroup>"], 1),
        "go.mod": (["module ", "go ", "require "], 1),
        "go.sum": (["h1:", "/go.mod h1:"], 1),
    }

    for file_path in PACKAGE_FILES:
        test_url = f"{url.rstrip('/')}/{file_path}"

        status_code, body, _ = await _fetch_url(test_url, timeout=10)

        if status_code == 200 and body:
            # CONTENT VALIDATION: Check if response is actually a package file
            body_lower = body.lower()[:5000]

            # Reject if response looks like HTML
            html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<div>"]
            html_matches = sum(1 for ind in html_indicators if ind in body_lower)
            if html_matches >= 2:
                continue  # Skip - this is HTML, not a package file

            # Check for package file-specific patterns
            patterns, min_matches = package_patterns.get(file_path, ([], 0))
            if patterns:
                matches = sum(1 for p in patterns if p.lower() in body_lower)
                if matches < min_matches:
                    continue  # Skip - doesn't look like the expected file type

            results["vulnerable"] = True
            results["exposed_files"].append({
                "file": file_path,
                "url": test_url,
                "size_bytes": len(body)
            })

        await asyncio.sleep(0.1)

    return results


# ============================================================================
# 3. CLOUD STORAGE BUCKET ENUMERATION
# ============================================================================

async def test_cloud_buckets(
    url: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for publicly accessible cloud storage buckets (S3, Azure, GCP).

    Why This Matters:
    - "Public S3 Bucket" is a top data breach cause
    - Companies often use predictable naming (company-backups, company-assets)
    - Misconfigured ACLs expose sensitive data

    Detection Strategy:
    1. Extract domain name from URL (e.g., example.com -> example)
    2. Generate permutations: example-assets, example-backups, example-prod, etc.
    3. Test S3: https://s3.amazonaws.com/example-assets
    4. Test Azure: https://exampleassets.blob.core.windows.net
    5. Test GCP: https://storage.googleapis.com/example-assets
    6. Check if bucket exists and is publicly readable

    Args:
        url: Base URL to test (domain name extracted from this)
        safe_mode: If True, limit to 10 permutations

    Returns:
        {
            "vulnerable": bool,
            "public_buckets": [
                {
                    "provider": "aws_s3",
                    "bucket_name": "example-assets",
                    "url": "https://s3.amazonaws.com/example-assets",
                    "readable": true,
                    "sample_files": ["backup.sql", "config.json"]
                }
            ],
            "total_buckets_tested": int,
            "cwe": "CWE-552",
            "owasp": "A05:2021 - Security Misconfiguration"
        }
    """
    results = {
        "vulnerable": False,
        "public_buckets": [],
        "total_buckets_tested": 0,
        "cwe": "CWE-552",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "critical",
        "recommendation": "Configure bucket ACLs to private, enable bucket policies, use AWS IAM"
    }

    # Extract domain name from URL
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname or ""
    domain_parts = domain.split('.')
    company_name = domain_parts[0] if domain_parts else "unknown"

    # Common bucket name permutations
    permutations = [
        company_name,
        f"{company_name}-assets",
        f"{company_name}-backups",
        f"{company_name}-backup",
        f"{company_name}-data",
        f"{company_name}-prod",
        f"{company_name}-production",
        f"{company_name}-dev",
        f"{company_name}-staging",
        f"{company_name}-files",
        f"{company_name}-uploads",
        f"{company_name}-static",
        f"{company_name}-public",
        f"{company_name}-private",  # Ironically, often public
        f"{company_name}-logs",
    ]

    if safe_mode:
        permutations = permutations[:10]  # Limit to 10

    for bucket_name in permutations:
        # Test AWS S3
        s3_url = f"https://s3.amazonaws.com/{bucket_name}"
        results["total_buckets_tested"] += 1

        status_code, body, _ = await _fetch_url(s3_url, timeout=10)
        if status_code == 200 and body:
            # Bucket exists and is readable
            sample_files = _extract_s3_files(body)
            results["vulnerable"] = True
            results["public_buckets"].append({
                "provider": "aws_s3",
                "bucket_name": bucket_name,
                "url": s3_url,
                "readable": True,
                "sample_files": sample_files[:10]  # First 10 files
            })

        # Test Azure Blob Storage
        azure_url = f"https://{bucket_name.replace('-', '')}.blob.core.windows.net"
        results["total_buckets_tested"] += 1

        status_code, _, _ = await _fetch_url(azure_url, timeout=10)
        if status_code == 200:
            results["vulnerable"] = True
            results["public_buckets"].append({
                "provider": "azure_blob",
                "bucket_name": bucket_name,
                "url": azure_url,
                "readable": True
            })

        # Test GCP Storage
        gcp_url = f"https://storage.googleapis.com/{bucket_name}"
        results["total_buckets_tested"] += 1

        status_code, _, _ = await _fetch_url(gcp_url, timeout=10)
        if status_code == 200:
            results["vulnerable"] = True
            results["public_buckets"].append({
                "provider": "gcp_storage",
                "bucket_name": bucket_name,
                "url": gcp_url,
                "readable": True
            })

        await asyncio.sleep(0.3)  # Rate limiting

    return results


# ============================================================================
# 5. DIRECTORY LISTING EXPOSURE
# ============================================================================

async def test_directory_listing(
    url: str,
    discovered_urls: list[str] | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Detect exposed directory listings (Index of /).
    """
    results = {
        "vulnerable": False,
        "exposed_directories": [],
        "directories_tested": 0,
        "cwe": "CWE-548",
    }

    common_dirs = {
        "/uploads/", "/files/", "/static/", "/assets/", "/backup/",
        "/backups/", "/data/", "/logs/", "/images/", "/downloads/",
        # Node serve-index style listings (e.g. OWASP Juice Shop /ftp, /support/logs)
        "/ftp/", "/encryptionkeys/", "/support/logs/",
    }

    if discovered_urls:
        for u in discovered_urls:
            try:
                path = urllib.parse.urlparse(u).path
                if not path:
                    continue
                if not path.endswith("/"):
                    path = path.rsplit("/", 1)[0] + "/"
                if path and path != "/":
                    common_dirs.add(path)
            except Exception:
                continue

    dirs_to_test = list(common_dirs)
    if safe_mode and len(dirs_to_test) > 25:
        dirs_to_test = dirs_to_test[:25]

    for directory in dirs_to_test:
        results["directories_tested"] += 1
        test_url = urllib.parse.urljoin(url.rstrip("/") + "/", directory.lstrip("/"))
        status_code, body, _ = await _fetch_url(test_url, timeout=10)
        if status_code != 200 or not body:
            continue

        body_lower = body.lower()
        listing_markers = [
            "index of /",
            "parent directory",
            "directory listing for",
            "<title>index of",
            # Node.js serve-index middleware (Express) renders this, not "Index of"
            "listing directory",
            "<title>listing directory",
            'id="files"',
        ]
        if any(marker in body_lower for marker in listing_markers):
            results["vulnerable"] = True
            results["exposed_directories"].append({
                "directory": directory,
                "url": test_url,
                "content_preview": body[:300],
            })

    return results


def _extract_s3_files(xml_content: str) -> list[str]:
    """Extract file names from S3 bucket XML listing"""
    files = []
    try:
        # Parse XML
        root = ET.fromstring(xml_content)
        # S3 XML namespace
        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
        for key_elem in root.findall('.//s3:Key', ns):
            if key_elem.text:
                files.append(key_elem.text)
        # Fallback: regex if namespace parsing fails
        if not files:
            key_pattern = r'<Key>([^<]+)</Key>'
            files = re.findall(key_pattern, xml_content)
    except Exception:
        # Fallback: regex
        key_pattern = r'<Key>([^<]+)</Key>'
        files = re.findall(key_pattern, xml_content)
    return files


# ============================================================================
# 4. BACKUP FILE DETECTION
# ============================================================================

BACKUP_FILES = [
    # Database backups
    'backup.sql',
    'db.sql',
    'database.sql',
    'dump.sql',
    'backup.sql.gz',
    'db_backup.sql',
    'mysql.sql',
    'postgres.sql',

    # Archive files
    'backup.zip',
    'backup.tar.gz',
    'backup.tar',
    'site.zip',
    'website.zip',
    'www.zip',
    'htdocs.zip',

    # Editor backup files
    '.swp',
    '.swo',
    '.bak',
    '.old',
    '.orig',
    'index.php.bak',
    'config.php.old',
    'web.config.old',
]


async def test_backup_files(
    url: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for exposed backup files.

    Common Scenarios:
    - Admin creates database backup and forgets to delete
    - Editor backup files (.swp, .bak) left on server
    - Archive files (backup.zip) accessible via web

    Returns:
        {
            "vulnerable": bool,
            "exposed_backups": [...],
            "cwe": "CWE-219",
            "owasp": "A05:2021 - Security Misconfiguration"
        }
    """
    results = {
        "vulnerable": False,
        "exposed_backups": [],
        "total_files_tested": len(BACKUP_FILES),
        "cwe": "CWE-219",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "critical",
        "recommendation": "Remove all backup files from web root, use proper backup storage"
    }

    # Content validation patterns for backup files
    sql_patterns = ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "ALTER TABLE",
                    "-- MySQL", "-- PostgreSQL", "PGDMP", "BEGIN TRANSACTION"]
    archive_content_types = ["application/zip", "application/x-tar", "application/gzip",
                             "application/x-gzip", "application/octet-stream"]

    for file_path in BACKUP_FILES:
        test_url = f"{url.rstrip('/')}/{file_path}"

        # First try HEAD request
        head_status, headers = await _head_url(test_url, timeout=10)

        if head_status == 200:
            content_type = headers.get('Content-Type', '').lower()
            file_size = int(headers.get('Content-Length', 0))

            # CONTENT VALIDATION: Check Content-Type
            # For archives, content-type should NOT be text/html
            if 'text/html' in content_type:
                continue  # Skip - server returned HTML (SPA catch-all)

            is_sql_file = file_path.endswith('.sql') or file_path.endswith('.sql.gz')
            is_archive = file_path.endswith(('.zip', '.tar', '.tar.gz', '.gz'))

            # For SQL files, validate content (not archives which are binary)
            if is_sql_file and file_size < 100000:  # Only validate SQL files < 100KB
                _, body, _ = await _fetch_url(test_url, timeout=10)
                if body:
                    body_upper = body.upper()[:5000]
                    # Reject if it looks like HTML
                    if "<!DOCTYPE" in body_upper or "<HTML" in body_upper:
                        continue  # Skip - this is HTML
                    # Require SQL patterns
                    sql_matches = sum(1 for p in sql_patterns if p in body_upper)
                    if sql_matches < 1:
                        continue  # Skip - doesn't look like SQL

            # For archives, verify content-type is appropriate
            if is_archive:
                valid_archive_ct = any(act in content_type for act in archive_content_types)
                if not valid_archive_ct and file_size == 0:
                    continue  # Skip - likely not a real archive

            results["vulnerable"] = True
            results["exposed_backups"].append({
                "file": file_path,
                "url": test_url,
                "size_bytes": file_size,
                "size_human": _format_bytes(file_size),
                "content_type": content_type
            })

        await asyncio.sleep(0.1)

    return results


def _format_bytes(bytes_int: int) -> str:
    """Format bytes to human-readable (KB, MB, GB)"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_int < 1024:
            return f"{bytes_int:.1f} {unit}"
        bytes_int /= 1024
    return f"{bytes_int:.1f} TB"


# ============================================================================
# 5. CLOUD METADATA SSRF TESTING
# ============================================================================

# Cloud metadata endpoints
CLOUD_METADATA_ENDPOINTS = [
    # AWS EC2 Instance Metadata Service (IMDSv1)
    ("http://169.254.169.254/latest/meta-data/", "AWS EC2 IMDSv1", ["ami-id", "instance-id", "iam", "hostname"]),
    ("http://169.254.169.254/latest/user-data/", "AWS EC2 User Data", ["#!/bin", "aws", "password", "secret"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Credentials", ["AccessKeyId", "SecretAccessKey", "Token"]),

    # AWS ECS Task Metadata
    ("http://169.254.170.2/v2/credentials/", "AWS ECS Task Metadata", ["AccessKeyId", "SecretAccessKey"]),

    # Google Cloud Platform
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", ["attributes", "instance", "project"]),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP Metadata (alt)", ["attributes", "instance", "project"]),

    # Azure IMDS
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS", ["compute", "network", "vmId"]),
    ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", "Azure Identity", ["access_token"]),

    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", "DigitalOcean Metadata", ["droplet_id", "hostname", "region"]),
    ("http://169.254.169.254/metadata/v1.json", "DigitalOcean Metadata JSON", ["droplet_id", "hostname"]),

    # Oracle Cloud
    ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud Metadata", ["availabilityDomain", "compartmentId"]),

    # Alibaba Cloud
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud Metadata", ["instance-id", "mac", "network"]),

    # Kubernetes
    ("https://kubernetes.default.svc/api/v1/", "Kubernetes API", ["apiVersion", "kind", "items"]),
]

# Common SSRF-vulnerable parameters
SSRF_PARAMETERS = [
    "url", "uri", "path", "file", "load", "fetch", "src", "href", "link",
    "redirect", "dest", "destination", "target", "page", "view", "site",
    "img", "image", "preview", "callback", "return", "next", "data",
    "resource", "ref", "proxy", "forward", "location", "api", "endpoint",
]


async def test_cloud_metadata_ssrf(
    url: str,
    discovered_urls: list[str] | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for SSRF vulnerabilities that could expose cloud metadata.

    Cloud providers expose instance metadata at well-known IP addresses.
    If an application has an SSRF vulnerability, attackers can:
    - Steal IAM credentials (AWS)
    - Access service account tokens (GCP)
    - Retrieve managed identity tokens (Azure)
    - Exfiltrate sensitive configuration

    This test attempts to detect SSRF by:
    1. Finding URL parameters in the target
    2. Injecting metadata endpoint URLs
    3. Checking if metadata indicators appear in response

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs with parameters to test
        safe_mode: Not used (all tests are read-only)

    Returns:
        {
            "vulnerable": bool,
            "ssrf_findings": [
                {
                    "url": "https://example.com/fetch?url=...",
                    "parameter": "url",
                    "metadata_endpoint": "AWS EC2 IMDSv1",
                    "evidence": ["ami-id", "instance-id"],
                    "severity": "critical"
                }
            ],
            "tested_parameters": int,
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery (SSRF)"
        }
    """
    results = {
        "vulnerable": False,
        "ssrf_findings": [],
        "tested_parameters": 0,
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "severity": "info",
        "recommendation": "Implement allowlist validation for user-supplied URLs, block internal IP ranges"
    }

    # Collect URLs to test
    test_urls = [url]
    if discovered_urls:
        # Only test URLs that have query parameters
        for disc_url in discovered_urls[:20]:  # Limit to 20
            if '?' in disc_url or any(p in disc_url.lower() for p in SSRF_PARAMETERS):
                test_urls.append(disc_url)

    def _is_actual_cloud_metadata(body: str, service_name: str) -> bool:
        """
        Validate that response contains actual cloud metadata, not just keywords in normal HTML.

        Real cloud metadata responses have specific JSON structures and don't contain
        typical web page elements like <script>, <html>, or auth SDK references.

        Returns True if response looks like real metadata, False if it's clearly a normal web page.
        """
        body_lower = body.lower()

        # Reject if response looks like a normal HTML page
        html_indicators = ['<html', '<!doctype', '<script', '<div', '<head>', '<body>']
        if any(ind in body_lower for ind in html_indicators):
            return False

        # Reject if response contains common auth SDK markers (false positive sources)
        auth_sdk_markers = ['clerk', 'auth0', 'firebase', 'supabase', 'cognito', 'okta',
                           'publishable_key', 'clerk-js', 'nextauth', 'react']
        if any(marker in body_lower for marker in auth_sdk_markers):
            return False

        # Validate AWS metadata structure - multiple patterns to cover different endpoints
        if "AWS" in service_name:
            aws_metadata_patterns = [
                ('"AccessKeyId"' in body and '"SecretAccessKey"' in body),  # IAM/ECS credentials
                ('"Code"' in body and '"AccessKeyId"' in body),  # IAM credentials with code
                ('ami-' in body_lower and 'instance-' in body_lower),  # Instance metadata
                ('"accountId"' in body and '"arn":' in body),  # IAM info
                ('"region"' in body_lower and '"availabilityZone"' in body_lower),  # Instance identity
                ('instance-id' in body_lower and 'local-ipv4' in body_lower),  # Plain text metadata
            ]
            if any(aws_metadata_patterns):
                return True
            # For user-data endpoint, accept if it's not HTML (user-data can be anything)
            # service_name is like "AWS EC2 User Data", not a URL path
            if 'user data' in service_name.lower() or 'user-data' in body_lower[:100]:
                return not any(ind in body_lower for ind in html_indicators)
            return False

        # Validate GCP metadata structure
        if "GCP" in service_name:
            gcp_patterns = [
                ('"instance"' in body_lower and '"zone"' in body_lower),
                ('"project"' in body_lower and '"attributes"' in body_lower),
                ('Metadata-Flavor' in body),  # GCP metadata header indicator
            ]
            if any(gcp_patterns):
                return True
            return False

        # Validate Azure metadata structure
        if "Azure" in service_name:
            azure_patterns = [
                ('"compute"' in body_lower and '"vmId"' in body_lower),
                ('"access_token"' in body_lower),  # Azure Identity (may not have expires)
                ('"subscriptionId"' in body and '"resourceGroupName"' in body),
            ]
            if any(azure_patterns):
                return True
            return False

        # For other cloud providers, require JSON structure without HTML
        if body.strip().startswith('{') or body.strip().startswith('['):
            # Looks like JSON - could be real metadata
            return True

        return False

    async def test_single_ssrf(test_url: str, param: str, metadata_endpoint: str, service_name: str, indicators: list[str]):
        """Test single parameter for SSRF"""
        # Build test URL with metadata endpoint
        if '?' in test_url:
            # URL already has parameters, append ours
            ssrf_url = f"{test_url}&{param}={metadata_endpoint}"
        else:
            ssrf_url = f"{test_url}?{param}={metadata_endpoint}"

        results["tested_parameters"] += 1

        status_code, body, _ = await _fetch_url(ssrf_url, timeout=10)

        if status_code == 200 and body:
            # First validate this looks like actual cloud metadata, not a normal web page
            if not _is_actual_cloud_metadata(body, service_name):
                return None

            # Check for metadata indicators
            matched_indicators = []
            body_lower = body.lower()
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    matched_indicators.append(indicator)

            # If metadata structure validated AND at least 1 indicator, report it
            # The _is_actual_cloud_metadata check is already strict enough
            if len(matched_indicators) >= 1:
                return {
                    "url": ssrf_url,
                    "parameter": param,
                    "metadata_service": service_name,
                    "metadata_endpoint": metadata_endpoint,
                    "evidence": matched_indicators,
                    "severity": "critical"
                }

        return None

    # Test each URL with each parameter against each metadata endpoint
    tasks = []
    for test_url in test_urls[:10]:  # Limit URLs
        for param in SSRF_PARAMETERS[:10]:  # Limit parameters
            for endpoint, service, indicators in CLOUD_METADATA_ENDPOINTS[:5]:  # Limit endpoints
                tasks.append(test_single_ssrf(test_url, param, endpoint, service, indicators))

    # Run with concurrency limit
    for i in range(0, len(tasks), 10):
        batch = tasks[i:i+10]
        batch_results = await asyncio.gather(*batch, return_exceptions=True)

        for result in batch_results:
            if result and not isinstance(result, Exception):
                results["vulnerable"] = True
                results["severity"] = "critical"
                results["ssrf_findings"].append(result)

        await asyncio.sleep(0.2)  # Rate limiting between batches

    return results


# ============================================================================
# 6. KUBERNETES API EXPOSURE TESTING
# ============================================================================

K8S_PATHS = [
    ("/api", "Kubernetes API root"),
    ("/api/v1", "Kubernetes Core API v1"),
    ("/api/v1/namespaces", "Kubernetes Namespaces"),
    ("/api/v1/pods", "Kubernetes Pods"),
    ("/api/v1/secrets", "Kubernetes Secrets"),
    ("/api/v1/configmaps", "Kubernetes ConfigMaps"),
    ("/apis", "Kubernetes API Groups"),
    ("/version", "Kubernetes Version"),
    ("/healthz", "Kubernetes Health"),
    ("/metrics", "Kubernetes Metrics"),
    ("/openapi/v2", "Kubernetes OpenAPI Spec"),
    ("/swagger.json", "Kubernetes Swagger"),
]

K8S_PORTS = [443, 6443, 8443, 8080, 10250]

K8S_INDICATORS = [
    '"kind":', '"apiVersion":', '"kubernetes"', '"items":', '"metadata":',
    '"apiGroups":', '"pods"', '"services"', '"secrets"', '"configmaps"',
    '"gitVersion"', '"goVersion"', '"platform"', '"buildDate"',
]


async def test_kubernetes_exposure(
    host: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for exposed Kubernetes API servers.

    Exposed K8s APIs can allow:
    - Cluster reconnaissance
    - Secret extraction
    - Pod creation (container escape)
    - Full cluster takeover

    Args:
        host: Hostname to test
        safe_mode: Not used (all tests are read-only)

    Returns:
        {
            "vulnerable": bool,
            "exposed_endpoints": [
                {
                    "url": "https://example.com:6443/api/v1",
                    "port": 6443,
                    "path": "/api/v1",
                    "description": "Kubernetes Core API v1",
                    "authenticated": bool,
                    "indicators": [...]
                }
            ],
            "severity": "critical" if secrets/pods accessible
        }
    """
    results = {
        "vulnerable": False,
        "exposed_endpoints": [],
        "ports_tested": [],
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "info",
        "recommendation": "Restrict Kubernetes API access, use RBAC, enable authentication"
    }

    async def test_k8s_endpoint(port: int, path: str, description: str):
        """Test single K8s endpoint"""
        url = f"https://{host}:{port}{path}"

        status_code, body, headers = await _fetch_url(url, timeout=10)

        if status_code in [200, 401, 403] and body:
            body_lower = body.lower()[:5000]

            # CONTENT VALIDATION: Reject if response looks like HTML (not K8s API)
            html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script"]
            html_matches = sum(1 for ind in html_indicators if ind in body_lower)
            if html_matches >= 2:
                return None  # Skip - this is HTML, not K8s API

            # Check for K8s indicators
            matched_indicators = []
            for indicator in K8S_INDICATORS:
                if indicator in body:
                    matched_indicators.append(indicator)

            # FIXED: Require at least 2 K8s indicators to confirm it's actually K8s
            # A single indicator like '"kind":' could appear in any JSON API
            if len(matched_indicators) >= 2:
                return {
                    "url": url,
                    "port": port,
                    "path": path,
                    "description": description,
                    "status_code": status_code,
                    "authenticated": status_code in [401, 403],
                    "indicators": matched_indicators[:5],  # Limit
                    "severity": "critical" if status_code == 200 and path in ["/api/v1/secrets", "/api/v1/pods"] else "high"
                }

        return None

    # Test each port
    for port in K8S_PORTS:
        results["ports_tested"].append(port)

        tasks = [test_k8s_endpoint(port, path, desc) for path, desc in K8S_PATHS]
        port_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in port_results:
            if result and not isinstance(result, Exception):
                results["vulnerable"] = True
                results["exposed_endpoints"].append(result)

                # Update severity
                if result.get("severity") == "critical":
                    results["severity"] = "critical"
                elif results["severity"] != "critical":
                    results["severity"] = "high"

        await asyncio.sleep(0.1)

    return results


# ============================================================================
# 7. TERRAFORM STATE FILE EXPOSURE
# ============================================================================

TF_STATE_PATHS = [
    "/.terraform/terraform.tfstate",
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform.tfstate",
    "/state/terraform.tfstate",
    "/terraform/terraform.tfstate",
    "/infra/terraform.tfstate",
    "/infrastructure/terraform.tfstate",
    "/.terraform/terraform.tfstate.backup",
    "/tf.state",
    "/tfstate",
]

TF_STATE_INDICATORS = [
    '"terraform_version"',
    '"serial"',
    '"lineage"',
    '"resources"',
    '"provider"',
    '"instances"',
    '"attributes"',
]

# Sensitive patterns in Terraform state
TF_SECRET_PATTERNS = [
    (r'"password"\s*:\s*"[^"]+"', 'password'),
    (r'"secret"\s*:\s*"[^"]+"', 'secret'),
    (r'"api_key"\s*:\s*"[^"]+"', 'api_key'),
    (r'"access_key"\s*:\s*"[A-Z0-9]{20}"', 'aws_access_key'),
    (r'"secret_key"\s*:\s*"[^"]+"', 'aws_secret_key'),
    (r'"private_key"\s*:\s*"[^"]+"', 'private_key'),
    (r'"token"\s*:\s*"[^"]+"', 'token'),
    (r'"connection_string"\s*:\s*"[^"]+"', 'connection_string'),
]


async def test_terraform_state(
    url: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for exposed Terraform state files.

    Terraform state files contain:
    - Infrastructure configuration
    - Resource IDs and ARNs
    - Sensitive outputs (passwords, keys)
    - Cloud provider credentials

    Args:
        url: Base URL to test
        safe_mode: Not used (all tests are read-only)

    Returns:
        {
            "vulnerable": bool,
            "exposed_files": [
                {
                    "url": "https://example.com/terraform.tfstate",
                    "size_bytes": 102400,
                    "terraform_version": "1.5.0",
                    "contains_secrets": True,
                    "secret_types": ["password", "api_key"],
                    "resource_count": 25
                }
            ],
            "severity": "critical"
        }
    """
    results = {
        "vulnerable": False,
        "exposed_files": [],
        "total_tested": len(TF_STATE_PATHS),
        "cwe": "CWE-200",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "info",
        "recommendation": "Never store Terraform state on web servers. Use remote backends (S3, GCS, etc.) with encryption."
    }

    for path in TF_STATE_PATHS:
        test_url = f"{url.rstrip('/')}{path}"

        status_code, body, _ = await _fetch_url(test_url, timeout=10)

        if status_code == 200 and body:
            # Verify it's actual Terraform state
            if any(indicator in body for indicator in TF_STATE_INDICATORS):
                results["vulnerable"] = True
                results["severity"] = "critical"

                # Extract metadata
                tf_version = None
                resource_count = 0

                # Try to parse version
                version_match = re.search(r'"terraform_version"\s*:\s*"([^"]+)"', body)
                if version_match:
                    tf_version = version_match.group(1)

                # Count resources
                resource_count = body.count('"type":')

                # Check for secrets
                secrets_found = []
                for pattern, secret_type in TF_SECRET_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        secrets_found.append(secret_type)

                results["exposed_files"].append({
                    "url": test_url,
                    "path": path,
                    "size_bytes": len(body),
                    "size_human": _format_bytes(len(body)),
                    "terraform_version": tf_version,
                    "resource_count": resource_count,
                    "contains_secrets": len(secrets_found) > 0,
                    "secret_types": list(set(secrets_found))
                })

        await asyncio.sleep(0.1)

    return results


# ============================================================================
# 8. DOCKER/CONTAINER REGISTRY EXPOSURE
# ============================================================================

REGISTRY_PATHS = [
    "/v2/", "/v2/_catalog",
    "/v1/repositories", "/v1/_ping",
]


async def test_container_registry_exposure(
    url: str,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for exposed Docker/container registries.

    Exposed registries can allow:
    - Pulling private images
    - Pushing malicious images
    - Discovering internal services

    Args:
        url: Base URL to test
        safe_mode: Not used

    Returns:
        {
            "vulnerable": bool,
            "registry_type": "docker" | "harbor" | "nexus",
            "catalog_accessible": bool,
            "image_count": int
        }
    """
    results = {
        "vulnerable": False,
        "registry_type": None,
        "catalog_accessible": False,
        "repositories": [],
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "info",
        "recommendation": "Require authentication for container registry access"
    }

    # Check v2 API (Docker Registry HTTP API V2)
    v2_url = f"{url.rstrip('/')}/v2/"
    status_code, body, headers = await _fetch_url(v2_url, timeout=10)

    if status_code == 200 and body:
        body_lower = body.lower()[:3000]

        # CONTENT VALIDATION: Reject if response looks like HTML (SPA catch-all)
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script"]
        html_matches = sum(1 for ind in html_indicators if ind in body_lower)
        if html_matches >= 2:
            return results  # Skip - this is HTML, not a Docker registry

        # Docker registry v2 API returns specific JSON structure
        # Valid responses: {} or {"errors": [...]} or content-type: application/json
        content_type = headers.get("Content-Type", "").lower() if headers else ""
        is_json_response = "application/json" in content_type or body.strip().startswith("{")

        # Check for Docker-specific header
        docker_header = headers.get("Docker-Distribution-Api-Version", "") if headers else ""
        has_docker_header = "registry/2" in docker_header.lower()

        # Require either Docker header OR valid JSON response
        if not has_docker_header and not is_json_response:
            return results  # Skip - doesn't look like a Docker registry

        results["vulnerable"] = True
        results["severity"] = "high"
        results["registry_type"] = "docker"

        # Check if catalog is accessible
        catalog_url = f"{url.rstrip('/')}/v2/_catalog"
        cat_status, cat_body, _ = await _fetch_url(catalog_url, timeout=10)

        if cat_status == 200 and cat_body:
            # Validate catalog response is JSON with repositories
            try:
                import json
                catalog_data = json.loads(cat_body)
                if "repositories" in catalog_data:
                    results["catalog_accessible"] = True
                    results["severity"] = "critical"
                    repos = catalog_data.get("repositories", [])
                    results["repositories"] = repos[:20]  # Limit to 20
            except Exception:
                pass

    elif status_code == 401:
        # Registry exists but requires auth
        results["registry_type"] = "docker"
        results["severity"] = "info"

    return results
