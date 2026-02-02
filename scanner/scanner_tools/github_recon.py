"""
GitHub Reconnaissance and Credential Scanning Module

Scans GitHub organizations and repositories for exposed secrets:
- API keys (AWS, GCP, Azure, Stripe, etc.)
- Private keys (SSH, RSA, EC, PGP)
- Database connection strings
- JWT secrets
- OAuth credentials
- Environment variables

Uses pattern-based detection similar to TruffleHog/GitLeaks methodologies.

IMPORTANT: This module is for DEFENSIVE security scanning only.
It helps organizations identify and remediate leaked credentials.
"""

import asyncio
import base64
import logging
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Classification of discovered secrets"""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GCP_API_KEY = "gcp_api_key"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    AZURE_CLIENT_SECRET = "azure_client_secret"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    SLACK_TOKEN = "slack_token"
    SLACK_WEBHOOK = "slack_webhook"
    STRIPE_KEY = "stripe_key"
    STRIPE_RESTRICTED = "stripe_restricted"
    TWILIO_KEY = "twilio_key"
    SENDGRID_KEY = "sendgrid_key"
    MAILGUN_KEY = "mailgun_key"
    NPM_TOKEN = "npm_token"
    PYPI_TOKEN = "pypi_token"
    DOCKER_CONFIG = "docker_config"
    SSH_PRIVATE_KEY = "ssh_private_key"
    RSA_PRIVATE_KEY = "rsa_private_key"
    EC_PRIVATE_KEY = "ec_private_key"
    PGP_PRIVATE_KEY = "pgp_private_key"
    JWT_SECRET = "jwt_secret"
    DATABASE_URL = "database_url"
    GENERIC_SECRET = "generic_secret"
    GENERIC_API_KEY = "generic_api_key"
    OAUTH_CLIENT_SECRET = "oauth_client_secret"
    FIREBASE_KEY = "firebase_key"
    HEROKU_API_KEY = "heroku_api_key"
    SHOPIFY_KEY = "shopify_key"
    SQUARE_KEY = "square_key"
    PAYPAL_KEY = "paypal_key"


@dataclass
class SecretFinding:
    """Represents a discovered secret"""
    secret_type: SecretType
    severity: str  # critical, high, medium, low
    file_path: str
    line_number: int | None
    commit_sha: str | None
    commit_author: str | None
    commit_date: str | None
    match_text: str  # Redacted version of the match
    full_match: str  # Full match for verification (redacted in output)
    context: str  # Surrounding code context
    repository: str
    branch: str | None
    verified: bool  # Whether the secret was verified as active


# Secret detection patterns
# Each pattern includes: regex, secret type, severity, description
SECRET_PATTERNS: list[tuple[str, SecretType, str, str]] = [
    # AWS
    (
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        SecretType.AWS_ACCESS_KEY,
        "critical",
        "AWS Access Key ID"
    ),
    (
        r"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        SecretType.AWS_SECRET_KEY,
        "critical",
        "AWS Secret Access Key"
    ),

    # GCP
    (
        r"AIza[0-9A-Za-z_-]{35}",
        SecretType.GCP_API_KEY,
        "high",
        "Google Cloud API Key"
    ),
    (
        r'"type"\s*:\s*"service_account"',
        SecretType.GCP_SERVICE_ACCOUNT,
        "critical",
        "GCP Service Account JSON"
    ),

    # Azure
    (
        r"(?i)(?:azure|client)[_-]?(?:client)?[_-]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9~._-]{34,})['\"]?",
        SecretType.AZURE_CLIENT_SECRET,
        "critical",
        "Azure Client Secret"
    ),

    # GitHub
    (
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
        SecretType.GITHUB_TOKEN,
        "critical",
        "GitHub Personal Access Token"
    ),
    (
        r"github_pat_[A-Za-z0-9_]{22,}",
        SecretType.GITHUB_TOKEN,
        "critical",
        "GitHub Fine-grained PAT"
    ),

    # GitLab
    (
        r"glpat-[A-Za-z0-9_-]{20,}",
        SecretType.GITLAB_TOKEN,
        "critical",
        "GitLab Personal Access Token"
    ),

    # Slack
    (
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        SecretType.SLACK_TOKEN,
        "high",
        "Slack Token"
    ),
    (
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        SecretType.SLACK_WEBHOOK,
        "medium",
        "Slack Webhook URL"
    ),

    # Stripe
    (
        r"sk_live_[0-9a-zA-Z]{24,}",
        SecretType.STRIPE_KEY,
        "critical",
        "Stripe Live Secret Key"
    ),
    (
        r"sk_test_[0-9a-zA-Z]{24,}",
        SecretType.STRIPE_KEY,
        "medium",
        "Stripe Test Secret Key"
    ),
    (
        r"rk_live_[0-9a-zA-Z]{24,}",
        SecretType.STRIPE_RESTRICTED,
        "high",
        "Stripe Live Restricted Key"
    ),

    # Twilio
    (
        r"SK[0-9a-fA-F]{32}",
        SecretType.TWILIO_KEY,
        "high",
        "Twilio API Key"
    ),

    # SendGrid
    (
        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        SecretType.SENDGRID_KEY,
        "high",
        "SendGrid API Key"
    ),

    # Mailgun
    (
        r"key-[0-9a-zA-Z]{32}",
        SecretType.MAILGUN_KEY,
        "high",
        "Mailgun API Key"
    ),

    # NPM
    (
        r"npm_[A-Za-z0-9]{36}",
        SecretType.NPM_TOKEN,
        "high",
        "NPM Access Token"
    ),

    # PyPI
    (
        r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
        SecretType.PYPI_TOKEN,
        "high",
        "PyPI API Token"
    ),

    # Firebase
    (
        r"(?i)firebase[a-z0-9_-]*['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
        SecretType.FIREBASE_KEY,
        "high",
        "Firebase API Key"
    ),

    # Heroku
    (
        r"(?i)heroku[a-z0-9_-]*['\"]?\s*[:=]\s*['\"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]?",
        SecretType.HEROKU_API_KEY,
        "high",
        "Heroku API Key"
    ),

    # Shopify
    (
        r"shpat_[a-fA-F0-9]{32}",
        SecretType.SHOPIFY_KEY,
        "high",
        "Shopify Admin Access Token"
    ),
    (
        r"shpss_[a-fA-F0-9]{32}",
        SecretType.SHOPIFY_KEY,
        "high",
        "Shopify Shared Secret"
    ),

    # Square
    (
        r"sq0atp-[0-9A-Za-z_-]{22}",
        SecretType.SQUARE_KEY,
        "high",
        "Square Access Token"
    ),
    (
        r"sq0csp-[0-9A-Za-z_-]{43}",
        SecretType.SQUARE_KEY,
        "critical",
        "Square OAuth Secret"
    ),

    # PayPal
    (
        r"(?i)paypal[a-z0-9_-]*secret['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
        SecretType.PAYPAL_KEY,
        "critical",
        "PayPal Secret Key"
    ),

    # Private Keys
    (
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        SecretType.RSA_PRIVATE_KEY,
        "critical",
        "RSA Private Key"
    ),
    (
        r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
        SecretType.EC_PRIVATE_KEY,
        "critical",
        "EC Private Key"
    ),
    (
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
        SecretType.SSH_PRIVATE_KEY,
        "critical",
        "OpenSSH Private Key"
    ),
    (
        r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
        SecretType.SSH_PRIVATE_KEY,
        "critical",
        "DSA Private Key"
    ),
    (
        r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
        SecretType.PGP_PRIVATE_KEY,
        "critical",
        "PGP Private Key"
    ),
    (
        r"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----",
        SecretType.RSA_PRIVATE_KEY,
        "high",
        "Encrypted Private Key"
    ),

    # Database Connection Strings
    (
        r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|oracle|redis|amqp)://[^\s'\"<>]+",
        SecretType.DATABASE_URL,
        "critical",
        "Database Connection String"
    ),
    (
        r"(?i)(?:jdbc:(?:mysql|postgresql|oracle|sqlserver|sqlite)):[^\s'\"<>]+",
        SecretType.DATABASE_URL,
        "critical",
        "JDBC Connection String"
    ),

    # JWT
    (
        r"(?i)(?:jwt[_-]?secret|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,})['\"]?",
        SecretType.JWT_SECRET,
        "high",
        "JWT Secret Key"
    ),
    (
        r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        SecretType.JWT_SECRET,
        "medium",
        "JWT Token (may contain sensitive claims)"
    ),

    # OAuth
    (
        r"(?i)(?:client[_-]?secret|oauth[_-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
        SecretType.OAUTH_CLIENT_SECRET,
        "high",
        "OAuth Client Secret"
    ),

    # Generic patterns (lower confidence)
    (
        r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,64})['\"]?",
        SecretType.GENERIC_API_KEY,
        "medium",
        "Generic API Key"
    ),
    (
        r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,64})['\"]?",
        SecretType.GENERIC_SECRET,
        "medium",
        "Password in code"
    ),
    (
        r"(?i)(?:secret|token|auth)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,64})['\"]?",
        SecretType.GENERIC_SECRET,
        "low",
        "Generic Secret/Token"
    ),
]

# File patterns that commonly contain secrets
SENSITIVE_FILE_PATTERNS = [
    r"\.env$",
    r"\.env\.[a-z]+$",
    r"\.env\.local$",
    r"\.env\.production$",
    r"\.env\.development$",
    r"config\.json$",
    r"secrets\.json$",
    r"credentials\.json$",
    r"\.aws/credentials$",
    r"\.aws/config$",
    r"\.npmrc$",
    r"\.pypirc$",
    r"\.netrc$",
    r"\.htpasswd$",
    r"\.git-credentials$",
    r"id_rsa$",
    r"id_dsa$",
    r"id_ecdsa$",
    r"id_ed25519$",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"docker-compose\.ya?ml$",
    r"Dockerfile$",
    r"\.dockercfg$",
    r"\.docker/config\.json$",
    r"terraform\.tfvars$",
    r"\.tfstate$",
    r"ansible/.*\.ya?ml$",
    r"vault\.ya?ml$",
]

# Files to skip (too large, binary, or irrelevant)
SKIP_FILE_PATTERNS = [
    r"\.min\.js$",
    r"\.bundle\.js$",
    r"node_modules/",
    r"vendor/",
    r"\.git/objects/",
    r"\.pyc$",
    r"\.class$",
    r"\.jar$",
    r"\.exe$",
    r"\.dll$",
    r"\.so$",
    r"\.dylib$",
    r"\.png$",
    r"\.jpg$",
    r"\.gif$",
    r"\.svg$",
    r"\.ico$",
    r"\.woff",
    r"\.ttf$",
    r"\.pdf$",
    r"\.zip$",
    r"\.tar",
    r"\.gz$",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"Gemfile\.lock$",
    r"composer\.lock$",
]


def redact_secret(secret: str, reveal_chars: int = 4) -> str:
    """Redact a secret, showing only first and last few characters."""
    if len(secret) <= reveal_chars * 2:
        return "*" * len(secret)
    return secret[:reveal_chars] + "*" * (len(secret) - reveal_chars * 2) + secret[-reveal_chars:]


def should_skip_file(file_path: str) -> bool:
    """Check if a file should be skipped during scanning."""
    for pattern in SKIP_FILE_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


def is_sensitive_file(file_path: str) -> bool:
    """Check if a file is likely to contain secrets based on its path."""
    for pattern in SENSITIVE_FILE_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


def extract_context(content: str, match_start: int, match_end: int, context_lines: int = 2) -> str:
    """Extract surrounding context around a match."""
    # Find line boundaries
    lines = content.split("\n")
    char_count = 0
    match_line_idx = 0

    for i, line in enumerate(lines):
        line_end = char_count + len(line) + 1  # +1 for newline
        if char_count <= match_start < line_end:
            match_line_idx = i
            break
        char_count = line_end

    # Extract context lines
    start_idx = max(0, match_line_idx - context_lines)
    end_idx = min(len(lines), match_line_idx + context_lines + 1)

    context_lines_list = []
    for i in range(start_idx, end_idx):
        prefix = ">>> " if i == match_line_idx else "    "
        context_lines_list.append(f"{prefix}{lines[i]}")

    return "\n".join(context_lines_list)


def scan_content_for_secrets(
    content: str,
    file_path: str,
    repository: str,
    branch: str | None = None,
    commit_sha: str | None = None,
    commit_author: str | None = None,
    commit_date: str | None = None,
) -> list[SecretFinding]:
    """
    Scan content for secrets using pattern matching.

    Args:
        content: File content to scan
        file_path: Path of the file
        repository: Repository name
        branch: Branch name
        commit_sha: Commit SHA
        commit_author: Commit author
        commit_date: Commit date

    Returns:
        List of SecretFinding objects
    """
    findings = []
    seen_matches = set()  # Avoid duplicates

    # Check if this is a sensitive file (increases severity)
    is_sensitive = is_sensitive_file(file_path)

    for pattern, secret_type, severity, description in SECRET_PATTERNS:
        try:
            for match in re.finditer(pattern, content, re.MULTILINE):
                match_text = match.group(0)

                # Deduplicate
                match_key = (file_path, match_text[:50])
                if match_key in seen_matches:
                    continue
                seen_matches.add(match_key)

                # Calculate line number
                line_number = content[:match.start()].count("\n") + 1

                # Extract context
                context = extract_context(content, match.start(), match.end())

                # Boost severity for sensitive files
                effective_severity = severity
                if is_sensitive and severity in ("medium", "low"):
                    effective_severity = "high" if severity == "medium" else "medium"

                # Validate the finding (basic entropy check for generic patterns)
                if secret_type in (SecretType.GENERIC_SECRET, SecretType.GENERIC_API_KEY):
                    # Skip low-entropy matches for generic patterns
                    if not _has_sufficient_entropy(match_text):
                        continue

                finding = SecretFinding(
                    secret_type=secret_type,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_number,
                    commit_sha=commit_sha,
                    commit_author=commit_author,
                    commit_date=commit_date,
                    match_text=redact_secret(match_text),
                    full_match=match_text,
                    context=context,
                    repository=repository,
                    branch=branch,
                    verified=False,  # Would need API calls to verify
                )
                findings.append(finding)

        except re.error as e:
            logger.warning(f"Regex error for pattern {pattern}: {e}")

    return findings


def _has_sufficient_entropy(text: str, threshold: float = 3.0) -> bool:
    """Check if a string has sufficient entropy to be a real secret."""
    import math
    from collections import Counter

    if len(text) < 8:
        return False

    # Calculate Shannon entropy
    freq = Counter(text)
    probs = [count / len(text) for count in freq.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)

    return entropy >= threshold


async def scan_github_repository(
    repo_url: str,
    github_token: str | None = None,
    branch: str = "main",
    include_history: bool = False,
    max_commits: int = 100,
) -> list[SecretFinding]:
    """
    Scan a GitHub repository for exposed secrets.

    Args:
        repo_url: GitHub repository URL (e.g., https://github.com/owner/repo)
        github_token: Optional GitHub token for API access
        branch: Branch to scan
        include_history: Whether to scan commit history
        max_commits: Maximum commits to scan in history

    Returns:
        List of SecretFinding objects
    """
    findings = []

    # Parse repository URL
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?", repo_url)
    if not match:
        logger.error(f"Invalid GitHub repository URL: {repo_url}")
        return findings

    owner, repo = match.groups()
    repo = repo.rstrip(".git")
    repository = f"{owner}/{repo}"

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ShakeSpan-Scanner/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    async with httpx.AsyncClient(headers=headers) as client:
        # Get repository default branch if not specified
        try:
            resp = await client.get(
                f"https://api.github.com/repos/{repository}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                repo_data = resp.json()
                if branch == "main":
                    branch = repo_data.get("default_branch", "main")
        except httpx.RequestError:
            pass

        # Get repository tree
        try:
            tree_url = f"https://api.github.com/repos/{repository}/git/trees/{branch}?recursive=1"
            resp = await client.get(tree_url, timeout=30.0)

            if resp.status_code == 200:
                tree_data = resp.json()
                files = [
                    item["path"]
                    for item in tree_data.get("tree", [])
                    if item["type"] == "blob" and not should_skip_file(item["path"])
                ]

                # Prioritize sensitive files
                sensitive_files = [f for f in files if is_sensitive_file(f)]
                other_files = [f for f in files if not is_sensitive_file(f)]
                files = sensitive_files + other_files[:200]  # Limit to avoid rate limits

                logger.info(f"Scanning {len(files)} files in {repository}")

                # Scan files
                for file_path in files:
                    try:
                        content_url = f"https://api.github.com/repos/{repository}/contents/{file_path}?ref={branch}"
                        resp = await client.get(content_url, timeout=10.0)

                        if resp.status_code == 200:
                            content_data = resp.json()

                            # Decode content
                            if content_data.get("encoding") == "base64":
                                content = base64.b64decode(content_data["content"]).decode("utf-8", errors="ignore")
                            else:
                                content = content_data.get("content", "")

                            # Scan for secrets
                            file_findings = scan_content_for_secrets(
                                content=content,
                                file_path=file_path,
                                repository=repository,
                                branch=branch,
                            )
                            findings.extend(file_findings)

                    except httpx.RequestError as e:
                        logger.debug(f"Failed to fetch {file_path}: {e}")
                    except UnicodeDecodeError:
                        pass  # Skip binary files

                    # Rate limit awareness
                    await asyncio.sleep(0.1)

            elif resp.status_code == 404:
                logger.warning(f"Repository or branch not found: {repository}/{branch}")
            elif resp.status_code == 403:
                logger.warning("GitHub API rate limit exceeded. Consider using a token.")

        except httpx.RequestError as e:
            logger.error(f"Failed to fetch repository tree: {e}")

        # Scan commit history if requested
        if include_history:
            findings.extend(
                await _scan_commit_history(
                    client=client,
                    repository=repository,
                    branch=branch,
                    max_commits=max_commits,
                )
            )

    return findings


async def _scan_commit_history(
    client: httpx.AsyncClient,
    repository: str,
    branch: str,
    max_commits: int,
) -> list[SecretFinding]:
    """Scan commit history for secrets that may have been removed."""
    findings = []

    try:
        commits_url = f"https://api.github.com/repos/{repository}/commits?sha={branch}&per_page={min(max_commits, 100)}"
        resp = await client.get(commits_url, timeout=30.0)

        if resp.status_code != 200:
            return findings

        commits = resp.json()
        logger.info(f"Scanning {len(commits)} commits for {repository}")

        for commit_data in commits[:max_commits]:
            commit_sha = commit_data["sha"]
            commit_author = commit_data.get("commit", {}).get("author", {}).get("name")
            commit_date = commit_data.get("commit", {}).get("author", {}).get("date")

            # Get commit diff
            try:
                commit_url = f"https://api.github.com/repos/{repository}/commits/{commit_sha}"
                resp = await client.get(commit_url, timeout=10.0)

                if resp.status_code == 200:
                    commit_detail = resp.json()

                    for file_data in commit_detail.get("files", []):
                        patch = file_data.get("patch", "")
                        file_path = file_data.get("filename", "")

                        if should_skip_file(file_path):
                            continue

                        # Scan the patch for secrets
                        file_findings = scan_content_for_secrets(
                            content=patch,
                            file_path=file_path,
                            repository=repository,
                            branch=branch,
                            commit_sha=commit_sha,
                            commit_author=commit_author,
                            commit_date=commit_date,
                        )

                        for finding in file_findings:
                            finding.severity = "critical"  # Historical secrets are more concerning
                        findings.extend(file_findings)

            except httpx.RequestError:
                pass

            await asyncio.sleep(0.2)  # Rate limiting

    except httpx.RequestError as e:
        logger.error(f"Failed to fetch commit history: {e}")

    return findings


async def scan_github_organization(
    org_name: str,
    github_token: str | None = None,
    include_forks: bool = False,
    include_history: bool = False,
    max_repos: int = 50,
) -> dict[str, list[SecretFinding]]:
    """
    Scan all repositories in a GitHub organization.

    Args:
        org_name: GitHub organization name
        github_token: GitHub token (required for private repos)
        include_forks: Whether to include forked repositories
        include_history: Whether to scan commit history
        max_repos: Maximum repositories to scan

    Returns:
        Dict mapping repository names to lists of findings
    """
    results = {}

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ShakeSpan-Scanner/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    async with httpx.AsyncClient(headers=headers) as client:
        try:
            # Get organization repositories
            repos_url = f"https://api.github.com/orgs/{org_name}/repos?per_page=100&sort=pushed"
            resp = await client.get(repos_url, timeout=30.0)

            if resp.status_code != 200:
                logger.error(f"Failed to fetch organization repos: {resp.status_code}")
                return results

            repos = resp.json()

            # Filter forks if requested
            if not include_forks:
                repos = [r for r in repos if not r.get("fork", False)]

            repos = repos[:max_repos]
            logger.info(f"Scanning {len(repos)} repositories in {org_name}")

            for repo_data in repos:
                repo_name = repo_data["full_name"]
                repo_url = repo_data["html_url"]

                logger.info(f"Scanning {repo_name}")

                findings = await scan_github_repository(
                    repo_url=repo_url,
                    github_token=github_token,
                    include_history=include_history,
                )

                if findings:
                    results[repo_name] = findings

        except httpx.RequestError as e:
            logger.error(f"Failed to scan organization: {e}")

    return results


def scan_local_directory(
    directory: str,
    repository_name: str = "local",
) -> list[SecretFinding]:
    """
    Scan a local directory for secrets.

    Args:
        directory: Path to directory to scan
        repository_name: Name to use for the repository in findings

    Returns:
        List of SecretFinding objects
    """
    import os

    findings = []

    for root, dirs, files in os.walk(directory):
        # Skip hidden directories and common non-source directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__", "venv", ".venv")]

        for filename in files:
            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, directory)

            if should_skip_file(relative_path):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                file_findings = scan_content_for_secrets(
                    content=content,
                    file_path=relative_path,
                    repository=repository_name,
                )
                findings.extend(file_findings)

            except (IOError, OSError) as e:
                logger.debug(f"Failed to read {file_path}: {e}")

    return findings


async def run_trufflehog_scan(
    target: str,
    scan_type: str = "github",
) -> list[SecretFinding]:
    """
    Run TruffleHog for additional secret scanning (if installed).

    Args:
        target: Target to scan (repo URL or directory path)
        scan_type: Type of scan (github, filesystem, git)

    Returns:
        List of SecretFinding objects
    """
    findings = []

    # Check if trufflehog is installed
    try:
        result = subprocess.run(
            ["trufflehog", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            logger.debug("TruffleHog not installed, skipping")
            return findings
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.debug("TruffleHog not available")
        return findings

    # Build command based on scan type
    cmd = ["trufflehog", "--json", "--no-update"]

    if scan_type == "github":
        cmd.extend(["github", "--repo", target])
    elif scan_type == "filesystem":
        cmd.extend(["filesystem", target])
    elif scan_type == "git":
        cmd.extend(["git", target])
    else:
        return findings

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        for line in result.stdout.split("\n"):
            if not line.strip():
                continue

            try:
                import json
                data = json.loads(line)

                # Convert TruffleHog output to our format
                finding = SecretFinding(
                    secret_type=SecretType.GENERIC_SECRET,
                    severity="high",
                    file_path=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown"),
                    line_number=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line"),
                    commit_sha=data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit"),
                    commit_author=None,
                    commit_date=None,
                    match_text=redact_secret(data.get("Raw", "")[:100]),
                    full_match=data.get("Raw", ""),
                    context="",
                    repository=target,
                    branch=None,
                    verified=data.get("Verified", False),
                )

                # Map detector type to our SecretType
                detector = data.get("DetectorType", "").lower()
                if "aws" in detector:
                    finding.secret_type = SecretType.AWS_ACCESS_KEY
                    finding.severity = "critical"
                elif "github" in detector:
                    finding.secret_type = SecretType.GITHUB_TOKEN
                    finding.severity = "critical"
                elif "slack" in detector:
                    finding.secret_type = SecretType.SLACK_TOKEN
                    finding.severity = "high"
                elif "stripe" in detector:
                    finding.secret_type = SecretType.STRIPE_KEY
                    finding.severity = "critical"

                findings.append(finding)

            except (json.JSONDecodeError, KeyError):
                continue

    except subprocess.TimeoutExpired:
        logger.warning("TruffleHog scan timed out")
    except Exception as e:
        logger.error(f"TruffleHog scan failed: {e}")

    return findings


def format_findings_report(findings: list[SecretFinding]) -> str:
    """Format findings into a readable report."""
    if not findings:
        return "No secrets detected."

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for finding in findings:
        by_severity[finding.severity].append(finding)

    lines = []
    lines.append(f"GitHub Credential Scan Report")
    lines.append(f"=" * 50)
    lines.append(f"Total findings: {len(findings)}")
    lines.append(f"  Critical: {len(by_severity['critical'])}")
    lines.append(f"  High: {len(by_severity['high'])}")
    lines.append(f"  Medium: {len(by_severity['medium'])}")
    lines.append(f"  Low: {len(by_severity['low'])}")
    lines.append("")

    for severity in ["critical", "high", "medium", "low"]:
        if not by_severity[severity]:
            continue

        lines.append(f"{severity.upper()} Severity Findings")
        lines.append("-" * 40)

        for finding in by_severity[severity]:
            lines.append(f"\n[{finding.secret_type.value}]")
            lines.append(f"  File: {finding.file_path}:{finding.line_number}")
            lines.append(f"  Repository: {finding.repository}")
            if finding.commit_sha:
                lines.append(f"  Commit: {finding.commit_sha[:8]}")
                if finding.commit_author:
                    lines.append(f"  Author: {finding.commit_author}")
            lines.append(f"  Match: {finding.match_text}")
            if finding.context:
                lines.append(f"  Context:\n{finding.context}")

        lines.append("")

    return "\n".join(lines)


# Convenience function for scanner integration
async def scan_for_credentials(
    target: str,
    github_token: str | None = None,
    include_history: bool = False,
) -> dict[str, Any]:
    """
    Main entry point for credential scanning.

    Args:
        target: GitHub repo URL, org name, or local directory
        github_token: GitHub token for API access
        include_history: Whether to scan commit history

    Returns:
        Dict with findings and summary
    """
    findings = []

    if target.startswith("https://github.com/"):
        # Single repository
        findings = await scan_github_repository(
            repo_url=target,
            github_token=github_token,
            include_history=include_history,
        )
    elif "/" not in target and not target.startswith("/"):
        # Assume organization name
        org_results = await scan_github_organization(
            org_name=target,
            github_token=github_token,
            include_history=include_history,
        )
        for repo_findings in org_results.values():
            findings.extend(repo_findings)
    else:
        # Local directory
        findings = scan_local_directory(target)

    # Convert to dict format
    return {
        "findings": [
            {
                "type": f.secret_type.value,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "match": f.match_text,
                "repository": f.repository,
                "commit_sha": f.commit_sha,
                "verified": f.verified,
            }
            for f in findings
        ],
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "report": format_findings_report(findings),
    }
