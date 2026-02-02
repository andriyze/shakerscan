"""
Google Dorking Automation Module

Automates Google dork searches to find exposed files, admin panels,
and sensitive information for a target domain.

Categories of dorks:
- Exposed files (env, sql, bak, config)
- Admin panels
- Directory listings
- Login pages
- Error messages with stack traces
- Sensitive documents
- Third-party exposure (Pastebin, Trello, etc.)

IMPORTANT: This module is for DEFENSIVE security reconnaissance.
It helps organizations discover their own exposed assets.

Note: Direct Google scraping violates ToS. This module is designed
to work with search APIs (SerpAPI, Google Custom Search, etc.) or
generate dork queries for manual use.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import quote_plus, urlencode, urlparse

import httpx

logger = logging.getLogger(__name__)


class DorkCategory(Enum):
    """Categories of Google dorks"""
    EXPOSED_FILES = "exposed_files"
    ADMIN_PANELS = "admin_panels"
    LOGIN_PAGES = "login_pages"
    DIRECTORY_LISTING = "directory_listing"
    SENSITIVE_DOCS = "sensitive_docs"
    DATABASE_FILES = "database_files"
    BACKUP_FILES = "backup_files"
    CONFIG_FILES = "config_files"
    ERROR_MESSAGES = "error_messages"
    TECHNOLOGY_DETECTION = "tech_detection"
    THIRD_PARTY_EXPOSURE = "third_party"
    CLOUD_EXPOSURE = "cloud_exposure"
    API_EXPOSURE = "api_exposure"


@dataclass
class DorkResult:
    """Represents a Google dork search result"""
    dork_query: str
    category: DorkCategory
    severity: str  # critical, high, medium, low, info
    title: str
    url: str
    snippet: str
    cached_url: str | None
    discovered_at: datetime


@dataclass
class DorkQuery:
    """Represents a Google dork query template"""
    template: str
    category: DorkCategory
    severity: str
    description: str
    risk_info: str


# Google dork templates organized by category
DORK_TEMPLATES: list[DorkQuery] = [
    # Exposed Environment Files (Critical)
    DorkQuery(
        template='site:{domain} filetype:env',
        category=DorkCategory.EXPOSED_FILES,
        severity="critical",
        description="Environment files with credentials",
        risk_info="May contain database passwords, API keys, and secrets"
    ),
    DorkQuery(
        template='site:{domain} filetype:env DB_PASSWORD',
        category=DorkCategory.EXPOSED_FILES,
        severity="critical",
        description="Environment files with database passwords",
        risk_info="Exposed database credentials"
    ),
    DorkQuery(
        template='site:{domain} "DB_PASSWORD" OR "DATABASE_URL" OR "MONGODB_URI"',
        category=DorkCategory.EXPOSED_FILES,
        severity="critical",
        description="Database connection strings",
        risk_info="Exposed database credentials in code or configs"
    ),

    # SQL Database Files (Critical)
    DorkQuery(
        template='site:{domain} filetype:sql',
        category=DorkCategory.DATABASE_FILES,
        severity="critical",
        description="SQL dump files",
        risk_info="May contain entire database dumps with user data"
    ),
    DorkQuery(
        template='site:{domain} filetype:sql "INSERT INTO" "users"',
        category=DorkCategory.DATABASE_FILES,
        severity="critical",
        description="SQL dumps with user data",
        risk_info="User records possibly including passwords"
    ),
    DorkQuery(
        template='site:{domain} filetype:mdb OR filetype:accdb',
        category=DorkCategory.DATABASE_FILES,
        severity="high",
        description="Microsoft Access database files",
        risk_info="Database files with potential sensitive data"
    ),

    # Backup Files (High)
    DorkQuery(
        template='site:{domain} filetype:bak',
        category=DorkCategory.BACKUP_FILES,
        severity="high",
        description="Backup files",
        risk_info="May contain outdated but sensitive configurations"
    ),
    DorkQuery(
        template='site:{domain} filetype:old OR filetype:backup',
        category=DorkCategory.BACKUP_FILES,
        severity="high",
        description="Old/backup files",
        risk_info="Legacy files that may contain secrets"
    ),
    DorkQuery(
        template='site:{domain} inurl:backup OR inurl:bkp OR inurl:old',
        category=DorkCategory.BACKUP_FILES,
        severity="medium",
        description="Backup directories",
        risk_info="Backup folders possibly containing sensitive files"
    ),

    # Configuration Files (High)
    DorkQuery(
        template='site:{domain} filetype:conf OR filetype:cnf',
        category=DorkCategory.CONFIG_FILES,
        severity="high",
        description="Configuration files",
        risk_info="Server/application configuration with possible credentials"
    ),
    DorkQuery(
        template='site:{domain} filetype:ini',
        category=DorkCategory.CONFIG_FILES,
        severity="medium",
        description="INI configuration files",
        risk_info="Application settings possibly with credentials"
    ),
    DorkQuery(
        template='site:{domain} filetype:yml OR filetype:yaml "password:"',
        category=DorkCategory.CONFIG_FILES,
        severity="critical",
        description="YAML files with passwords",
        risk_info="Configuration files containing credentials"
    ),
    DorkQuery(
        template='site:{domain} filetype:json "password" OR "apiKey" OR "secret"',
        category=DorkCategory.CONFIG_FILES,
        severity="high",
        description="JSON files with credentials",
        risk_info="Configuration or data files with sensitive values"
    ),
    DorkQuery(
        template='site:{domain} filetype:xml "password" OR "apikey"',
        category=DorkCategory.CONFIG_FILES,
        severity="high",
        description="XML files with credentials",
        risk_info="Configuration files with possible credentials"
    ),
    DorkQuery(
        template='site:{domain} ".htpasswd" OR "htpasswd"',
        category=DorkCategory.CONFIG_FILES,
        severity="high",
        description="Apache htpasswd files",
        risk_info="HTTP authentication password hashes"
    ),
    DorkQuery(
        template='site:{domain} filetype:log',
        category=DorkCategory.CONFIG_FILES,
        severity="medium",
        description="Log files",
        risk_info="Application logs possibly with sensitive data"
    ),

    # Admin Panels (High)
    DorkQuery(
        template='site:{domain} inurl:admin',
        category=DorkCategory.ADMIN_PANELS,
        severity="medium",
        description="Admin panel URLs",
        risk_info="Administrative interfaces"
    ),
    DorkQuery(
        template='site:{domain} inurl:admin intitle:admin',
        category=DorkCategory.ADMIN_PANELS,
        severity="high",
        description="Admin panel pages",
        risk_info="Confirmed administrative pages"
    ),
    DorkQuery(
        template='site:{domain} inurl:administrator OR inurl:wp-admin OR inurl:phpmyadmin',
        category=DorkCategory.ADMIN_PANELS,
        severity="high",
        description="Common admin panels",
        risk_info="WordPress admin, phpMyAdmin, or administrator panels"
    ),
    DorkQuery(
        template='site:{domain} inurl:panel OR inurl:dashboard OR inurl:controlpanel',
        category=DorkCategory.ADMIN_PANELS,
        severity="medium",
        description="Control panels",
        risk_info="Web application control panels"
    ),
    DorkQuery(
        template='site:{domain} intitle:"index of" inurl:admin',
        category=DorkCategory.ADMIN_PANELS,
        severity="high",
        description="Admin directory listing",
        risk_info="Exposed admin directory contents"
    ),

    # Login Pages (Medium)
    DorkQuery(
        template='site:{domain} inurl:login OR inurl:signin OR inurl:auth',
        category=DorkCategory.LOGIN_PAGES,
        severity="info",
        description="Login pages",
        risk_info="Authentication endpoints"
    ),
    DorkQuery(
        template='site:{domain} intitle:login OR intitle:"log in" OR intitle:signin',
        category=DorkCategory.LOGIN_PAGES,
        severity="info",
        description="Login page titles",
        risk_info="User authentication pages"
    ),

    # Directory Listings (High)
    DorkQuery(
        template='site:{domain} intitle:"index of"',
        category=DorkCategory.DIRECTORY_LISTING,
        severity="high",
        description="Directory listings",
        risk_info="Exposed directory contents"
    ),
    DorkQuery(
        template='site:{domain} intitle:"index of" "parent directory"',
        category=DorkCategory.DIRECTORY_LISTING,
        severity="high",
        description="Apache directory listings",
        risk_info="Apache-style directory browsing enabled"
    ),
    DorkQuery(
        template='site:{domain} intitle:"index of" filetype:php',
        category=DorkCategory.DIRECTORY_LISTING,
        severity="high",
        description="PHP file directory listings",
        risk_info="Exposed PHP source files"
    ),
    DorkQuery(
        template='site:{domain} intitle:"index of" "wp-content"',
        category=DorkCategory.DIRECTORY_LISTING,
        severity="medium",
        description="WordPress content listings",
        risk_info="Exposed WordPress content directory"
    ),

    # Sensitive Documents (High)
    DorkQuery(
        template='site:{domain} filetype:pdf "confidential" OR "internal use only"',
        category=DorkCategory.SENSITIVE_DOCS,
        severity="high",
        description="Confidential PDF documents",
        risk_info="Potentially confidential documents"
    ),
    DorkQuery(
        template='site:{domain} filetype:xlsx OR filetype:xls "password" OR "user"',
        category=DorkCategory.SENSITIVE_DOCS,
        severity="high",
        description="Excel files with sensitive data",
        risk_info="Spreadsheets possibly containing credentials or user data"
    ),
    DorkQuery(
        template='site:{domain} filetype:doc OR filetype:docx "confidential"',
        category=DorkCategory.SENSITIVE_DOCS,
        severity="medium",
        description="Confidential Word documents",
        risk_info="Internal documents marked confidential"
    ),
    DorkQuery(
        template='site:{domain} filetype:ppt OR filetype:pptx "internal"',
        category=DorkCategory.SENSITIVE_DOCS,
        severity="low",
        description="Internal presentations",
        risk_info="Internal company presentations"
    ),

    # Error Messages (Medium)
    DorkQuery(
        template='site:{domain} "mysql error" OR "sql syntax" OR "ORA-"',
        category=DorkCategory.ERROR_MESSAGES,
        severity="medium",
        description="SQL error messages",
        risk_info="Database error messages revealing structure"
    ),
    DorkQuery(
        template='site:{domain} "warning:" "on line" filetype:php',
        category=DorkCategory.ERROR_MESSAGES,
        severity="medium",
        description="PHP error messages",
        risk_info="PHP warnings revealing file paths"
    ),
    DorkQuery(
        template='site:{domain} "stack trace" OR "traceback" OR "Exception"',
        category=DorkCategory.ERROR_MESSAGES,
        severity="medium",
        description="Stack traces",
        risk_info="Application stack traces revealing code structure"
    ),
    DorkQuery(
        template='site:{domain} "Fatal error" OR "Parse error"',
        category=DorkCategory.ERROR_MESSAGES,
        severity="medium",
        description="Fatal PHP errors",
        risk_info="PHP fatal errors with path information"
    ),

    # Technology Detection (Info)
    DorkQuery(
        template='site:{domain} "powered by" OR "built with"',
        category=DorkCategory.TECHNOLOGY_DETECTION,
        severity="info",
        description="Technology fingerprinting",
        risk_info="Technology stack information"
    ),
    DorkQuery(
        template='site:{domain} inurl:wp-content OR inurl:wp-includes',
        category=DorkCategory.TECHNOLOGY_DETECTION,
        severity="info",
        description="WordPress installation",
        risk_info="WordPress CMS detected"
    ),
    DorkQuery(
        template='site:{domain} "joomla" OR inurl:com_content',
        category=DorkCategory.TECHNOLOGY_DETECTION,
        severity="info",
        description="Joomla installation",
        risk_info="Joomla CMS detected"
    ),
    DorkQuery(
        template='site:{domain} "drupal" OR inurl:sites/default',
        category=DorkCategory.TECHNOLOGY_DETECTION,
        severity="info",
        description="Drupal installation",
        risk_info="Drupal CMS detected"
    ),

    # Third-Party Exposure (High)
    DorkQuery(
        template='site:pastebin.com "{domain}"',
        category=DorkCategory.THIRD_PARTY_EXPOSURE,
        severity="high",
        description="Pastebin mentions",
        risk_info="Domain mentioned in paste sites (possible data leaks)"
    ),
    DorkQuery(
        template='site:trello.com "{domain}"',
        category=DorkCategory.THIRD_PARTY_EXPOSURE,
        severity="medium",
        description="Trello mentions",
        risk_info="Domain mentioned in Trello boards (possible internal info)"
    ),
    DorkQuery(
        template='site:github.com "{domain}" password OR api_key OR secret',
        category=DorkCategory.THIRD_PARTY_EXPOSURE,
        severity="critical",
        description="GitHub credential exposure",
        risk_info="Credentials mentioning domain on GitHub"
    ),
    DorkQuery(
        template='site:gitlab.com "{domain}" password OR api_key',
        category=DorkCategory.THIRD_PARTY_EXPOSURE,
        severity="high",
        description="GitLab credential exposure",
        risk_info="Credentials mentioning domain on GitLab"
    ),
    DorkQuery(
        template='site:stackoverflow.com "{domain}"',
        category=DorkCategory.THIRD_PARTY_EXPOSURE,
        severity="info",
        description="StackOverflow mentions",
        risk_info="Domain discussed on StackOverflow (may reveal tech details)"
    ),

    # Cloud Exposure (Critical)
    DorkQuery(
        template='site:s3.amazonaws.com "{domain}"',
        category=DorkCategory.CLOUD_EXPOSURE,
        severity="high",
        description="AWS S3 buckets",
        risk_info="S3 buckets associated with domain"
    ),
    DorkQuery(
        template='site:blob.core.windows.net "{domain}"',
        category=DorkCategory.CLOUD_EXPOSURE,
        severity="high",
        description="Azure Blob storage",
        risk_info="Azure storage associated with domain"
    ),
    DorkQuery(
        template='site:storage.googleapis.com "{domain}"',
        category=DorkCategory.CLOUD_EXPOSURE,
        severity="high",
        description="Google Cloud Storage",
        risk_info="GCS buckets associated with domain"
    ),
    DorkQuery(
        template='"{domain}" site:*.amazonaws.com filetype:pdf OR filetype:xlsx',
        category=DorkCategory.CLOUD_EXPOSURE,
        severity="high",
        description="AWS-hosted documents",
        risk_info="Documents hosted on AWS infrastructure"
    ),

    # API Exposure (High)
    DorkQuery(
        template='site:{domain} inurl:api OR inurl:rest OR inurl:graphql',
        category=DorkCategory.API_EXPOSURE,
        severity="medium",
        description="API endpoints",
        risk_info="Discovered API endpoints"
    ),
    DorkQuery(
        template='site:{domain} inurl:api filetype:json',
        category=DorkCategory.API_EXPOSURE,
        severity="medium",
        description="API JSON responses",
        risk_info="API endpoints returning JSON"
    ),
    DorkQuery(
        template='site:{domain} "swagger" OR "openapi" OR "api-docs"',
        category=DorkCategory.API_EXPOSURE,
        severity="medium",
        description="API documentation",
        risk_info="Exposed API documentation (Swagger/OpenAPI)"
    ),
    DorkQuery(
        template='site:{domain} intitle:"API" intitle:"documentation"',
        category=DorkCategory.API_EXPOSURE,
        severity="info",
        description="API docs pages",
        risk_info="API documentation pages"
    ),
]


def generate_dork_queries(domain: str, categories: list[DorkCategory] | None = None) -> list[tuple[str, DorkQuery]]:
    """
    Generate Google dork queries for a domain.

    Args:
        domain: Target domain
        categories: Optional list of categories to include

    Returns:
        List of (query_string, DorkQuery) tuples
    """
    queries = []

    for dork in DORK_TEMPLATES:
        if categories and dork.category not in categories:
            continue

        # Replace {domain} placeholder
        query = dork.template.replace("{domain}", domain)
        queries.append((query, dork))

    return queries


def generate_google_search_url(query: str) -> str:
    """Generate a Google search URL for a dork query."""
    return f"https://www.google.com/search?q={quote_plus(query)}"


def generate_bing_search_url(query: str) -> str:
    """Generate a Bing search URL for a dork query."""
    return f"https://www.bing.com/search?q={quote_plus(query)}"


def generate_duckduckgo_url(query: str) -> str:
    """Generate a DuckDuckGo search URL for a dork query."""
    return f"https://duckduckgo.com/?q={quote_plus(query)}"


async def search_with_serpapi(
    query: str,
    api_key: str,
    num_results: int = 10,
) -> list[dict]:
    """
    Execute a search using SerpAPI.

    Args:
        query: Search query
        api_key: SerpAPI key
        num_results: Number of results to fetch

    Returns:
        List of search result dicts
    """
    results = []

    params = {
        "q": query,
        "api_key": api_key,
        "engine": "google",
        "num": num_results,
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                "https://serpapi.com/search",
                params=params,
                timeout=30.0,
            )

            if resp.status_code == 200:
                data = resp.json()

                for result in data.get("organic_results", []):
                    results.append({
                        "title": result.get("title", ""),
                        "url": result.get("link", ""),
                        "snippet": result.get("snippet", ""),
                        "cached_url": result.get("cached_page_link"),
                    })

        except httpx.RequestError as e:
            logger.warning(f"SerpAPI search failed: {e}")

    return results


async def search_with_google_cse(
    query: str,
    api_key: str,
    cse_id: str,
    num_results: int = 10,
) -> list[dict]:
    """
    Execute a search using Google Custom Search API.

    Args:
        query: Search query
        api_key: Google API key
        cse_id: Custom Search Engine ID
        num_results: Number of results to fetch

    Returns:
        List of search result dicts
    """
    results = []

    params = {
        "q": query,
        "key": api_key,
        "cx": cse_id,
        "num": min(num_results, 10),  # API limit
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                params=params,
                timeout=30.0,
            )

            if resp.status_code == 200:
                data = resp.json()

                for item in data.get("items", []):
                    results.append({
                        "title": item.get("title", ""),
                        "url": item.get("link", ""),
                        "snippet": item.get("snippet", ""),
                        "cached_url": item.get("cacheId"),
                    })

        except httpx.RequestError as e:
            logger.warning(f"Google CSE search failed: {e}")

    return results


async def run_dork_scan(
    domain: str,
    api_key: str | None = None,
    api_provider: str = "serpapi",
    cse_id: str | None = None,
    categories: list[DorkCategory] | None = None,
    max_results_per_dork: int = 10,
    delay_between_queries: float = 2.0,
) -> list[DorkResult]:
    """
    Run a Google dorking scan against a domain.

    Args:
        domain: Target domain
        api_key: Search API key (SerpAPI or Google CSE)
        api_provider: API provider ("serpapi" or "google_cse")
        cse_id: Google Custom Search Engine ID (required for google_cse)
        categories: Optional list of categories to include
        max_results_per_dork: Max results per dork query
        delay_between_queries: Delay between queries (for rate limiting)

    Returns:
        List of DorkResult objects
    """
    results = []

    # Generate queries
    queries = generate_dork_queries(domain, categories)
    logger.info(f"Generated {len(queries)} dork queries for {domain}")

    for query_string, dork in queries:
        # Execute search
        search_results = []

        if api_key:
            if api_provider == "serpapi":
                search_results = await search_with_serpapi(
                    query_string,
                    api_key,
                    max_results_per_dork,
                )
            elif api_provider == "google_cse" and cse_id:
                search_results = await search_with_google_cse(
                    query_string,
                    api_key,
                    cse_id,
                    max_results_per_dork,
                )

        # Convert to DorkResult objects
        for sr in search_results:
            if sr.get("url"):
                result = DorkResult(
                    dork_query=query_string,
                    category=dork.category,
                    severity=dork.severity,
                    title=sr.get("title", ""),
                    url=sr.get("url", ""),
                    snippet=sr.get("snippet", ""),
                    cached_url=sr.get("cached_url"),
                    discovered_at=datetime.now(),
                )
                results.append(result)

        # Rate limiting
        if api_key:
            await asyncio.sleep(delay_between_queries)

    return results


def generate_manual_dork_list(
    domain: str,
    categories: list[DorkCategory] | None = None,
    include_urls: bool = True,
) -> str:
    """
    Generate a list of dork queries for manual searching.

    Args:
        domain: Target domain
        categories: Optional list of categories to include
        include_urls: Whether to include Google search URLs

    Returns:
        Formatted string with dork queries
    """
    queries = generate_dork_queries(domain, categories)

    lines = []
    lines.append(f"Google Dork Queries for: {domain}")
    lines.append("=" * 60)
    lines.append("")

    current_category = None

    for query_string, dork in queries:
        # Category header
        if dork.category != current_category:
            current_category = dork.category
            lines.append(f"\n### {dork.category.value.upper().replace('_', ' ')}")
            lines.append("-" * 40)

        # Query info
        lines.append(f"\n[{dork.severity.upper()}] {dork.description}")
        lines.append(f"Risk: {dork.risk_info}")
        lines.append(f"Query: {query_string}")

        if include_urls:
            lines.append(f"URL: {generate_google_search_url(query_string)}")

    return "\n".join(lines)


def filter_results_by_domain(
    results: list[DorkResult],
    domain: str,
    include_subdomains: bool = True,
) -> list[DorkResult]:
    """
    Filter results to only include those matching the target domain.

    Args:
        results: List of DorkResult objects
        domain: Target domain
        include_subdomains: Whether to include subdomain matches

    Returns:
        Filtered list of results
    """
    filtered = []

    for result in results:
        try:
            parsed = urlparse(result.url)
            result_domain = parsed.netloc.lower()

            if include_subdomains:
                if result_domain == domain or result_domain.endswith(f".{domain}"):
                    filtered.append(result)
            else:
                if result_domain == domain:
                    filtered.append(result)
        except Exception:
            continue

    return filtered


def deduplicate_results(results: list[DorkResult]) -> list[DorkResult]:
    """Remove duplicate URLs from results."""
    seen_urls = set()
    unique = []

    for result in results:
        url_normalized = result.url.rstrip("/").lower()
        if url_normalized not in seen_urls:
            seen_urls.add(url_normalized)
            unique.append(result)

    return unique


def format_dork_report(results: list[DorkResult], domain: str) -> str:
    """Format dork results into a readable report."""
    if not results:
        return f"No dork results found for {domain}"

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for result in results:
        by_severity[result.severity].append(result)

    lines = []
    lines.append(f"Google Dorking Report for: {domain}")
    lines.append("=" * 60)
    lines.append(f"Total findings: {len(results)}")
    lines.append(f"  Critical: {len(by_severity['critical'])}")
    lines.append(f"  High: {len(by_severity['high'])}")
    lines.append(f"  Medium: {len(by_severity['medium'])}")
    lines.append(f"  Low: {len(by_severity['low'])}")
    lines.append(f"  Info: {len(by_severity['info'])}")
    lines.append("")

    for severity in ["critical", "high", "medium", "low", "info"]:
        if not by_severity[severity]:
            continue

        lines.append(f"\n{severity.upper()} Severity Findings")
        lines.append("-" * 40)

        for result in by_severity[severity]:
            lines.append(f"\n[{result.category.value}]")
            lines.append(f"  Title: {result.title}")
            lines.append(f"  URL: {result.url}")
            lines.append(f"  Dork: {result.dork_query}")
            if result.snippet:
                snippet = result.snippet[:200] + "..." if len(result.snippet) > 200 else result.snippet
                lines.append(f"  Snippet: {snippet}")

    return "\n".join(lines)


# Main entry point for scanner integration
async def run_google_dorking(
    domain: str,
    api_key: str | None = None,
    api_provider: str = "serpapi",
    cse_id: str | None = None,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    """
    Main entry point for Google dorking scan.

    Args:
        domain: Target domain
        api_key: Search API key
        api_provider: API provider
        cse_id: Google CSE ID
        categories: Category names to include

    Returns:
        Dict with results, queries, and report
    """
    # Convert category names to enums
    category_enums = None
    if categories:
        category_enums = []
        for cat_name in categories:
            try:
                category_enums.append(DorkCategory(cat_name))
            except ValueError:
                logger.warning(f"Unknown category: {cat_name}")

    results = []
    if api_key:
        # Run actual search
        results = await run_dork_scan(
            domain=domain,
            api_key=api_key,
            api_provider=api_provider,
            cse_id=cse_id,
            categories=category_enums,
        )

        # Filter and deduplicate
        results = filter_results_by_domain(results, domain)
        results = deduplicate_results(results)

    # Generate manual query list regardless of API key
    manual_queries = generate_manual_dork_list(domain, category_enums)

    # Generate all queries for reference
    all_queries = generate_dork_queries(domain, category_enums)

    return {
        "domain": domain,
        "total_queries": len(all_queries),
        "results": [
            {
                "category": r.category.value,
                "severity": r.severity,
                "title": r.title,
                "url": r.url,
                "dork_query": r.dork_query,
                "snippet": r.snippet,
            }
            for r in results
        ],
        "summary": {
            "total_results": len(results),
            "critical": sum(1 for r in results if r.severity == "critical"),
            "high": sum(1 for r in results if r.severity == "high"),
            "medium": sum(1 for r in results if r.severity == "medium"),
            "low": sum(1 for r in results if r.severity == "low"),
            "info": sum(1 for r in results if r.severity == "info"),
        },
        "manual_queries": manual_queries,
        "report": format_dork_report(results, domain) if results else manual_queries,
    }


# CLI helper for generating dork lists
def print_dork_list(domain: str, categories: list[str] | None = None) -> None:
    """Print dork queries for a domain."""
    category_enums = None
    if categories:
        category_enums = [DorkCategory(c) for c in categories if c in DorkCategory.__members__]

    print(generate_manual_dork_list(domain, category_enums))
