"""
Scan configuration dataclasses.

This module consolidates the 100+ parameters of scan() into organized dataclasses,
improving code clarity and maintainability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanType(Enum):
    """Scan type enumeration."""
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    FULL = "full"
    AGGRESSIVE = "aggressive"
    SMART = "smart"

    @classmethod
    def from_string(cls, value: str) -> "ScanType":
        """Convert string to ScanType, defaulting to STANDARD."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.STANDARD


@dataclass
class AuthConfig:
    """Authentication configuration for scanning.

    Consolidates 15 scattered auth parameters into a single structured object.
    """
    # Bearer/API token authentication
    auth_header: str | None = None

    # Cookie-based authentication
    auth_cookies: str | None = None

    # Custom headers (JSON string or dict)
    auth_headers_json: str | None = None

    # Form-based login credentials
    login_url: str | None = None
    login_username: str | None = None
    login_password: str | None = None
    login_extra_fields: str | None = None  # JSON string

    # Second user for BOLA/IDOR testing
    user2_header: str | None = None
    user2_cookies: str | None = None

    # Session management
    refresh_token: str | None = None
    token_refresh_url: str | None = None
    session_timeout_minutes: int = 30

    def has_credentials(self) -> bool:
        """Check if any authentication credentials are configured."""
        return bool(
            self.auth_header or
            self.auth_cookies or
            self.auth_headers_json or
            self.login_username
        )

    def has_multi_user(self) -> bool:
        """Check if multi-user auth is configured for BOLA/IDOR testing."""
        return bool(self.user2_header or self.user2_cookies)


@dataclass
class TestConfig:
    """Test toggle configuration.

    Controls which security tests are enabled/disabled.
    """
    # Active testing (requires explicit permission)
    active: bool = False
    xss: bool = False
    sqli: bool = False

    # Passive tests (safe by default)
    nuclei: bool = True
    tls: bool = True
    headers: bool = True
    cookies: bool = True
    cors: bool = True
    dns: bool = True

    # Discovery
    discovery: bool = True
    port_scan: bool = False
    subdomain_enum: bool = False

    # Advanced tests
    graphql: bool = True
    websocket: bool = True
    jwt: bool = True
    oauth: bool = True

    # Business logic tests
    bola: bool = False
    idor: bool = False
    csrf: bool = True
    race_condition: bool = False

    # Infrastructure tests
    cloud_storage: bool = True
    cicd_exposure: bool = True
    k8s_exposure: bool = True


@dataclass
class LimitConfig:
    """Performance and resource limit configuration."""
    # Timeouts (seconds)
    timeout: int = 30
    nuclei_timeout: int = 300
    sqlmap_timeout: int = 180
    browser_timeout: int = 60

    # Rate limiting
    requests_per_second: int = 10
    max_concurrent_requests: int = 50

    # Discovery limits
    max_crawl_depth: int = 4
    max_crawl_pages: int = 100
    max_endpoints: int = 1000

    # Active test limits
    max_sqli_endpoints: int = 50
    max_xss_endpoints: int = 50
    max_params_per_endpoint: int = 10

    # Port scanning
    port_scan_top_ports: int = 1000

    # Worker settings
    max_workers: int = 5


@dataclass
class OutputConfig:
    """Output and reporting configuration."""
    # Output format
    output_format: str = "json"  # json, html, sarif
    output_file: str | None = None

    # Verbosity
    verbose: bool = False
    debug: bool = False
    quiet: bool = False

    # Result filtering
    min_severity: str = "info"
    min_confidence: float = 0.0
    exclude_info: bool = False

    # AI features
    ai_enabled: bool = False
    ai_correlations: bool = False


@dataclass
class ScanConfig:
    """Main scan configuration.

    Consolidates all scan parameters into a single structured configuration object.
    This replaces the 100+ parameter scan() function signature.

    Example usage:
        config = ScanConfig(
            target="https://example.com",
            scan_type=ScanType.SMART,
            auth=AuthConfig(auth_header="Bearer token123"),
            tests=TestConfig(xss=True, sqli=True),
            limits=LimitConfig(max_crawl_pages=200),
        )
        result = await scan(config)
    """
    # Required
    target: str

    # Scan type
    scan_type: ScanType = ScanType.STANDARD

    # Grouped configurations
    auth: AuthConfig = field(default_factory=AuthConfig)
    tests: TestConfig = field(default_factory=TestConfig)
    limits: LimitConfig = field(default_factory=LimitConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    # Smart scan specific options
    no_early_stop: bool = False
    thorough_params: bool = False

    # Custom endpoints to test
    custom_endpoints: list[str] = field(default_factory=list)

    # Discovery options
    json_link_following: bool = False
    options_method_discovery: bool = False
    grpc_discovery: bool = False

    # OpenAPI/Swagger spec
    openapi_spec: str | None = None

    # Callback URLs for OOB testing
    oob_callback_url: str | None = None

    # Metadata
    scan_id: str | None = None
    project_id: str | None = None
    tags: list[str] = field(default_factory=list)

    def is_smart_scan(self) -> bool:
        """Check if this is a smart scan."""
        return self.scan_type == ScanType.SMART

    def is_active_scan(self) -> bool:
        """Check if active testing is enabled."""
        return self.tests.active or self.tests.xss or self.tests.sqli

    def requires_permission(self) -> bool:
        """Check if scan type requires explicit user permission."""
        return self.scan_type in (ScanType.FULL, ScanType.AGGRESSIVE, ScanType.SMART)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        """Create ScanConfig from a dictionary (e.g., API request body).

        This allows backward compatibility with existing API calls.
        """
        # Extract nested configs
        auth_data = {}
        tests_data = {}
        limits_data = {}
        output_data = {}

        # Map flat parameters to nested structure
        auth_keys = {
            'auth_header', 'auth_cookies', 'auth_headers_json',
            'login_url', 'login_username', 'login_password', 'login_extra_fields',
            'user2_header', 'user2_cookies', 'refresh_token', 'token_refresh_url'
        }
        test_keys = {
            'active', 'xss', 'sqli', 'nuclei', 'tls', 'headers', 'cookies',
            'cors', 'dns', 'discovery', 'port_scan', 'subdomain_enum',
            'graphql', 'websocket', 'jwt', 'oauth', 'bola', 'idor', 'csrf', 'race_condition'
        }
        limit_keys = {
            'timeout', 'nuclei_timeout', 'sqlmap_timeout', 'browser_timeout',
            'requests_per_second', 'max_concurrent_requests', 'max_crawl_depth',
            'max_crawl_pages', 'max_endpoints', 'max_sqli_endpoints', 'max_xss_endpoints'
        }
        output_keys = {
            'output_format', 'output_file', 'verbose', 'debug', 'quiet',
            'min_severity', 'min_confidence', 'exclude_info', 'ai_enabled'
        }

        for key, value in data.items():
            if key in auth_keys:
                auth_data[key] = value
            elif key in test_keys:
                tests_data[key] = value
            elif key in limit_keys:
                limits_data[key] = value
            elif key in output_keys:
                output_data[key] = value

        # Get scan type
        scan_type_str = data.get('scan_type', 'standard')
        scan_type = ScanType.from_string(scan_type_str)

        return cls(
            target=data.get('target', ''),
            scan_type=scan_type,
            auth=AuthConfig(**auth_data) if auth_data else AuthConfig(),
            tests=TestConfig(**tests_data) if tests_data else TestConfig(),
            limits=LimitConfig(**limits_data) if limits_data else LimitConfig(),
            output=OutputConfig(**output_data) if output_data else OutputConfig(),
            no_early_stop=data.get('no_early_stop', False),
            thorough_params=data.get('thorough_params', False),
            custom_endpoints=data.get('custom_endpoints', []),
            json_link_following=data.get('json_link_following', False),
            options_method_discovery=data.get('options_method_discovery', False),
            grpc_discovery=data.get('grpc_discovery', False),
            openapi_spec=data.get('openapi', data.get('openapi_spec')),
            oob_callback_url=data.get('oob_callback_url'),
            scan_id=data.get('scan_id'),
            project_id=data.get('project_id'),
            tags=data.get('tags', []),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert config to flat dictionary for backward compatibility."""
        result = {
            'target': self.target,
            'scan_type': self.scan_type.value,
            'no_early_stop': self.no_early_stop,
            'thorough_params': self.thorough_params,
            'custom_endpoints': self.custom_endpoints,
            'json_link_following': self.json_link_following,
            'options_method_discovery': self.options_method_discovery,
            'grpc_discovery': self.grpc_discovery,
            'openapi_spec': self.openapi_spec,
            'oob_callback_url': self.oob_callback_url,
            'scan_id': self.scan_id,
            'project_id': self.project_id,
            'tags': self.tags,
        }

        # Flatten nested configs
        for key, value in self.auth.__dict__.items():
            if value is not None:
                result[key] = value
        for key, value in self.tests.__dict__.items():
            result[key] = value
        for key, value in self.limits.__dict__.items():
            result[key] = value
        for key, value in self.output.__dict__.items():
            if value is not None:
                result[key] = value

        return result
