"""
Tool interface protocols and result types.

This module defines standard interfaces for security tools, ensuring
consistent return formats and error handling across all scanner components.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable


def utc_now_iso_z() -> str:
    """Return a UTC timestamp with the existing trailing-Z format."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"


@dataclass
class Finding:
    """Standard finding structure for all security tools.

    This provides a consistent format for vulnerability findings
    regardless of which tool discovered them.
    """
    id: str
    tool: str
    title: str
    severity: str  # critical, high, medium, low, info
    evidence: dict[str, Any]

    # Optional fields
    cwe: str | None = None
    cvss_score: float = 0.0
    confidence: float = 0.5
    confidence_tier: str = "medium"  # verified, high, medium, low, uncertain

    # Compliance mappings
    owasp: str | None = None
    soc2: list[str] = field(default_factory=list)

    # Metadata
    url: str | None = None
    param: str | None = None
    payload: str | None = None
    method: str | None = None
    first_seen: str | None = None

    # AI classification
    ai_verdict: str | None = None  # true_positive, false_positive, needs_review

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        result = {
            "id": self.id,
            "tool": self.tool,
            "title": self.title,
            "severity": self.severity,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "confidence_tier": self.confidence_tier,
        }
        if self.cwe:
            result["cwe"] = self.cwe
        if self.owasp:
            result["owasp"] = self.owasp
        if self.soc2:
            result["soc2"] = self.soc2
        if self.url:
            result["url"] = self.url
        if self.param:
            result["param"] = self.param
        if self.payload:
            result["payload"] = self.payload
        if self.method:
            result["method"] = self.method
        if self.first_seen:
            result["first_seen"] = self.first_seen
        if self.ai_verdict:
            result["ai_verdict"] = self.ai_verdict
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create finding from dictionary."""
        return cls(
            id=data.get("id", ""),
            tool=data.get("tool", "unknown"),
            title=data.get("title", ""),
            severity=data.get("severity", "info"),
            evidence=data.get("evidence", {}),
            cwe=data.get("cwe"),
            cvss_score=data.get("cvss_score", 0.0),
            confidence=data.get("confidence", 0.5),
            confidence_tier=data.get("confidence_tier", "medium"),
            owasp=data.get("owasp"),
            soc2=data.get("soc2", []),
            url=data.get("url"),
            param=data.get("param"),
            payload=data.get("payload"),
            method=data.get("method"),
            first_seen=data.get("first_seen"),
            ai_verdict=data.get("ai_verdict"),
        )


@dataclass
class ToolResult:
    """Standard result structure for all security tools.

    This ensures consistent handling of tool outputs across the scanner,
    regardless of which underlying tool was used.
    """
    tool: str
    scan_completed: bool
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    # Additional metadata
    target: str = ""
    scan_type: str = ""
    timestamp: str = field(default_factory=utc_now_iso_z)

    # Raw output for debugging
    raw_output: Any = None

    @property
    def has_findings(self) -> bool:
        """Check if any findings were discovered."""
        return len(self.findings) > 0

    @property
    def has_errors(self) -> bool:
        """Check if any errors occurred."""
        return len(self.errors) > 0

    @property
    def critical_count(self) -> int:
        """Count critical severity findings."""
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        """Count high severity findings."""
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        """Count medium severity findings."""
        return sum(1 for f in self.findings if f.severity == "medium")

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "tool": self.tool,
            "scan_completed": self.scan_completed,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
            "target": self.target,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolResult":
        """Create result from dictionary."""
        findings = [
            Finding.from_dict(f) if isinstance(f, dict) else f
            for f in data.get("findings", [])
        ]
        return cls(
            tool=data.get("tool", "unknown"),
            scan_completed=data.get("scan_completed", False),
            findings=findings,
            errors=data.get("errors", []),
            duration_seconds=data.get("duration_seconds", 0.0),
            target=data.get("target", ""),
            scan_type=data.get("scan_type", ""),
            timestamp=data.get("timestamp", ""),
            raw_output=data.get("raw_output"),
        )

    @classmethod
    def empty(cls, tool: str, error: str | None = None) -> "ToolResult":
        """Create an empty result (for skipped/failed tools)."""
        return cls(
            tool=tool,
            scan_completed=False,
            errors=[error] if error else [],
        )

    @classmethod
    def success(cls, tool: str, findings: list[Finding], duration: float = 0.0) -> "ToolResult":
        """Create a successful result."""
        return cls(
            tool=tool,
            scan_completed=True,
            findings=findings,
            duration_seconds=duration,
        )


@runtime_checkable
class SecurityTool(Protocol):
    """Protocol that all security tools should implement.

    This defines the standard interface for security scanning tools,
    ensuring consistent behavior and making tools interchangeable.

    Example implementation:
        class NucleiTool:
            async def scan(
                self,
                target: str,
                auth_session: AuthSession | None = None,
                **options
            ) -> ToolResult:
                # Run nuclei scan
                raw_result = await staged_nuclei_scan(target, ...)
                # Normalize to ToolResult
                return ToolResult(
                    tool="nuclei",
                    scan_completed=True,
                    findings=self._normalize_findings(raw_result),
                )
    """

    async def scan(
        self,
        target: str,
        auth_session: Any | None = None,
        **options: Any
    ) -> ToolResult:
        """Run security scan against target.

        Args:
            target: URL or hostname to scan
            auth_session: Optional authentication session
            **options: Tool-specific options

        Returns:
            ToolResult with findings and metadata
        """
        ...


@runtime_checkable
class DiscoveryTool(Protocol):
    """Protocol for discovery/enumeration tools.

    These tools discover endpoints, parameters, and other scan targets
    rather than finding vulnerabilities directly.
    """

    async def discover(
        self,
        target: str,
        auth_session: Any | None = None,
        **options: Any
    ) -> "DiscoveryResult":
        """Discover endpoints and parameters.

        Args:
            target: Base URL to discover from
            auth_session: Optional authentication session
            **options: Tool-specific options

        Returns:
            DiscoveryResult with discovered endpoints
        """
        ...


@dataclass
class DiscoveryResult:
    """Standard result structure for discovery tools."""
    tool: str
    completed: bool
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def endpoint_count(self) -> int:
        """Count discovered endpoints."""
        return len(self.endpoints)

    @property
    def parameterized_endpoints(self) -> list[dict[str, Any]]:
        """Get endpoints with parameters."""
        return [ep for ep in self.endpoints if ep.get("params")]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool": self.tool,
            "completed": self.completed,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "technologies": self.technologies,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


# Type aliases for common patterns
FindingList = list[Finding]
ToolResultDict = dict[str, ToolResult]
