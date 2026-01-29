"""
Unified error handling for the scanner.

This module provides consistent error handling across all scanner components,
replacing the scattered error patterns (accumulate vs single string vs silent).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum
from typing import Any


class ErrorSeverity(Enum):
    """Error severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ToolError:
    """Structured error from a security tool.

    Provides consistent error tracking with context about:
    - Which tool failed
    - What phase of scanning
    - Whether the error is recoverable
    - Full error details for debugging
    """
    tool: str
    phase: str
    message: str
    recoverable: bool = True
    severity: ErrorSeverity = ErrorSeverity.ERROR
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Additional context
    exception_type: str | None = None
    stack_trace: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.tool}] {self.phase}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "tool": self.tool,
            "phase": self.phase,
            "message": self.message,
            "recoverable": self.recoverable,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "exception_type": self.exception_type,
            "context": self.context,
        }

    @classmethod
    def from_exception(
        cls,
        tool: str,
        phase: str,
        exc: Exception,
        recoverable: bool = True,
        context: dict[str, Any] | None = None
    ) -> "ToolError":
        """Create ToolError from an exception."""
        import traceback
        return cls(
            tool=tool,
            phase=phase,
            message=str(exc)[:500],  # Truncate long messages
            recoverable=recoverable,
            exception_type=type(exc).__name__,
            stack_trace=traceback.format_exc(),
            context=context or {},
        )


class ErrorCollector:
    """Collects and manages errors from multiple tools.

    This provides a centralized way to track errors across the scan,
    with support for:
    - Categorizing errors by severity and tool
    - Determining if scan should abort
    - Generating error summaries for reports

    Example usage:
        collector = ErrorCollector()

        try:
            result = await some_tool_scan()
        except Exception as e:
            collector.add_exception("nuclei", "wave1", e)

        if collector.has_critical():
            # Abort scan
            ...

        # Include in report
        report["errors"] = collector.summary()
    """

    def __init__(self, max_errors: int = 1000):
        self._errors: list[ToolError] = []
        self._max_errors = max_errors
        self._logger = logging.getLogger("scanner.errors")

    @property
    def errors(self) -> list[ToolError]:
        """Get all collected errors."""
        return self._errors.copy()

    def add(
        self,
        tool: str,
        phase: str,
        message: str,
        recoverable: bool = True,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        context: dict[str, Any] | None = None
    ) -> None:
        """Add an error to the collector.

        Args:
            tool: Name of the tool that failed
            phase: Phase of scanning (e.g., "discovery", "wave1", "validation")
            message: Human-readable error message
            recoverable: Whether scanning can continue
            severity: Error severity level
            context: Additional context for debugging
        """
        if len(self._errors) >= self._max_errors:
            # Prevent memory exhaustion from error floods
            if len(self._errors) == self._max_errors:
                self._log_warning(f"Error limit reached ({self._max_errors}), discarding new errors")
            return

        error = ToolError(
            tool=tool,
            phase=phase,
            message=message[:500],  # Truncate
            recoverable=recoverable,
            severity=severity,
            context=context or {},
        )
        self._errors.append(error)

        # Log based on severity and recoverability
        if not recoverable:
            self._logger.error(str(error))
        elif severity in (ErrorSeverity.ERROR, ErrorSeverity.CRITICAL):
            self._logger.error(str(error))
        elif severity == ErrorSeverity.WARNING:
            self._logger.warning(str(error))
        else:
            self._logger.debug(str(error))

    def add_exception(
        self,
        tool: str,
        phase: str,
        exc: Exception,
        recoverable: bool = True,
        context: dict[str, Any] | None = None
    ) -> None:
        """Add an error from an exception.

        Args:
            tool: Name of the tool that failed
            phase: Phase of scanning
            exc: The caught exception
            recoverable: Whether scanning can continue
            context: Additional context for debugging
        """
        error = ToolError.from_exception(tool, phase, exc, recoverable, context)

        if len(self._errors) < self._max_errors:
            self._errors.append(error)

        # Always log exceptions at error level
        self._logger.error(str(error), exc_info=True)

    def _log_warning(self, message: str) -> None:
        """Log a warning message."""
        self._logger.warning(message)

    def has_critical(self) -> bool:
        """Check if any critical (non-recoverable) errors occurred."""
        return any(not e.recoverable for e in self._errors)

    def has_errors(self) -> bool:
        """Check if any errors occurred."""
        return len(self._errors) > 0

    def error_count(self) -> int:
        """Get total error count."""
        return len(self._errors)

    def errors_by_tool(self) -> dict[str, list[ToolError]]:
        """Group errors by tool name."""
        result: dict[str, list[ToolError]] = {}
        for error in self._errors:
            if error.tool not in result:
                result[error.tool] = []
            result[error.tool].append(error)
        return result

    def errors_by_severity(self) -> dict[str, list[ToolError]]:
        """Group errors by severity."""
        result: dict[str, list[ToolError]] = {}
        for error in self._errors:
            sev = error.severity.value
            if sev not in result:
                result[sev] = []
            result[sev].append(error)
        return result

    def get_tool_errors(self, tool: str) -> list[ToolError]:
        """Get all errors for a specific tool."""
        return [e for e in self._errors if e.tool == tool]

    def clear(self) -> None:
        """Clear all collected errors."""
        self._errors.clear()

    def summary(self) -> dict[str, Any]:
        """Generate error summary for reports.

        Returns a dictionary suitable for including in scan reports.
        """
        by_tool = self.errors_by_tool()
        by_severity = self.errors_by_severity()

        return {
            "total_errors": len(self._errors),
            "has_critical": self.has_critical(),
            "by_tool": {
                tool: len(errors) for tool, errors in by_tool.items()
            },
            "by_severity": {
                sev: len(errors) for sev, errors in by_severity.items()
            },
            "errors": [e.to_dict() for e in self._errors[:100]],  # Limit for report size
        }

    def to_list(self) -> list[dict[str, Any]]:
        """Convert all errors to list of dictionaries."""
        return [e.to_dict() for e in self._errors]

    def __len__(self) -> int:
        return len(self._errors)

    def __bool__(self) -> bool:
        return len(self._errors) > 0


class ScanError(Exception):
    """Base exception for scanner errors."""

    def __init__(
        self,
        message: str,
        tool: str | None = None,
        phase: str | None = None,
        recoverable: bool = True
    ):
        super().__init__(message)
        self.tool = tool
        self.phase = phase
        self.recoverable = recoverable


class ToolExecutionError(ScanError):
    """Error during tool execution."""

    def __init__(
        self,
        message: str,
        tool: str,
        phase: str = "execution",
        command: str | None = None,
        exit_code: int | None = None
    ):
        super().__init__(message, tool, phase, recoverable=True)
        self.command = command
        self.exit_code = exit_code


class AuthenticationError(ScanError):
    """Authentication-related error."""

    def __init__(self, message: str, tool: str | None = None):
        super().__init__(message, tool, "authentication", recoverable=False)


class RateLimitError(ScanError):
    """Rate limiting error from target."""

    def __init__(self, message: str, tool: str, retry_after: int | None = None):
        super().__init__(message, tool, "rate_limit", recoverable=True)
        self.retry_after = retry_after


class TimeoutError(ScanError):
    """Scan timeout error."""

    def __init__(self, message: str, tool: str, timeout_seconds: int):
        super().__init__(message, tool, "timeout", recoverable=True)
        self.timeout_seconds = timeout_seconds


class ConfigurationError(ScanError):
    """Configuration error."""

    def __init__(self, message: str, config_key: str | None = None):
        super().__init__(message, None, "configuration", recoverable=False)
        self.config_key = config_key


def safe_execute(func):
    """Decorator for safe execution with error collection.

    Wraps async functions to catch exceptions and add them to an error collector.

    Example:
        @safe_execute
        async def scan_with_nuclei(target, error_collector):
            # If this raises, error is added to collector
            result = await nuclei_scan(target)
            return result
    """
    import functools

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        error_collector = kwargs.get('error_collector')
        tool_name = kwargs.get('tool_name', func.__name__)

        try:
            return await func(*args, **kwargs)
        except Exception as e:
            if error_collector and isinstance(error_collector, ErrorCollector):
                error_collector.add_exception(
                    tool=tool_name,
                    phase="execution",
                    exc=e,
                    recoverable=True,
                )
            raise

    return wrapper
