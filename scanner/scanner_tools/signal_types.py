"""
Scored Signal System for Smart Scan

Replaces boolean signals with confidence-scored objects that track evidence
and source. Maintains backward compatibility with existing boolean checks
via __bool__ method.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Signal:
    """
    A scored signal representing a detected vulnerability indicator.

    Attributes:
        active: Whether the signal was detected (for backward compat)
        confidence: Confidence score 0.0-1.0
        evidence: List of evidence strings (template IDs, patterns, etc.)
        source: Origin of the signal (nuclei, header_analysis, error_detection, etc.)
    """

    active: bool = False
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    source: str = ""

    def __bool__(self) -> bool:
        """Backward compatibility: allows `if signal:` checks."""
        return self.active

    def add_evidence(self, evidence: str, confidence_boost: float = 0.0) -> None:
        """Add evidence and optionally boost confidence."""
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)
        if confidence_boost > 0:
            self.confidence = min(1.0, self.confidence + confidence_boost)

    def merge(self, other: "Signal") -> "Signal":
        """Merge another signal into this one, combining evidence."""
        if not isinstance(other, Signal):
            return self

        return Signal(
            active=self.active or other.active,
            confidence=max(self.confidence, other.confidence),
            evidence=list(set(self.evidence + other.evidence)),
            source=self.source or other.source,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "active": self.active,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Signal":
        """Deserialize from dictionary."""
        return cls(
            active=data.get("active", False),
            confidence=data.get("confidence", 0.0),
            evidence=data.get("evidence", []),
            source=data.get("source", ""),
        )


@dataclass
class SignalSet:
    """
    Collection of all signals for a scan.

    Provides dict-like access for backward compatibility with existing code
    that uses signals.get("sql_errors") patterns.
    """

    sql_errors: Signal = field(default_factory=Signal)
    xss_reflection: Signal = field(default_factory=Signal)
    auth_issues: Signal = field(default_factory=Signal)
    file_inclusion: Signal = field(default_factory=Signal)
    ssrf_potential: Signal = field(default_factory=Signal)
    rce_potential: Signal = field(default_factory=Signal)
    api_exposure: Signal = field(default_factory=Signal)
    information_disclosure: Signal = field(default_factory=Signal)
    misconfig: Signal = field(default_factory=Signal)
    default_creds: Signal = field(default_factory=Signal)

    # Aggregate counts (for early stopping compatibility)
    critical_count: int = 0
    high_count: int = 0

    # High-value targets discovered
    high_value_targets: list[str] = field(default_factory=list)

    # Tech-specific findings
    tech_specific: dict[str, list[str]] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like access for backward compatibility."""
        if hasattr(self, key):
            value = getattr(self, key)
            # For Signal objects, return the object (truthy if active)
            if isinstance(value, Signal):
                return value
            return value
        return default

    def __getitem__(self, key: str) -> Any:
        """Dict-like bracket access."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-like bracket assignment."""
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(f"Unknown signal: {key}")

    def __contains__(self, key: str) -> bool:
        """Support `in` operator."""
        return hasattr(self, key)

    def items(self):
        """Iterate over signal name-value pairs."""
        for name in self._signal_names():
            yield name, getattr(self, name)

    def _signal_names(self) -> list[str]:
        """List of signal field names."""
        return [
            "sql_errors",
            "xss_reflection",
            "auth_issues",
            "file_inclusion",
            "ssrf_potential",
            "rce_potential",
            "api_exposure",
            "information_disclosure",
            "misconfig",
            "default_creds",
        ]

    def active_signals(self) -> list[str]:
        """Return list of active signal names."""
        return [name for name in self._signal_names() if getattr(self, name).active]

    def total_confidence(self) -> float:
        """Sum of all signal confidences."""
        return sum(getattr(self, name).confidence for name in self._signal_names())

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        result = {}
        for name in self._signal_names():
            signal = getattr(self, name)
            result[name] = signal.to_dict()

        result["critical_count"] = self.critical_count
        result["high_count"] = self.high_count
        result["high_value_targets"] = self.high_value_targets
        result["tech_specific"] = self.tech_specific

        # Legacy format for backward compat
        result["signal_confidence"] = {
            name: getattr(self, name).confidence for name in self._signal_names()
        }

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignalSet":
        """Deserialize from dictionary."""
        signal_set = cls()

        for name in signal_set._signal_names():
            if name in data:
                value = data[name]
                if isinstance(value, dict):
                    setattr(signal_set, name, Signal.from_dict(value))
                elif isinstance(value, bool):
                    # Legacy boolean format
                    confidence = data.get("signal_confidence", {}).get(name, 0.7 if value else 0.0)
                    setattr(
                        signal_set,
                        name,
                        Signal(active=value, confidence=confidence, source="legacy"),
                    )

        signal_set.critical_count = data.get("critical_count", 0)
        signal_set.high_count = data.get("high_count", 0)
        signal_set.high_value_targets = data.get("high_value_targets", [])
        signal_set.tech_specific = data.get("tech_specific", {})

        return signal_set


# Severity weights for confidence-weighted early stopping
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.1,
}


def calculate_weighted_score(findings: list[dict]) -> float:
    """
    Calculate confidence-weighted severity score for early stopping decisions.

    Args:
        findings: List of finding dicts with 'severity' and optional 'confidence'

    Returns:
        Weighted score (higher = more severe findings with higher confidence)
    """
    score = 0.0
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        confidence = finding.get("confidence", 0.65)  # Default to medium confidence
        weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        score += weight * confidence
    return score


def should_early_stop_weighted(
    findings: list[dict],
    signals: SignalSet | dict,
    threshold: float = 12.0,
    min_coverage: float = 0.0,
    current_coverage: float = 1.0,
) -> tuple[bool, str]:
    """
    Confidence-weighted early stopping decision.

    Args:
        findings: List of finding dicts
        signals: SignalSet or legacy dict
        threshold: Weighted score threshold to trigger stop (default 12.0 ≈ 3 high-conf criticals)
        min_coverage: Minimum endpoint coverage before stopping allowed (0.0-1.0)
        current_coverage: Current endpoint coverage ratio

    Returns:
        Tuple of (should_stop, reason_message)
    """
    # Don't stop if coverage is below minimum
    if current_coverage < min_coverage:
        return False, ""

    weighted_score = calculate_weighted_score(findings)

    if weighted_score >= threshold:
        return True, f"Confidence-weighted score {weighted_score:.1f} exceeds threshold {threshold}"

    return False, ""
