"""
Coverage Tracking for Smart Scan

Tracks endpoint, parameter, and template coverage throughout the scan
to enable coverage-driven decision making and reporting.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CoverageMetrics:
    """
    Tracks coverage metrics throughout a scan.

    Used to:
    - Report coverage to users
    - Gate early stopping (don't stop if coverage is too low)
    - Guide scanning decisions (prioritize uncovered areas)
    """

    # Endpoint coverage
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    endpoints_by_method: dict[str, int] = field(default_factory=dict)

    # Parameter coverage
    params_discovered: int = 0
    params_tested: int = 0
    params_by_location: dict[str, int] = field(default_factory=dict)  # query, body, path, header

    # Template coverage (Nuclei)
    templates_run: int = 0
    templates_matched: int = 0
    templates_by_category: dict[str, int] = field(default_factory=dict)

    # Auth coverage
    auth_states_tested: list[str] = field(default_factory=list)  # anonymous, user1, user2

    # Discovery source coverage
    discovery_sources_used: list[str] = field(default_factory=list)

    @property
    def endpoint_coverage(self) -> float:
        """Ratio of tested to discovered endpoints (0.0-1.0)."""
        if self.endpoints_discovered == 0:
            return 0.0
        return min(1.0, self.endpoints_tested / self.endpoints_discovered)

    @property
    def param_coverage(self) -> float:
        """Ratio of tested to discovered parameters (0.0-1.0)."""
        if self.params_discovered == 0:
            return 0.0
        return min(1.0, self.params_tested / self.params_discovered)

    @property
    def template_hit_rate(self) -> float:
        """Ratio of matching templates to total run (0.0-1.0)."""
        if self.templates_run == 0:
            return 0.0
        return min(1.0, self.templates_matched / self.templates_run)

    def record_endpoint_discovered(self, method: str = "GET") -> None:
        """Record discovery of an endpoint."""
        self.endpoints_discovered += 1
        method = method.upper()
        self.endpoints_by_method[method] = self.endpoints_by_method.get(method, 0) + 1

    def record_endpoint_tested(self, count: int = 1) -> None:
        """Record testing of endpoint(s)."""
        self.endpoints_tested += count

    def record_param_discovered(self, location: str = "query", count: int = 1) -> None:
        """Record discovery of parameter(s)."""
        self.params_discovered += count
        self.params_by_location[location] = self.params_by_location.get(location, 0) + count

    def record_param_tested(self, count: int = 1) -> None:
        """Record testing of parameter(s)."""
        self.params_tested += count

    def record_templates(self, run: int = 0, matched: int = 0, category: str | None = None) -> None:
        """Record Nuclei template execution."""
        self.templates_run += run
        self.templates_matched += matched
        if category:
            self.templates_by_category[category] = self.templates_by_category.get(category, 0) + run

    def record_auth_state(self, state: str) -> None:
        """Record testing with an auth state."""
        if state not in self.auth_states_tested:
            self.auth_states_tested.append(state)

    def record_discovery_source(self, source: str) -> None:
        """Record use of a discovery source."""
        if source not in self.discovery_sources_used:
            self.discovery_sources_used.append(source)

    def merge(self, other: "CoverageMetrics") -> "CoverageMetrics":
        """Merge another CoverageMetrics into this one."""
        self.endpoints_discovered += other.endpoints_discovered
        self.endpoints_tested += other.endpoints_tested
        self.params_discovered += other.params_discovered
        self.params_tested += other.params_tested
        self.templates_run += other.templates_run
        self.templates_matched += other.templates_matched

        for method, count in other.endpoints_by_method.items():
            self.endpoints_by_method[method] = self.endpoints_by_method.get(method, 0) + count

        for loc, count in other.params_by_location.items():
            self.params_by_location[loc] = self.params_by_location.get(loc, 0) + count

        for cat, count in other.templates_by_category.items():
            self.templates_by_category[cat] = self.templates_by_category.get(cat, 0) + count

        for state in other.auth_states_tested:
            if state not in self.auth_states_tested:
                self.auth_states_tested.append(state)

        for source in other.discovery_sources_used:
            if source not in self.discovery_sources_used:
                self.discovery_sources_used.append(source)

        return self

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "endpoints": {
                "discovered": self.endpoints_discovered,
                "tested": self.endpoints_tested,
                "coverage": round(self.endpoint_coverage, 3),
                "by_method": self.endpoints_by_method,
            },
            "parameters": {
                "discovered": self.params_discovered,
                "tested": self.params_tested,
                "coverage": round(self.param_coverage, 3),
                "by_location": self.params_by_location,
            },
            "nuclei_templates": {
                "run": self.templates_run,
                "matched": self.templates_matched,
                "hit_rate": round(self.template_hit_rate, 3),
                "by_category": self.templates_by_category,
            },
            "auth_states_tested": self.auth_states_tested,
            "discovery_sources": self.discovery_sources_used,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageMetrics":
        """Deserialize from dictionary."""
        metrics = cls()

        endpoints = data.get("endpoints", {})
        metrics.endpoints_discovered = endpoints.get("discovered", 0)
        metrics.endpoints_tested = endpoints.get("tested", 0)
        metrics.endpoints_by_method = endpoints.get("by_method", {})

        params = data.get("parameters", {})
        metrics.params_discovered = params.get("discovered", 0)
        metrics.params_tested = params.get("tested", 0)
        metrics.params_by_location = params.get("by_location", {})

        templates = data.get("nuclei_templates", {})
        metrics.templates_run = templates.get("run", 0)
        metrics.templates_matched = templates.get("matched", 0)
        metrics.templates_by_category = templates.get("by_category", {})

        metrics.auth_states_tested = data.get("auth_states_tested", [])
        metrics.discovery_sources_used = data.get("discovery_sources", [])

        return metrics


class CoverageTracker:
    """
    Singleton-style tracker for accumulating coverage throughout a scan.

    Usage:
        tracker = CoverageTracker()
        tracker.record_endpoint_discovered("POST")
        tracker.record_param_discovered("body", count=3)
        ...
        report["coverage"] = tracker.get_metrics().to_dict()
    """

    def __init__(self):
        self._metrics = CoverageMetrics()

    def reset(self) -> None:
        """Reset all metrics for a new scan."""
        self._metrics = CoverageMetrics()

    def get_metrics(self) -> CoverageMetrics:
        """Get current metrics."""
        return self._metrics

    # Delegate methods to metrics
    def record_endpoint_discovered(self, method: str = "GET") -> None:
        self._metrics.record_endpoint_discovered(method)

    def record_endpoint_tested(self, count: int = 1) -> None:
        self._metrics.record_endpoint_tested(count)

    def record_param_discovered(self, location: str = "query", count: int = 1) -> None:
        self._metrics.record_param_discovered(location, count)

    def record_param_tested(self, count: int = 1) -> None:
        self._metrics.record_param_tested(count)

    def record_templates(self, run: int = 0, matched: int = 0, category: str | None = None) -> None:
        self._metrics.record_templates(run, matched, category)

    def record_auth_state(self, state: str) -> None:
        self._metrics.record_auth_state(state)

    def record_discovery_source(self, source: str) -> None:
        self._metrics.record_discovery_source(source)

    @property
    def endpoint_coverage(self) -> float:
        return self._metrics.endpoint_coverage

    @property
    def param_coverage(self) -> float:
        return self._metrics.param_coverage

    def to_dict(self) -> dict[str, Any]:
        return self._metrics.to_dict()
