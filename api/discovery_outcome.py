"""How a subdomain discovery run reports sources that failed.

A source that fails (crt.sh answering 502/503/429, a timeout, an error page) is not a source that
found nothing. The run records which sources failed and why; when every source that was asked
failed and nothing was found, the run itself failed instead of reporting that no subdomains exist.
"""
from __future__ import annotations

from typing import Any, Mapping

SOURCE_LABELS = {"crtsh": "crt.sh", "gungnir": "Gungnir", "subfinder": "subfinder"}


def source_errors(result: Mapping[str, Any]) -> dict[str, str]:
    """Failed sources of a discovery result, ``{source: reason}`` (unavailable tools excluded)."""
    errors = result.get("source_errors")
    if isinstance(errors, Mapping):
        return {str(name): str(reason)[:300] for name, reason in errors.items() if reason}
    by_source = result.get("by_source")
    if not isinstance(by_source, Mapping):
        return {}
    return {
        str(name): str(entry.get("error"))[:300]
        for name, entry in by_source.items()
        if isinstance(entry, Mapping) and entry.get("error") and not entry.get("unavailable")
    }


def describe(errors: Mapping[str, str]) -> str:
    return "; ".join(f"{SOURCE_LABELS.get(name, name)}: {reason}" for name, reason in sorted(errors.items()))


def failed_run_message(result: Mapping[str, Any]) -> str | None:
    """The run's error when no source answered and nothing was found, else ``None``."""
    errors = source_errors(result)
    if not errors or result.get("subdomains"):
        return None
    answered = result.get("sources_answered")
    if isinstance(answered, list) and answered:
        return None
    by_source = result.get("by_source")
    if not isinstance(answered, list) and isinstance(by_source, Mapping):
        # Older reports: a source answered when it has an entry without an error.
        if any(isinstance(entry, Mapping) and not entry.get("error") for entry in by_source.values()):
            return None
    return f"No discovery source answered ({describe(errors)}); subdomains were not checked, try again later"
