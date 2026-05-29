"""Centralized helpers for focused-manual-active scan scoping.

ShakerScan's smart-scan mode can run in "focused" sub-mode when the caller
provides both a `focused_active_family` (e.g. ``"xss"`` or ``"sqli"``) and a
list of `manual_endpoints` to target. In that sub-mode many discovery,
posture, and broad-vulnerability modules are intentionally skipped so the
active scan concentrates its budget on the requested family.

Historically the focused flag was open-coded as `focused_manual_active_scope`
across ~50 sites in `scanner/scanner.py`. New modules silently opted in by
forgetting to add the skip check, which caused several regressions. This
module gives the flag a name, a shape, and a single place to evolve.

Usage (after migration):

    scope = FocusedScope.from_request(
        smart_mode=smart_mode,
        family=focused_active_family,
        manual_endpoints=manual_endpoints_norm,
    )

    if scope.skip_posture():
        dns_policy = scope.skipped_result(DNS_POLICY_SHAPE)
    else:
        dns_policy = await check_dns_policy(host)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Canonical skip reason emitted into module results when focused mode disables
# a check. Existing report consumers already match this exact string.
FOCUSED_SKIP_REASON = "focused_manual_active_scope"


async def async_value(value: Any) -> Any:
    """Wrap a value as a coroutine so it can be scheduled with create_task.

    Lets migrated sites replace ad-hoc ``async def dummy_X(): return {...}``
    closures with ``asyncio.create_task(async_value(scope.skipped_result(SHAPE)))``.
    """
    return value


@dataclass(frozen=True)
class FocusedScope:
    """Represents whether the current scan is in focused-manual-active mode.

    Instances should be created once near the top of `build_report` and
    threaded into helpers. `active=False` means the scan is broad; nothing
    is skipped on focused-scope grounds.
    """

    active: bool
    family: str | None = None
    manual_endpoint_count: int = 0

    @classmethod
    def from_request(
        cls,
        *,
        smart_mode: bool,
        family: str | None,
        manual_endpoints: list[Any] | None,
    ) -> "FocusedScope":
        endpoints = manual_endpoints or []
        return cls(
            active=bool(smart_mode and family and endpoints),
            family=(family or None) if smart_mode else None,
            manual_endpoint_count=len(endpoints) if smart_mode and family else 0,
        )

    # ---- skip predicates ---------------------------------------------------

    def __bool__(self) -> bool:
        return self.active

    def skip_posture(self) -> bool:
        """Skip public-internet posture (HSTS, DMARC, CAA, MTA-STS, …)."""
        return self.active

    def skip_discovery(self) -> bool:
        """Skip generic discovery (vhost fuzzing, port scan, recursive dirs)."""
        return self.active

    def skip_module(self, module: str) -> bool:
        """Module-agnostic check. Reserved for future per-module overrides."""
        return self.active

    # ---- result shaping ----------------------------------------------------

    def skipped_result(
        self,
        shape: dict[str, Any] | None = None,
        *,
        reason: str = FOCUSED_SKIP_REASON,
    ) -> dict[str, Any]:
        """Return a dict carrying the canonical skip markers merged onto a shape.

        The shape arg is the empty/zero version of the module's normal result
        (e.g. `{"records": [], "vulnerable": False}`). The returned dict adds
        ``skipped: True`` and ``reason: <reason>`` so downstream completion-
        status code recognises the skip.
        """
        result: dict[str, Any] = dict(shape or {})
        result["skipped"] = True
        result["reason"] = reason
        return result


# Empty dataclass with all the right zero values for callers who want the
# "no focused scope" object without computing one.
NO_FOCUSED_SCOPE = FocusedScope(active=False)


# ---- Common result shapes for module dummies -----------------------------
#
# These are the empty/zero versions of common module results. Keeping them
# named here lets each migrated site read `scope.skipped_result(DNS_POLICY_SHAPE)`
# instead of redeclaring the dict inline. New modules should add their shape
# here as part of the migration.

NMAP_CIPHERS_SHAPE: dict[str, Any] = {"raw": "", "weak_indicators": [], "ciphers_by_protocol": {}}
TESTSSL_SHAPE: dict[str, Any] = {"supports_tls13": None, "issues": [], "raw_present": False}
SSLYZE_SHAPE: dict[str, Any] = {
    "certificate_chain": [],
    "cipher_suites": {},
    "vulnerabilities": [],
    "tls_versions": {},
    "ocsp_stapling": False,
    "session_resumption": {},
    "scan_completed": False,
}
DMARC_SHAPE: dict[str, Any] = {"record": None, "fields": {}}
DNSSEC_SHAPE: dict[str, Any] = {"status": "skipped", "algorithm": None}
CAA_SHAPE: dict[str, Any] = {"records": []}
TLSRPT_SHAPE: dict[str, Any] = {"record": None, "rua": None}
SECURITY_TXT_SHAPE: dict[str, Any] = {"present": False, "sample": None}
CORS_SHAPE: dict[str, Any] = {"vulnerable": False, "issues": []}
SUBDOMAIN_TAKEOVER_SHAPE: dict[str, Any] = {"vulnerable": False, "cname": None, "issues": []}
EXPOSED_FILES_SHAPE: dict[str, Any] = {"exposed_files": []}
VHOST_SHAPE: dict[str, Any] = {"hosts_tested": 0, "potential_vhosts": [], "baseline": {}}
