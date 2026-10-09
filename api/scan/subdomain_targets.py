"""Record a Scan's own subdomain discovery the way the Targets page records its discovery.

The Scan option "Discover subdomains" ran the bounded ``subdomains.discover`` capability and its
names reached only the endpoint manifest, where they were out of the scan's origin scope: the
action reported success while no report section, discovery run or target named a single host.
The finalizer now lists the names in ``report.discovery.subdomains``; this module turns that list
into the same durable state the Targets-page discovery produces -- a ``discovery_runs`` row and
DNS-checked targets -- and writes the outcome back into the report section.

It never widens a Scan: the names become targets for their own, separately authorized scans.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence
import uuid

try:  # Preserve one module identity under api.scan.* host imports.
    from .. import target_resolution
except (ImportError, ModuleNotFoundError):  # top-level scan.* worker imports
    import target_resolution

try:
    from scanner_tools.discovered_names import canonical_name, filter_subdomains
except ModuleNotFoundError:  # package import (api.scan.subdomain_targets)
    from scanner.scanner_tools.discovered_names import canonical_name, filter_subdomains


DISCOVERY_SOURCE = "subfinder"
# The whole DNS check of one scan's names, not each lookup. Recording runs between finalization
# and the saved result; with a dead resolver every name used to cost its full lookup timeout --
# about a minute for a full window -- before the finished scan was stored.
DNS_DEADLINE_SECONDS = 10.0


async def _plan_with_deadline(
    hosts: list[str], *, root_domain: str | None = None,
    evidence: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    return await target_resolution.plan_discovered_targets(
        hosts, root_domain=root_domain, evidence=evidence, deadline_seconds=DNS_DEADLINE_SECONDS,
    )


def _count(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _plan_accounting(
    plan: Mapping[str, Any], *, found: int, considered: int, rejected: int = 0,
) -> dict[str, Any]:
    """What the DNS plan left out and why, kept with the run's DNS outcome."""
    classified = (
        len(plan.get("scannable") or ()) + len(plan.get("unresolved") or ())
        + len(plan.get("wildcard_suppressed") or ())
    )
    not_checked = len(plan.get("not_checked") or ())
    scannable = len(plan.get("scannable") or ())
    target_limit = int(target_resolution.DISCOVERY_TARGET_LIMIT)
    return {
        "found": found,
        "considered": considered,
        "rejected": rejected,
        "judged": max(0, classified - not_checked),
        "beyond_resolve_limit": max(
            0, _count(plan.get("submitted_count"), considered) - classified,
        ),
        "resolve_limit": plan.get("resolve_limit"),
        "dns_deadline_skipped": not_checked,
        "target_limit": target_limit,
        "over_target_limit": max(0, scannable - target_limit),
    }


def _recorded_outcome(
    discovery_id: str, resolution: Mapping[str, Any], *, found: int,
) -> dict[str, Any]:
    """The report's account of the run: what was added and every name that was not checked.

    Each cap is named: the report lists at most a bounded number of names, DNS checks a bounded
    window of those within one deadline, and at most a bounded number become targets per run.
    """
    considered = _count(resolution.get("considered"), found)
    rejected = _count(resolution.get("rejected"))
    scannable = _count(resolution.get("scannable"))
    unresolved = _count(resolution.get("unresolved_count"))
    deadline_skipped = _count(resolution.get("dns_deadline_skipped"))
    # A run recorded before the accounting fields counted every planned name as checked.
    judged = _count(resolution.get("judged"), max(
        0, _count(resolution.get("checked"), scannable + unresolved) - deadline_skipped,
    ))
    beyond_window = _count(resolution.get("beyond_resolve_limit"))
    over_target_limit = _count(resolution.get("over_target_limit"))
    insert_failed = _count(resolution.get("insert_failed"))
    wildcard_suppressed = _count(resolution.get("wildcard_suppressed_count"))
    reasons = [
        reason for reason, applies in (
            ("report_list_limit", found > considered + rejected),
            ("names_outside_root_domain", rejected > 0),
            ("dns_resolve_limit", beyond_window > 0),
            ("dns_deadline", deadline_skipped > 0),
            ("target_limit", over_target_limit > 0),
            ("insert_failed", insert_failed > 0),
            ("wildcard_dns", wildcard_suppressed > 0),
        ) if applies
    ]
    return {
        "status": "recorded",
        "discovery_id": discovery_id,
        "added": _count(resolution.get("added")),
        "scannable": scannable,
        "unresolved_count": unresolved,
        "unknown_count": _count(resolution.get("unknown_count")),
        "found": found,
        "checked": judged,
        "not_checked": max(0, found - judged),
        "rejected": rejected,
        "dns_deadline_skipped": deadline_skipped,
        "target_limit": resolution.get("target_limit"),
        "over_target_limit": over_target_limit,
        "insert_failed": insert_failed,
        "wildcard_suppressed": wildcard_suppressed,
        # Suppressed names stay visible: a wildcard verdict is a judgement, not a deletion.
        "wildcard_suppressed_names": list(resolution.get("wildcard_suppressed") or ())[:100],
        "wildcards": list(resolution.get("wildcards") or ()),
        "notes": list(resolution.get("notes") or ()),
        "partial": bool(reasons),
        "partial_reasons": reasons,
    }


async def record_scan_subdomain_discovery(
    pool: Any,
    report: Mapping[str, Any],
    *,
    scan_id: str,
    allowed_root_domains: Sequence[str] | None = None,
    plan_targets: Any = None,
) -> dict[str, Any] | None:
    """Store the report's discovered subdomains as a discovery run and targets.

    Idempotent per Scan: a redelivered job finds its own run and reports it again instead of
    recording a second one. Returns the outcome it wrote into the report section, or None when
    the report lists no subdomains. Every name the run did not check or add is counted with its
    reason; nothing is dropped silently.

    The report may come from a fleet node, so its section is not authority: only a root domain
    in the Scan's own binding (``allowed_root_domains``; none given records nothing) is recorded,
    and only names that are DNS names under it.
    """
    discovery = report.get("discovery") if isinstance(report, Mapping) else None
    section = discovery.get("subdomains") if isinstance(discovery, Mapping) else None
    if not isinstance(section, dict) or not section.get("hosts"):
        return None
    root_domain = canonical_name(section.get("root_domain")) or ""
    if not root_domain:
        outcome = {"status": "not_recorded", "reason": "ambiguous_root_domain"}
        section["targets"] = outcome
        return outcome
    bound = {canonical_name(item) for item in (allowed_root_domains or ())} - {None}
    if root_domain not in bound:
        outcome = {"status": "not_recorded", "reason": "root_domain_not_bound"}
        section["targets"] = outcome
        return outcome
    listed = list(section.get("hosts") or ())
    # The report may come from a fleet node: only canonical names strictly below the bound
    # root, on a label boundary, are recorded (``notexample.com`` is not under ``example.com``).
    hosts, _refused = filter_subdomains(listed, root_domain)
    if not hosts:
        outcome = {"status": "not_recorded", "reason": "no_names_under_root_domain"}
        section["targets"] = outcome
        return outcome
    found = max(len(listed), _count(section.get("total"), len(listed)))
    # Which sources named each host (a certificate keeps a name a wildcard would otherwise
    # explain away). Absent in reports finalized before sources were listed.
    sources = section.get("sources") if isinstance(section.get("sources"), Mapping) else {}
    evidence = {
        name: [f"{DISCOVERY_SOURCE}:{item}" for item in sources.get(name) or ()]
        for name in hosts
    }
    planner = plan_targets or (
        lambda names: _plan_with_deadline(names, root_domain=root_domain, evidence=evidence)
    )
    try:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                """SELECT id, sources_used FROM discovery_runs
                    WHERE sources_used->>'scan_id' = $1
                    ORDER BY created_at LIMIT 1""",
                str(scan_id),
            )
        if existing is not None:
            sources = existing["sources_used"]
            if isinstance(sources, str):
                sources = json.loads(sources)
            resolution = dict((sources or {}).get("dns_resolution") or {})
            discovery_id = str(existing["id"])
        else:
            # DNS before a connection is taken, as the Targets-page job does, so a slow resolver
            # never holds one. Only names with an address record become targets.
            plan = await planner(hosts)
            discovery_id = str(uuid.uuid4())
            # No transaction: store_discovered_targets tolerates one refused row, which an
            # enclosing transaction would turn into an aborted run.
            async with pool.acquire() as conn:
                resolution = await target_resolution.store_discovered_targets(
                    conn, plan, root_domain, source=DISCOVERY_SOURCE,
                )
                resolution = {
                    **resolution,
                    **_plan_accounting(
                        plan, found=found, considered=len(hosts),
                        rejected=len(listed) - len(hosts),
                    ),
                }
                await conn.execute(
                    """INSERT INTO discovery_runs
                           (id, root_domain, status, subdomains_found, new_subdomains,
                            result, sources_used, started_at, completed_at)
                       VALUES ($1, $2, 'completed', $3, $4, $5::jsonb, $6::jsonb, NOW(), NOW())""",
                    uuid.UUID(discovery_id), root_domain, found,
                    int(resolution.get("added") or 0), json.dumps(hosts),
                    json.dumps({
                        DISCOVERY_SOURCE: found,
                        "scan_id": str(scan_id),
                        "dns_resolution": resolution,
                    }),
                )
    except Exception as exc:  # noqa: BLE001 -- recording must not fail the finished scan
        outcome = {"status": "failed", "error": type(exc).__name__}
        section["targets"] = outcome
        return outcome
    outcome = _recorded_outcome(discovery_id, resolution, found=found)
    section["targets"] = outcome
    return outcome


def bound_root_domains(options: Mapping[str, Any]) -> tuple[str, ...] | None:
    """The root domains a canonical Scan job is bound to, or None when none can be derived."""
    try:
        from .executor import build_native_scan_execution
        from .worker_dispatch import prepare_worker_dispatch

        normalized, admission = prepare_worker_dispatch(options)
        if not admission.canonical or admission.plan is None:
            return None
        execution = build_native_scan_execution(admission.plan, normalized)
        return tuple(execution.target_binding.allowed_root_domains)
    except Exception:  # noqa: BLE001 -- a job whose binding cannot be derived records nothing
        return None


async def load_recorded_scan_report(
    pool: Any,
    store: Any,
    final_result: Any,
    *,
    scan_id: str,
    root_domains: Sequence[str],
    invalid_error: type[Exception] = ValueError,
) -> dict[str, Any]:
    """The finalized Scan report, with the Scan's subdomain discovery recorded into it.

    Recording writes the outcome into the report section, so it runs before the caller saves
    the report, and only under the root domains the Scan is bound to.
    """
    async with pool.acquire() as conn:
        final_observations = await store.load(
            conn,
            reference=final_result.observation_manifest_ref,
            scan_id=scan_id,
            action_id="finalize.report",
        )
    if (
        not final_observations
        or final_observations[0].get("kind") != "scan_report"
        or not isinstance(final_observations[0].get("report"), Mapping)
    ):
        raise invalid_error("canonical Scan report observation is invalid")
    report = dict(final_observations[0]["report"])
    await record_scan_subdomain_discovery(
        pool, report, scan_id=scan_id, allowed_root_domains=tuple(root_domains),
    )
    return report


async def record_ingested_report_subdomains(
    pool: Any, report: Mapping[str, Any], *, scan_id: str, options: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Record the subdomain discovery of a report finalized on a fleet node.

    The node finalizes the same report but has no database, so its names reached the report and
    never the inventory. The control plane records them under the root domains it derives from
    the job itself, never from the node's report.
    """
    discovery = report.get("discovery") if isinstance(report, Mapping) else None
    if not isinstance(discovery, Mapping) or not isinstance(discovery.get("subdomains"), Mapping):
        return None
    return await record_scan_subdomain_discovery(
        pool, report, scan_id=scan_id, allowed_root_domains=bound_root_domains(options),
    )


__all__ = [
    "DNS_DEADLINE_SECONDS",
    "bound_root_domains",
    "load_recorded_scan_report",
    "record_ingested_report_subdomains",
    "record_scan_subdomain_discovery",
]
