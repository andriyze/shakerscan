"""Shared method-aware Nuclei options for durable Scan actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .nuclei_template_index import resolve_active_nuclei_selection


@dataclass(frozen=True)
class ActiveScanNucleiOptions:
    capability_args: Mapping[str, Any]
    worker_options: Mapping[str, Any]
    skip_reason: str | None = None


def resolve_active_scan_nuclei_options(
    template_options: Mapping[str, Any],
    *,
    templates_dir: str,
    allow_state_changing_http: bool,
) -> ActiveScanNucleiOptions:
    """Resolve exact template IDs without putting a large allowlist in API args."""
    selection = resolve_active_nuclei_selection(
        templates_dir,
        severities=template_options.get("severity"),
        tags=template_options.get("tags"),
        allow_state_changing_http=allow_state_changing_http,
    )
    if selection.skip:
        return ActiveScanNucleiOptions(
            {}, {}, selection.skip_reason or "not_applicable",
        )
    worker_options = {
        "severity": template_options.get("severity", "high,critical"),
        "template_ids": ",".join(selection.template_ids),
        "template_profile": "active",
        "nuclei_active_state_changing": selection.includes_state_changing,
    }
    if template_options.get("template_pack_digest"):
        worker_options["template_pack_digest"] = template_options["template_pack_digest"]
    # IDs can exceed the schema's string ceiling; control flags are worker-only.
    # The immutable manifest digest continues to bind the capability input.
    capability_args = {
        key: template_options[key]
        for key in ("severity", "template_pack_digest")
        if key in template_options
    }
    return ActiveScanNucleiOptions(capability_args, worker_options)
