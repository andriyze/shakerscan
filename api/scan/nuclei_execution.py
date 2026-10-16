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


#: Active templates one attempt is given. Measured on the 2.11 scanner image (pinned
#: bundle, 1,146 permitted active templates with state-changing HTTP) against a local
#: counting server, with the engine's own argv at the per-endpoint hold (120 requests,
#: 45 s, paced to 2 requests/s): given the whole allowlist, an attempt sent requests for
#: 25 templates (10% of nuclei's 2,601-request plan), and the SAME 25 on every attempt,
#: so about 97% of active templates never ran on any endpoint of any Scan
#: (dvwa-default-login among them). Windows of 30 finished (100% of their plan, 27-30
#: templates sending requests) in five measured windows; windows of 40 and 90 did not.
ACTIVE_TEMPLATE_WINDOW_SIZE = 30


@dataclass(frozen=True)
class ActiveTemplateWindow:
    template_ids: str
    index: int
    count: int
    templates: int

    def record(self) -> dict[str, int]:
        return {"index": self.index, "count": self.count, "templates": self.templates}


def active_template_window(
    template_ids: str, ordinal: int, *, size: int | None = None,
) -> ActiveTemplateWindow:
    """The share of the active allowlist one endpoint attempt runs.

    The allowlist is split into equal stride windows (each a cross-section of the
    sorted ids, so every window mixes products and tags) sized to what one attempt can
    finish, and the endpoint's manifest ordinal picks the window. A Scan with at least
    as many endpoints as windows runs every permitted template once; templates that
    address the host (most default-login and exposure checks send absolute paths) need
    no particular endpoint. The choice depends only on the manifest position, so a
    resumed or retried attempt runs the same templates.
    """
    ids = [item for item in str(template_ids or "").split(",") if item]
    if not ids:
        raise ValueError("active template allowlist is empty")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise ValueError("manifest ordinal must be a non-negative integer")
    size = ACTIVE_TEMPLATE_WINDOW_SIZE if size is None else int(size)
    count = max(1, -(-len(ids) // max(1, size)))
    index = ordinal % count
    chosen = ids[index::count]
    return ActiveTemplateWindow(",".join(chosen), index, count, len(chosen))
