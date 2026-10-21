"""Shared method-aware Nuclei options for durable Scan actions."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

# Defined beside the batch attempt costs, which the planner and the report (shipped to the
# host by the installer, unlike this module) read; re-exported here for the adapter.
from .external_process import (  # noqa: F401
    ACTIVE_TEMPLATE_PLANNED_WINDOWS,
    ACTIVE_TEMPLATE_WINDOWS_RECORD_KIND,
    TEMPLATE_WINDOW_BEYOND_ALLOWLIST,
    TEMPLATE_WINDOW_PAST_BASES,
)
from .nuclei_template_index import resolve_active_nuclei_selection


@dataclass(frozen=True)
class ActiveScanNucleiOptions:
    capability_args: Mapping[str, Any]
    worker_options: Mapping[str, Any]
    skip_reason: str | None = None
    verify_selection: Mapping[str, Any] | None = None


def resolve_active_scan_nuclei_options(
    template_options: Mapping[str, Any],
    *,
    templates_dir: str,
    allow_state_changing_http: bool,
    allow_exploit_classes: bool = False,
) -> ActiveScanNucleiOptions:
    """Resolve exact template IDs without putting a large allowlist in API args."""
    selection = resolve_active_nuclei_selection(
        templates_dir,
        severities=template_options.get("severity"),
        tags=template_options.get("tags"),
        allow_state_changing_http=allow_state_changing_http,
        only_template_ids=template_options.get("verify_template_ids"),
        allow_exploit_classes=allow_exploit_classes,
    )
    if selection.skip:
        return ActiveScanNucleiOptions(
            {}, {}, selection.skip_reason or "not_applicable",
            verify_selection=selection.verify_selection,
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
    return ActiveScanNucleiOptions(capability_args, worker_options, verify_selection=selection.verify_selection)


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


def active_template_window_count(template_ids: str, *, size: int | None = None) -> int:
    """How many windows the allowlist splits into (see ``active_template_window``)."""
    ids = [item for item in str(template_ids or "").split(",") if item]
    size = ACTIVE_TEMPLATE_WINDOW_SIZE if size is None else int(size)
    return max(1, -(-len(ids) // max(1, size))) if ids else 0


def active_template_window_applies(
    template_ids: str, position: int, *, endpoint_entries: int,
) -> bool:
    """Whether a planned position past the endpoints still names a window of its own.

    A position below the endpoint count is an endpoint's own attempt and runs exactly as it
    always did. A later position runs window ``position`` on endpoint ``position % E`` only
    while the allowlist has that many windows; past them it would repeat a window already run
    on the same host, so it runs nothing.
    """
    if position < max(0, int(endpoint_entries)):
        return True
    return position < active_template_window_count(template_ids)


def planned_endpoint_entries(
    capability_args: Mapping[str, Any], manifest_entries: int,
) -> int | None:
    """E when an active-template slice plans positions past its endpoints, else None.

    The planner declares ``endpoint_entries`` (E, the endpoint manifest's size) beside
    ``manifest_entries`` (the positions it plans) only when it planned more positions than
    endpoints. Both must agree with the immutable manifest and the planned window count.
    """
    raw = capability_args.get("endpoint_entries")
    if raw is None:
        return None
    declared = capability_args.get("manifest_entries")
    if (
        isinstance(raw, bool) or not isinstance(raw, int) or raw < 1
        or raw != int(manifest_entries)
        or isinstance(declared, bool) or not isinstance(declared, int)
        or not raw <= declared <= max(raw, ACTIVE_TEMPLATE_PLANNED_WINDOWS)
    ):
        raise ValueError("active template positions disagree with the endpoint manifest")
    return raw


def _origin(scheme: str, host: str, port: int | None) -> str:
    scheme = scheme.lower()
    host = host.lower().rstrip(".")
    authority = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{authority}" if port in (None, default) else f"{scheme}://{authority}:{port}"


def active_sweep_bases(
    target_url: str, entries: Sequence[Mapping[str, Any]], *, exclude_origins: Sequence[str] = (),
) -> tuple[str, ...]:
    """The base URLs an active-template sweep runs its windows at, in order.

    A window's templates address the host from nuclei's base URL: ``{{BaseURL}}/images/json``,
    and a raw ``GET /version`` is joined to the base path as well. Running window o at endpoint
    o % E put a discovered endpoint's path under them: zoo docker's endpoints were /version,
    /info and /, so misconfigured-docker asked /version/images/json and docker-daemon-exposed
    asked under /info, both got 404, and both windows counted as run with the host's two
    critical findings lost.

    The first base is the directory of the URL the Scan targets (the dispatcher's own target
    URL, so a parallel shard has the same one): a path ending in ``/`` is kept, otherwise its
    last segment is dropped (``/app/login.php`` -> ``/app/``; ``/app`` -> ``/``, since nothing
    says ``app`` is a directory), and the query and fragment are dropped. Every other origin the
    endpoint manifest names (all inside the Scan's frozen binding) follows at its root, sorted,
    except ``exclude_origins``: a scheme-inferred Scan's origin it did not select (the other
    scheme usually only redirects, and batch attempts follow no redirects).

    No permitted template needs a discovered endpoint's path (pinned bundle, 1,145 permitted
    templates): none fuzzes the endpoint or appends a query to it; 550 append a path to
    {{BaseURL}}, 495 send raw requests with absolute paths (joined to the base path), and 108 ask
    {{BaseURL}} itself to recognise a product's page -- which a window ran on one arbitrary
    endpoint, never on each, so the bases are where that check is meaningful.
    """
    parsed = urllib.parse.urlsplit(str(target_url or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("an active-template sweep needs an absolute HTTP(S) target URL")
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path[: path.rfind("/") + 1] or "/"
    first_origin = _origin(parsed.scheme, parsed.hostname, parsed.port)
    others = sorted({
        _origin(str(entry["scheme"]), str(entry["host"]), int(entry["port"]))
        for entry in entries
        if entry.get("scheme") and entry.get("host") and entry.get("port")
    } - {first_origin} - {str(origin).rstrip("/").lower() for origin in exclude_origins})
    return (first_origin + path, *(origin + "/" for origin in others))


def active_sweep_base(position: int, *, bases: Sequence[str], window_count: int) -> str | None:
    """Where a sweep position runs: window ``position % W`` at base ``position // W``.

    Every (base, window) pair runs once. A position past ``len(bases) x W`` would repeat a
    pair already run -- a host with 215 endpoints and one origin repeated each of its 39
    windows five or six times at the same URL, mutating templates included -- so it runs
    nothing (``None``). The window a position runs is unchanged
    (``active_template_window``), and so are the plan, the holds and the attempt identities.
    """
    count = max(1, int(window_count))
    index = int(position) // count
    return bases[index] if 0 <= index < len(bases) else None


def window_position_candidate_id(
    candidate_id: str, position: int, endpoint_entries: int | None,
) -> str:
    """The attempt identity of a planned position: an endpoint's own below E, unchanged.

    A position past the endpoints runs another window on endpoint ``position % E``, so it is
    its own attempt; positions below E keep the identity -- and so the checkpoints and resume
    -- every earlier release gave them.
    """
    if endpoint_entries is None or position < int(endpoint_entries):
        return candidate_id
    return f"{candidate_id}:window:{int(position)}"
