"""Scan execution of the opt-in ``recon_active`` family (``capabilities/recon_active.py``).

The dispatcher calls :func:`execute_recon_active` for ``dns.enumerate``, ``vhost.discover`` and
``web.param_discover``. Each runs under the action's durable reservation, the Scan's frozen
binding, and the inline preparation that re-checks active-testing approval. HTTP goes through
``execute_bound_http_request`` (frozen origin and address; every request recorded in the Scan's
HTTP archive); DNS questions go to the worker's resolver for names under the Scan's declared
apex roots only (``runtime.models.apex_recon_roots``).
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping
import urllib.parse

try:
    import target_resolution
    from runtime.models import apex_recon_roots
    from capabilities.http import execute_bound_http_request
    from capabilities.inline import ReconActiveExecutionAdapter
    from capabilities import recon_active
    from scan.negative_control import indistinguishable_from_absent
except (ImportError, ModuleNotFoundError):  # package import layout
    from .. import target_resolution
    from ..runtime.models import apex_recon_roots
    from ..capabilities.http import execute_bound_http_request
    from ..capabilities.inline import ReconActiveExecutionAdapter
    from ..capabilities import recon_active
    from .negative_control import indistinguishable_from_absent

RECON_ACTIVE_CAPABILITIES = frozenset({"dns.enumerate", "vhost.discover", "web.param_discover"})
_VHOST_BODY_LIMIT = 256 * 1024
_PARAMETER_BODY_LIMIT = 512 * 1024


def _signature(private: Any, *, requested_host: str) -> recon_active.ResponseSignature:
    body = private.body()
    headers = {str(name).lower(): value for name, value in private.headers().items()}
    return recon_active.ResponseSignature(
        status=int(private.status_code),
        length=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        location=recon_active.normalized_location(headers.get("location"), requested_host),
        edge=recon_active.edge_from_headers(headers),
    )


def _origin(target_url: str) -> str:
    parts = urllib.parse.urlsplit(str(target_url or ""))
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "", "", ""))


async def execute_recon_active(dispatcher: Any, action: Any, heartbeat: Any) -> Any:
    name = action.capability_name
    budget = dict(action.requested_budget)
    wall = max(1, int(budget.get("tool_wall_seconds") or 1))
    target = dispatcher.target
    policy = dispatcher.policy
    if not (policy.active_testing and policy.approval_receipt_id):
        return dispatcher._skip(action, "active_approval_missing")

    # Name guessing needs apex authority (subdomain discovery and an operator-declared apex),
    # re-derived here from the frozen binding and policy, never from the action's arguments.
    apex_roots = apex_recon_roots(policy, target)
    if name == "dns.enumerate":
        roots = apex_roots
        if not roots:
            return dispatcher._skip(action, "not_applicable")
        wordlist = recon_active.load_bundled_list(recon_active.DNS_WORDLIST)

        def operation(cancelled: Any) -> Any:
            return recon_active.enumerate_dns_names(
                roots=roots, labels=wordlist.entries, answer=target_resolution.system_answer,
                name_limit=int(budget.get("hosts_attempted") or 0), deadline_seconds=wall,
                cancelled=cancelled, wordlist=wordlist.receipt(),
            )

        args: dict[str, Any] = {}
    else:
        await dispatcher._restore_selected_origin()
        origin = _origin(dispatcher.target_url)
        if origin not in target.allowed_origins:
            return dispatcher._skip(action, "not_applicable")
        recorder = dispatcher._scan_call_recorder(action)

        async def fetch(path: str, query: Mapping[str, str] | None, *, virtual_host: str | None,
                        body_limit: int, headers: tuple[str, ...] = ("location",)) -> Any:
            private: list[Any] = []
            result = await execute_bound_http_request(
                origin, {"method": "GET", "path": path, "follow_redirects": False,
                         **({"query": dict(query)} if query else {})},
                target=target, allow_write=False, transaction_recorder=recorder,
                timeout_seconds=10, private_response_sink=private.append,
                private_response_headers=headers, response_body_limit=body_limit,
                virtual_host=virtual_host,
            )
            if not private:
                error = str(result.get("error") or "")
                if error.startswith("scope:"):
                    raise ValueError(error)
                raise OSError(error or "no response")
            return private[-1]

        if name == "vhost.discover":
            if not apex_roots:
                return dispatcher._skip(action, "not_applicable")
            wordlist = recon_active.load_bundled_list(recon_active.VHOST_WORDLIST)
            canonical = str(target.canonical_host or "")
            # Infrastructure intelligence, when this plan gathered it, may already place the
            # bound address on a CDN; the bound name's own response headers are checked too.
            infrastructure: list[Mapping[str, Any]] = []
            for planned in getattr(getattr(dispatcher, "plan", None), "actions", ()) or ():
                if planned.capability_name == "infrastructure.inspect":
                    infrastructure.extend(await dispatcher._observations(planned.action_id))
            edge = recon_active.edge_from_infrastructure(infrastructure)

            async def ask_host(host: str | None) -> Any:
                private = await fetch("/", None, virtual_host=host, body_limit=_VHOST_BODY_LIMIT,
                                      headers=("location", *recon_active.EDGE_HEADERS))
                return _signature(private, requested_host=host or canonical)

            def operation(cancelled: Any) -> Any:
                return recon_active.discover_virtual_hosts(
                    canonical_host=canonical, roots=apex_roots,
                    labels=wordlist.entries, request=ask_host,
                    request_limit=int(budget.get("http_requests") or 0), deadline_seconds=wall,
                    cancelled=cancelled, wordlist=wordlist.receipt(), edge=edge,
                )
        else:
            wordlist = recon_active.load_bundled_list(recon_active.PARAMETER_WORDLIST)
            observed: list[Mapping[str, Any]] = []
            for dependency in action.dependencies:
                observed.extend(await dispatcher._observations(dependency))
            absent = indistinguishable_from_absent(
                [item for item in observed if item.get("kind") == "content_discovery"]
            )
            routes = recon_active.parameter_routes(observed, origin=origin, excluded_urls=absent)

            async def ask_route(route_origin: str, path: str, query: Mapping[str, str] | None,
                                marker: str | None) -> Any:
                private = await fetch(path, query, virtual_host=None,
                                      body_limit=_PARAMETER_BODY_LIMIT)
                return recon_active.ParameterResponse(
                    signature=_signature(private, requested_host=str(target.canonical_host or "")),
                    reflected=bool(marker) and marker.encode() in private.body(),
                )

            def operation(cancelled: Any) -> Any:
                return recon_active.discover_parameters(
                    origin=origin, routes=routes, names=wordlist.entries, request=ask_route,
                    request_limit=int(budget.get("http_requests") or 0), deadline_seconds=wall,
                    cancelled=cancelled, wordlist=wordlist.receipt(),
                )

        args = {}
    adapter = dispatcher._prepared_inline(action, args, operation, ReconActiveExecutionAdapter)
    return await dispatcher._execute_adapter(action, adapter, heartbeat, managed_cancellation=True)


__all__ = ["RECON_ACTIVE_CAPABILITIES", "execute_recon_active"]
