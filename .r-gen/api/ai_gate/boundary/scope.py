"""Transport adapter for the existing shared scope guard, including DNS checks."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from .contract import ContractError


class BoundaryScope:
    def __init__(self, origin: str, guard: dict[str, Any] | None) -> None:
        self.origin = origin
        self.host = urlsplit(origin).hostname or ""
        self.guard = guard
        self.addresses: dict[str, list[str]] = {}
        try:
            literal = ipaddress.ip_address(self.host)
        except ValueError:
            literal = None
        if literal:
            self.addresses[self.host] = [str(literal)]
        # Only the developer's loopback fixture may omit persisted worker scope.
        if not guard and not (literal and literal.is_loopback):
            raise ContractError("boundary_requires_worker_runtime_scope_guard")
        self.validate(origin, resolving=False)

    def validate(self, url: str, *, resolving: bool = False) -> None:
        if not self.guard:
            return
        try:
            from action_scope import evaluate_runtime_destination_scope
        except ModuleNotFoundError:
            from ...action_scope import evaluate_runtime_destination_scope
        observations = [{"host": host, "ips": ips} for host, ips in self.addresses.items()]
        result = evaluate_runtime_destination_scope(self.guard, url, resolution_observations=observations)
        # DNS may be unavailable before the resolver runs, but must be proven
        # before a connection is opened. All other uncertainty fails closed.
        warnings = set(result.get("warnings") or [])
        acceptable_pre_resolution = not resolving and warnings <= {"runtime_dns_unverified"}
        if result["status"] == "blocked" or (result["status"] != "allowed" and not acceptable_pre_resolution):
            raise ContractError("boundary_runtime_scope_rejected")

    def resolver(self, aiohttp_module: Any):
        scope = self

        class CheckedResolver(aiohttp_module.abc.AbstractResolver):
            def __init__(self) -> None:
                self.delegate = aiohttp_module.resolver.DefaultResolver()

            async def resolve(self, host: str, port: int = 0, family: int = 0):
                if host != scope.host:
                    raise ContractError("boundary_resolver_host_mismatch")
                rows = await self.delegate.resolve(host, port, family)
                scope.addresses[host] = list(dict.fromkeys(str(row["host"]) for row in rows))
                if not scope.addresses[host]:
                    raise ContractError("boundary_dns_empty")
                scope.validate(scope.origin, resolving=True)
                return rows

            async def close(self) -> None:
                await self.delegate.close()

        return CheckedResolver()
