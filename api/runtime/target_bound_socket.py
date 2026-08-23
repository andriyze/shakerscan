"""Socket-level connection factory for a frozen runtime target binding."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from typing import Any, Callable, Iterable


class FrozenTargetSocketError(OSError):
    """No authorized frozen address could be connected."""


@dataclass(frozen=True)
class FrozenSocketEndpoint:
    hostname: str
    address: str
    port: int
    family: socket.AddressFamily

    @property
    def sockaddr(self) -> tuple[Any, ...]:
        if self.family == socket.AF_INET6:
            return (self.address, self.port, 0, 0)
        return (self.address, self.port)


class FrozenTargetSocketFactory:
    """Connect directly to admitted addresses without resolving the hostname."""

    resolves_during_connect = False

    def __init__(
        self,
        *,
        hostname: str,
        port: int,
        frozen_addresses: Iterable[str],
    ) -> None:
        normalized_host = str(hostname or "").strip().lower().rstrip(".")
        if not normalized_host or any(character.isspace() for character in normalized_host):
            raise ValueError("hostname is invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("port must be between 1 and 65535")
        addresses: list[str] = []
        for raw in frozen_addresses:
            address = str(ipaddress.ip_address(str(raw or "").strip()))
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ValueError("at least one frozen address is required")
        self.hostname = normalized_host
        self.port = port
        self.addresses = tuple(addresses)

    def endpoints(self, *, start_index: int = 0) -> tuple[FrozenSocketEndpoint, ...]:
        offset = int(start_index) % len(self.addresses)
        ordered = self.addresses[offset:] + self.addresses[:offset]
        return tuple(
            FrozenSocketEndpoint(
                hostname=self.hostname,
                address=address,
                port=self.port,
                family=(
                    socket.AF_INET6
                    if ipaddress.ip_address(address).version == 6
                    else socket.AF_INET
                ),
            )
            for address in ordered
        )

    def connect(
        self,
        *,
        timeout: float | None = None,
        start_index: int = 0,
        socket_factory: Callable[..., socket.socket] = socket.socket,
    ) -> socket.socket:
        """Try only frozen numeric sockaddr values, closing failed sockets."""
        failures: list[str] = []
        for endpoint in self.endpoints(start_index=start_index):
            candidate = socket_factory(endpoint.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            try:
                if timeout is not None:
                    candidate.settimeout(float(timeout))
                candidate.connect(endpoint.sockaddr)
                return candidate
            except OSError as exc:
                failures.append(f"{endpoint.address}:{type(exc).__name__}")
                candidate.close()
        raise FrozenTargetSocketError(
            "all frozen target addresses failed: " + ",".join(failures)
        )
