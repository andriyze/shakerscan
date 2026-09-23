"""Target-bound network capability adapters with server-owned argv."""

from __future__ import annotations

import asyncio
from contextlib import suppress
import ipaddress
import json
import math
import re
import time
from typing import Any, Awaitable, Callable, Mapping
import xml.etree.ElementTree as ET

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.models import (
    ParsedCapabilityResult,
    PreparedCommand,
    PreparedExecution,
    ScanPolicy,
    TargetBinding,
)
from .network_inputs import (
    CapabilityInputError, _addresses, _port_range, _ports, _require_network_policy,
)


NETWORK_CAPABILITY_ADAPTERS = {
    "ports.discover": lambda: PortsDiscoverAdapter(),
    "service.fingerprint": lambda: ServiceFingerprintAdapter(),
    "service.nse_check": lambda: _nse_check_adapter(),
    "subdomains.discover": lambda: SubdomainsDiscoverAdapter(),
}


def _nse_check_adapter():
    from .nse import NseCheckAdapter
    return NseCheckAdapter()


def network_capability_adapter(name: str) -> Any:
    """Return a fresh canonical adapter for a registry capability name."""
    try:
        factory = NETWORK_CAPABILITY_ADAPTERS[str(name or "").strip().lower()]
    except KeyError as exc:
        raise CapabilityInputError("unknown canonical network capability") from exc
    return factory()


CommandRunner = Callable[..., Awaitable[Any]]


class NetworkExecutionAdapter:
    """Execute one prepared network capability through the shared Hunt boundary.

    Preparation owns target binding and server-authored argv. This runtime adapter
    owns only process execution, parsing, cancellation, heartbeat, and measured
    consumption so the shared ``CapabilityExecutor`` can normalize failures and
    enforce the registry identity contract for every network capability.
    """

    def __init__(
        self,
        *,
        prepared: PreparedExecution,
        parser: Any,
        command_runner: CommandRunner,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        heartbeat_interval_seconds: float = 30.0,
    ) -> None:
        self.capability_name = prepared.capability_name
        self.adapter_name = prepared.adapter_name
        self.adapter_version = prepared.adapter_version
        self._prepared = prepared
        self._parser = parser
        self._command_runner = command_runner
        self._max_stdout_bytes = int(max_stdout_bytes)
        self._max_stderr_bytes = int(max_stderr_bytes)
        self._heartbeat_interval_seconds = float(heartbeat_interval_seconds)
        if self._heartbeat_interval_seconds <= 0:
            raise ValueError("network capability heartbeat interval must be positive")

    async def _run_command_with_heartbeats(self, command, **kwargs):
        if self.capability_name != "service.nse_check":
            return await self._run_process_with_heartbeats(command, **kwargs)
        from .nse_http_runtime import NseCommandResult, command_transport
        async with command_transport(self._prepared, command, heartbeat=kwargs["heartbeat"],
                                     cancelled=kwargs["cancelled"]) as (bound_command, bridge):
            process = await self._run_process_with_heartbeats(bound_command, **kwargs)
        return NseCommandResult(process, bridge)

    async def _run_process_with_heartbeats(
        self,
        command: PreparedCommand,
        *,
        per_command_wall: int,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> Any:
        """Keep the durable lease alive while one bounded subprocess is running."""
        task = asyncio.create_task(self._command_runner(
            [command.binary, *command.argv],
            soft_timeout=float(per_command_wall),
            flush_grace=0.0,
            hard_timeout=float(per_command_wall),
            cancel_check=cancelled,
            max_stdout_bytes=self._max_stdout_bytes,
            max_stderr_bytes=self._max_stderr_bytes,
        ))
        try:
            while True:
                done, _pending = await asyncio.wait(
                    {task}, timeout=self._heartbeat_interval_seconds,
                )
                if task in done:
                    return await task
                await heartbeat()
        except BaseException:
            if not task.done():
                task.cancel()
            with suppress(BaseException):
                await task
            raise

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        prepared = self._prepared
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        partial = False
        timed_out = False
        attempted_commands = 0
        elapsed_seconds = 0
        command_count = max(1, len(prepared.commands))
        per_command_wall = max(
            1,
            int(prepared.estimated_budget.get("tool_wall_seconds") or 1)
            // command_count,
        )
        status = "failed"
        process_failed = False
        nse_http_actual = {"http_requests": 0, "state_changing_requests": 0}

        for command in prepared.commands:
            if cancelled():
                status = "cancelled"
                errors.insert(0, "cancelled")
                break
            command_started = time.monotonic()
            try:
                attempted_commands += 1
                streamed = await self._run_command_with_heartbeats(
                    command,
                    per_command_wall=per_command_wall,
                    heartbeat=heartbeat,
                    cancelled=cancelled,
                )
            except FileNotFoundError:
                attempted_commands -= 1
                errors.insert(0, "scanner_not_available")
                status = "failed"
                break
            finally:
                elapsed_seconds += max(
                    0, math.ceil(time.monotonic() - command_started)
                )

            parse_kwargs: dict[str, Any] = {"timed_out": streamed.timed_out}
            if prepared.capability_name == "subdomains.discover":
                parse_kwargs["root_domain"] = str(
                    prepared.redacted_execution["root_domain"]
                )
            elif prepared.capability_name == "service.nse_check":
                parse_kwargs["expected_ports"] = tuple(
                    int(item) for item in prepared.redacted_execution.get("ports") or ()
                )
                parse_kwargs["expected_scripts"] = tuple(
                    str(item) for item in prepared.redacted_execution.get("scripts") or ()
                )
            parsed = self._parser.parse(streamed.stdout, **parse_kwargs)
            parsed_observations = parsed.observations
            bridge = getattr(streamed, "nse_http", None)
            if bridge is not None:
                from .nse_http_runtime import decorate_observations
                parsed_observations = decorate_observations(parsed_observations, bridge)
                for key in nse_http_actual:
                    nse_http_actual[key] += bridge.actual[key]
                errors.extend(bridge.errors)
                partial = partial or bool(bridge.errors)
            observations.extend(dict(row) for row in parsed_observations)
            errors.extend(str(item) for item in parsed.errors)
            partial = bool(
                partial
                or parsed.partial
                or streamed.partial
                or streamed.stdout_truncated
            )
            timed_out = bool(
                timed_out or parsed.timed_out or streamed.timed_out
            )
            await heartbeat()
            if streamed.cancelled:
                status = "cancelled"
                errors.insert(0, "cancelled")
                break
            if streamed.returncode != 0:
                process_failed = True
                partial = True
                errors.insert(
                    0,
                    f"{prepared.adapter_name}_exit_{streamed.returncode}",
                )
                # A failed host must not discard its usable output or prevent
                # examination of the other admitted addresses.
        else:
            status = "failed" if process_failed and not observations else "partial" if partial else "success"

        actual: dict[str, int] = {}
        for dimension, reserved_amount in prepared.estimated_budget.items():
            reserved_amount = int(reserved_amount)
            if dimension == "tool_wall_seconds":
                actual[dimension] = min(reserved_amount, elapsed_seconds)
            elif dimension in {"hosts_attempted", "tcp_ports_attempted"}:
                actual[dimension] = min(
                    reserved_amount,
                    (
                        reserved_amount * attempted_commands
                        + command_count
                        - 1
                    )
                    // command_count,
                )
            elif prepared.capability_name == "service.nse_check":
                if dimension in nse_http_actual:
                    actual[dimension] = nse_http_actual[dimension]
                elif dimension == "device_fragility_points":
                    # Native connects/TLS retain an explicitly labelled cost
                    # estimate; HTTP is measured and unused HTTP grant released.
                    non_http = reserved_amount - int(prepared.estimated_budget.get("http_requests") or 0)
                    actual[dimension] = ((non_http * attempted_commands + command_count - 1) // command_count
                                         + nse_http_actual["http_requests"])


        return CapabilityAdapterResult(
            status=status,
            observations=tuple(observations),
            errors=tuple(errors[:20]),
            actual_budget=actual,
            partial=partial,
            timed_out=timed_out,
            execution_started=attempted_commands > 0,
            parser_version=prepared.parser_version,
            redacted_execution=dict(prepared.redacted_execution),
        )


PORT_PROFILES: Mapping[str, tuple[int, ...] | str] = {
    "known_services": (21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                       1433, 1521, 1883, 3000, 3306, 5432, 6379, 8080, 8443, 8883, 9200),
    "top_100": "100",
    "top_1000": "1000",
    "device_common": (22, 23, 53, 80, 81, 443, 445, 554, 631, 1883, 1900, 5000,
                      7000, 8008, 8009, 8060, 8080, 8443, 8883, 9000, 9100, 49152, 55000),
}


class PortsDiscoverAdapter:
    capability_name = "ports.discover"
    adapter_name = "naabu"
    adapter_version = "1"
    parser_version = "naabu-jsonl/v1"

    def prepare(
        self, *, target: TargetBinding, args: Mapping[str, Any], policy: ScanPolicy
    ) -> PreparedExecution:
        _require_network_policy(policy)
        addresses = _addresses(target)
        profile = str(args.get("profile") or "top_100").strip().lower()
        custom = args.get("ports")
        port_range = args.get("port_range")
        selected = None
        if custom is not None:
            selected = _ports(custom, maximum=1_000)
            port_args = ("-p", ",".join(map(str, selected)))
            attempted_per_host = len(selected)
            profile = "custom"
        elif port_range is not None:
            # A contiguous range on the authorized host. Bounded to the same
            # per-call ceiling as a custom list so one call never becomes a
            # full-range sweep; the planner chunks a wider span across calls.
            start, end = _port_range(port_range, maximum=1_000)
            port_args = ("-p", f"{start}-{end}")
            attempted_per_host = end - start + 1
            profile = "range"
        else:
            configured = PORT_PROFILES.get(profile)
            if configured is None:
                raise CapabilityInputError(f"unknown port profile: {profile}")
            if isinstance(configured, str):
                port_args = ("-top-ports", configured)
                attempted_per_host = int(configured)
            else:
                port_args = ("-p", ",".join(map(str, configured)))
                attempted_per_host = len(configured)
        commands = tuple(
            PreparedCommand(
                "naabu",
                ("-host", address, *port_args, "-Pn", "-scan-type", "c", "-rate", "10",
                 "-c", "10", "-timeout", "1500ms", "-retries", "1", "-json", "-silent",
                 "-no-color", "-disable-update-check", "-no-stdin"),
                address,
            )
            for address in addresses
        )
        # port_args is part of the digest so two different ranges/profiles never
        # collide on the same idempotency key.
        normalized = {"profile": profile, "ports": list(selected) if selected is not None else None,
                      "port_args": list(port_args),
                      "target_id": target.target_id, "addresses": list(addresses)}
        return PreparedExecution(
            self.capability_name, self.adapter_name, self.adapter_version, commands,
            {"tcp_ports_attempted": attempted_per_host * len(addresses),
             "hosts_attempted": len(addresses), "tool_wall_seconds": 120 * len(addresses)},
            PreparedExecution.digest_input(normalized),
            {"profile": profile, "port_count": attempted_per_host,
             "approved_addresses": list(addresses)}, self.parser_version,
        )
    def parse(self, output: str, *, timed_out: bool = False) -> ParsedCapabilityResult:
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        seen_ports: set[tuple[str, int]] = set()
        for line in str(output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                address = str(ipaddress.ip_address(str(row.get("ip") or row.get("host"))))
                port = int(row.get("port"))
                if not 1 <= port <= 65_535:
                    raise ValueError("invalid port")
                if (address, port) not in seen_ports:
                    seen_ports.add((address, port))
                    observations.append({"kind": "open_port", "address": address, "port": port,
                                         "transport": "tcp"})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                errors.append(f"malformed_naabu_record:{type(exc).__name__}")
        partial = bool(timed_out or errors)
        return ParsedCapabilityResult(
            "partial" if partial else "succeeded", tuple(observations), partial, bool(timed_out),
            tuple(errors[:20]), {"record_count": len(observations)},
        )


class ServiceFingerprintAdapter:
    capability_name = "service.fingerprint"
    adapter_name = "nmap"
    adapter_version = "1"
    parser_version = "nmap-xml/v1"

    def prepare(
        self, *, target: TargetBinding, args: Mapping[str, Any], policy: ScanPolicy
    ) -> PreparedExecution:
        _require_network_policy(policy)
        addresses = _addresses(target)
        selected = _ports(args.get("ports"), maximum=256)
        profile = str(args.get("profile") or "version_light").strip().lower()
        if profile not in {"version_light", "version_default"}:
            raise CapabilityInputError("profile must be version_light or version_default")
        version_args = ("--version-light",) if profile == "version_light" else ()
        commands = tuple(
            PreparedCommand(
                "nmap",
                ("-sT", "-Pn", "-n", "-sV", *version_args, "--reason", "--host-timeout",
                 "120s", "-p", ",".join(map(str, selected)), "-oX", "-", address),
                address,
            )
            for address in addresses
        )
        normalized = {"profile": profile, "ports": list(selected), "target_id": target.target_id,
                      "addresses": list(addresses)}
        return PreparedExecution(
            self.capability_name, self.adapter_name, self.adapter_version, commands,
            {"tcp_ports_attempted": len(selected) * len(addresses),
             "hosts_attempted": len(addresses), "tool_wall_seconds": 120 * len(addresses)},
            PreparedExecution.digest_input(normalized),
            {"profile": profile, "ports": list(selected), "approved_addresses": list(addresses)},
            self.parser_version,
        )

    def parse(self, output: str, *, timed_out: bool = False) -> ParsedCapabilityResult:
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        text = str(output or "")
        try:
            root = ET.fromstring(text)
            for host in root.findall("host"):
                address_node = host.find("address")
                address = str((address_node.attrib if address_node is not None else {}).get("addr") or "")
                try:
                    address = str(ipaddress.ip_address(address))
                except ValueError:
                    continue
                for port_node in host.findall("./ports/port"):
                    state_node = port_node.find("state")
                    service_node = port_node.find("service")
                    attributes = service_node.attrib if service_node is not None else {}
                    raw_confidence = attributes.get("conf", "")
                    confidence = int(raw_confidence) if re.fullmatch(r"[0-9]{1,2}", raw_confidence) else None
                    if confidence is not None and not 0 <= confidence <= 10:
                        confidence = None
                    state = (state_node.attrib if state_node is not None else {}).get("state")
                    port = int(port_node.attrib["portid"])
                    transport = port_node.attrib.get("protocol", "tcp")
                    if state == "open":
                        observations.append({
                            "kind": "open_port", "address": address, "port": port,
                            "transport": transport,
                        })
                    observations.append({
                        "kind": "service",
                        **{key: value for key, value in {
                            "method": attributes.get("method"),
                            "confidence": confidence,
                            "tunnel": attributes.get("tunnel"),
                        }.items() if value is not None},
                        "address": address,
                        "port": port,
                        "transport": transport,
                        "state": state,
                        "reason": (state_node.attrib if state_node is not None else {}).get("reason"),
                        "service": (service_node.attrib if service_node is not None else {}).get("name"),
                        "product": (service_node.attrib if service_node is not None else {}).get("product"),
                        "version": (service_node.attrib if service_node is not None else {}).get("version"),
                        "cpe": [node.text for node in port_node.findall("./service/cpe") if node.text],
                    })
        except (ET.ParseError, ValueError, KeyError) as exc:
            errors.append(f"malformed_nmap_xml:{type(exc).__name__}")
        partial = bool(timed_out or errors)
        return ParsedCapabilityResult(
            "partial" if partial else "succeeded", tuple(observations), partial, bool(timed_out),
            tuple(errors), {"record_count": len(observations)},
        )


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class SubdomainsDiscoverAdapter:
    capability_name = "subdomains.discover"
    adapter_name = "subfinder"
    adapter_version = "1"
    parser_version = "subfinder-lines/v1"

    def prepare(
        self, *, target: TargetBinding, args: Mapping[str, Any], policy: ScanPolicy
    ) -> PreparedExecution:
        if not policy.subdomain_discovery:
            raise CapabilityInputError("subdomain discovery policy is not enabled")
        root = str(args.get("root_domain") or (target.allowed_root_domains[0]
                   if target.allowed_root_domains else target.canonical_host) or "").lower().rstrip(".")
        if root not in target.allowed_root_domains:
            raise CapabilityInputError("root domain is not present in the target binding")
        if not _DOMAIN_RE.fullmatch(root):
            raise CapabilityInputError("root domain is invalid")
        command = PreparedCommand(
            "subfinder", ("-d", root, "-silent", "-json", "-disable-update-check", "-timeout", "10",
                          "-max-time", "2"), None,
        )
        normalized = {"root_domain": root, "target_id": target.target_id}
        return PreparedExecution(
            self.capability_name, self.adapter_name, self.adapter_version, (command,),
            {"hosts_attempted": 1, "tool_wall_seconds": 120},
            PreparedExecution.digest_input(normalized), {"root_domain": root}, self.parser_version,
        )

    def parse(self, output: str, *, root_domain: str, timed_out: bool = False) -> ParsedCapabilityResult:
        suffix = "." + root_domain.lower().rstrip(".")
        observations: list[Mapping[str, Any]] = []
        errors: list[str] = []
        for line in str(output or "").splitlines():
            try:
                row = json.loads(line)
                host = str(row.get("host") or row.get("input") or "").lower().rstrip(".")
            except json.JSONDecodeError:
                host = line.strip().lower().rstrip(".")
            if host.endswith(suffix) and _DOMAIN_RE.fullmatch(host):
                observations.append({"kind": "subdomain", "host": host, "root_domain": root_domain})
            elif line.strip():
                errors.append("out_of_scope_or_malformed_subdomain_record")
        partial = bool(timed_out or errors)
        return ParsedCapabilityResult(
            "partial" if partial else "succeeded", tuple(observations), partial, bool(timed_out),
            tuple(errors[:20]), {"record_count": len(observations)},
        )
