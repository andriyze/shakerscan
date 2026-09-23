"""A fixed, low-impact NSE surface for target-bound Hunt service checks."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Mapping
from xml.etree import ElementTree as ET

from runtime.models import ParsedCapabilityResult, PreparedCommand, PreparedExecution, ScanPolicy, TargetBinding


# Every ID is a reviewed, server-owned script shipped in the worker image. Do
# not accept NSE categories, paths, script-args, or arbitrary script names here.
NSE_SCRIPTS = frozenset({
    "ssl-enum-ciphers", "http-security-headers", "http-methods", "http-trace",
})
_HEADER_NAMES = (
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
)


def _signals(script_id: str, output: str) -> dict[str, Any]:
    if script_id == "ssl-enum-ciphers":
        grades = re.findall(r"least strength:\s*([A-F])\b", output, re.I)
        return {
            "tls_versions": sorted(set(re.findall(r"\b(?:SSLv[23]|TLSv1(?:\.[0-3])?)\b", output))),
            "least_strength": max(grades) if grades else None,
        }
    if script_id == "http-methods":
        match = re.search(r"Supported Methods:\s*([A-Z ,]+)", output)
        return {"methods": sorted(set(re.findall(r"\b[A-Z]{3,12}\b", match.group(1)))) if match else []}
    if script_id == "http-security-headers":
        lowered = output.lower().replace("_", "-")
        mentioned = [name for name in _HEADER_NAMES if name in lowered]
        missing = []
        if "hsts not configured" in lowered:
            missing.append("strict-transport-security")
            if "strict-transport-security" not in mentioned:
                mentioned.append("strict-transport-security")
        return {"mentioned_headers": mentioned, "missing_headers": missing}
    if script_id == "http-trace":
        return {"trace_enabled_reported": bool(re.search(r"TRACE\s+(?:is\s+)?enabled", output, re.I))}
    return {}


class NseCheckAdapter:
    capability_name = "service.nse_check"
    adapter_name = "nmap"
    adapter_version = "1"
    parser_version = "nmap-nse-observation/v1"

    def prepare(self, *, target: TargetBinding, args: Mapping[str, Any], policy: ScanPolicy) -> PreparedExecution:
        from .network import CapabilityInputError, _addresses, _ports, _require_network_policy

        _require_network_policy(policy)
        if set(args) - {"ports", "scripts"}:
            raise CapabilityInputError("NSE accepts only ports and server-approved scripts")
        ports = _ports(args.get("ports"), maximum=4)
        raw_scripts = args.get("scripts")
        if not isinstance(raw_scripts, list) or not 1 <= len(raw_scripts) <= 3:
            raise CapabilityInputError("NSE requires one to three approved scripts")
        if any(not isinstance(item, str) or item not in NSE_SCRIPTS for item in raw_scripts):
            raise CapabilityInputError("NSE script is not in the server-approved allowlist")
        scripts = tuple(sorted(set(raw_scripts)))
        addresses = _addresses(target)
        commands = tuple(PreparedCommand(
            "nmap", ("-sT", "-Pn", "-n", "-sV", "--version-light", "--reason",
                     "--max-retries", "1", "--max-parallelism", "1",
                     "--host-timeout", "90s", "--script-timeout", "15s",
                     "-p", ",".join(map(str, ports)), "--script", ",".join(scripts),
                     "-oX", "-", address), address,
        ) for address in addresses)
        normalized = {"target_id": target.target_id, "addresses": list(addresses),
                      "ports": list(ports), "scripts": list(scripts)}
        http_scripts = sum(item.startswith("http-") for item in scripts)
        tls_scripts = sum(item == "ssl-enum-ciphers" for item in scripts)
        estimated_budget = {
            "hosts_attempted": len(addresses),
            "tcp_ports_attempted": len(addresses) * len(ports),
            "http_requests": len(addresses) * len(ports) * http_scripts * 4,
            "tool_wall_seconds": 90 * len(addresses),
        }
        if target.target_kind == "device":
            # NSE may open many sockets per port. Charge a conservative device
            # allowance even when its HTTP request count is zero (TLS checks).
            estimated_budget["device_fragility_points"] = (
                len(addresses) * len(ports) * (2 + 4 * http_scripts + 32 * tls_scripts)
            )
        return PreparedExecution(
            self.capability_name, self.adapter_name, self.adapter_version, commands,
            estimated_budget,
            PreparedExecution.digest_input(normalized),
            {"approved_addresses": list(addresses), "ports": list(ports), "scripts": list(scripts)},
            self.parser_version,
        )

    def parse(self, output: str, *, timed_out: bool = False) -> ParsedCapabilityResult:
        observations: list[dict[str, Any]] = []
        errors: list[str] = []
        address = ""
        port: int | None = None
        parser = ET.XMLPullParser(events=("start", "end"))
        try:
            content = str(output or "")
            for offset in range(0, len(content), 1024):
                parser.feed(content[offset:offset + 1024])
                for event, element in parser.read_events():
                    if event == "start" and element.tag == "address":
                        try:
                            address = str(ipaddress.ip_address(element.attrib.get("addr", "")))
                        except ValueError:
                            address = ""
                    elif event == "start" and element.tag == "port":
                        try:
                            parsed_port = int(element.attrib.get("portid", ""))
                            port = parsed_port if 1 <= parsed_port <= 65535 and element.attrib.get("protocol") == "tcp" else None
                        except ValueError:
                            port = None
                    elif event == "end" and element.tag == "script" and address and port:
                        script_id = element.attrib.get("id", "")
                        if script_id in NSE_SCRIPTS:
                            script_output = element.attrib.get("output", "")
                            if not script_output.strip():
                                errors.append(f"nse_script_no_output:{script_id}:{port}")
                            observations.append({
                                "kind": "nse_observation", "address": address, "port": port,
                                "transport": "tcp", "script_id": script_id,
                                "status": "reported" if script_output.strip() else "no_output",
                                "signals": _signals(script_id, script_output),
                                "output_sha256": hashlib.sha256(script_output.encode()).hexdigest(),
                                "proof_state": "observation_only",
                            })
                    elif event == "end" and element.tag == "port":
                        port = None
                    elif event == "end" and element.tag == "host":
                        address = ""
            parser.close()
        except ET.ParseError as exc:
            errors.append(f"malformed_nmap_xml:{type(exc).__name__}")
        partial = bool(timed_out or errors)
        return ParsedCapabilityResult(
            "partial" if partial else "succeeded", tuple(observations), partial,
            bool(timed_out), tuple(errors[:20]), {"record_count": len(observations)},
        )
