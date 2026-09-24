"""A fixed, low-impact NSE surface for target-bound Hunt service checks."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
from xml.etree import ElementTree as ET

from runtime.models import ParsedCapabilityResult, PreparedCommand, PreparedExecution, ScanPolicy, TargetBinding
from .network_inputs import CapabilityInputError, _addresses, _ports, _require_network_policy
from .nse_http_transport import HTTP_SCRIPT_LIMITS, http_envelope


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


def _script_outputs(element):
    script_id = element.attrib.get("id", "")
    if script_id != "nse_http":
        return [(script_id, element.attrib.get("output", ""))]
    def text(node):
        # Preserve installed NSE structured output (named tables plus scalar
        # elements), not only an optional pre-rendered output string.
        return " ".join(
            ((child.attrib.get("key", "") + ": ") if child.attrib.get("key") else "")
            + (text(child) if child.tag == "table" else child.text or "")
            for child in node
        )
    return [(row.attrib.get("key", ""), row.findtext("elem[@key='output']") or text(row))
            for row in element.findall("table")]


class NseCheckAdapter:
    capability_name = "service.nse_check"
    adapter_name = "nmap"
    adapter_version = "1"
    parser_version = "nmap-nse-observation/v1"

    def prepare(self, *, target: TargetBinding, args: Mapping[str, Any], policy: ScanPolicy) -> PreparedExecution:
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
        # Service checks must not secretly run -sV's additional HTTP/POST probes.
        # HTTP schemes are detected through the metered bridge; force native TLS
        # to examine explicitly selected nonstandard ports without a version scan.
        execution_scripts = ([str(Path(__file__).with_name("nse_http.nse"))]
                             if any(name in HTTP_SCRIPT_LIMITS for name in scripts) else [])
        if "ssl-enum-ciphers" in scripts:
            execution_scripts.append("+ssl-enum-ciphers")
        sni = ("--script-args", "tls.servername=" + json.dumps(target.canonical_host or ""))
        commands = tuple(PreparedCommand(
            "nmap", (("-6",) if ipaddress.ip_address(address).version == 6 else ()) +
                    ("-sT", "-Pn", "-n", "--reason", "-v",
                     "--max-retries", "1", "--max-parallelism", "1",
                     "--host-timeout", "90s", "--script-timeout", "60s",
                     "-p", ",".join(map(str, ports)), "--script", ",".join(execution_scripts),
                     *sni, "-oX", "-", address), address,
        ) for address in addresses)
        normalized = {"target_id": target.target_id, "addresses": list(addresses),
                      "ports": list(ports), "scripts": list(scripts),
                      "allow_state_changing_http": policy.allow_state_changing_http}
        envelope = http_envelope(scripts, len(ports), allow_write=policy.allow_state_changing_http)
        tls_scripts = sum(item == "ssl-enum-ciphers" for item in scripts)
        # Durable reservations omit zero grants. Use that canonical shape at
        # both admission and worker reconstruction, including TLS-only checks.
        estimated_budget = {
            "hosts_attempted": len(addresses),
            "tcp_ports_attempted": len(addresses) * len(ports),
            **{key: len(addresses) * value for key, value in envelope.items() if value},
            "tool_wall_seconds": 90 * len(addresses),
        }
        if target.target_kind == "device":
            # Native TLS still uses a device cost estimate, not a measured
            # handshake count. The HTTP component is measured at execution.
            estimated_budget["device_fragility_points"] = (
                len(addresses) * (len(ports) * (2 + 32 * tls_scripts) + envelope["http_requests"])
            )
        return PreparedExecution(
            self.capability_name, self.adapter_name, self.adapter_version, commands,
            estimated_budget,
            PreparedExecution.digest_input(normalized),
            {"approved_addresses": list(addresses), "ports": list(ports), "scripts": list(scripts),
             "http_target": target.canonical_dict(), "allow_state_changing_http": policy.allow_state_changing_http,
             "http_accounting": "request_header_attempts", "http_transport": "frozen_address_bridge",
             "redirect_policy": "same_frozen_asset_anonymous",
             "device_non_http_accounting": "estimated_allowance"},
            self.parser_version,
        )

    def parse(
        self, output: str, *, timed_out: bool = False,
        expected_ports: Sequence[int] = (), expected_scripts: Sequence[str] = (),
    ) -> ParsedCapabilityResult:
        observations: list[dict[str, Any]] = []
        errors: list[str] = []
        address = ""
        port: int | None = None
        port_states: dict[int, str] = {}
        parser = ET.XMLPullParser(events=("start", "end"))
        try:
            content = str(output or "")
            for offset in range(0, len(content), 1024):
                parser.feed(content[offset:offset + 1024])
                for event, element in parser.read_events():
                    if event == "start" and element.tag == "address":
                        # A directly attached LAN host also carries a MAC address
                        # element. Only an IP address identifies the scanned host;
                        # other address types must not clear it.
                        if element.attrib.get("addrtype") not in {"ipv4", "ipv6"}:
                            continue
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
                    elif event == "start" and element.tag == "state" and port:
                        port_states[port] = element.attrib.get("state", "unknown")
                    elif event == "end" and element.tag == "finished":
                        if element.attrib.get("exit") == "error":
                            errors.append("nmap_run_error")
                    elif event == "end" and element.tag == "script" and address and port:
                        for script_id, script_output in _script_outputs(element):
                            if script_id in NSE_SCRIPTS:
                                failed = bool(re.match(
                                    r"\s*(?:ERROR(?:\s*:|\s*$)|Script execution failed\b|Request failed\b)",
                                    script_output, re.I,
                                ))
                                if failed:
                                    errors.append(f"nse_script_failed:{script_id}:{port}")
                                if not script_output.strip():
                                    errors.append(f"nse_script_no_output:{script_id}:{port}")
                                observations.append({
                                    "kind": "nse_observation", "address": address, "port": port,
                                    "transport": "tcp", "script_id": script_id,
                                    "status": "failed" if failed else "reported" if script_output.strip() else "no_output",
                                    "signals": {} if failed else _signals(script_id, script_output),
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
        # Silence is not proof that a script did not run: positive-only scripts
        # also return nil on a normal response. Keep this coverage inconclusive,
        # preserve other observations, and let the planner choose another check.
        reported = {(item["port"], item["script_id"]) for item in observations}
        coverage = []
        for expected_port in expected_ports:
            for script_id in expected_scripts:
                if (int(expected_port), script_id) not in reported:
                    errors.append(f"nse_script_no_result:{script_id}:{int(expected_port)}")
                    state = port_states.get(int(expected_port), "unknown")
                    coverage.append({"port": int(expected_port), "script_id": script_id,
                                     "status": "not_applicable" if state == "closed" else "inconclusive",
                                     "port_state": state})
        partial = bool(timed_out or errors)
        return ParsedCapabilityResult(
            "partial" if partial else "succeeded", tuple(observations), partial,
            bool(timed_out), tuple(errors[:20]), {"record_count": len(observations), "coverage_gaps": coverage},
        )
