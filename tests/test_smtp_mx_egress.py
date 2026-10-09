"""SMTP MX egress is classified under the scan's destination policy and pinned (review gap (a)).

``check_smtp_security`` connected by name to every MX host (and to the target, re-resolved by
name, when it had none) on 25, 465 and 587, and sent EHLO, MAIL FROM and RCPT TO. An authorized
target's DNS could point MX at 169.254.169.254, an internal address or a Docker service name and
get past ``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=refuse``, with the banner returned in the result,
and each tool resolved the name again (DNS rebinding). Each host is now resolved once, every
address is judged by the shared classifier, and every connection goes to the admitted address; a
refused host is recorded with a named reason and never contacted.

The DNS answers, the dig/openssl/nmap runner and the socket are labelled test doubles (unit
fixtures); nothing touches the network.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope
from scanner_tools import address_classes, smtp_scanner

PUBLIC = "93.184.216.34"
REFUSE = smtp_scanner.SmtpDestinationPolicy(environment="production", allow_private=False)
ALLOW = smtp_scanner.SmtpDestinationPolicy(environment="production", allow_private=True)
LAB = smtp_scanner.SmtpDestinationPolicy(environment="lab", allow_private=False)


class Wire:
    """Unit fixture: records every resolution, command and connection the scanner attempts."""

    def __init__(self, monkeypatch, *, mx=(), answers=None, starttls=False):
        self.mx = list(mx)
        self.answers = {name: list(values) for name, values in (answers or {}).items()}
        self.lookups: list[str] = []
        self.commands: list[list[str]] = []
        self.connections: list[tuple[str, int]] = []
        self.starttls = starttls

        async def run_command(cmd, timeout=30):
            if cmd[0] == "dig":
                return "".join(f"{priority} {host}.\n" for priority, host in self.mx), "", 0
            self.commands.append(list(cmd))
            if cmd[0] == "openssl" and self.starttls:
                return "CONNECTION ESTABLISHED\nProtocol : TLSv1.3\n", "", 0
            return "", "Connection refused", 1

        async def open_connection(host, port, *args, **kwargs):
            self.connections.append((host, port))
            raise ConnectionRefusedError

        monkeypatch.setattr(smtp_scanner, "_run_command", run_command)
        monkeypatch.setattr(smtp_scanner.asyncio, "open_connection", open_connection)

    async def resolve(self, host):
        self.lookups.append(host)
        values = self.answers.get(host) or []
        if not values:
            raise OSError("no address")
        return values.pop(0) if isinstance(values[0], list) else values

    def contacted(self):
        targets = {host for host, _port in self.connections}
        for cmd in self.commands:
            if "-connect" in cmd:
                targets.add(cmd[cmd.index("-connect") + 1].rsplit(":", 1)[0].strip("[]"))
            if cmd[0] == "nmap":
                targets.add(cmd[-1])
        return targets


def _check(wire, domain="example.test", policy=REFUSE):
    return asyncio.run(smtp_scanner.check_smtp_security(
        domain, timeout=1, policy=policy, resolver=wire.resolve,
    ))


REFUSED_ANSWERS = {
    "private": ["10.0.0.5"],
    "loopback": ["127.0.0.1"],
    "metadata": ["169.254.169.254"],
    "azure_wireserver": ["168.63.129.16"],
    "mapped_metadata": ["::ffff:169.254.169.254"],
    "nat64_metadata": ["64:ff9b::a9fe:a9fe"],
    "siit_private": ["::ffff:0:a00:5"],
    "nat64_private": ["64:ff9b::a00:5"],
    "6to4_private": ["2002:a00:5::1"],
    "cgnat": ["100.64.0.9"],
}


@pytest.mark.parametrize("answer", REFUSED_ANSWERS.values(), ids=REFUSED_ANSWERS.keys())
def test_an_mx_host_at_a_refused_address_is_skipped_with_a_named_reason(monkeypatch, answer):
    wire = Wire(monkeypatch, mx=[(10, "mx.example.test")], answers={"mx.example.test": answer})
    result = _check(wire)
    assert wire.connections == [] and wire.commands == []
    skipped = result["skipped_hosts"]["mx.example.test"]
    assert skipped["reason"] == "loopback_or_private_range"
    assert "not contacted" in skipped["detail"]
    assert result["smtp_hosts"] == {} and result["relay_tests"] == {} and result["banner_analysis"] == {}
    assert any("mx.example.test was not tested" in item for item in result["overall_assessment"]["recommendations"])


@pytest.mark.parametrize("policy", [ALLOW, LAB], ids=["private_allowed", "lab"])
@pytest.mark.parametrize("answer", ["169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "fd00:ec2::254"])
def test_a_metadata_mx_is_refused_whatever_the_policy(monkeypatch, policy, answer):
    wire = Wire(monkeypatch, mx=[(10, "mx.example.test")], answers={"mx.example.test": [answer]})
    result = _check(wire, policy=policy)
    assert wire.contacted() == set()
    assert result["skipped_hosts"]["mx.example.test"]["reason"] == "loopback_or_private_range"


@pytest.mark.parametrize("name", ["db", "redis", "postgres", "api"])
def test_a_docker_service_name_mx_is_never_resolved_or_contacted(monkeypatch, name):
    wire = Wire(monkeypatch, mx=[(10, name)], answers={name: ["172.18.0.4"]})
    result = _check(wire, policy=ALLOW)
    assert wire.lookups == [] and wire.contacted() == set()
    assert result["skipped_hosts"][name]["reason"] == "mx_host_not_fully_qualified"


def test_an_unresolvable_mx_is_recorded_not_skipped_silently(monkeypatch):
    wire = Wire(monkeypatch, mx=[(10, "gone.example.test")])
    result = _check(wire)
    assert wire.contacted() == set()
    assert result["skipped_hosts"]["gone.example.test"]["reason"] == "unresolved"


def test_a_mixed_answer_pins_the_admitted_address(monkeypatch):
    wire = Wire(monkeypatch, mx=[(10, "mx.example.test")],
                answers={"mx.example.test": ["10.0.0.5", "169.254.169.254", PUBLIC]})
    result = _check(wire)
    assert wire.contacted() == {PUBLIC}
    destination = result["smtp_destinations"]["mx.example.test"]
    assert destination["address"] == PUBLIC
    assert {item["address"] for item in destination["refused"]} == {"10.0.0.5", "169.254.169.254"}


def test_the_no_mx_fallback_resolves_the_target_once_and_pins_it(monkeypatch):
    """DNS rebinding: a second lookup of the target would answer 10.0.0.5."""
    wire = Wire(monkeypatch, mx=[], answers={"example.test": [[PUBLIC], ["10.0.0.5"], ["10.0.0.5"]]})
    result = _check(wire)
    assert wire.lookups == ["example.test"]
    assert wire.contacted() == {PUBLIC}
    assert result["smtp_hosts"]["example.test"]["address"] == PUBLIC


def test_the_no_mx_fallback_refuses_a_private_target_address(monkeypatch):
    wire = Wire(monkeypatch, mx=[], answers={"example.test": ["10.0.0.5"]})
    result = _check(wire)
    assert wire.contacted() == set()
    assert result["skipped_hosts"]["example.test"]["reason"] == "loopback_or_private_range"


def test_the_allowed_public_case_is_tested_at_the_pinned_address(monkeypatch):
    wire = Wire(monkeypatch, mx=[(10, "mx.example.test"), (20, "mx6.example.test")], starttls=True,
                answers={"mx.example.test": [PUBLIC], "mx6.example.test": ["2606:4700:4700::1111"]})
    result = _check(wire)
    assert wire.lookups == ["mx.example.test", "mx6.example.test"]
    assert wire.contacted() == {PUBLIC, "2606:4700:4700::1111"}
    assert result["skipped_hosts"] == {}
    assert set(result["smtp_hosts"]) == {"mx.example.test", "mx6.example.test"}
    assert set(result["relay_tests"]) == {"mx.example.test", "mx6.example.test"}
    openssl = [cmd for cmd in wire.commands if cmd[0] == "openssl"]
    assert {cmd[cmd.index("-connect") + 1] for cmd in openssl} == {
        f"{PUBLIC}:25", f"{PUBLIC}:465", f"{PUBLIC}:587",
        "[2606:4700:4700::1111]:25", "[2606:4700:4700::1111]:465", "[2606:4700:4700::1111]:587",
    }
    assert {cmd[cmd.index("-servername") + 1] for cmd in openssl} == {"mx.example.test", "mx6.example.test"}
    nmap = [cmd for cmd in wire.commands if cmd[0] == "nmap"]
    assert nmap and all(cmd[-1] in {PUBLIC, "2606:4700:4700::1111"} for cmd in nmap)
    assert all("-6" in cmd for cmd in nmap if ":" in cmd[-1])
    assert {(host, port) for host, port in wire.connections} >= {(PUBLIC, 25), ("2606:4700:4700::1111", 25)}


def test_a_private_mx_is_tested_when_the_deployment_allows_private_targets(monkeypatch):
    wire = Wire(monkeypatch, mx=[(10, "mail.corp.test")], answers={"mail.corp.test": ["10.0.0.5"]})
    result = _check(wire, policy=ALLOW)
    assert wire.contacted() == {"10.0.0.5"}
    assert result["skipped_hosts"] == {}


def test_the_policy_is_the_scans(monkeypatch):
    assert address_classes.LAB_ENVIRONMENTS == action_scope.SAFE_LAB_ENVIRONMENTS
    envelope = json.dumps({"target_binding": {"environment": "Staging"}})
    assert smtp_scanner.smtp_destination_policy({
        "SHAKERSCAN_CANONICAL_SCAN_EXECUTION": envelope, "SHAKERSCAN_PRIVATE_NETWORK_TARGETS": "refuse",
    }) == smtp_scanner.SmtpDestinationPolicy(environment="staging", allow_private=False)
    assert smtp_scanner.smtp_destination_policy({}) == ALLOW  # the OSS default admits private targets
    assert smtp_scanner.smtp_destination_policy({
        "SHAKERSCAN_PRIVATE_NETWORK_TARGETS": "10.0.0.0/8",
    }) == REFUSE
    assert smtp_scanner.smtp_destination_policy({
        "SHAKERSCAN_CANONICAL_SCAN_EXECUTION": "not json", "SHAKERSCAN_PRIVATE_NETWORK_TARGETS": "refuse",
    }) == REFUSE
