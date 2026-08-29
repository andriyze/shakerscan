from __future__ import annotations

import asyncio
from types import SimpleNamespace

from api.capabilities.dns import inspect_dns_posture
from api.capabilities.inline import DnsInspectionExecutionAdapter
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding


class _Answer(list):
    def __init__(self, values, *, flags=0, ttl=300):
        super().__init__(values)
        self.response = SimpleNamespace(flags=flags)
        self.rrset = SimpleNamespace(ttl=ttl)


class _Resolver:
    def __init__(self):
        self.calls = []

    async def resolve(self, name, query_type, **kwargs):
        self.calls.append((name, query_type, kwargs))
        if query_type == "MX":
            return _Answer([
                SimpleNamespace(preference=10, exchange="mail.example.test."),
            ])
        if query_type == "CAA":
            return _Answer([
                SimpleNamespace(flags=0, tag=b"issue", value=b"ca.test"),
            ])
        if query_type == "DNSKEY":
            return _Answer([
                SimpleNamespace(flags=257, protocol=3, algorithm=13),
            ])
        if query_type == "DS":
            return _Answer([
                SimpleNamespace(key_tag=12345, algorithm=13, digest_type=2, digest="abcdef"),
            ])
        if query_type == "SOA":
            return _Answer([
                SimpleNamespace(
                    mname="ns1.example.test.", rname="hostmaster.example.test.",
                    serial=2026082901, refresh=3600, retry=600, expire=1209600,
                    minimum=300,
                ),
            ])
        if query_type == "NS":
            return _Answer(["ns1.example.test.", "ns2.example.test."])
        if query_type in {"A", "AAAA"}:
            return _Answer([])
        if query_type == "CNAME":
            return _Answer([])
        if name.startswith("_dmarc."):
            return _Answer([
                SimpleNamespace(strings=(b"v=DMARC1; p=reject",)),
            ])
        if name.startswith("_smtp._tls."):
            return _Answer([
                SimpleNamespace(
                    strings=(b"v=TLSRPTv1; rua=mailto:tls@example.test",),
                ),
            ])
        if name.startswith("_mta-sts."):
            return _Answer([
                SimpleNamespace(strings=(b"v=STSv1; id=20260822",)),
            ])
        return _Answer([
            SimpleNamespace(strings=(b"v=spf1 -all",)),
        ])


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10", "2001:db8::10"),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )


def test_dns_inspection_queries_only_binding_derived_names():
    resolver = _Resolver()
    result = asyncio.run(inspect_dns_posture(
        _target(), timeout_seconds=15, resolver=resolver,
    ))

    assert result["ok"] is True
    assert result["status"] == "success"
    assert result["budget_consumed"] == {
        "hosts_attempted": 5,
        "tool_wall_seconds": 1,
    }
    observation = result["observation"]
    assert observation["bound_addresses"] == {
        "A": ["192.0.2.10"],
        "AAAA": ["2001:db8::10"],
    }
    assert observation["records"]["host_mx"] == [{
        "priority": 10,
        "host": "mail.example.test",
    }]
    assert observation["records"]["host_caa"] == [{
        "flags": 0,
        "tag": "issue",
        "value": "ca.test",
    }]
    assert observation["records"]["root_ns"] == [
        "ns1.example.test", "ns2.example.test",
    ]
    assert observation["records"]["root_soa"][0]["serial"] == 2026082901
    assert observation["records"]["root_ds"][0]["key_tag"] == 12345
    assert observation["record_metadata"]["root_ns"]["ttl"] == 300
    assert observation["records"]["dmarc"] == ["v=DMARC1; p=reject"]
    assert len(resolver.calls) == 13
    assert {name for name, _query_type, _kwargs in resolver.calls} == {
        "app.example.test",
        "example.test",
        "_dmarc.app.example.test",
        "_smtp._tls.app.example.test",
        "_mta-sts.app.example.test",
    }
    assert all(call[2]["search"] is False for call in resolver.calls)


def test_dns_inspection_blocks_host_outside_root_binding():
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("other.test",),
        scope_receipt_id="scope-1",
    )
    result = asyncio.run(inspect_dns_posture(
        target, timeout_seconds=15, resolver=_Resolver(),
    ))

    assert result["ok"] is False
    assert result["status"] == "blocked"
    assert result["error"].startswith("scope:")
    assert result["budget_consumed"] == {}


def test_dns_adapter_marks_host_budget_as_started():
    async def operation():
        return {
            "ok": True,
            "status": "success",
            "observation": {"kind": "dns_posture"},
            "budget_consumed": {
                "hosts_attempted": 5,
                "tool_wall_seconds": 1,
            },
        }

    adapter = DnsInspectionExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("dns.inspect"),
        operation=operation,
        requested_budget={"hosts_attempted": 5, "tool_wall_seconds": 15},
        redacted_execution={"input": {}},
    )
    result = asyncio.run(adapter.execute(heartbeat=None, cancelled=None))

    assert result.status == "success"
    assert result.execution_started is True
    assert result.actual_budget == {
        "hosts_attempted": 5,
        "tool_wall_seconds": 1,
    }
    assert result.observations == ({"kind": "dns_posture"},)
