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
        # One per distinct query name: the host, the root, the three mail-policy
        # names and the six conventional DKIM selectors.
        "hosts_attempted": 11,
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
    assert len(resolver.calls) == 19
    assert {name for name, _query_type, _kwargs in resolver.calls} == {
        "app.example.test",
        "example.test",
        "_dmarc.app.example.test",
        "_smtp._tls.app.example.test",
        "_mta-sts.app.example.test",
        # DKIM keys are published under a selector the sender chooses, so the
        # conventional ones are asked for by name. Every one stays derived from
        # the binding: the host is the frozen host and nothing else.
        "default._domainkey.app.example.test",
        "google._domainkey.app.example.test",
        "selector1._domainkey.app.example.test",
        "selector2._domainkey.app.example.test",
        "k1._domainkey.app.example.test",
        "mail._domainkey.app.example.test",
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


def test_dns_inspection_bounds_its_fan_out_so_records_are_not_lost_to_contention():
    """The plan must not flood one resolver and then report its own pressure.

    Firing all thirteen lookups at once made the later ones report
    LifetimeTimeout after the full five seconds, while the same queries answer
    in under a tenth of a second on their own. A measured scan lost TXT, CAA,
    DNSKEY, MX and CNAME that way, so the report silently dropped SPF, CAA
    policy and DNSSEC while spending only a third of its wall.
    """
    import api.capabilities.dns as dns_module

    class _ConcurrencyProbe(_Resolver):
        def __init__(self) -> None:
            super().__init__()
            self.inflight = 0
            self.peak = 0

        async def resolve(self, name, query_type, **kwargs):
            self.inflight += 1
            self.peak = max(self.peak, self.inflight)
            try:
                await asyncio.sleep(0)
                return await super().resolve(name, query_type, **kwargs)
            finally:
                self.inflight -= 1

    resolver = _ConcurrencyProbe()
    posture = asyncio.run(inspect_dns_posture(
        _target(), timeout_seconds=15, resolver=resolver,
    ))

    assert resolver.peak <= dns_module._MAX_CONCURRENT_QUERIES
    # Bounding the fan-out must not drop any planned lookup.
    assert len(resolver.calls) == 19
    assert not posture.get("errors")


def test_the_action_deadline_keeps_the_answers_that_already_arrived():
    """A deadline must end the remaining work, not the work already done.

    The plan was wrapped in one deadline whose expiry replaced the whole result
    with an empty list. A nineteen-query plan run four at a time can cross that
    deadline mid-wave, and the run then reported no records at all while its own
    metadata still showed a dozen completed answers.
    """
    class _Slow(_Resolver):
        def __init__(self) -> None:
            super().__init__()
            self.started = 0

        async def resolve(self, name, query_type, **kwargs):
            self.started += 1
            await asyncio.sleep(0.3)
            return await super().resolve(name, query_type, **kwargs)

    resolver = _Slow()
    result = asyncio.run(inspect_dns_posture(
        _target(), timeout_seconds=1, resolver=resolver,
    ))
    observation = result["observation"]
    answered = {label for label, values in observation["records"].items() if values}

    # Every query that finished inside the deadline is reported, and its values
    # agree with the metadata it recorded. Before this, metadata showed a dozen
    # completed answers while every record set was empty.
    assert answered, "a crossed deadline discarded records that had already arrived"
    for label, meta in observation["record_metadata"].items():
        assert len(observation["records"][label]) == meta["answer_count"], label
    # The run is honest about the part that did not finish, and states the
    # reason the receipt will carry: the queries timed out. Nothing was cut off,
    # so the action must not be explained as a bounded-output truncation.
    assert result["partial"] is True
    assert any(item.startswith("dns_inspection:Timeout") for item in observation["errors"])
    assert result["errors"][0] == "timed_out"


def test_a_resolver_failure_is_not_reported_as_truncated_output():
    class _Failing(_Resolver):
        async def resolve(self, name, query_type, **kwargs):
            if query_type == "CAA":
                raise RuntimeError("NoNameservers")
            return await super().resolve(name, query_type, **kwargs)

    result = asyncio.run(inspect_dns_posture(_target(), timeout_seconds=5, resolver=_Failing()))
    assert result["partial"] is True
    assert result["errors"][0] == "adapter_failed"
    assert any(item.endswith(":RuntimeError") for item in result["errors"][1:])


class _ForwarderDroppingRareTypes(_Resolver):
    """Docker Desktop's embedded DNS: A/MX/TXT answer at once, CAA/DNSKEY/DS time out."""

    async def resolve(self, name, query_type, **kwargs):
        if query_type in {"CAA", "DNSKEY", "DS"}:
            raise type("LifetimeTimeout", (Exception,), {})("resolution lifetime expired")
        return await super().resolve(name, query_type, **kwargs)


def _public_target() -> TargetBinding:
    return TargetBinding(
        target_id="target-2", target_kind="web", canonical_host="www.example.org",
        allowed_origins=("https://www.example.org",), allowed_addresses=("93.184.216.34",),
        allowed_root_domains=("example.org",), scope_receipt_id="scope-2",
    )


def _doh_answers(name, query_type):
    import dns.rdatatype

    class _RRset(list):
        def __init__(self, values, rdtype):
            super().__init__(values)
            self.rdtype = rdtype
            self.ttl = 120

    wanted = dns.rdatatype.from_text(query_type)
    values = {
        "CAA": [SimpleNamespace(flags=0, tag=b"issue", value=b"letsencrypt.org")],
        "DNSKEY": [SimpleNamespace(flags=257, protocol=3, algorithm=13)],
        "DS": [],
    }.get(query_type, [])
    return SimpleNamespace(answer=[_RRset(values, wanted)] if values else [])


def test_a_query_the_forwarder_drops_is_recovered_over_https_for_a_public_name():
    calls = []

    async def doh(name, query_type):
        calls.append((name, query_type))
        return _doh_answers(name, query_type)

    result = asyncio.run(inspect_dns_posture(
        _public_target(), timeout_seconds=5, resolver=_ForwarderDroppingRareTypes(), doh_query=doh,
    ))
    observation = result["observation"]
    assert result["status"] == "success" and not observation["errors"]
    assert {qt for _name, qt in calls} == {"CAA", "DNSKEY", "DS"}
    assert observation["records"]["host_caa"] and observation["records"]["host_dnskey"]
    assert observation["records"]["root_ds"] == []
    assert observation["record_metadata"]["host_caa"]["resolver"] == "doh"
    assert set(observation["doh_fallback_queries"]) == {"host_caa", "host_dnskey", "root_ds"}


def test_an_internal_name_never_leaves_the_network_as_a_doh_query():
    calls = []

    async def doh(name, query_type):
        calls.append((name, query_type))
        return _doh_answers(name, query_type)

    # app.example.test resolves to a TEST-NET address and carries a private suffix.
    result = asyncio.run(inspect_dns_posture(
        _target(), timeout_seconds=5, resolver=_ForwarderDroppingRareTypes(), doh_query=doh,
    ))
    assert calls == []
    assert result["partial"] is True
    assert result["errors"][0] == "timed_out"


def test_doh_permission_requires_a_public_name_and_public_addresses():
    from api.capabilities.dns import doh_permitted

    assert doh_permitted(_public_target()) is True
    assert doh_permitted(_target()) is False
    private_address = TargetBinding(
        target_id="t3", target_kind="web", canonical_host="intranet.example.org",
        allowed_origins=("https://intranet.example.org",), allowed_addresses=("10.0.0.5",),
        allowed_root_domains=("example.org",), scope_receipt_id="scope-3",
    )
    assert doh_permitted(private_address) is False
    bare = TargetBinding(
        target_id="t4", target_kind="web", canonical_host="crapi-web",
        allowed_origins=("http://crapi-web",), allowed_addresses=("172.18.0.14",),
        allowed_root_domains=("crapi-web",), scope_receipt_id="scope-4",
    )
    assert doh_permitted(bare) is False


def test_a_doh_failure_keeps_the_primary_timeout_as_the_error():
    async def doh(name, query_type):
        raise RuntimeError("upstream 502")

    result = asyncio.run(inspect_dns_posture(
        _public_target(), timeout_seconds=5, resolver=_ForwarderDroppingRareTypes(), doh_query=doh,
    ))
    assert result["partial"] is True
    assert result["errors"][0] == "timed_out"
    assert any(item.startswith("host_caa:doh:RuntimeError") for item in result["errors"])
    assert any(item == "host_caa:LifetimeTimeout" for item in result["errors"])
