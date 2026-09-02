from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from api.capabilities.infrastructure import (
    _validated_external_url,
    inspect_infrastructure_intelligence,
)
from api.runtime.models import TargetBinding


class _Answer(list):
    pass


class _Resolver:
    async def resolve(self, name, query_type, **_kwargs):
        if query_type == "PTR":
            return _Answer(["edge.example.test."])
        if str(name).startswith("AS64500."):
            return _Answer([SimpleNamespace(strings=(b"64500 | US | arin | 2020-01-01 | EXAMPLE-NET",))])
        return _Answer([SimpleNamespace(strings=(b"64500 | 192.0.2.10 | 192.0.2.0/24 | US | arin | 2020-01-01",))])


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )


async def _fetch(url: str, _timeout: int):
    if url.endswith("/rdap/dns.json"):
        return {"services": [[["test"], ["https://rdap.registry.test"]]]}
    if url.endswith("/rdap/ipv4.json"):
        return {"services": [[["192.0.2.0/24"], ["https://rdap.network.test"]]]}
    if url.endswith("/rdap/ipv6.json"):
        return {"services": []}
    if "/domain/" in url:
        return {
            "ldhName": "EXAMPLE.TEST",
            "handle": "EXAMPLE-1",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}],
            "secureDNS": {"delegationSigned": True},
            "entities": [{
                "handle": "REG-1",
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }],
        }
    if "/ip/" in url:
        return {
            "handle": "NET-192-0-2-0-1",
            "name": "EXAMPLE-NET",
            "type": "DIRECT ALLOCATION",
            "country": "US",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
            "entities": [],
        }
    raise AssertionError(url)


def test_infrastructure_intelligence_is_explicitly_informational_and_bound():
    result = asyncio.run(inspect_infrastructure_intelligence(
        _target(), fetch_json=_fetch, resolver=_Resolver(), timeout_seconds=10,
    ))

    assert result["ok"] is True
    assert result["status"] == "success"
    observation = result["observation"]
    assert observation["informational_only"] is True
    assert observation["scoring_effect"] == "none"
    assert observation["registration_domain"] == "example.test"
    assert observation["registration"]["registrar"]["name"] == "Example Registrar"
    assert observation["addresses"][0]["address"] == "192.0.2.10"
    assert observation["addresses"][0]["network"]["cidrs"] == ["192.0.2.0/24"]
    assert observation["addresses"][0]["asn"]["asn"] == "64500"
    assert observation["addresses"][0]["ptr_names"] == ["edge.example.test"]
    assert observation["related_names"] == [{
        "name": "edge.example.test",
        "source": "ptr",
        "scope": "external_unverified",
    }]
    assert result["budget_consumed"]["hosts_attempted"] <= 40


def test_infrastructure_intelligence_has_no_implicit_external_transport():
    result = asyncio.run(inspect_infrastructure_intelligence(_target()))

    assert result == {
        "ok": False,
        "status": "blocked",
        "error": "infrastructure_intelligence_transport_unavailable",
        "budget_consumed": {},
    }


@pytest.mark.parametrize("url", (
    "http://rdap.example.test",
    "https://localhost/rdap",
    "https://127.0.0.1/rdap",
    "https://user:secret@rdap.example.test/rdap",
))
def test_infrastructure_intelligence_rejects_unsafe_external_destinations(url):
    with pytest.raises(ValueError):
        _validated_external_url(url)
