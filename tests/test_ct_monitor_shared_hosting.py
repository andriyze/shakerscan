"""The CT monitor never takes another registrant's host as a target (unit tests; fixture callables,
no gungnir, database or Redis).

A target at ``app.<env>.<region>.azurecontainerapps.io`` had the root ``azurecontainerapps.io``:
the Public Suffix List does not carry that service yet, so the monitor watched the whole service
and took every other customer's certificate name as a target. Shared hosting namespaces the list
does carry (PRIVATE section: ``github.io``, ``herokuapp.com``, ``blogspot.com``) and ICANN ones
(``co.uk``) must keep holding, for any spelling of the name.
"""
from __future__ import annotations

import asyncio
from datetime import date
import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from scope import psl  # noqa: E402
from scope import roots as scope_roots  # noqa: E402
from scope.roots import root_for_host  # noqa: E402

ACA_OWN = "shop.happyhill-1a2b3c4d.eastus.azurecontainerapps.io"
ACA_ENV = "happyhill-1a2b3c4d.eastus.azurecontainerapps.io"


@pytest.fixture
def gungnir(monkeypatch):
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=object, from_url=lambda *_a, **_k: None))
    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(create_pool=None))
    monkeypatch.syspath_prepend(str(ROOT / "api"))
    spec = importlib.util.spec_from_file_location("gungnir_shared_hosting_under_test", ROOT / "api" / "gungnir_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Redis:
    def hincrby(self, *_args):
        return None


def ingest(gungnir, lines, stored_roots, *, cap=1000):
    """What the monitor stores for ``lines`` when the targets table holds ``stored_roots``."""
    roots = gungnir.monitored_roots(stored_roots)
    stored: list[tuple[str, str]] = []

    async def store(name, root):
        stored.append((name, root))
        return True

    async def count_today(_apex, _day):
        return 0

    limiter = gungnir.ApexDailyCap(cap, today=lambda: date(2026, 11, 24))

    async def go():
        seen: set[str] = set()
        return [await gungnir.handle_ct_name(line, roots, seen, limiter, store=store,
                                             count_today=count_today, redis_client=_Redis())
                for line in lines]

    return roots, asyncio.run(go()), stored


# --- the root a target gets -------------------------------------------------------------------

@pytest.mark.parametrize(("host", "root"), [
    (ACA_OWN, ACA_ENV),
    ("SHOP.HappyHill-1a2b3c4d.EastUS.AzureContainerApps.io.", ACA_ENV),
    ("api.internal.happyhill-1a2b3c4d.eastus.azurecontainerapps.io", ACA_ENV),
    ("vm1.westeurope.cloudapp.azure.com", "vm1.westeurope.cloudapp.azure.com"),
    ("myregistry.azurecr.io", "myregistry.azurecr.io"),
    ("kv-prod.vault.azure.net", "kv-prod.vault.azure.net"),
    ("hub1.azure-devices.net", "hub1.azure-devices.net"),
    # PRIVATE section of the list.
    ("www.victim.github.io", "victim.github.io"),
    ("api.someapp.herokuapp.com", "someapp.herokuapp.com"),
    ("x.myblog.blogspot.com", "myblog.blogspot.com"),
    # ICANN section.
    ("shop.example.co.uk", "example.co.uk"),
    # IDN: Unicode and its punycode spelling give one root.
    ("www.bücher.example.co.uk", "example.co.uk"),
    ("www.bücher.de", "xn--bcher-kva.de"),
    ("WWW.XN--BCHER-KVA.DE.", "xn--bcher-kva.de"),
])
def test_a_target_root_is_its_registrants_domain(host, root):
    assert root_for_host(host) == root


@pytest.mark.parametrize("name", [
    "azurecontainerapps.io", "eastus.azurecontainerapps.io", "AzureContainerApps.IO.",
    "cloudapp.azure.com", "westeurope.cloudapp.azure.com", "azurecr.io", "vault.azure.net",
    "azure-devices.net", "github.io", "herokuapp.com", "blogspot.com", "co.uk",
])
def test_shared_hosting_namespaces_are_public_suffixes(name):
    assert psl.spans_public_suffix(name)
    assert psl.registrable_domain(name) is None


def test_the_hosting_rules_only_narrow_and_are_part_of_the_group_cache_version():
    # Every added rule covers a name the list leaves registrable; none removes a list rule.
    assert psl.SHARED_HOSTING_RULES
    for rule in psl.SHARED_HOSTING_RULES:
        assert psl.is_public_suffix(rule.removeprefix("*."))
    source = (ROOT / "api" / "targets" / "asset_inventory.py").read_text()
    assert "SHARED_HOSTING_RULES" in source.split("def psl_version", 1)[1].split("_PSL_VERSION: str", 1)[0]


# --- what the monitor watches and takes ----------------------------------------------------------

def test_a_container_apps_target_watches_its_own_environment_not_the_service(gungnir):
    roots, outcomes, stored = ingest(gungnir, [
        "*.happyhill-1a2b3c4d.eastus.azurecontainerapps.io",
        "api.happyhill-1a2b3c4d.eastus.azurecontainerapps.io",
        "orders.bluesky-99ffee00.westus2.azurecontainerapps.io",
        "*.bluesky-99ffee00.westus2.azurecontainerapps.io",
        "billing.redfox-12345678.eastus.azurecontainerapps.io",
        "eastus.azurecontainerapps.io",
    ], [root_for_host(ACA_OWN), "azurecontainerapps.io"])
    assert roots == [ACA_ENV]
    # The root itself (``*.<env>`` names it) is not a new name, as for example.com.
    assert outcomes == ["out_of_scope", "added", "out_of_scope", "out_of_scope", "out_of_scope", "out_of_scope"]
    assert stored == [(f"api.{ACA_ENV}", ACA_ENV)]


@pytest.mark.parametrize(("own", "strangers"), [
    ("me.github.io", ["you.github.io", "www.you.github.io", "github.io"]),
    ("myapp.herokuapp.com", ["other.herokuapp.com", "api.other.herokuapp.com"]),
    ("myblog.blogspot.com", ["yourblog.blogspot.com"]),
    ("example.co.uk", ["other.co.uk", "shop.other.co.uk"]),
])
def test_names_of_other_registrants_under_a_shared_suffix_are_never_taken(gungnir, own, strangers):
    # The stored roots include the shared suffix an older engine may have kept.
    shared = own.split(".", 1)[1]
    roots, outcomes, stored = ingest(gungnir, [*strangers, f"new.{own}"], [own, shared])
    assert roots == [own]
    assert outcomes == ["out_of_scope"] * len(strangers) + ["added"]
    assert stored == [(f"new.{own}", own)]


def test_spelling_does_not_change_the_answer(gungnir):
    _roots, outcomes, stored = ingest(gungnir, [
        "API.HappyHill-1a2b3c4d.EASTUS.azurecontainerapps.io.",
        "Orders.BlueSky-99ffee00.WestUS2.AzureContainerApps.IO.",
        "www.bücher.example.co.uk", "www.xn--bcher-kva.other.co.uk",
    ], [ACA_ENV, "example.co.uk"])
    assert outcomes == ["added", "out_of_scope", "added", "out_of_scope"]
    assert stored == [(f"api.{ACA_ENV}", ACA_ENV), ("www.xn--bcher-kva.example.co.uk", "example.co.uk")]


def test_a_name_is_taken_only_with_the_roots_registrable_domain(gungnir):
    # A root list that still holds a shared suffix (loaded before the list rules changed) takes
    # nothing under it: the check runs per name, not only when the roots are loaded.
    seen: set[str] = set()
    stored = []

    async def store(name, root):
        stored.append((name, root))
        return True

    async def count_today(_apex, _day):
        return 0

    limiter = gungnir.ApexDailyCap(1000, today=lambda: date(2026, 11, 24))
    outcome = asyncio.run(gungnir.handle_ct_name(
        "orders.bluesky-99ffee00.westus2.azurecontainerapps.io", ["azurecontainerapps.io"], seen, limiter,
        store=store, count_today=count_today, redis_client=_Redis()))
    assert outcome == "out_of_scope" and stored == []


def test_roots_never_come_from_the_monitors_own_targets(gungnir):
    """Under a root later marked shared, each stranger's name the monitor took would otherwise
    become a root of its own once the startup migration recomputed it."""
    queries = []

    class Conn:
        async def fetch(self, query, *args):
            queries.append(" ".join(query.split()))
            if "DISTINCT root_domain" in query:
                return [{"root_domain": "azurecontainerapps.io"}]
            return [{"root_domain": "azurecontainerapps.io", "url": f"https://{ACA_OWN}"}]

    class Pool:
        def acquire(self):
            class Acquire:
                async def __aenter__(self):
                    return Conn()

                async def __aexit__(self, *exc):
                    return False

            return Acquire()

    gungnir.db_pool = Pool()
    assert gungnir.monitored_roots(asyncio.run(gungnir.get_monitored_domains())) == [ACA_ENV]
    assert len(queries) == 2
    assert all("discovery_source IS DISTINCT FROM 'gungnir-monitor'" in query for query in queries)
    assert "gungnir-monitor" in scope_roots.ROOT_SOURCE_SQL and "declared" in scope_roots.ROOT_SOURCE_SQL
