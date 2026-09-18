"""Findings from the 18 September review of fix/private-target-onboarding.

Four defects, two of them introduced by that branch:

P04  A lab label admitted link-local, multicast and unspecified addresses, contradicting the
     predicate's own docstring. Pre-existing, but the branch forwards the add-target dialog's
     cohort into the authorization environment, so picking "Lab" and typing 169.254.169.254 --
     the cloud metadata address -- reached it from the ordinary UI.
P02  New. The display floor that stops the dashboard reading "9 running, max 5" was fed into
     _publish_max_active_scans, which writes the Redis cap workers obey. A GET of the worker
     list could therefore raise real execution concurrency, counting stopped containers, above
     an explicitly configured SHAKERSCAN_MAX_WORKERS.
P01  The private-network opt-out is documented as the way a deployment refuses intranet
     targets, but neither Compose file passes it to the API or the workers, so setting it in
     .env changed nothing. Harmless while the default refused; load-bearing now it admits.
P06  The page was changed to show the server's reason, but createTarget() still threw a fixed
     string, so the reason never reached it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import action_scope  # noqa: E402
import deployment_policy  # noqa: E402

RESTRICTED = ("169.254.169.254", "224.0.0.1", "0.0.0.0", "255.255.255.255")


@pytest.mark.parametrize("host", RESTRICTED)
@pytest.mark.parametrize("environment", ["lab", "test", "staging", "dev", "production"])
def test_a_label_never_admits_a_restricted_address_class(host, environment):
    """P04. Link-local, multicast and unspecified are never a web application, whatever the
    environment is called. The metadata address is the one that matters."""
    reason = action_scope._ip_scope_block_reason(host, environment)
    assert reason == "loopback_or_private_range", (host, environment, reason)


@pytest.mark.parametrize("environment", ["lab", "test"])
def test_a_lab_label_still_admits_ordinary_local_addresses(environment):
    """The lab convenience itself is deliberate and stays."""
    for host in ("127.0.0.1", "192.168.1.50", "10.0.0.5", "localhost"):
        assert action_scope._ip_scope_block_reason(host, environment) is None, host


def test_a_scope_receipt_refuses_the_metadata_address_under_a_lab_cohort():
    """The whole path, not just the predicate: Lab plus the metadata address is blocked."""
    receipt = action_scope.evaluate_scope(
        "http://169.254.169.254/latest/meta-data/",
        allowed_hosts=["169.254.169.254"],
        environment="lab",
    )
    assert receipt.verdict == "blocked"
    assert "loopback_or_private_range" in receipt.blocked_by


def test_reporting_a_fleet_never_raises_the_configured_execution_cap():
    """P02. The display floor and the operational cap are different numbers.

    Reporting a running fleet larger than the computed cap is honest; letting that reported
    number become the concurrency workers obey is not, especially as the worker list includes
    exited containers.
    """
    configured = deployment_policy.max_allowed_workers_for_memory_gb(8)
    assert deployment_policy.reported_max_allowed_workers(configured, running_count=9) == 9
    # ...but the operational cap is derived from the configuration alone.
    assert deployment_policy.operational_max_allowed_workers(configured, running_count=9) == configured
    assert deployment_policy.operational_max_allowed_workers(configured, running_count=0) == configured


def test_the_workers_endpoint_publishes_the_configured_cap_not_the_reported_one():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    publish = re.search(r"_publish_max_active_scans\(max_allowed=([^)]+)\)", source)
    assert publish, "the workers endpoint no longer publishes an active-scan cap"
    assert "reported" not in publish.group(1), (
        "the reported (display) maximum is being published as the execution cap: a GET of the "
        "worker list can then raise real concurrency"
    )


@pytest.mark.parametrize("compose", ["docker-compose.yml", "docker-compose.release.yml"])
@pytest.mark.parametrize("service", ["api", "worker", "agent-tool-worker"])
def test_the_private_network_policy_reaches_the_containers(compose, service):
    """P01. A deployment that must refuse intranet targets sets one variable; it has to arrive."""
    import yaml

    rendered = yaml.safe_load((ROOT / compose).read_text(encoding="utf-8"))
    env = (rendered.get("services", {}).get(service, {}) or {}).get("environment") or []
    names = [str(item).split("=", 1)[0] for item in env] if isinstance(env, list) else list(env)
    assert "SHAKERSCAN_PRIVATE_NETWORK_TARGETS" in names, (
        f"{compose}:{service} never receives the private-network policy, so setting it in .env "
        f"does nothing and the documented opt-out cannot be applied"
    )


def test_create_target_surfaces_the_servers_reason():
    """P06. The page shows err.message; the helper has to put the reason in it."""
    api_ts = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text(encoding="utf-8")
    start = api_ts.index("export async function createTarget(")
    body = api_ts[start:start + 1200]
    thrown = re.search(r"if \(!res\.ok\) throw new Error\(([^\n]+)\)", body)
    assert thrown, "createTarget no longer raises on a failed response"
    assert "getApiErrorMessage" in thrown.group(1), (
        "createTarget still throws a fixed string, so the scope refusal the server sent never "
        "reaches the toast the page was changed to show"
    )
