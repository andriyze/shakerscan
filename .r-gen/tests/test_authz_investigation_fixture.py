"""The seeded authorization fixture must be a real acceptance test, not a prop.

A cross-principal differential is only trustworthy if it fires on a genuine ownership bypass and
stays silent everywhere else. These pin the fixture's behaviour so a later investigation result
means something: the vulnerable and patched twins serve identical data over identical routes and
differ only in whether ownership is enforced, and the negative controls cover the three ways a
"the attacker got 200" check produces false proof -- a public object, an expired session, and a
collection the attacker legitimately owns.
"""

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests/e2e/fixtures"))

import fixtures_server  # noqa: E402

USER_A = "authz-token-a"
USER_B = "authz-token-b"
EXPIRED = "authz-token-expired"


@pytest.fixture(scope="module")
def base_url():
    server = fixtures_server.start(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def get(base, path, token=None):
    request = urllib.request.Request(base + path)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def test_the_vulnerable_twin_lets_one_principal_read_anothers_object(base_url):
    status, body = get(base_url, "/authz/vuln/orders/1001", USER_B)
    assert status == 200
    # The proof that matters: user-b received an object owned by user-a.
    assert body["order"]["owner"] == "user-a"


def test_the_patched_twin_refuses_the_same_request(base_url):
    status, _ = get(base_url, "/authz/safe/orders/1001", USER_B)
    assert status == 403


def test_both_twins_serve_the_owner_identically(base_url):
    """The twins must differ only in enforcement, or a finding could be an artefact."""
    vulnerable = get(base_url, "/authz/vuln/orders/1001", USER_A)
    patched = get(base_url, "/authz/safe/orders/1001", USER_A)
    assert vulnerable == patched
    assert vulnerable[0] == 200


def test_each_listing_is_caller_scoped_so_a_baseline_exists(base_url):
    """The differential needs the victim's id to be absent from the attacker's own baseline."""
    _, mine = get(base_url, "/authz/vuln/orders", USER_B)
    owned = {order["id"] for order in mine["orders"]}
    assert owned == {"2001"}
    assert "1001" not in owned


def test_a_public_object_is_readable_by_everyone_and_is_not_a_finding(base_url):
    """Negative control: both principals get the same ownerless object."""
    first = get(base_url, "/authz/public/notices/9001", USER_A)
    second = get(base_url, "/authz/public/notices/9001", USER_B)
    assert first[0] == second[0] == 200
    assert first[1] == second[1]
    assert first[1]["notice"]["owner"] is None if "notice" in first[1] else first[1]["owner"] is None


def test_an_expired_session_proves_nothing(base_url):
    """Negative control: an expired token must not read anything, in either twin."""
    for mode in ("vuln", "safe"):
        status, _ = get(base_url, f"/authz/{mode}/orders/1001", EXPIRED)
        assert status == 401


def test_an_unauthenticated_caller_proves_nothing(base_url):
    status, _ = get(base_url, "/authz/vuln/orders/1001")
    assert status == 401


def test_a_principal_reading_its_own_object_is_not_a_bypass(base_url):
    """Negative control: the attacker's own collection must not look like a violation."""
    status, body = get(base_url, "/authz/vuln/orders/2001", USER_B)
    assert status == 200 and body["order"]["owner"] == "user-b"


def test_an_absent_object_is_a_404_in_both_twins(base_url):
    for mode in ("vuln", "safe"):
        status, _ = get(base_url, f"/authz/{mode}/orders/404404", USER_A)
        assert status == 404
