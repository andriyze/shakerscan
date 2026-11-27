"""Anonymous replay to another bound service port is metered like http.request."""
from __future__ import annotations

from hunt.service_binding import collection_uses_service_origin
from runtime.models import TargetBinding


TARGET = TargetBinding(
    target_id="device-1", target_kind="device", canonical_host="192.0.2.10",
    allowed_origins=("http://192.0.2.10",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=(),
)


def _context(*origins: str) -> dict:
    return {"request_collections": [{
        "collection_id": "c-1", "selection_id": "s-1", "allowed_origins": list(origins),
    }]}


def test_replay_to_a_collection_bound_on_another_port_is_a_service_origin_act():
    context = _context("http://192.0.2.10", "https://192.0.2.10:8443")
    assert collection_uses_service_origin(TARGET, context, "c-1") is True
    assert collection_uses_service_origin(TARGET, context, "s-1") is True


def test_replay_on_the_registered_origin_stays_on_its_passive_tier():
    for origin in ("http://192.0.2.10", "http://192.0.2.10:80"):
        assert collection_uses_service_origin(TARGET, _context(origin), "c-1") is False
    # An unbound collection is refused later by the binding lookup; it is not
    # reclassified here.
    assert collection_uses_service_origin(TARGET, _context("http://192.0.2.10:9000"), "other") is False
    assert collection_uses_service_origin(TARGET, _context("http://192.0.2.10:9000"), None) is False
