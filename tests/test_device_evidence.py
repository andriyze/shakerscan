import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.device_evidence import build_device_evidence_graph  # noqa: E402


def _graph():
    return build_device_evidence_graph(
        locator="tv.test",
        identity={"addresses": [{"address": "192.0.2.40", "type": "ipv4", "vendor": "Fixture"}]},
        services=[{
            "transport": "tcp", "port": 8443, "state": "open", "service_name": "https",
            "product": "Fixture UI", "version": "1.0", "policy_eligible": True,
        }],
        inconclusive_observations=[{
            "transport": "udp", "port": 1900, "state": "open|filtered", "service_name": "upnp",
            "policy_eligible": False,
        }],
        web_origins=[{
            "origin": "https://tv.test:8443", "port": 8443, "tls": True,
            "status_line": "HTTP/1.1 200 OK", "peer_certificate_present": True,
        }],
        tool_receipts=[{"stage": "tcp_scope_discovery", "complete": True}],
        safety_receipt={"health_checkpoints": [{"stage": "final", "status": "healthy"}]},
    )


def test_evidence_graph_is_stable_and_links_web_to_the_exact_service():
    first = _graph()
    second = _graph()
    assert first == second
    assert first["schema_version"] == "device-evidence/v1"
    kinds = {node["kind"] for node in first["nodes"]}
    assert kinds == {"device", "network_interface", "network_service", "web_origin"}
    assert any(edge["kind"] == "served_by" for edge in first["edges"])
    assert any(item["kind"] == "device_health" for item in first["observations"])
    uncertain = next(
        node for node in first["nodes"]
        if node["kind"] == "network_service" and node["attributes"].get("port") == 1900
    )
    assert uncertain["confidence"] == "inconclusive"
