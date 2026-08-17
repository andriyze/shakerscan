import asyncio

from scanner.scanner_tools import device_application


def test_catalog_automatic_probes_are_safe_and_controls_are_available():
    catalog = device_application.load_device_api_catalog()
    probes = [probe for platform in catalog["platforms"] for probe in platform.get("probes") or []]
    controls = [operation for platform in catalog["platforms"] for operation in platform.get("controlled_operations") or []]

    assert probes
    assert controls
    assert all(probe["action_class"] in device_application._SAFE_AUTOMATIC_ACTIONS for probe in probes)
    assert any(operation["action_class"] in {"ephemeral_control", "persistent_mutation", "persistent_or_disruptive"} for operation in controls)

    public = device_application.public_device_api_catalog()
    exported = [operation for platform in public["platforms"] for operation in platform["controlled_operations"]]
    assert all(operation["status"] == "available_with_confirmation" for operation in exported)
    assert all(operation["execution_mode"] == "exact_user_confirmed_request" for operation in exported)


def test_same_device_ssdp_description_is_fetched_and_normalized(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {
            "status": 200,
            "headers": {"content-type": "text/xml", "server": "Fixture/1"},
            "body": b"""<?xml version='1.0'?>
            <root xmlns='urn:schemas-upnp-org:device-1-0'><device>
              <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
              <friendlyName>Living Room TV</friendlyName><manufacturer>Fixture Corp</manufacturer>
              <modelName>Fixture TV</modelName><modelNumber>F-1</modelNumber><UDN>uuid:fixture</UDN>
              <serviceList><service><serviceType>urn:test:service:Remote:1</serviceType>
                <serviceId>urn:test:remote</serviceId><SCPDURL>/remote.xml</SCPDURL>
                <controlURL>/remote/control</controlURL><eventSubURL>/remote/events</eventSubURL>
              </service></serviceList>
            </device></root>""",
            "truncated": False,
            "elapsed_ms": 4,
        }

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    protocols = [{
        "protocol": "ssdp",
        "responses": [{"location": "http://192.0.2.10:49152/device.xml", "location_in_scope": True}],
    }]
    result = asyncio.run(device_application.enrich_ssdp_descriptions(
        connect_address="192.0.2.10", protocols=protocols,
    ))

    assert calls[0]["connect_address"] == "192.0.2.10"
    assert calls[0]["port"] == 49152
    assert calls[0]["path"] == "/device.xml"
    assert result["identity"]["manufacturer"] == "Fixture Corp"
    assert result["identity"]["model_name"] == "Fixture TV"
    assert result["services"][0]["port"] == 49152
    assert result["web_origins"][0]["origin"] == "http://192.0.2.10:49152"
    assert result["observations"][0]["descriptor"]["services"][0]["control_url"] == "/remote/control"


def test_cross_host_ssdp_location_is_never_fetched(monkeypatch):
    async def fail_request(**_kwargs):
        raise AssertionError("cross-host SSDP URL must not be fetched")

    monkeypatch.setattr(device_application, "request_pinned_device_http", fail_request)
    protocols = [{
        "protocol": "ssdp",
        "responses": [{"location": "http://192.0.2.99:8008/device.xml", "location_in_scope": False}],
    }]
    result = asyncio.run(device_application.enrich_ssdp_descriptions(
        connect_address="192.0.2.10", protocols=protocols,
    ))

    assert result["receipt"]["attempted"] == 0
    assert result["receipt"]["skipped"] == 1
    assert protocols[0]["responses"][0]["description_fetch"]["reason"] == "location_not_exact_authorized_device"


def _surface_kwargs(**overrides):
    values = {
        "connect_address": "192.0.2.10",
        "origin_locator": "tv.example.test",
        "profile": "inventory",
        "safety_profile": "safe_remote",
        "device_name": "Living room TV",
        "manufacturer": "",
        "model": "",
        "identity": {"hostnames": []},
        "services": [],
        "web_origins": [],
        "protocols": [],
        "descriptor_enrichment": None,
    }
    values.update(overrides)
    return values


def test_roku_port_runs_identity_probe_and_exposes_confirmed_controls(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {
            "status": 200,
            "headers": {"content-type": "text/xml", "server": "Roku/15"},
            "body": b"<device-info><vendor-name>Roku</vendor-name><model-name>TV</model-name></device-info>",
            "truncated": False,
            "elapsed_ms": 3,
        }

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        services=[{"transport": "tcp", "port": 8060, "state": "open", "service_name": "http"}],
    )))

    assert [(call["method"], call["path"]) for call in calls] == [("GET", "/query/device-info")]
    assert result["platforms"][0]["id"] == "roku_ecp"
    assert result["platforms"][0]["confidence"] == "confirmed"
    assert result["summary"]["confirmed_endpoints"] == 1
    assert result["controlled_operations"]
    assert all(item["status"] == "available_with_confirmation" for item in result["controlled_operations"])
    assert result["summary"]["state_changing_automatically_executed"] == 0
    assert any(item["title"] == "Connected-device API is exposed over cleartext HTTP" for item in result["findings"])


def test_lg_secure_websocket_transport_uses_upgrade_handshake(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {
            "status": 101,
            "headers": {"upgrade": "websocket", "connection": "Upgrade"},
            "body": b"",
            "truncated": False,
            "elapsed_ms": 2,
        }

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        manufacturer="LG webOS",
        services=[{"transport": "tcp", "port": 3001, "state": "open", "service_name": "unknown"}],
    )))

    assert calls[0]["scheme"] == "https"
    assert calls[0]["headers"]["Upgrade"] == "websocket"
    assert calls[0]["path"] == "/"
    assert result["observations"][0]["outcome"] == "confirmed"
    assert any(item["family"] == "ssap_inventory" for item in result["controlled_operations"])


def test_short_vendor_marker_is_not_selected_from_an_unrelated_substring(monkeypatch):
    async def fake_request(**_kwargs):
        return {"status": 400, "headers": {}, "body": b"", "truncated": False, "elapsed_ms": 1}

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        device_name="LG TV",
        manufacturer="Bulgarian Displays",
        services=[{"transport": "tcp", "port": 3001, "state": "open", "service_name": "unknown"}],
    )))

    lg = next(item for item in result["platforms"] if item["id"] == "lg_webos")
    assert lg["confidence"] == "candidate"
    assert lg["signals"] == ["open_tcp:3001"]


def test_observe_only_maps_platform_but_sends_no_catalog_request(monkeypatch):
    async def fail_request(**_kwargs):
        raise AssertionError("observe-only must not execute API catalog probes")

    monkeypatch.setattr(device_application, "request_pinned_device_http", fail_request)
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        safety_profile="observe_only",
        services=[{"transport": "tcp", "port": 7345, "state": "open", "service_name": "unknown"}],
    )))

    assert result["platforms"][0]["id"] == "vizio_smartcast"
    assert result["skipped_probes"][0]["reason"] == "available_with_safe_remote"
    assert result["controlled_operations"][0]["status"] == "available_with_confirmation"


def test_sony_readonly_post_requires_non_port_platform_evidence(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {"status": 200, "headers": {"content-type": "application/json"}, "body": b'{"result":[{"model":"BRAVIA"}]}', "truncated": False, "elapsed_ms": 3}

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    generic = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        profile="posture",
        services=[{"transport": "tcp", "port": 80, "state": "open", "service_name": "http"}],
    )))
    assert calls == []
    assert any(item["reason"] == "awaiting_platform_evidence" for item in generic["skipped_probes"])

    sony = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        profile="posture",
        manufacturer="Sony BRAVIA",
        services=[{"transport": "tcp", "port": 80, "state": "open", "service_name": "http"}],
    )))
    assert calls[0]["method"] == "POST"
    assert calls[0]["path"] == "/sony/system"
    assert sony["observations"][0]["action_class"] == "read_only_rpc"


def test_privacy_sensitive_read_becomes_a_deterministic_finding(monkeypatch):
    async def fake_request(**kwargs):
        if kwargs["path"] == "/query/apps":
            body = b"<apps><app id='1'>Private App</app></apps>"
        else:
            body = b"<device-info><vendor-name>Roku</vendor-name></device-info>"
        return {"status": 200, "headers": {}, "body": body, "truncated": False, "elapsed_ms": 1}

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        profile="thorough",
        manufacturer="Roku",
        services=[{"transport": "tcp", "port": 8060, "state": "open", "service_name": "http"}],
    )))
    finding = next(item for item in result["findings"] if item["title"].startswith("Privacy-sensitive"))
    assert finding["severity"] == "medium"
    assert finding["cwe"] == "CWE-306"
    assert "Private App" not in str(result)
