import asyncio

from scanner.scanner_tools import device_application, device_control_plane


ROUTER_DESCRIPTION_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Fixture Router</friendlyName>
    <manufacturer>Fixture Net</manufacturer>
    <modelName>FX-Router</modelName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <SCPDURL>/igd.xml</SCPDURL>
        <controlURL>/ud/?action&amp;service=WANIPConn1</controlURL>
        <eventSubURL>/event</eventSubURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
        <SCPDURL>/wancommon.xml</SCPDURL>
        <controlURL>/control/WANCommonIFC1</controlURL>
        <eventSubURL>/event2</eventSubURL>
      </service>
      <service>
        <serviceType>urn:test:service:Unrelated:1</serviceType>
        <controlURL>/unrelated</controlURL>
      </service>
    </serviceList>
  </device>
</root>"""


def test_soap_request_builder_is_wellformed_and_escapes_arguments():
    body = device_control_plane.build_soap_envelope(
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "GetGenericPortMappingEntry",
        {"NewPortMappingIndex": "0<>&"},
    )
    assert body.startswith('<?xml version="1.0" encoding="utf-8"?>')
    assert 'xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"' in body
    assert "<u:GetGenericPortMappingEntry" in body
    assert "<NewPortMappingIndex>0&lt;&gt;&amp;</NewPortMappingIndex>" in body
    assert device_control_plane.soap_action_header(
        "urn:schemas-upnp-org:service:WANIPConnection:1", "GetExternalIPAddress",
    ) == '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"'


def test_router_description_xml_selects_only_wan_control_services():
    descriptor = device_application.parse_upnp_device_description(ROUTER_DESCRIPTION_XML)
    selected = device_control_plane.select_wan_control_services(descriptor["services"])

    assert [item["service_type"].split(":service:")[-1] for item in selected] == [
        "WANIPConnection:1", "WANCommonInterfaceConfig:1",
    ]
    assert device_control_plane.control_url_path(selected[0]["control_url"]) == (
        "/ud/?action&service=WANIPConn1"
    )
    assert device_control_plane.control_url_path("http://192.0.2.1:49152/absolute") == "/absolute"
    assert device_control_plane.control_url_path("ftp://evil/x") is None


def test_soap_response_classifier_external_ip_and_auth_boundary():
    ok = device_control_plane.classify_soap_response(
        "GetExternalIPAddress", 200,
        "<s:Body><u:GetExternalIPAddressResponse>"
        "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>"
        "</u:GetExternalIPAddressResponse></s:Body>",
    )
    assert ok["outcome"] == "external_ip_returned"
    assert ok["details"]["external_ip"] == "203.0.113.7"
    assert ok["auth_required"] is False

    no_ip = device_control_plane.classify_soap_response(
        "GetExternalIPAddress", 200,
        "<NewExternalIPAddress>0.0.0.0</NewExternalIPAddress>",
    )
    assert no_ip["outcome"] == "external_ip_absent"

    auth = device_control_plane.classify_soap_response(
        "GetExternalIPAddress", 401, "",
    )
    assert auth["outcome"] == "authentication_required"
    assert auth["auth_required"] is True

    missing = device_control_plane.classify_soap_response("GetExternalIPAddress", 404, "")
    assert missing["outcome"] == "not_supported"


def test_soap_port_mapping_classifier_and_wildcard_severity():
    wildcard = device_control_plane.classify_soap_response(
        "GetGenericPortMappingEntry", 200,
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>8443</NewExternalPort>"
        "<NewInternalPort>443</NewInternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "<NewLeaseDuration>0</NewLeaseDuration>"
        "<NewPortMappingDescription>webcam rule that goes on and on and on past the limit</NewPortMappingDescription>",
    )
    assert wildcard["outcome"] == "port_mapping_returned"
    mapping = wildcard["details"]["port_mapping"]
    assert mapping["external_port"] == "8443"
    assert mapping["internal_port"] == "443"
    assert mapping["protocol"] == "TCP"
    assert mapping["lease_duration"] == "0"
    assert "description" not in mapping  # long operator description is never retained
    assert device_control_plane.port_mapping_is_wildcard(mapping) is True

    pinned = device_control_plane.classify_soap_response(
        "GetGenericPortMappingEntry", 200,
        "<NewRemoteHost>198.51.100.9</NewRemoteHost>"
        "<NewExternalPort>8080</NewExternalPort><NewInternalPort>80</NewInternalPort>"
        "<NewProtocol>UDP</NewProtocol>",
    )
    assert pinned["outcome"] == "port_mapping_returned"
    assert device_control_plane.port_mapping_is_wildcard(pinned["details"]["port_mapping"]) is False

    empty = device_control_plane.classify_soap_response(
        "GetGenericPortMappingEntry", 200,
        "<s:Body><s:Fault><UPnPError><errorCode>713</errorCode></UPnPError></s:Fault></s:Body>",
    )
    assert empty["outcome"] == "no_port_mapping"


def test_rtsp_response_classifier_covers_sdp_auth_and_garbage():
    sdp = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\n" \
          b"v=0\r\no=- 0 0 IN IP4 192.0.2.20\r\ns=Front user:secret@cam/cam1\r\n" \
          b"m=video 0 RTP/AVP 96\r\nm=audio 0 RTP/AVP 97\r\n"
    parsed = device_control_plane.parse_rtsp_response(sdp)
    assert parsed["status"] == 200
    verdict = device_control_plane.classify_rtsp_describe(parsed)
    assert verdict["outcome"] == "media_described"
    assert verdict["details"]["track_count"] == 2
    assert "user:secret@" not in verdict["details"]["session_name"]
    assert "redacted@" in verdict["details"]["session_name"]

    auth = device_control_plane.classify_rtsp_describe(
        device_control_plane.parse_rtsp_response(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n"),
    )
    assert auth["outcome"] == "authentication_required"

    gone = device_control_plane.classify_rtsp_describe(
        device_control_plane.parse_rtsp_response(b"RTSP/1.0 404 Not Found\r\nCSeq: 2\r\n\r\n"),
    )
    assert gone["outcome"] == "not_available"

    garbage = device_control_plane.parse_rtsp_response(b"HTTP/1.1 200 OK\r\n\r\nnot rtsp")
    assert garbage["valid"] is False or garbage["status"] == 0
    assert device_control_plane.classify_rtsp_describe(garbage)["outcome"] == "not_available"

    no_sdp = device_control_plane.classify_rtsp_describe(
        device_control_plane.parse_rtsp_response(b"RTSP/1.0 200 OK\r\n\r\n<html/>"),
    )
    assert no_sdp["outcome"] == "responded"


def test_onvif_response_classifier():
    clock = device_control_plane.classify_onvif_response(
        "GetSystemDateAndTime", 200,
        '<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime/></tds:GetSystemDateAndTimeResponse>',
    )
    assert clock["outcome"] == "onvif_service_accessible"

    info = device_control_plane.classify_onvif_response(
        "GetDeviceInformation", 200,
        "<tds:GetDeviceInformationResponse>"
        "<tds:Manufacturer>Fixture Cam</tds:Manufacturer>"
        "<tds:Model>FC-100</tds:Model>"
        "<tdd:FirmwareVersion>1.2.3</tdd:FirmwareVersion>"
        "</tds:GetDeviceInformationResponse>",
    )
    assert info["outcome"] == "device_information_exposed"
    assert info["details"] == {"manufacturer": "Fixture Cam", "model": "FC-100", "firmware": "1.2.3"}

    missing = device_control_plane.classify_onvif_response("GetDeviceInformation", 404, "")
    assert missing["outcome"] == "not_available"
    denied = device_control_plane.classify_onvif_response("GetSystemDateAndTime", 401, "")
    assert denied["outcome"] == "authentication_required"


def test_plan_truncates_against_budget_and_thorough_tier():
    thorough = device_control_plane.plan_control_plane_requests(
        open_ports={554},
        wan_service_endpoints=[
            {"port": 49152, "scheme": "http", "origin": "http://192.0.2.1:49152",
             "service_type": "urn:schemas-upnp-org:service:WANIPConnection:1", "path": "/ud"},
        ],
        web_origins=[{"port": 80, "scheme": "http", "origin": "http://192.0.2.1"}],
        profile="thorough",
        remaining_budget=40,
    )
    probes = [unit["probe"] for unit in thorough["units"]]
    assert probes == [
        "upnp_igd:GetExternalIPAddress:", "upnp_igd:GetStatusInfo:",
        "upnp_igd:GetGenericPortMappingEntry:0", "upnp_igd:GetGenericPortMappingEntry:1",
        "rtsp_describe:554", "onvif:GetSystemDateAndTime", "onvif:GetDeviceInformation",
    ]

    inventory = device_control_plane.plan_control_plane_requests(
        open_ports={554},
        wan_service_endpoints=[
            {"port": 49152, "scheme": "http", "origin": "http://192.0.2.1:49152",
             "service_type": "urn:schemas-upnp-org:service:WANIPConnection:1", "path": "/ud"},
        ],
        web_origins=[{"port": 80, "scheme": "http", "origin": "http://192.0.2.1"}],
        profile="inventory",
        remaining_budget=8,
    )
    probes = [unit["probe"] for unit in inventory["units"]]
    assert "upnp_igd:GetGenericPortMappingEntry:1" not in probes
    assert "onvif:GetDeviceInformation" not in probes
    reasons = {item["reason"] for item in inventory["skipped"]}
    assert "available_in_deeper_profile" in reasons

    tiny = device_control_plane.plan_control_plane_requests(
        open_ports={554, 8554},
        wan_service_endpoints=[],
        web_origins=[{"port": 80, "scheme": "http", "origin": "http://192.0.2.1"}],
        profile="posture",
        remaining_budget=1,
    )
    assert [unit["kind"] for unit in tiny["units"]] == ["onvif_probe"]
    budget_skipped = [item for item in tiny["skipped"] if item["reason"] == "profile_request_budget"]
    assert {item["probe"] for item in budget_skipped} == {"rtsp_describe:554", "rtsp_describe:8554"}
    assert device_control_plane.MAX_SOAP_CALLS == 6


def test_finding_shape_matches_application_finding_contract():
    observations = [{
        "source": "device_control_plane", "platform": "upnp_igd",
        "title": "UPnP IGD GetExternalIPAddress read-only control request",
        "origin": "http://192.0.2.1:49152", "port": 49152, "method": "POST",
        "path": "/ud", "status": 200, "outcome": "external_ip_returned",
        "auth_required": False, "action_class": "read_only_rpc",
        "data_class": "device_control_plane", "protocol": "upnp_soap",
        "service_type": "urn:schemas-upnp-org:service:WANIPConnection:1",
        "soap_action": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"',
        "external_ip": "203.0.113.7", "body_bytes": 300, "body_sha256": "0" * 64,
    }]
    findings = device_control_plane.build_control_plane_findings(observations)
    assert len(findings) == 1
    finding = findings[0]
    for key in ("fingerprint", "title", "description", "severity", "tool", "source", "cwe", "url", "evidence", "remediation", "verification"):
        assert key in finding
    assert finding["title"] == "UPnP WAN address exposed without authentication"
    assert finding["severity"] == "medium"
    assert finding["cwe"] == "CWE-306"
    assert finding["tool"] == "device_control_plane_dast"
    assert finding["source"] == "device"
    assert finding["verification"] == "deterministic_observation"
    assert finding["evidence"]["external_ip"] == "203.0.113.7"
    assert finding["url"].startswith("http://192.0.2.1:49152/")

    # Auth boundaries, missing mappings, and unsupported control URLs stay observational.
    quiet = [
        {"source": "device_control_plane", "outcome": "authentication_required", "platform": "upnp_igd"},
        {"source": "device_control_plane", "outcome": "not_supported", "platform": "upnp_igd"},
        {"source": "device_control_plane", "outcome": "no_port_mapping", "platform": "upnp_igd"},
    ]
    assert device_control_plane.build_control_plane_findings(quiet) == []


def _surface_kwargs(**overrides):
    values = {
        "connect_address": "192.0.2.10",
        "origin_locator": "router.example.test",
        "profile": "thorough",
        "safety_profile": "safe_remote",
        "device_name": "Router",
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


def test_upnp_wan_surface_flows_through_application_discovery(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        path = kwargs["path"]
        if path == "/device.xml":
            return {"status": 200, "headers": {"content-type": "text/xml"},
                    "body": ROUTER_DESCRIPTION_XML, "truncated": False, "elapsed_ms": 2}
        if "GetExternalIPAddress" in kwargs["body"].decode():
            return {"status": 200, "headers": {},
                    "body": b"<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>",
                    "truncated": False, "elapsed_ms": 2}
        if "NewPortMappingIndex" in kwargs["body"].decode() and ">0<" in kwargs["body"].decode():
            return {"status": 200, "headers": {},
                    "body": b"<NewRemoteHost></NewRemoteHost><NewExternalPort>8443</NewExternalPort>"
                            b"<NewInternalPort>443</NewInternalPort><NewProtocol>TCP</NewProtocol>"
                            b"<NewLeaseDuration>0</NewLeaseDuration>",
                    "truncated": False, "elapsed_ms": 2}
        return {"status": 500, "headers": {}, "body": b"", "truncated": False, "elapsed_ms": 1}

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    monkeypatch.setattr(device_control_plane, "request_pinned_device_http", fake_request)
    descriptor_enrichment = asyncio.run(device_application.enrich_ssdp_descriptions(
        connect_address="192.0.2.10",
        protocols=[{"protocol": "ssdp", "responses": [
            {"location": "http://192.0.2.10:49152/device.xml"},
        ]}],
    ))
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        services=[{"transport": "tcp", "port": 49152, "state": "open", "service_name": "http"}],
        descriptor_enrichment=descriptor_enrichment,
    )))

    soap_calls = [call for call in calls if call["method"] == "POST" and "SOAPAction" in (call.get("headers") or {})]
    # Two WAN services from the descriptor: 4 read-only calls (thorough) + 2 first-tier calls
    assert len(soap_calls) == 6
    assert all(call["connect_address"] == "192.0.2.10" for call in soap_calls)
    titles = {finding["title"]: finding for finding in result["findings"]}
    assert titles["UPnP WAN address exposed without authentication"]["severity"] == "medium"
    assert titles["UPnP port mapping exposed"]["severity"] == "high"
    assert titles["UPnP WAN address exposed without authentication"]["evidence"]["external_ip"] == "203.0.113.7"
    assert result["summary"]["requests_executed"] == len(calls)


def test_rtsp_and_onvif_surface_flows_through_application_discovery(monkeypatch):
    soap_calls = []
    sdp = (
        b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n"
        b"v=0\r\no=- 0 0 IN IP4 192.0.2.20\r\ns=Lobby\r\nm=video 0 RTP/AVP 96\r\n"
    )

    async def fake_request(**kwargs):
        soap_calls.append(kwargs)
        if kwargs["path"] == "/onvif/device_service" and "GetSystemDateAndTime" in kwargs["body"].decode():
            return {"status": 200, "headers": {},
                    "body": b"<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime/></tds:GetSystemDateAndTimeResponse>",
                    "truncated": False, "elapsed_ms": 2}
        if kwargs["path"] == "/onvif/device_service" and "GetDeviceInformation" in kwargs["body"].decode():
            return {"status": 200, "headers": {},
                    "body": b"<tds:GetDeviceInformationResponse><tds:Manufacturer>ACME</tds:Manufacturer>"
                            b"<tds:Model>Cam</tds:Model></tds:GetDeviceInformationResponse>",
                    "truncated": False, "elapsed_ms": 2}
        return {"status": 404, "headers": {}, "body": b"", "truncated": False, "elapsed_ms": 1}

    async def fake_rtsp_exchange(**kwargs):
        assert kwargs["connect_address"] == "192.0.2.10"
        return [b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n", sdp]

    monkeypatch.setattr(device_application, "request_pinned_device_http", fake_request)
    monkeypatch.setattr(device_control_plane, "request_pinned_device_http", fake_request)
    monkeypatch.setattr(device_control_plane, "_rtsp_exchange", fake_rtsp_exchange)
    result = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        device_name="Camera",
        services=[{"transport": "tcp", "port": 554, "state": "open", "service_name": "rtsp"},
                  {"transport": "tcp", "port": 80, "state": "open", "service_name": "http"}],
        web_origins=[{"origin": "http://camera.example.test", "scheme": "http", "port": 80}],
    )))

    titles = {finding["title"]: finding for finding in result["findings"]}
    rtsp = titles["RTSP media stream accessible without authentication"]
    assert rtsp["severity"] == "high"
    assert rtsp["cwe"] == "CWE-306"
    assert rtsp["evidence"]["rtsp_session_name"] == "Lobby"
    assert rtsp["evidence"]["rtsp_track_count"] == 1
    onvif = titles["ONVIF device information exposed without authentication"]
    assert onvif["severity"] == "medium"
    assert onvif["cwe"] == "CWE-200"
    assert onvif["evidence"]["onvif_manufacturer"] == "ACME"
    assert "ONVIF device service accessible" in titles
    # OPTIONS + DESCRIBE + GetSystemDateAndTime + GetDeviceInformation
    assert result["summary"]["requests_executed"] == 2 + len(soap_calls)


def test_observe_only_and_exhausted_budget_run_no_control_plane_probes(monkeypatch):
    async def fail_request(**_kwargs):
        raise AssertionError("no control-plane request may be sent")

    async def fail_rtsp(**_kwargs):
        raise AssertionError("no RTSP exchange may be sent")

    monkeypatch.setattr(device_application, "request_pinned_device_http", fail_request)
    monkeypatch.setattr(device_control_plane, "request_pinned_device_http", fail_request)
    monkeypatch.setattr(device_control_plane, "_rtsp_exchange", fail_rtsp)
    common = {
        "services": [{"transport": "tcp", "port": 554, "state": "open", "service_name": "rtsp"}],
        "web_origins": [{"origin": "http://camera.example.test", "scheme": "http", "port": 80}],
    }
    observe_only = asyncio.run(device_application.discover_device_application_surface(**_surface_kwargs(
        safety_profile="observe_only", **common,
    )))
    assert observe_only["findings"] == []
    assert observe_only["summary"]["requests_executed"] == 0
