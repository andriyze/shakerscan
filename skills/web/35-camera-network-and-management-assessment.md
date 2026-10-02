---
id: skill.network.camera-assessment
name: camera-network-and-management-assessment
title: 35. Camera Network and Management Assessment
description: Assess IP cameras, webcams, NVRs and DVRs through listener discovery, management-interface authentication, TLS and retained streaming or ONVIF descriptors.
version: 1.0.0
kind: specialist
phase: discovery
risk: medium
support: supported
target_kinds: [network, device]
capabilities: [http.request]
optional_capabilities: [service.nse_check, tls.inspect, device.inspect, device.capabilities.inspect, device.scan, device.service.verify]
missing_capabilities: []
server_enforced: [policy.evaluate]
budget: {}
routing:
  triggers: [camera, cameras, webcam, surveillance, nvr, dvr, onvif, hikvision, dahua, axis]
  indicators: [camera_management_interface, video_descriptor, camera_model]
  exclusions: []
preconditions: [registered_target]
techniques: [camera-service-inventory, management-login-baselines, administrative-authorization, descriptor-review, tls-assessment]
promotion_gate: server-owned-applicable-proof-contract
requires_skills: [skill.network.discovery-and-service-assessment]
deferred_techniques:
- technique: Native RTSP streaming and ONVIF WS-Discovery exchanges
  requires: Typed protocol executors; service fingerprints and imported HTTP requests do not implement native streaming or multicast discovery
- technique: Video, microphone, recording and physical controls
  requires: Explicit operator intent and typed privacy-aware state-changing executors
source: Authored for the shared ShakerScan Hunt runtime
---

# Camera network and management assessment

Assess an exact camera or recorder asset, preserving its target instructions and the operator's
privacy exclusions. Apply the [network baseline](33-network-discovery-and-service-assessment.md)
to identify listeners and actual protocols before choosing tests. A camera and its NVR are distinct
assets unless each is explicitly in scope; neither a descriptor nor a stored channel grants another
host's authority.

## Inventory and select useful checks

Correlate model and firmware claims from existing evidence, Nmap fingerprints and observed management
responses. Record HTTP/HTTPS, RTSP and other listeners without equating a port number to a protocol.
Use `device.inspect`, `device.capabilities.inspect` or `device.scan` only when a device profile and
the respective capabilities are available. A generic network target can use the same network and
HTTP workflow without these optional device operations.

For management interfaces, inspect the actual scheme and port with `http.request`. Follow recorded
login steps and select saved credentials or request collections the operator requested. Use TLS
inspection and reviewed NSE checks for reachable services; an invalid certificate does not prevent
an authorized same-asset login. Avoid guessing default passwords, stream paths or account names.

## Authentication and authorization hypotheses

Compare anonymous, authenticated and applicable role baselines for configuration metadata,
administrative endpoints, session lifecycle and documented APIs. Use distinct selected principals
for high-risk account comparisons, and read the relevant authentication/session/authorization
methodology. Preserve exact origin and principal evidence. A login page being reachable is normal;
a response code or model/version match alone is not vulnerability proof.

An operator-selected ONVIF SOAP/HTTP collection can seed exact same-asset request replay through an
admitted replay capability. Classify operations before execution: device information is different
from stream acquisition, configuration writes or movement commands. Imported requests do not add
WS-Discovery or native RTSP executors, nor authorize another host advertised in a response.

Do not fetch household video, snapshots, audio or recordings merely to prove a listener exists.
Use operator-approved synthetic fixtures if content access is the actual objective. PTZ movement,
recording deletion, alarm changes, firmware updates, reboot and account changes require their own
admitted action contract and explicit intent. Unsupported native protocols remain coverage gaps;
continue supported interface, TLS and service assessment.

## Evidence and handoff

Report positively identified services, tested interfaces, principal coverage, response evidence and
untested streaming/control techniques. Keep partial port results, silent UDP and uncertain firmware
claims explicit. Deterministic proofs govern verified findings; service exposure and advisory matches
can motivate evidence-backed candidates without claiming compromise.
