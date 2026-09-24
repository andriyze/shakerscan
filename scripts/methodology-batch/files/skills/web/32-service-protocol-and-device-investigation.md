---
id: skill.network.service-protocol-and-device-investigation
name: service-protocol-and-device-investigation
title: 32. Service, Protocol and Connected-device Investigation
description: Investigate observed network services and connected devices using retained evidence, targeted fingerprints, supported service checks and web-interface pivots.
version: 1.0.0
kind: specialist
phase: discovery
risk: medium
support: partial
target_kinds:
- network
- device
capabilities:
- ports.discover
- service.fingerprint
optional_capabilities:
- service.nse_check
- tls.inspect
- http.request
- device.inspect
- device.capabilities.inspect
- device.service.verify
- device.ssh.propose
missing_capabilities:
- protocol.exchange
server_enforced:
- policy.evaluate
budget: {}
routing:
  triggers:
  - network_service
  - connected_device
  - service_inventory
  - mqtt
  - mosquitto
  - ssh
  - smb
  - snmp
  - upnp
  - ssdp
  - dlna
  - smart_tv
  indicators:
  - open_port
  - service_fingerprint
  - management_interface
  - protocol_banner
  - device_protocol
  exclusions: []
preconditions:
- registered_target
techniques:
- retained-service-evidence
- targeted-service-discovery
- protocol-capability-comparison
- web-interface-pivot
- service-state-verification
- protocol-gap-handoff
promotion_gate: server-owned-applicable-proof-contract
requires_skills: []
source: Authored for ShakerScan canonical Hunt and connected-device capabilities
---

# Service, protocol and connected-device investigation

Turn observed listeners and device capabilities into useful hypotheses, not a list of open ports.
Use the [Hunt execution guide](core/02-tool-execution-safety.md). This methodology is knowledge,
not permission to start every protocol operation or a claim that every protocol has an executor.

## Start with retained evidence

Query `service_intelligence` before repeating discovery. Keep the service's actual address,
transport, port, origin, fingerprint provenance, timestamp and source Hunt/Scan/action IDs.
Historical locators, truncated evidence and unknown backend addresses remain explicit.
For devices, use `device.inspect` and `device.capabilities.inspect` when available to understand
what was discovered and what the registered class can actually test.

A port-number label is not positive protocol identification. An open TCP listener is not proof
of a vulnerable product version. UDP silence and `open|filtered` are inconclusive; do not score
them as closed, healthy or safe. A previous fingerprint is a lead, not current proof after a
locator, firmware or service change.

## Choose the next useful action

Use `ports.discover` for missing listener evidence and `service.fingerprint` for selected services.
Use current service knowledge to avoid repeating settled work, except for requested retests,
changed environments or a new principal/chain hypothesis. Respect the actual run budget; a
methodology does not impose a smaller port range than the operator authorized.

`service.nse_check` executes only its advertised reviewed scripts, not arbitrary NSE names.
Select a check that answers a specific question. Optional unrequested method probes are coverage
gaps; genuine transport/script failures remain failures. Preserve observations from partial work
without calling the entire test successful. No service observation becomes a verified finding
without the relevant server-owned proof.

Use `tls.inspect` or the supported TLS NSE check on an admitted TLS service. Invalid certificates
and nonstandard ports are reasons to inspect the service, not to abandon the authorized target.

## Protocol hypotheses and evidence

| Observed surface | Useful questions | Evidence or next supported action |
|---|---|---|
| SSH | Is the banner reliable, is the expected service reachable, and does the selected identity match? | Retained fingerprint and typed device verification; a managed SSH proposal only when requested |
| SMB or SNMP | What protocol/version and management surface are actually exposed? | Targeted fingerprint and registered device capabilities; do not infer share/community access from a port label |
| MQTT or a broker banner | Is the service really a broker, is TLS exposed, and what authorization needs validation? | Retained service evidence, supported fingerprint/TLS checks and an explicit protocol-exchange gap |
| UPnP, SSDP or DLNA | Which description/control endpoints belong to this device, and which advertise web interfaces? | Retained device capability data; inspect an admitted HTTP description without treating advertised URLs as new asset authority |
| Smart-TV management web UI | What authentication, role and application surfaces are present? | Read-only HTTP/browser capabilities plus the relevant authentication, session or authorization methodology |

Native publish/subscribe messages, SNMP queries, SMB share operations and arbitrary discovery
packets are not supplied by `protocol.exchange`: that name declares an implementation gap.
Do not invent protocol success from a banner or send an unsupported message through another
capability. Keep the precise hypothesis, service and required evidence for a later executor.
An unavailable protocol exchange does not prevent supported fingerprint, TLS or interface work.

## Pivot to the observed interface

When evidence reveals HTTP, GraphQL, JavaScript, authentication or a related web surface, supply
that fresh signal to `POST /hunts/{hunt_id}/skills/suggestions` and read the relevant methodology.
Preserve the device/network asset kind. Select an admitted same-asset service explicitly; do not
forward credentials to a different asset mentioned in a description or redirect.

Use saved principals, sessions and request collections when the operator requests authenticated
work. Keep identities separate. `device.ssh.propose` creates an immutable proposed plan; it does
not execute the plan or replace its existing confirmation path.

## Continue and report

A full investigation follows queued `device.service.verify` results and then chooses the next
hypothesis; a submission-only request returns its ID. Record actual action IDs, incomplete
techniques, unsupported protocols and evidence-linked candidates. Methodology binding does not
change capability permissions, credentials, budgets or health state.

Stop on an operator stop or a run-wide freeze. Otherwise recover from a failed or unavailable
technique by selecting useful compatible work. Do not ask for the same authorization repeatedly,
and never present an unexecuted protocol technique as either a finding or a clean result.
