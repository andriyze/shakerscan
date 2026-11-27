---
id: skill.network.discovery-and-service-assessment
name: network-discovery-and-service-assessment
title: 33. Network Discovery and Service Assessment
description: Discover TCP ports with built-in Naabu, fingerprint listeners with Nmap, assess TLS and HTTP services, and reuse retained evidence on an authorized hostname or IP.
version: 1.0.0
kind: baseline
phase: discovery
risk: medium
support: supported
target_kinds: [web, api, network, device]
capabilities: [ports.discover, service.fingerprint]
optional_capabilities: [service.nse_check, tls.inspect, http.request, subdomains.discover]
missing_capabilities: []
server_enforced: [policy.evaluate]
budget: {}
routing:
  triggers: [network_discovery, port_scan, ports, naabu, nmap, fingerprint, listener_inventory]
  indicators: [unknown_services, missing_port_inventory, exposed_listener]
  exclusions: []
preconditions: [registered_target]
techniques: [retained-inventory, tcp-discovery, service-fingerprinting, tls-assessment, http-pivot, coverage-comparison]
promotion_gate: server-owned-applicable-proof-contract
requires_skills: []
deferred_techniques:
- technique: UDP service discovery on a generic network target
  requires: A registered UDP discovery executor; Naabu ports.discover is TCP only
source: Authored for the shared ShakerScan Hunt runtime
---

# Network discovery and service assessment

Answer which services this exact asset exposes, what they actually speak, and which deserve
further investigation. This applies equally to a hostname, IP, application host or connected
device. Use the [shared execution guide](core/02-tool-execution-safety.md).

## Plan from the objective and existing knowledge

Read the Hunt's target instructions and query retained service intelligence before sending traffic.
Preserve address, transport, port, service origin, timestamp and source action. Reuse current evidence
unless the operator requests a fresh scan or the locator, firmware, configuration or hypothesis
changed. Resolve an ambiguous household label through registered target metadata rather than scanning
neighboring addresses to guess which asset it means.

For “scan ports with naabu”, call `ports.discover`: the server runs its installed Naabu adapter.
There is no need to produce a shell command or ask the operator to run the binary. Use the exact
ports/range requested, or choose a documented discovery profile when the objective leaves it open.
Custom lists accept at most 1,000 ports; inspect the current contract and remaining budget for each
range. Split a wider authorized span across calls rather than silently truncating it to common ports.
Describe incomplete examination if the total budget cannot cover the requested span.

## Discover, identify, then test

1. Call `ports.discover` using `known_services`, `top_100`, `top_1000`, `device_common`, an explicit
   `ports` list, or `port_range`. Let runtime binding supply addresses; never submit another host.
2. Follow the queued action to completion or trustworthy partial output. Keep attempted ports
   separate from discovered listeners. A failed or truncated scan is not a closed-port result.
3. Call `service.fingerprint` on useful open ports using `version_light` initially; use
   `version_default` when stronger identification will answer a concrete question. A familiar port
   number alone does not identify the protocol or product.
4. For TLS services use `tls.inspect` where its live schema accepts the selected service, or
   `service.nse_check` with `ssl-enum-ciphers`. For confirmed HTTP services use `http.request`
   and reviewed `http-security-headers`, `http-methods` or `http-trace` NSE checks as relevant.
   NSE accepts at most three reviewed scripts on four TCP ports per call, not arbitrary scripts.
5. Supply observed HTTP, login, JavaScript or API signals to skill suggestions and read a useful
   application methodology. Keep the same Hunt asset and use the actual scheme and service port.

For a hostname whose domain inventory is relevant, `subdomains.discover` runs passive Subfinder
enumeration. The resulting names are leads; they do not become authorized destinations automatically.
Do not use domain enumeration for a literal IP or silently extend a single-device investigation.

## Interpret and continue

Use selected saved identities on authorized services of the same frozen asset and preserve the
actual principal and origin in comparisons. Certificates with defects and unusual ports are valid
investigation leads; they do not require another same-asset authorization prompt. When the operator
requests reuse from a different target, use the canonical credential grant or collection binding
operation before selection; a skill cannot supply that intent itself.

An open port, product banner, certificate defect or version/advisory match is an observation or
candidate. Only deterministic proof establishes a verified vulnerability. Try useful alternative
services when one fingerprint or identity comparison is inconclusive.

Report discovered listeners, positively identified services, tested services, failed/partial actions,
unexamined ports, evidence references and next hypotheses. TCP silence and UDP `open|filtered` are
inconclusive. Do not present an incomplete inventory as a clean assessment. Record methodology
usage against the actions that actually ran.
