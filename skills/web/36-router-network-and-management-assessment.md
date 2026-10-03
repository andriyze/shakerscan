---
id: skill.network.router-assessment
name: router-network-and-management-assessment
title: 36. Router Network and Management Assessment
description: Assess routers, gateways, firewalls and access points through service discovery, administrative-interface testing, TLS and evidence-led management exposure review.
version: 1.1.0
kind: specialist
phase: discovery
risk: medium
support: supported
target_kinds: [network, device]
capabilities: [http.request]
optional_capabilities: [service.nse_check, service.snmp.inspect, tls.inspect, ssh.exec, ssh.close, device.inspect, device.capabilities.inspect, device.scan, device.service.verify, device.ssh.propose]
missing_capabilities: []
server_enforced: [policy.evaluate]
budget: {}
routing:
  triggers: [router, routers, gateway, firewall, access_point, openwrt, mikrotik, ubiquiti, pfsense, opnsense]
  indicators: [router_management_interface, routing_appliance, gateway_model]
  exclusions: []
preconditions: [registered_target]
techniques: [management-service-inventory, anonymous-admin-baseline, authenticated-role-comparison, tls-assessment, retained-configuration-review]
promotion_gate: server-owned-applicable-proof-contract
requires_skills: [skill.network.discovery-and-service-assessment]
deferred_techniques:
- technique: Authenticated SNMP OID walks/SET, routing, DNS-recursion and firewall-rule mutation tests
  requires: Typed protocol or configuration executors; a TCP fingerprint cannot demonstrate these behaviors
- technique: WAN exposure assessment from another network
  requires: An explicitly scoped public address and admitted worker placement; LAN observations do not establish WAN reachability
source: Authored for the shared ShakerScan Hunt runtime
---

# Router network and management assessment

Investigate the exact router, firewall, gateway or access point target. Apply the
[network baseline](33-network-discovery-and-service-assessment.md) and the target's instructions.
Its routing role does not place attached clients, a subnet, upstream equipment or a public address
in scope. Retained routing/configuration evidence is useful knowledge, not authorization to test
every destination named in it.

## Inventory management exposure

Use Naabu to discover TCP listeners and Nmap to identify services. Correlate management HTTP/HTTPS,
SSH and other observed protocols with product and firmware evidence. Use device inspection or a
queued `device.scan` when those optional operations are available for the target. Keep external
reachability, LAN reachability and historical observations distinct; do not infer WAN exposure from
an internal listener. UDP silence cannot establish that DNS, SNMP or VPN services are disabled.

Read administrative pages and documented API metadata at their actual service origin. Use selected
managed identities and operator-selected request collections for requested authenticated tests.
Compare anonymous, ordinary-user and administrative behavior where distinct identities are available.
Prioritize missing authentication, role isolation, session lifecycle, sensitive metadata exposure
and cross-origin request handling. Read relevant web methodologies when the management surface
supports them; do not blindly apply web injection probes to native routing protocols.

TLS and reviewed NSE checks can assess certificates, ciphers and HTTP behavior. Banners and version
matches justify investigation, not a verified finding. Do not guess passwords or SNMP community
strings, equate a port label with access, or treat a management redirect as authority for another host.

## Deeper configuration evidence

Use `service.snmp.inspect` on the actual UDP port (161 by default) for bounded SNMPv3 engine
discovery. This uses no community strings or credential guesses and performs no OID walk or SET.
Silence remains inconclusive. Save positive engine information as service knowledge.

With a selected SSH identity granted `ssh.exec`, inspect logs, interface configuration and runtime
state directly on the authorized asset. Reuse the returned session and close it when finished.
Use saved target actions for repeatable commands. A bounded SSH log watch can overlap external
HTTP/service checks; correlate timestamps and action evidence. Do not wait for an inventory scan
or create a separate command proposal when direct command permission is already granted.

If authorized SSH credentials and a device profile are selected, `device.scan` can request the fixed
`ssh-authenticated-host-review` bundle to gather host evidence. When the operator explicitly requests
additional reviewed commands rather than delegated execution, `device.ssh.propose` creates a bounded immutable proposal for separate review.
It does not execute commands and never grants shell access to the ShakerScan host.

Treat reboot, firmware changes, factory reset, WAN/LAN configuration, DHCP, DNS, firewall rules,
account changes and UPnP mappings as changes to the household or business network. Do not perform
them as discovery. Continue with supported read-only evidence and admitted application tests when a
configuration or native-protocol executor is unavailable.

## Results

Report listeners, identified management services, placement, tested roles, evidence references,
partial discovery and missing protocol coverage. Keep current behavior separate from advisory
matches and inferred configuration. Only deterministic proof can verify a finding; untested WAN,
UDP and configuration behavior remains unresolved rather than healthy.
