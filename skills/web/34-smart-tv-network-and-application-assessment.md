---
id: skill.network.smart-tv-assessment
name: smart-tv-network-and-application-assessment
title: 34. Smart TV Network and Application Assessment
description: Assess smart TVs, connected displays and media appliances through service discovery, management-interface testing, retained LAN descriptors and evidence-led platform review.
version: 1.1.0
kind: specialist
phase: discovery
risk: medium
support: supported
target_kinds: [network, device]
capabilities: [http.request]
optional_capabilities: [service.nse_check, tls.inspect, device.inspect, device.capabilities.inspect, device.scan, device.service.verify, ssh.connect, ssh.exec, ssh.close, targets.actions.read, targets.actions.create, targets.skill.read, targets.skill.update]
missing_capabilities: []
server_enforced: [policy.evaluate]
budget: {}
routing:
  triggers: [smart_tv, television, tizen, webos, android_tv, chromecast, roku, media_appliance]
  indicators: [tv_management_interface, casting_descriptor, television_model]
  exclusions: []
preconditions: [registered_target]
techniques: [tv-service-inventory, descriptor-review, management-authentication, platform-correlation, selected-identity-comparison]
promotion_gate: server-owned-applicable-proof-contract
requires_skills: [skill.network.discovery-and-service-assessment]
deferred_techniques:
- technique: Native pairing, casting and remote-control exchanges
  requires: Typed protocol executors with state tracking and restoration; generic protocol.exchange is not implemented
- technique: Firmware, wireless and physical assessment
  requires: Acquired artifacts and registered artifact, sensor or isolated lab executors
source: Adapted from shipped Smart TV references for canonical Hunt
---

# Smart TV network and application assessment

Investigate an identified television or media appliance through the shared Hunt runtime. Start with
the [network baseline](33-network-discovery-and-service-assessment.md), target instructions, retained
service evidence and the operator's intended depth. A generic host target can receive this methodology
without becoming a separate Device Hunt engine.

## Establish identity and useful services

Correlate model, manufacturer and firmware claims with descriptors, service fingerprints, trusted
operator information or authenticated evidence. Keep conflicting claims and address changes visible.
Use Naabu discovery and Nmap fingerprints from the baseline; do not assume port numbers prove a TV
platform. For a target with a device profile, `device.inspect` and `device.capabilities.inspect`
explain existing evidence and available typed checks. These device-only calls are optional; a plain
network target can still be examined with the network and HTTP capabilities.

Where admitted, `device.scan` queues the existing posture scanner. Its profile and permitted UDP
scope determine whether SSDP/UPnP and mDNS/DNS-SD discovery run. Read completed results and retained
descriptors instead of treating a queued scan as evidence. Naabu itself does not discover UDP.
Inspect descriptions at observed same-asset HTTP origins with `http.request`; advertised LOCATION,
control, event, media or companion URLs do not authorize other assets.

## Test the observed application

Inventory management, companion API and login surfaces on their actual ports, including HTTP and
HTTPS with invalid certificates. Establish an anonymous baseline, then use operator-selected managed
credentials and collections for requested authenticated work. Compare login success signals and
principal identity before drawing access-control conclusions. Reuse admitted identities across the
same asset's services; do not confuse different ports with one authorization baseline.

Prioritize exposed administrative data, missing authentication, session invalidation, role boundaries,
unexpected cross-origin access and sensitive configuration responses. Suggest and read the relevant
authentication, session or authorization methodology when the interface supports it. Use reviewed
NSE/TLS checks when they answer a service question. A successful HTTP status, banner or version match
does not establish proof.

Respect the operator's exclusions and current viewing state. Discovery and baseline inspection do
not imply reboot, factory reset, update, app installation, pairing, media playback, recording or
developer-mode changes. Do not invent a casting or pairing executor by submitting raw messages to
another tool. When one technique is unavailable, continue supported service and interface work.

## Platform evidence and deeper work

Read [platform guidance](../device-hunt/references/smart-tv-platforms.md) only after evidence supports
Android TV, Tizen or webOS. Read the [protocol/application reference](../device-hunt/references/smart-tv-protocol-application.md)
for a relevant surface. These are hypothesis guides; the run manifest determines executable actions.
If an SSH identity is selected and the operator requests host review, use `ssh.exec` for the
requested remote commands under the stored command grant. Use the operator's advised port, the
profile's saved port, or port 22. `ssh.connect` can establish authentication without commands;
reuse the returned session ID for successive commands rather than reconnecting each time. Inspect
logs over SSH while HTTP or other admitted service checks run, correlating timestamps and evidence.
Cancel long commands through the canonical SSH action cancellation route, retain partial output,
and report uncertain remote termination. `ssh.close` disconnects the session before changing port.

Read saved target actions and fixed operator instructions at startup. Reuse suitable actions; save
or edit reusable actions when the operator requests it. Record discoveries as advisory target
knowledge without replacing fixed login guidance, exclusions or critical endpoint instructions.
The fixed `device.scan` host review remains useful for a bounded posture report; it is optional
and is not required around each direct SSH command.

Report identified services, authentication coverage, device health, state-changing techniques not
performed, protocol gaps and deterministic evidence. Explain firmware/version uncertainty and
unavailable sensors or lab work without turning those omissions into findings or a clean result.
