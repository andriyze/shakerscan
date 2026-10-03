---
id: skill.network.managed-ssh-assessment
name: managed-ssh-authentication-and-host-review
title: 37. Managed SSH Authentication and Host Review
description: Authenticate to SSH using the Hunt-selected encrypted password or private key on port 22, a saved service port, or an operator-specified port; distinguish login from host review and confirmed commands.
version: 1.0.0
kind: specialist
phase: active_testing
risk: medium
support: supported
target_kinds: [web, api, network, device]
capabilities: [ssh.connect]
optional_capabilities: [ports.discover, service.fingerprint, device.scan, device.ssh.propose]
missing_capabilities: []
server_enforced: [policy.evaluate]
budget: {}
routing:
  triggers: [ssh, ssh_login, ssh_credentials, ssh_connect, private_key, ssh_host_review]
  indicators: [ssh_authentication, ssh_identity, ssh_host_key]
  exclusions: []
preconditions: [registered_target, selected_ssh_identity]
techniques: [exact-service-selection, pinned-key-authentication, managed-identity-validation, host-review-handoff]
promotion_gate: server-owned-applicable-proof-contract
requires_skills: []
deferred_techniques:
- technique: Interactive shell or unrestricted command execution
  requires: Not a Hunt capability; additional exact commands use the separately confirmed immutable device SSH plan
source: Authored for the shared ShakerScan Hunt runtime
---

# Managed SSH authentication and host review

When the operator asks to connect using stored SSH credentials, use `ssh.connect` rather than
asking them to run ssh or paste a password/key. Select an encrypted SSH profile through
`credential_refs.ssh_credential_profile_id` when starting Hunt. The exact target must have an
active profile grant including `ssh.connect`, and the run must admit active network work. Read
the saved manifest and target instructions; the target's standing authorization is reused.

The input accepts a service `port` and optional OpenSSH SHA256 `host_key_fingerprint`. An explicit
port wins over the profile's saved service port; otherwise the saved port is used, then port 22.
An operator-specified nonstandard port is an ordinary same-asset SSH destination. Do not change
the profile or request another authorization solely because the port differs.

The worker binds the connection to a frozen asset address, checks current authority and the exact
credential grant/version, and decrypts only in worker memory. It uses an operator-saved host key.
Without one, it reports the observed key and does not log in. The operator may instead authorize
first-contact trust in target Hunt permissions; the first observed key is then saved atomically.
A changed key fails before the identity is sent. Never silently accept a mismatch as a successful
login or disable host-key checks to make it work. Record first-observed trust separately from an
operator-saved fingerprint. A planner-supplied fingerprint is only a hint, never trust authority.

`ssh.connect` attempts the selected identity once, reports whether authentication actually
succeeded, and closes the connection. It accepts no hostname override, password, key, shell or
command. Passwords, private keys and passphrases stay out of planner context and receipts.
Authentication failure is evidence; do not substitute password guessing or repeat failures until
the budget is exhausted. Cancelled connections stop before further authentication.

For an explicitly requested host assessment on a target with a device profile, use the optional
`device.scan` fixed `ssh-authenticated-host-review` bundle where admitted. For additional remote
commands use `device.ssh.propose`, which produces an immutable plan for the operator's separate
exact-command confirmation. Neither path changes what `ssh.connect` proved: a successful login
does not prove command execution, host hardening or a vulnerability.

Report target/address, actual SSH port, credential profile/version, host-key provenance,
authentication result, connection closure, evidence references and any unperformed host review.
