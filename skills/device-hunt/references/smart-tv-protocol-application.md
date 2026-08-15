# Smart TV protocol and application playbooks

Use only sections matching confirmed evidence. These are planning checklists; invoke registered ShakerScan capabilities rather than constructing network traffic or commands.

## Web and API surfaces

- Inventory every confirmed HTTP origin, including nonstandard ports, without following cross-scope redirects.
- Derive endpoints from crawls, JavaScript, source maps, descriptors, companion traffic, and authenticated host evidence before wordlist discovery.
- Model REST, JSON-RPC, SOAP, GraphQL, WebSocket, SSE, and vendor operations with authentication, role, state class, identifiers, and discovery source.
- Establish repeated baselines before a controlled mutation. Require a negative control and reproducibility for differential findings.
- Prioritize unauthenticated access, BOLA/BFLA, property authorization, role boundaries, session binding, Origin/Host validation, DNS-rebinding exposure, replay, and CSRF/CORS.
- Use context-specific bounded injection checks only through an implemented deterministic executor. A reflection, delay, 500, or version match is not proof.
- Block reboot, reset, update, install, delete, account, purchase, recording, and persistent-setting operations.

## Authentication, sessions, and pairing

- Distinguish no credential, malformed/expired/revoked credential, unpaired client, paired client, and each authorized role.
- Map credential issuance, pairing confirmation, token storage, renewal, revocation, logout, timeout, and binding to device/client/account.
- Use supplied credentials only. Never guess passwords, PINs, communities, stream paths, or pairing secrets.
- Treat creating or revoking a pairing as persistent unless an approved reversible test fixture exists.
- Verify lockout and abuse controls only with small operator-approved attempts and stop before real account impact.

## SSDP, UPnP, mDNS, and DIAL

- Validate protocol structure rather than port convention.
- For SSDP/UPnP record source, LOCATION, USN, service type, server, boot/config identifiers, descriptors, control URLs, event URLs, and action schemas.
- Keep advertised cross-host URLs out of scope. Test callbacks only through a tester-owned endpoint registered by a deterministic capability.
- For mDNS/DNS-SD record PTR/SRV/TXT/A/AAAA data, interface scope, TTL, identifiers, and whether advertised services are confirmed listeners.
- For DIAL inventory client-referenced applications only. Launch/stop remains an ephemeral action requiring state journal and restoration.

## DLNA, RTSP, SNMP, MQTT, and CoAP

- DLNA: model MediaServer/Renderer, ContentDirectory, AVTransport, media URL authorization, object ownership, and event leakage without browsing private libraries.
- RTSP: begin with bounded OPTIONS/capability checks; assess authentication, URL/session binding, replay, and RTP destination control without streaming private content.
- SNMP: use only supplied community/user material, perform no brute force and no SET operations.
- MQTT: use a dedicated client identity and authorized test topics; avoid broad production subscriptions and real control topics.
- CoAP: use bounded discovery; assess transport protection, authorization, tokens, observe subscriptions, and path handling without amplification.
- SMB/NFS/FTP/TFTP/Telnet: inventory supplied or anonymous access with inert test data; never modify existing files.

## Casting and remote control

- Reconstruct the official-client state machine before testing variants.
- Compare unpaired, paired, expired/revoked, second-client, and browser-origin trust states.
- Separate discovery, pairing, app launch, media load, playback, keyboard/pointer/HID, events, and screen-data capabilities.
- Use benign input and dedicated media. Do not interrupt active viewing, enter sensitive text, purchase, change networks, open service menus, or activate developer mode.
- Record original state and verify restoration for every permitted ephemeral action.

## Evidence threshold

Store the exact device surface, state, baseline, mutation, negative control, observed effect, health samples, state journal, and evidence references. Keep agent conclusions as hypotheses until a deterministic receipt establishes the behavior.
