# Smart TV artifacts, sensors, and lab capabilities

These capability families require evidence acquisition, a registered sensor, or an isolated lab runner. They are not ordinary network-worker actions and must never be improvised by the agent.

## Firmware and update supply chain

- Acquire firmware only from an operator-provided artifact or an approved vendor source. Record source, exact version, model/region applicability, size, and cryptographic digest.
- Preserve the original artifact. Extract only in a sandbox with archive limits, path traversal protection, decompression-ratio controls, and parser timeouts.
- Inventory partitions, filesystems, boot metadata, certificates, keys, configuration, services, web assets, packages, and update scripts with evidence paths.
- Review signature verification, anti-rollback, transport, model binding, version binding, recovery behavior, and failure handling. Do not flash or modify a real device.
- Treat embedded credentials or keys as sensitive evidence; redact UI output and restrict raw artifact access.

## Components, SBOM, and CVE applicability

- Build component claims from package databases, binaries, manifests, lockfiles, licenses, and runtime evidence; retain source confidence for every claim.
- Normalize package identity and version conservatively. A filename or banner alone is low-confidence evidence.
- Correlate CVEs with architecture, build options, patch backports, reachability, configuration, and runtime behavior.
- Report version-only matches as candidates, not vulnerabilities. Promote only when applicability and affected behavior are supported.

## Privacy and companion ecosystems

- Model data categories, identities, destinations, purposes, retention indicators, consent state, and security controls from authorized captures and artifacts.
- Use dedicated test accounts and synthetic content. Avoid collecting household media, viewing history, voice, camera, microphone, contacts, or account data.
- Correlate companion-app endpoints and credentials with the device trust model without extracting secrets from unrelated applications or accounts.
- Mobile static/dynamic analysis, cloud API assessment, and account lifecycle testing require their own registered executors and scope receipts.

## Wireless sensors

- Bluetooth, BLE, Wi-Fi Direct, broadcast capture, RF monitoring, and packet capture require an explicitly registered sensor with interface, location, authorization, and retention metadata.
- Prefer passive discovery. Pairing, association, deauthentication, injection, replay, jamming, and downgrade tests are active and unavailable unless a dedicated bounded capability declares them.
- Record channel/interface, timestamps, device identifiers with privacy controls, capture filters, and evidence digests.

## Media and parser fuzzing

- Run only against an isolated lab target or emulator with health monitoring, automatic reset, corpus provenance, mutation limits, crash deduplication, and artifact retention.
- Use synthetic media and protocol inputs. Do not fuzz a household or production device.
- A hang is not automatically a security finding; require reproducibility, minimized input, affected component, and impact evidence.

## Hardware debug and physical testing

- UART, JTAG/SWD, test pads, chip-off, fault injection, secure-boot bypass, and storage extraction are lab-only.
- Require explicit device ownership, destructive-test consent where applicable, chain of custody, electrical safety controls, and a dedicated specimen.
- Never suggest wiring, voltage, unlock, erase, or bypass steps through the ordinary connected-device agent.

## Evidence and coverage

For every unavailable family, return the exact blocker: missing artifact, missing sensor, missing isolated runner, missing authorization, unsupported platform, or executor not implemented. The absence of that capability is an assessment limitation, not a clean result.
