# Model Intake security and acceptance boundary

**Status:** current product/security contract; reconciled 2026-08-29.

The former 2,600-line implementation roadmap mixed completed phases, proposed controls, and
point-in-time acceptance notes. It is archived at
[`archive/model-intake-security-review-roadmap.md`](archive/model-intake-security-review-roadmap.md).
Use this document for the supported boundary and the live OpenAPI for mechanics.

## Purpose and subject boundary

Model Intake reviews model repositories and artifacts before deployment. Model subjects stay out of
ordinary Web Targets, Domains, DAST scores, and ASM coverage. Their identity is the pinned source,
revision, artifact digest, and generated evidence set.

The core API and ordinary worker never import publisher model code. Static acquisition and scanners
produce bounded evidence. Runtime qualification, where supported, uses an isolated opt-in runner.
Workflow completion is not a model pass: `technical_outcome` independently reports `PASS`,
`REVIEW_REQUIRED`, `INCOMPLETE`, or `BLOCK`.

## Implemented controls

- Pinned source/revision and complete-or-explicitly-truncated acquisition semantics.
- SHA-256, signature/trust inputs, repository manifest, model card, license, secret/malware,
  serialization, dependency, and scanner evidence.
- CycloneDX, SPDX, and AIBOM output with declared coverage.
- Hash-locked ModelScan, Semgrep, Fickling, Trivy, OSV, and offline dependency scanning in rebuilt
  source workers, with readiness/self-test receipts.
- Fixed supported safetensors conversion and strict rescan path for unsafe `.bin` layouts.
- Separate execution, evaluation, policy, report, scanner, signer, and runner readiness.
- Admission evidence bound to the exact subject and scan; unavailable strict controls fail closed.
- Bounded storage planning before queue and immediately before isolated execution.

## Acquisition truth

`max_download_bytes` is an artifact-size ceiling, not a memory budget. A capped partial artifact is
`known_unverified_truncated`; it is never a full digest mismatch, verified subject, or complete
review. Quick checks intentionally omit full acquisition and adapters. Full scans require complete
authoritative acquisition wherever the selected strict policy requires it.

## Isolated runtime boundary

The Firecracker/microVM tier is separate host infrastructure and opt-in. It is unsupported on macOS,
Windows, or hosts without exposed hardware virtualization. `UNSUPPORTED_HOST` means the host cannot
run the configured tier; `NOT_READY` means a potentially capable host lacks prerequisites. Both fail
closed.

Installation requires explicit operator action, may require root, mutates the host, and downloads
large images. Agents and APIs must not install it or route installation through the Docker socket.
Acquired/converted evidence is never silently auto-deleted.

## Acceptance

Use `make e2e-model-intake` for the real public-model path. Use
`make e2e-model-intake-fixture` only when external network is intentionally unavailable. A release
claim must name the exact source SHA/image digest and distinguish static review, isolated execution,
evaluation, policy, signer, and deployment-platform evidence.

Human governance, organizational trust, deployed data-plane controls, external KMS/registry policy,
and production monitoring are not implied by a ShakerScan technical result.

