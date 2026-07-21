# ShakerScan 0.7.0 Must-Fix List

**Status:** stop-ship checklist, revised 2026-07-20 for the 0.7.0 product scope.
ShakerScan 0.7.0 is a **trusted-operator, self-hosted security scanner**, not a hosted SaaS or
multi-tenant security platform.

This is the short release-owner view, not a second implementation roadmap. Detailed implementation
work remains in [`proposed-next-steps.md`](proposed-next-steps.md), while candidate evidence and
publication checks remain in [`release-readiness.md`](release-readiness.md). The latter must be
reconciled with the scope decisions recorded here before 0.7.0 is published.

## 0.7.0 Product Boundary

The expected operator clones the repository or uses the curl installer, runs ShakerScan on a laptop
or private VPS, and scans systems they own or are authorized to test. Typical targets include personal
servers and local vulnerable applications such as crAPI and OWASP Juice Shop.

For 0.7.0:

- The person with access to the ShakerScan process, API, UI, database, Docker socket, and result files
  is a trusted operator. ShakerScan does not provide application login, users, roles, tenant isolation,
  or protection against another person who can access those resources.
- Localhost is the default. Remote VPS access must remain behind Tailscale, a VPN, firewall, or an
  operator-managed authenticated reverse proxy. Direct public exposure remains unsupported.
- Starting an active scan locally is treated as the operator's authorization. Clear target and active-
  testing warnings remain required, but SaaS-style approval receipts and role workflows are not a
  0.7.0 release gate.
- Scan evidence may contain request/response content, payloads, tokens, or application data. Results
  and backups must be treated as sensitive local files. Comprehensive secret masking and historical
  evidence rewriting are not promised in 0.7.0.
- **Target authentication is still core scanner functionality.** Deferring ShakerScan user login does
  not defer authenticated scanning, distinct-principal BOLA testing, credential rotation, or proof that
  the target accepted each test identity.

## 0.7.0 Stop-Ship Items

| ID | Must fix | Why this blocks 0.7.0 | Minimum exit evidence |
|---|---|---|---|
| **SCAN-01** | **Make findings, proof, severity, and attack chains trustworthy.** Deterministic evidence—not AI opinion, labels, or caller-supplied state—must control verified status and severity. Phantom or hypothetical attack-chain steps must not be presented as proven exploitation. | Accurate discovery, exploitation, and validation are the core 0.7.0 promise. A fast scanner with unreliable proof is not releasable. | Adversarial proof/promotion tests; registry `proof_contract` and `severity_rules` enforced at runtime; deterministic replay for verified findings; D-4-style no-phantom-chain coverage; AI cannot downgrade or manufacture deterministic proof. |
| **SCAN-02** | **Make execution and coverage receipts authoritative.** Route every runnable registered family through the registry boundary, including remaining phase-4 BOLA, NoSQL, and endpoint-scoped coverage paths. Report blocked, skipped, cancelled, failed, partial, and completed work honestly; missing telemetry must never mean clean or covered. | Users must be able to distinguish “tested and clean” from “not executed,” “not observed,” or “incomplete.” | No registered-family bypass tests; parent/shard/ASM rollups agree; malformed or absent telemetry degrades coverage; static and dynamic modes produce consistent canonical findings and attempt receipts. |
| **SCAN-03** | **Finish safe bounded execution.** Cancellation must stop active adapters and child processes. Enforce practical time, request, payload, redirect, and same-origin limits for active work. Typed mutating workflows must retain cleanup/restoration guarantees. | A local tool still must stop when asked and must not accidentally continue probing, escape target scope, or leave avoidable mutations behind. | Adapter cancellation matrix; orphan-process test; multi-worker rate/cancellation soak; active redirect/scope negatives; request-cap tests for every release-critical active adapter; mutation restoration tests. |
| **SCAN-04** | **Prove authenticated detector quality on real targets.** Fix authenticated API/spec/route discovery and require server-observed accepted-auth plus distinct-principal evidence before BOLA can pass. Do not count two configured or attempted contexts as successful dual-user testing. | Authenticated BOLA, SQLi, XSS, mass-assignment, and JWT results are central to useful DAST. The corrected crAPI scorecard did not satisfy verified-BOLA acceptance. | Current-fleet authenticated crAPI scorecard with accepted user1/user2 responses and deterministic BOLA proof; current-fleet Smart Juice Shop scorecard; seeded detector-isolation evidence remains labeled and is followed by an unseeded discovery run. |
| **UPGRADE-01** | **Make installation and upgrades reliable and fail closed.** A failed schema repair or required invariant must stop startup with actionable guidance. Test a real upgrade from the published release with legacy/duplicate data while preserving configuration, results, and volumes. | The curl installer and self-hosted upgrade path are primary 0.7.0 workflows. Starting against a half-migrated database can corrupt results or make findings unreliable. | Clean-install test; clean and dirty upgrade tests; deliberate migration-failure test that prevents startup; backup/rollback instructions; post-upgrade schema and data invariants. |
| **DEP-01** | **Clear known production dependency vulnerabilities and use supported runtimes.** Upgrade Next.js from `16.2.4` to at least the audited patched `16.2.10`, regenerate the lockfile, and replace the Node 20 image with a currently supported LTS runtime. Audit the resolved Python environment rather than only loose requirement ranges. | The current UI dependency audit reports a direct high-severity Next.js vulnerability. Shipping a new release on a known-vulnerable framework or retired runtime is avoidable risk even for a local product. | `npm audit --omit=dev` has no unaccepted high/critical findings; UI production build and browser smoke pass on the supported Node image; resolved Python lock/constraints and `pip-audit` report exist; any exception has owner, rationale, and expiry. |
| **BUILD-01** | **Make release builds reproducible enough to audit.** Pin release-critical scanner tools and replace floating downloads from `master` or default branches with immutable versions/commits plus checksums. Pin release base images and record final multi-architecture image digests. | The same source commit must not silently acquire different scanners, templates, wordlists, or vulnerability data during a later build. This directly affects detection behavior and incident response. | Immutable references/checksums for Nuclei templates, SecLists assets, Retire.js data, `testssl.sh`, Python scanners, and base images; repeat-build inventory comparison; final source SHA and image digests recorded. Formal SBOM signing/attestations may follow in 0.8.0. |
| **VAL-01** | **Freeze one candidate and prove the scanning engine end to end.** Run unit/contract tests, UI build and focused browser smoke, documentation/skill checks, release gates, real-stack E2E, D-5 truncation/NUL persistence, and the current-fleet DAST benchmarks above. | Historical green runs, stale workers, or tests from a different commit are not evidence for 0.7.0. Integration seams have caused prior escaped failures. | Exact candidate SHA and worker fingerprints; all 0.7.0 gates green; no stale workers; content-free artifacts retained; installer quick-scan and upgrade smoke pass. Additional AI Gate/Model Intake E2E rows may remain deferred if those surfaces are labeled preview. |
| **REL-01** | **Make publication fail closed and make documentation match the scoped product.** The release workflow must verify the approved candidate SHA and `VERSION`, require its successful gates, correct image license metadata, and use 0.7.0-specific notes. Regenerate the stale capability inventory and correct contradictions such as `auth` being described as both planned and runnable. | The release must accurately state what the local scanner does, what it does not protect, and which capabilities are preview or deferred. | Wrong SHA/version publication fails; required candidate run is linked; inventory check passes; README, walkthrough, AGENTS, CLI help, installer, OpenAPI, release readiness, and release notes agree on the 0.7.0 boundary. |

## Explicitly Deferred to 0.8.0 or Later

| Deferred capability | 0.7.0 position | Future direction |
|---|---|---|
| ShakerScan application authentication, users, roles, RBAC, tenant isolation, and session management | Not included. The deployment is controlled by one trusted operator and external network/host controls. | Design when ShakerScan is ready for shared, team, hosted, or SaaS-like deployments. |
| Comprehensive secret masking across nested evidence, transcripts, exports, screenshots, and historical rows | Existing safeguards may remain, but complete coverage and an old-data rewrite are not release gates. Documentation must warn that result storage is sensitive. | Add a typed redaction pipeline, migration/containment policy, and adversarial persistence/export tests. |
| Server-authoritative approval receipts for every local Full, Aggressive, Smart, scheduled, or routed action | Local execution plus an explicit warning/confirmation is sufficient for the trusted-operator model. Scope and same-origin enforcement still apply. | Add target-bound, expiring approvals before supporting shared control planes or untrusted API clients. |
| Full per-adapter metering-quality taxonomy and billing-grade accounting | 0.7.0 requires effective caps, cancellation, and honest partial/unknown reporting—not SaaS billing accuracy. | Standardize exact/estimated/reserved quality and hard/soft enforcement across every adapter. |
| Signed SBOMs, SLSA-style provenance, and public build attestations | Immutable inputs, checksums, source SHA, and image digests are required; the complete attestation stack is not. | Add automated SBOM publication, signing, verification, and provenance retention. |
| MI-7, AI-5, and AI-6 full-pipeline E2E coverage | May remain planned if AI Gate and Model Intake are clearly labeled preview for 0.7.0 and their existing smoke/unit gates pass. They must not be counted as implemented tests. | Promote these surfaces only after deployment-decision, exception, and deterministic-judge seams pass real-stack E2E. |
| Multi-node fleet, SaaS deployment controls, external CI/CD deployment enforcement, and team workflows | Not part of 0.7.0 claims. | Reassess after the local engine and single-node operational model are stable. |
| Smart shared phase allocator, additional focused SSRF/LFI/RCE/business-logic adapters, full registry-native Sigstore/cosign, built-in AV/YARA, and live MCP invocation fuzzing | Remain roadmap features and must not be implied by 0.7.0 release notes. | Prioritize based on scanner-quality evidence and user demand after 0.7.0. |

## Go/No-Go Rule

0.7.0 may ship only when every stop-ship row is fixed and evidenced on the exact frozen candidate, or
has a written release-owner exception with rationale, compensating control, owner, and expiry. Known
high/critical production dependency vulnerabilities, untrustworthy finding proof, unsafe unbounded
execution, migration failure that permits startup, stale-fleet validation, and failed core DAST
acceptance should not be waived.

Any code change after candidate validation invalidates the affected evidence and requires the relevant
gates to be rerun. Rebuilt images must retain the source SHA and record their new digests.
