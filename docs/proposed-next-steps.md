# Proposed Next Steps

**Status (2026-07-26):** future-only product roadmap. Shipped behavior belongs in the
[functionality reference](functionality-reference.md), release gates and candidate evidence belong in
[release readiness](release-readiness.md), while implementation history remains available in Git.

The coordinated **Multi-Node ShakerScan fleet is implemented** in both owned-WireGuard and
outbound-HTTPS broker forms. It is no longer future roadmap work. The immediate priority is proving
that implementation on the frozen release candidate, then improving DAST quality and operational
truth without weakening operator capability.

## 1. Multi-node fleet acceptance and operations

One control plane now coordinates local and remote workers, central state/artifacts, bounded
enrollment, placement, leases, reclaim, lifecycle changes, and build truth. Remaining work is
release evidence and operational hardening:

1. Preserve a passing two-VPS broker acceptance receipt on the frozen candidate, including physical
   worker loss, reclaim, duplicate completion, remote placement, cancellation, and central artifacts.
2. Run the equivalent owned-WireGuard acceptance or explicitly exclude that topology from the
   candidate boundary; an implemented but unproven topology must not be implied release-ready.
3. Exercise controlled multi-host enrollment with one expiring `--max-uses` token, then revoke its
   unused capacity and prove exhaustion/revocation under concurrent joins.
4. Test upgrade and rollback from the previous published database and from the earlier one-use fleet
   token schema; preserve nodes, credentials, desired state, scans, and artifacts.
5. Add operator-visible backup/restore and node-replacement exercises for a lost control plane or
   worker disk, without copying node identity between hosts.

The detailed design authority is [Multi-Node Architecture](multi-node-architecture.md). Do not
duplicate its topology, protocol, or security design here. Production enablement is gated by the
lease/fencing, evidence-transfer, and partition acceptance above—not merely by connecting another
worker to Redis.

## 2. DAST and authenticated discovery quality

- Improve universal authenticated OpenAPI, link, JavaScript, browser, producer/consumer, and
  response-guided request discovery without benchmark-specific routes or labels.
- Require redacted accepted-auth and distinct-principal receipts for BOLA; configured or attempted
  contexts alone never satisfy proof.
- Rerun current-fleet Smart Juice Shop and authenticated crAPI scorecards, preserving seeded
  detector-isolation runs as explicitly seeded evidence.
- Improve broad/stored XSS and workflow/write-BOLA recall while keeping deterministic proof gates.

## 3. Execution contracts and operational truth

- Close release-critical registry bypasses while keeping `proof_contract` authoritative and the
  wired XSS/SQLi/BOLA/auth/mass-assignment/JWT severity caps authoritative. Registry
  `severity_rules` may remain advisory.
- Finish cooperative cancellation and practical request/time/payload/redirect bounds for every
  claimed active path.
- Standardize metering quality (`exact`, `adapter_reported`, `reserved_upper_bound`, `estimated`, or
  `unknown`) and expose whether each budget is hard, soft, or unavailable.
- Keep static/dynamic Full Coverage and Continuous ASM rollups consistent under partial, failed,
  cancelled, and missing telemetry.

## 4. Continuous ASM and application graph

- Use observed auth, route, object, producer/consumer, attempt, and proof facts to prioritize the
  next campaign rather than treating endpoint touch count as coverage.
- Expand focused families only when their scanner integrations, proof contracts, budgets, and
  cancellation paths are runnable and tested.
- Complete large-target parity, rate, lease, cancellation, and placement soak before calling
  multi-node ASM campaigns release-proven.

## 5. Hunt acceptance

The engine design authority — ReAct loop, provenance gate, the two-tier verification bridge, and this
backlog mapped to concrete seams — is the historical
[retired investigation architecture](archive/deep-hunt-architecture.md).

- Replace tool-call-as-request accounting with adapter-reported or reserved-upper-bound target-request
  metering, and add an honest whole-session deadline for keyless runs.
- Align the evidence contract with runtime provenance: advertise `scan_N` safely or require HTTP
  confirmation, and make useful response diffs citeable.
- Add DB-backed integration coverage for both drivers, cancellation/restart boundaries, provenance
  persistence, deterministic retest queueing, and proof promotion before expanding active behavior.
- Improve target-observed object-instance route induction and persist authorized OpenAPI/custom
  endpoint ingestion into the canonical target surface.
- Add an operator-approved BOLA ownership oracle and restoration-backed PUT/PATCH mass-assignment
  verification without relaxing the family-proof moat.
- Measure useful action selection, verified net-new yield, false promotion, cost, retry behavior,
  cleanup, and stop quality across current-agent and configured-provider planners.
- Make configured-provider turns checkpointable and keyless in-flight recovery idempotent; never
  replay uncertain active traffic after a restart.
- Keep arbitrary shell, model-supplied credentials, and AI-only verified findings excluded.

## 6. Graduate the remaining AI preview surface

- Implement the remaining AI Gate full-pipeline E2E cases for deterministic-judge and exception
  seams.
- Promote AI Gate from preview only after its candidate build passes those real-stack gates.
- Keep Model Intake's real-model/KVM matrix current as a release gate; do not move deterministic
  admission authority into an AI planner.
- Keep live MCP invocation fuzzing, full registry-native Sigstore/cosign, and built-in AV/YARA as
  separately scoped future capabilities.

## Delivery order

1. Freeze and validate 0.8.0 using `release-readiness.md`.
2. Retain physical broker and Model Intake KVM acceptance evidence for the exact frozen SHA.
3. Run upgrade/rollback, installer, full E2E, and current-fleet benchmark gates without code changes.
4. Test WireGuard separately before considering it for a future supported release boundary.
5. Continue DAST/auth quality and execution-contract work only on a new post-candidate branch.
