# Proposed Next Steps

**Status (2026-07-21):** future-only product roadmap. Shipped behavior belongs in the
[functionality reference](functionality-reference.md), release gates and candidate evidence belong in
[release readiness](release-readiness.md), and implementation history belongs in the
[archive](archive/README.md).

The next largest functional improvement after 0.7.0 is a coordinated **Multi-Node ShakerScan
fleet**. DAST quality and execution correctness remain continuous release requirements, but they
should support—not displace—the multi-node product initiative.

## 1. Multi-Node fleet — primary post-0.7 initiative

One control plane should coordinate workers across multiple owned VMs/VPS hosts. This increases
concurrent-target capacity and lets one Full Coverage scan consume workers from several machines
without creating independent databases, queues, or findings stores.

The shipped parent → plan → shard → merge model is the execution substrate. The missing product
work is the remote fleet trust and lifecycle layer:

1. Add `shakerscan fleet init`, expiring join tokens, and a copy/paste `fleet join` workflow.
2. Start with an owned-fleet WireGuard overlay; keep Tailscale as an operator-managed alternative.
3. Persist node identity, role, capabilities, build fingerprint, heartbeat, health, and drain state.
4. Replace receive-and-forget queue ownership with lease, acknowledgement, reclaim, idempotency, and
   stale-owner fencing before production claims.
5. Add evidence/artifact upload contracts so remote workers never depend on local control-plane
   paths and partial uploads cannot become proof.
6. Add placement, target affinity, fleet-wide rate limits, cancellation, rolling upgrades, and
   mixed/stale-build rejection.
7. Prove a two-VPS owned fleet under worker loss, network partition, clock skew, duplicate delivery,
   cancellation, and Full Coverage merge.
8. Introduce an HTTPS broker with short-lived worker authority only after the owned-fleet model is
   stable; remote workers should not receive Redis or PostgreSQL credentials in that model.

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
- Complete large-target parity, rate, lease, and cancellation soak before multi-node ASM placement.

## 5. Deep Hunt acceptance

- Improve target-observed object-instance route induction and persist authorized OpenAPI/custom
  endpoint ingestion into the canonical target surface.
- Measure useful action selection, verified net-new yield, false promotion, cost, retry behavior,
  cleanup, and stop quality across current-agent and configured-provider planners.
- Keep arbitrary shell, model-supplied credentials, and AI-only verified findings excluded.

## 6. Graduate AI preview surfaces

- Implement the remaining AI Gate and Model Intake full-pipeline E2E cases for deterministic-judge,
  exception, and deployment-decision seams.
- Promote either surface from preview only after its candidate build passes those real-stack gates.
- Keep live MCP invocation fuzzing, full registry-native Sigstore/cosign, and built-in AV/YARA as
  separately scoped future capabilities.

## Delivery order

1. Freeze and validate 0.7.0 using `release-readiness.md`; do not add release scope here.
2. Begin the Multi-Node owned-fleet foundation as the next major feature line.
3. Land queue lease/fencing and evidence-transfer prerequisites before calling remote workers safe.
4. Continue DAST/auth quality and execution-contract work as acceptance gates for every fleet phase.
5. Add the HTTPS broker and broader placement automation only after the two-VPS owned-fleet proof.
