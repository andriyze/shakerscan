# Hunt verified-discovery work

Status: implementation started from PR #217 (`d5c9955`). This branch is not a release or an efficacy certification.

## Objective

Increase unique deterministically verified bugs beyond the deterministic Scan baseline while reducing operator interventions. Preserve explicit operator authorization and existing execution/proof contracts; do not add blanket restrictions, repeat consent prompts, a parallel scanner, or target-specific production logic.

The operator's initial two Juice Shop runs are directional evidence, not recall measurements. Candidates, successful requests and a known-route verifier acceptance are not autonomous discovery. The existing `scripts/benchmark_targets.py` submits deterministic Scans: keep that baseline distinct from externally driven Hunts.

## First implementation slice

1. Trace the existing two-principal `authz.verify` paths from captured request and identity baseline to canonical proof and persisted finding. Reproduce the failure before changing proof behavior. Exercise vulnerable and patched/public/same-principal controls without weakening the proof threshold.
2. Repair evidence integration where real worker receipts and consumers disagree. Cover safe collection replay contributing service knowledge and Hunt-origin findings remaining attributable to their producing run.
3. Reuse the existing benchmark answer key for explicit run-scoped Hunt evaluation, separating candidates from verified findings and recording the Scan baseline. Do not supply answer-key routes to the planner or call a scripted proof a blind discovery result.

## Acceptance and follow-up

Use focused regressions plus normal exact-head CI. Record tests actually executed, skips, and environment limitations. Run real Juice Shop two-principal acceptance when a built stack is available; report a failure or missing environment rather than fabricate recall. Keep full autonomous efficacy evaluation, state-changing workflows and broader protocol execution separate unless the investigation demonstrates they block this slice.

Each implementation update must distinguish shipped behavior from planned work. Nothing in this document authorizes a merge, release, deployment, new public-target scan, or silent budget increase.
