---
id: core.evidence-validation
title: "Core 04 \u2014 Evidence Validation and Finding Promotion"
version: 2.0.0
kind: core_policy
applies_to: all_skills
---

# Core 04 — Evidence Validation and Finding Promotion

## Purpose

Separate observations, hypotheses, validation, confirmed findings, attack paths, and reports. Prevent scanner alerts, reflections, errors, or model guesses from being presented as vulnerabilities.

## Hypothesis lifecycle

```text
candidate -> eligible -> planned -> executed -> observed
observed -> rejected | inconclusive | validation_required
validation_required -> false_positive | confirmed
confirmed -> reported -> regression_created -> retested
```

Transitions are append-only events. The current state is derived from the event history.

## Evidence hierarchy

From weakest to strongest:

1. Static indicator or version/banner match.
2. Single tool alert or response anomaly.
3. Reproducible differential against a stable baseline.
4. Independent confirmation with a negative control.
5. Authoritative state, identity, ownership, callback, browser-execution, or server-log proof.
6. Demonstrated bounded attack-path edge.

Each skill declares its minimum promotion gate and required evidence extension.

## Finding promotion

A candidate may become `confirmed` only when:

- Scope and approval decisions are valid for every evidence-producing action.
- Raw request/response or equivalent primary artifacts exist.
- The baseline is stable and relevant to the same identity and state.
- The changed variable is explicit.
- Skill-specific positive conditions are met.
- Required negative controls and confirmation runs pass.
- False-positive controls are addressed.
- Demonstrated impact is separated from likely or untested consequences.
- The evidence validator, not the probing skill, records the promotion event.

## Evidence records

Evidence is immutable and content-addressed. Redactions create derived artifacts without deleting the protected original. Each record binds engagement, policy revision, target, identity, test plan, action, tool version, timestamps, hashes, and storage references.

## Timing evidence

Timing claims require interleaved controls, enough samples for the declared noise level, a minimal delay, and a repeatable distribution shift. One slow request is not confirmation.

## Out-of-band evidence

OOB events require a unique token, allocation record, exact probe correlation, protocol, timestamp, observed source metadata, and expiry. Reused or ambiguous callbacks are inconclusive.

## Severity

Severity must be based on demonstrated preconditions and impact in the authorized environment. Do not copy scanner severity. Record confidence separately from severity.

## Root-cause deduplication

Cluster findings only when they share the same failing control and remediation. Keep distinct authorization boundaries, parsers, trust zones, or deployment components separate even if the symptom looks similar.

## Attack paths

Every edge in an attack path must reference a confirmed finding or an explicitly modeled non-vulnerability capability. Speculative edges are labeled and excluded from demonstrated impact.

## Schemas

- `../schemas/hypothesis.schema.json`
- `../schemas/evidence-record.schema.json`
- `../schemas/execution-result.schema.json`
- `../schemas/finding.schema.json`
