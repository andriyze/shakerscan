---
id: skill.web.software-supply-chain-and-integrity-testing
name: software-supply-chain-and-integrity-testing
title: 27. Software Supply Chain and Integrity Testing
description: Assess dependencies, client scripts, build/update artifacts, provenance, signatures, SBOMs,
  package namespaces, CI trust, and software/data integrity without publishing packages or modifying production
  pipelines.
version: 2.0.0
kind: specialist
phase: modeling
risk: medium_to_high
support: partial
target_kinds:
- web
- api
capabilities: []
optional_capabilities:
- templates.scan
missing_capabilities:
- artifact.inspect
- dependency.analyze
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 300
  max_duration_seconds: 1800
routing:
  triggers:
  - dependency_manifest
  - SBOM
  - client_script
  - build_artifact
  - update_package
  - CI_pipeline
  - signature_or_provenance
  indicators:
  - known_vulnerable_component
  - untrusted_resolution
  - missing_signature
  - mutable_third_party_code
  - artifact_digest_mismatch
  - pipeline_trust_gap
  exclusions:
  - public_or_private_package_publish
  - CI_modification
  - registry_or_update_feed_change
  - third_party_attack
preconditions:
- compiled_scope_policy
- approved_inventory_or_artifact
techniques:
- dependency-and-SBOM-inventory
- known-vulnerability-reachability
- namespace-and-resolution-review
- third-party-runtime-script-integrity
- artifact-signature-and-digest
- CI-trust-boundary-review
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 27-software-supply-chain-and-integrity-testing.md
---

# 27. Software Supply Chain and Integrity Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether the web application can be compromised through untrusted dependencies, build inputs, update channels, external scripts, artifacts, or unsigned data. Separate confirmed reachable risk from version-only speculation.

## Use this skill when

- Client/server dependencies, lockfiles, SBOMs, containers, plugins, themes, browser scripts, CI/CD, or update manifests are in scope.
- The web app loads third-party code or data at runtime.
- Version banners or source maps identify potentially vulnerable components.
- The application distributes agents, extensions, desktop/mobile packages, models, templates, or signed downloads.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `dependency_manifest`
- `SBOM`
- `client_script`
- `build_artifact`
- `update_package`
- `CI_pipeline`
- `signature_or_provenance`

**Useful indicators**

- `known_vulnerable_component`
- `untrusted_resolution`
- `missing_signature`
- `mutable_third_party_code`
- `artifact_digest_mismatch`
- `pipeline_trust_gap`

**Hard exclusions**

- `public_or_private_package_publish`
- `CI_modification`
- `registry_or_update_feed_change`
- `third_party_attack`

**Required preconditions**

- `compiled_scope_policy`
- `approved_inventory_or_artifact`

**Preferred preconditions**

- `SBOM`
- `build_provenance`
- `deployed_version_evidence`

## Required context

- Deployed asset inventory, repositories/build manifests where authorized, SBOMs, lockfiles, container images, and artifact registries.
- Build/update architecture, trusted publishers, signing/verifying keys, and release channels.
- Rules for CVE matching, reachability validation, and third-party testing.
- Explicit prohibition on dependency-confusion package publication or pipeline modification unless in a dedicated lab.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `dependency.analyze`
- `artifact.inspect`

**Optional adapters**

- `javascript.analyze`
- `shell.allowlisted`
- `scanner.run`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 300 |
| `max_duration_seconds` | 1800 |
| `max_concurrency` | 4 |
| `max_state_changes` | 0 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 230 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `namespace_or_pipeline_mutation` | test would publish a package, alter CI, registry, feed, or production artifact | `block` |

**State access**

- Reads: `compiled_policy`, `component_inventory`, `client_artifact_graph`, `build_artifacts`, `deployment_context`
- Writes: `component_inventory`, `provenance_records`, `vulnerability_reachability_records`, `integrity_observations`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- A known vulnerable or unmaintained component is deployed and the vulnerable functionality is reachable.
- Dependency provenance, lockfiles, registries, names, versions, hashes, or signatures are insufficiently controlled.
- Third-party scripts/plugins execute with first-party trust without pinning, SRI, CSP, or monitoring.
- Build/release/update artifacts can be replaced, downgraded, or accepted without signature/provenance verification.
- Untrusted data such as templates, rules, models, or configuration is treated as trusted code or integrity-protected content.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Never publish a package to a public/private namespace as a test unless a dedicated isolated registry and explicit approval exist.
- Do not modify CI/CD, registries, update feeds, or production artifacts.
- A version banner alone is not proof of a vulnerable reachable component.
- Third-party services and packages remain out of scope; assess the target's trust decision and deployed exposure.

## Agent workflow

### 1. Build a component and artifact inventory

- Collect SBOMs, lockfiles, package manifests, client bundles/source maps, container/image metadata, plugins, scripts, fonts, WASM, update manifests, and download artifacts.
- Record name, version, source, publisher, hash, signature, license, maintenance status, environment, and runtime reachability.
- Distinguish build-time, test-only, transitive, bundled, and dynamically loaded components.

### 2. Validate known-vulnerability relevance

- Match exact package/ecosystem/version and account for backports/vendor patches.
- Determine whether the vulnerable module, feature, configuration, and code path are actually reachable.
- Use non-destructive version/function probes or source evidence; label unconfirmed matches as suspected.

### 3. Assess dependency provenance and resolution

- Review registry allowlists, scoped names, internal/public namespace collisions, lockfile integrity, hash pinning, immutable versions, install scripts, and transitive controls.
- Use namespace analysis and an isolated registry simulation; do not publish packages.
- Check build reproducibility and review gates where visibility exists.

### 4. Assess third-party runtime code

- Inventory external scripts/styles/WASM/plugins and their origins, integrity attributes, CSP, permissions, update behavior, and data access.
- Test failure/compromise assumptions with a controlled substitute only in staging or a test harness.
- Identify code loaded without pinning or from user-controlled configuration.

### 5. Assess artifact and update integrity

- Inspect signatures, checksums, provenance/attestations, update-channel TLS, rollback/downgrade protection, key rotation/revocation, and verification failure behavior.
- Use a controlled altered artifact in an isolated test environment.
- Verify clients reject tampered/unsigned/wrong-channel artifacts.

### 6. Assess trusted data and pipeline boundaries

- Map templates, rules, models, prompts, configuration, schemas, migration scripts, and content that can influence execution.
- Check signing, approval, provenance, tenant isolation, and safe parsing.
- Hand execution/injection paths to specialized skills.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `dependency-and-SBOM-inventory` — Dependency and sbom inventory. Select only when the matching trigger and evidence preconditions are present.
- `known-vulnerability-reachability` — Known vulnerability reachability. Select only when the matching trigger and evidence preconditions are present.
- `namespace-and-resolution-review` — Namespace and resolution review. Select only when the matching trigger and evidence preconditions are present.
- `third-party-runtime-script-integrity` — Third party runtime script integrity. Select only when the matching trigger and evidence preconditions are present.
- `artifact-signature-and-digest` — Artifact signature and digest. Select only when the matching trigger and evidence preconditions are present.
- `CI-trust-boundary-review` — Ci trust boundary review. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Known component | Vulnerable version/function is deployed and reachable | Exact version plus benign feature/reachability check | Affected code path confirmed |
| Dependency namespace | Resolver cannot select attacker-controlled source | Isolated registry resolution simulation | Untrusted source wins |
| Third-party script | Runtime code is pinned/restricted | Inventory origin/SRI/CSP and controlled staging substitute | Untrusted replacement executes |
| Update artifact | Tampered/unsigned artifact is rejected | Altered artifact in isolated test | Client accepts/install proceeds |
| Trusted data | Integrity/provenance is enforced | Modify controlled test template/model/config | Unapproved content is consumed |

## Tool strategy

- Use Syft/CycloneDX/SPDX generators, OSV/official advisories, package-manager lock verification, container scanners, and local source analysis.
- Use Sigstore/cosign or platform-native signing verification where applicable.
- Use browser network/SRI/CSP inspection for runtime scripts.
- Perform registry/update simulations only in isolated owner-controlled infrastructure.

## Evidence required for a finding

- Exact component/artifact identity, version/hash, source, environment, and runtime/build reachability.
- Authoritative advisory and affected-feature/configuration match.
- For integrity findings, controlled modified artifact/data and verification failure/success behavior.
- Clear distinction among confirmed exploitable, reachable vulnerable, present-not-reachable, and version-suspected.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/software-supply-chain-and-integrity-testing.schema.json`.

**Skill-specific evidence fields**

- `component`
- `version`
- `source_or_namespace`
- `deployed_context`
- `digest`
- `signature_or_provenance`
- `vulnerability_reachability`
- `integrity_gap`

**Required validation controls**

- `deployed_reachability_required_for_CVE_finding`
- `no_namespace_publish`
- `artifact_hash_binding`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Version strings may be masked, backported, bundled but unused, or development-only.
- A CVE match without affected feature/configuration/reachability may overstate risk.
- Missing SRI is not automatically exploitable if scripts are first-party and strongly controlled, though it may reduce defense in depth.
- Unsigned internal artifacts may still have another strong trust mechanism; verify the actual chain.

## Stop conditions

- Testing would require publishing a dependency, changing a registry, pipeline, release, or production artifact.
- A component belongs to an out-of-scope third party and no target-side trust test is possible.
- An altered artifact could reach real users or devices.
- A live signing key or registry credential is exposed—redact, notify, and stop.

## Common remediation patterns

- Maintain complete SBOMs, lockfiles, approved registries, hashes, provenance, and dependency review/update processes.
- Remove unsupported components and patch reachable vulnerabilities based on authoritative advisories.
- Pin and integrity-protect runtime third-party code; apply CSP and minimize privileges.
- Sign and verify build/update artifacts with protected keys, provenance, rollback protection, and fail-closed behavior.
- Treat models, prompts, templates, rules, and configuration as supply-chain artifacts with ownership, review, signing, and isolation.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/software-supply-chain-and-integrity-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.software-supply-chain-and-integrity-testing
supporting_skills: []
selected_techniques: [dependency-and-SBOM-inventory]
hypothesis_id: HYP-example-001
risk: medium_to_high
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/software-supply-chain-and-integrity-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 04 for client bundle/script discovery.
- Skill 15/16/29 for reachable execution, client injection, or AI data-integrity effects.
- Skill 30 for evidence confidence and remediation prioritization.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
sources: [sbom.json, package-lock.json, client_bundles, container_image]
environments: [production, staging]
registry_testing: isolated_simulation_only
artifact_tampering: test_environment_only
```

## Authoritative references

- [OWASP Top 10 2025 — Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP Top 10 2025 — Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [SLSA Framework](https://slsa.dev/)
- [CycloneDX](https://cyclonedx.org/)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `artifact.inspect`, `dependency.analyze`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
