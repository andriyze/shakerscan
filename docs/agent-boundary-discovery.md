# Evidence-derived agent boundary discovery

**Status:** implementation design for the next slice after the Hunt-to-Boundary handoff. This document is not a claim of completed production acceptance.

## Objective

Move the starting point from a manually prepared candidate and fixture JSON to an existing Hunt's captured application evidence. Build a reviewable authorization-model projection, propose useful cross-tenant tests, and fill the existing AI Boundary workflow with the observed identity/resource bindings. Continue to use the existing candidate, verifier, scan, and regression paths.

The first supported automation is a controlled two-principal HTTP/JSON application. Native MCP, streaming, browser-agent execution, automatic fixture provisioning, and autonomous mutation/approval inference are outside this slice.

## Product path

1. Choose a Hunt and the configured AI target representing its agent endpoint.
2. Read retained, redacted HTTP observations from that Hunt. No new target request is made by discovery.
3. Associate consistent identity responses, tenant claims, resource IDs, owner claims, exact resource paths, and synthetic-canary field locations. Report contradictory, incomplete, or unsupported observations.
4. Present the resulting principal/tenant/resource relationships as application claims, not verified authorization rules. Inventory observed mutating endpoints as unresolved action leads, without fabricating approval semantics.
5. Suggest a supported cross-tenant read fixture and an unverified candidate. The operator maps Hunt principal slots to the configured AI credential roles. Matching hostnames do not share credentials or authorization.
6. Save the candidate through the normal Hunt candidate route, compile its server-loaded evidence, and materialize the existing BoundaryContract. Queue verification only through the existing AI Gate path.
7. Export and rerun the existing regression artifact after actual verification. Discovery alone cannot produce a passing regression or a verified finding.

## Architecture

Expose the model as an explicit derived view of the existing Hunt knowledge query, rather than creating another execution capability or orchestration engine:

```json
{
  "kind": "graph_nodes",
  "filter": {
    "node_type": "agent_authorization_model",
    "hunt_id": "<source-hunt-uuid>",
    "ai_target_id": "<configured-ai-target-uuid>",
    "owner_role": "victim",
    "attacker_role": "attacker"
  }
}
```

The view is computed from durable captured evidence. It is explicitly marked as a projection, not as independently verified persisted ownership. Ordinary graph-node reads remain unchanged. The existing Hunt query path and planner ingress remain the access path; no fictitious native capability is advertised.

The source Hunt must belong to the queried target. Captures must have the same Hunt and target ownership, and discovery uses only the selected agent service origin. The AI endpoint is read from the saved AI target, not supplied as an arbitrary URL. Current authorization and credential grants remain necessary when a later verification run executes.

## Evidence rules

- Consume the canonical redacted HTTP-archive projection, never a raw export or caller-supplied response body.
- Keep source IDs and bounded field locations. Do not copy response prose, credentials, or synthetic marker values into the model or generated prompts.
- A successful HTTP status is insufficient. Exclude failed, incomplete, truncated, unavailable, and non-wire captures from fixture derivation.
- Match resource IDs as complete literal path segments. Do not remove query parameters, decode paths, or turn a different request into an apparent match.
- Infer only unambiguous supported JSON field locations. Conflicts and unsupported shapes are gaps, not clean results.
- Synthetic canaries must actually be present in the controlled-resource observations. Ordinary private values are not silently treated as canaries.
- Preserve the distinction between an observed ownership claim and a verified access restriction. The existing verifier still establishes identity, ownership, backend denial, both principals' legitimate controls, and any actual disclosure.
- Automatic state-changing tests require more than an observed POST. This slice reports the missing policy, independent postcondition, and approval facts rather than guessing them.

## Bounds and freshness

Read a bounded, consistent source snapshot. Report capture and suggestion truncation separately; a partial model never represents complete application coverage. Discovery can inspect retained history, but saving a candidate or executing a verification still uses the normal live lifecycle and budget checks. Recompile and revalidate through the existing server paths before execution; a browser preview is not proof.

## Acceptance

Behavioral tests must cover flat and nested identity/resource shapes, two distinct controlled principals, exact same-origin paths, missing canaries, ambiguous selectors, conflicting observations, redacted/private captures, bounded input, cross-Hunt and cross-target references, and deterministic repeated output. At least one controlled loopback journey must take a generated fixture through the real Boundary verifier, showing a secure result and a verified vulnerable result with legitimate controls intact.

The operator UI must populate the existing workflow without hand-written fixture JSON, retain manual configuration as a fallback, reject stale selections when the Hunt or AI target changes, and never queue target traffic merely because discovery or selection completed. Tests must exercise actual query and handoff behavior, not just assert that an entry exists in a command catalog.
