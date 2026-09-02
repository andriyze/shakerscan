# Interactive session compatibility API

**Status:** compatibility-only agent API; reconciled 2026-08-29.

Interactive Testing no longer has a standalone UI in ShakerScan 2.0.0. The `/session*` browser API
remains because Command Arsenal and the shipped `ai-security-session` compatibility skill still use
it for bounded manual browser work. New adaptive investigations should normally use **Hunt**.

Use this API only when the user explicitly asks for manual browser interaction, visual evidence, or
a multi-step browser flow that Hunt capabilities do not cover cleanly. Do not describe it as a
third scanner engine, a background agent, or a primary UI workflow.

## Safety boundary

- Test only an exact authorized origin.
- Navigation is same-origin by default; additional origins require explicit scope.
- Use dedicated test accounts and non-production data where possible.
- Credentials must stay in managed profiles or worker-private session state, never findings or
  summaries.
- An HTTP 200, visual difference, reflection, or visible route is a lead, not proof.
- Findings saved through the compatibility API remain unverified until a deterministic proof
  contract establishes impact.
- State-changing actions require explicit user intent and the applicable server-side authority.

## Current workflow

1. Prefer existing Scan/Hunt evidence before generating more traffic.
2. Confirm the target and requested browser actions are authorized.
3. Read the live `/openapi.json` contract for `/session*`; do not reuse payloads from old guides.
4. Keep separate principals in separate contexts for access-control testing.
5. Save only redacted, evidence-backed findings.
6. End the session when the requested interaction is complete.

The compatibility surface includes session create/read/end, screenshot, bounded browser action,
endpoint comparison, and finding creation. Exact request bodies and action enums come from the live
OpenAPI document.

The pre-2.0 detailed walkthrough is preserved in
[`archive/interactive-sessions-guide.md`](archive/interactive-sessions-guide.md) for migration
history. It is not current operating guidance.

