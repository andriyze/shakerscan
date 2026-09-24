# Hunt evidence and verification

Observations, hypotheses, evidence-backed candidates and verified findings are different things.
A successful capability or a completed methodology is not automatically a vulnerability finding.
Only the server's applicable deterministic proof contract marks a result verified.

## Evidence for a hypothesis

Record the real source action/evidence references, actual service origin, selected principal,
object ownership, timestamp and observed outcome. Preserve the changed variable, stable baseline,
negative controls and repetition when needed. A matching version/banner, one response-length
difference or one slow response is not sufficient proof.

Keep partial observations from interrupted actions when they are useful. Never describe the
interrupted test as completed, or missing evidence as a negative finding. Normalize summaries
without discarding provenance; keep secret values out of planner-visible notes and output.

## Request verification, do not manufacture it

Use `POST /hunts/{hunt_id}/candidates` for evidence-linked leads and the live family-specific
verification path for proof. `candidate.verify` is not a universal verifier. SQL, XSS and
principal-differential operations have their own supported contracts and limitations.

The desired proof below is a validation strategy, not a promise that the runtime implements it:
interleaved timing controls, authenticated identity comparisons, browser execution, independently
observed state or correlated callbacks must come from actual supported evidence sources. A
methodology mentioning server logs or OOB events does not create an executor for collecting them.

## Interpret and report

Separate reproduced impact from plausible-but-untested consequences. Group findings only when
the failing control and remediation actually match; keep different principal and asset boundaries.
Every demonstrated attack-chain edge needs retained evidence; speculative edges stay labelled.
Missing or withheld techniques are coverage gaps, not findings or proof of safety.

An old verified finding is useful prior knowledge, not a reason to refuse an explicit retest.
Changed builds, locators, principals or a larger chain can justify fresh evidence. Preserve the
historical result and record the new observation rather than silently rewriting history.
