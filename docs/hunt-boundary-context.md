# Hunt candidate boundary-context inspection

**Status:** read-only candidate/evidence inspection. This is not an executable
Hunt capability, a verified vulnerability, or an automatic AI-boundary proposal.

## Read by candidate ID

`GET /hunts/{hunt_id}/candidates/{candidate_id}/boundary-context` loads the
candidate on the server. It accepts no request body and does not require the
caller to reconstruct candidate or evidence objects.

The route uses the existing Hunt lookup and a read-only, repeatable-read database
transaction. It requires both an observation belonging to the exact Hunt and a
matching web/device target binding. Unknown and out-of-scope candidates return
404. Completed Hunts can inspect retained history without starting new work.

## Evidence and context semantics

The inspector reads at most 50 immutable observations from this Hunt, collecting
at most 100 distinct UUID references. It does not use the canonical candidate's
aggregate references from other Hunts.

It currently resolves three reference kinds: Hunt actions, tool receipts linked
to those actions, and HTTP transactions owned by the Hunt and matching its target.
Unknown, deleted, unsupported or out-of-scope references remain unavailable.
Ambiguous IDs are not assigned a guessed kind. Both caps are reported explicitly.
A reference that resolves proves a database association, not content integrity,
successful execution or an authorization violation.

The response returns resolved record IDs and kinds, field-presence information,
missing structural fields, counts and limitations. It does **not** return request
or response bodies, arbitrary candidate prose, credentials, attack prompts,
policy values, tool inputs, or executable contract fragments. Unavailable raw
references are not echoed.

`context_available` means the inspected references and structural context are
available for review. It does not authorize execution or indicate that a rule has
been proven. Principal bindings, business-policy correctness and postcondition
validity remain explicitly unassessed. Generic BOLA candidates are not assumed
to concern an AI application.

The response always includes `execution_enabled: false`, `proposal_compiled:
false`, `verification_performed: false` and `promotion_authority: false`.

## Structured candidate metadata

New `locus.ai_boundary_context` values must be JSON objects. The candidate
normalizer now retains a bounded JSON copy instead of applying the scalar
`str(value)[:1000]` conversion. Explicit null, boolean, number, array and object
values retain their JSON types; non-finite values and objects over 16,384 bytes
are rejected before candidate creation.

Historical stringified contexts are not evaluated, guessed or automatically
migrated. Their inspection result contains `boundary_context_not_structured`.
Existing non-boundary scalar loci and legacy fingerprints remain unchanged.
Stored context remains user-supplied information, not independent evidence or
an authoritative business policy. This change does not make arbitrary stored
text safe to put in a model's instruction context.

## Integration boundaries

This endpoint does not invoke the hypothesis compiler or materializer, submit a
scan, resolve credentials, mutate a candidate, spend an execution budget or
promote a finding. It does not add a permission or consent gate to other Hunt
operations. Command Arsenal entries do not by themselves register native Hunt
runtime capabilities; this endpoint is not advertised under a fictitious native
capability name.

## Validation

`tests/test_hunt_boundary_context.py` exercises the production ownership SQL
against an in-memory SQLite fixture. Only PostgreSQL UUID casts and UUID-array
syntax are translated. The fixture rejects database writes. Tests also load the
actual route handler and candidate request model into isolated ASGI/schema
harnesses. They do not claim full-app, PostgreSQL, worker or deployment acceptance.

The checks cover cross-Hunt and cross-target access, shared candidates, forged
and missing references, deleted receipts, ambiguous reference namespaces, caps,
legacy metadata, JSON round trips, non-JSON values, metadata-only responses,
read-only transactions, UUID validation and OpenAPI visibility in that harness.
