# Hunt web-security skill library

Testing methodology a Hunt can bind, served by `GET /hunt/skills` and delivered to the planner in
the run's context pack.

A skill is methodology plus a declaration of the capabilities it needs. It is **not** an execution
path, an authority, or a safety fence. Binding retains supported and useful partial methodology even when some
required capabilities are absent from the Hunt's saved capability set. Each bound skill reports
`withheld_capabilities` for absent run permissions and `missing_capabilities` for declared
implementation gaps, including prerequisite requirements. Skip techniques that need them,
continue compatible work, and report untested techniques as coverage gaps, never findings or clean
results. Binding does not grant, remove, narrow, widen, or resize capabilities, policy, approval,
scope, or budget. Individual actions still pass through the runtime's execution checks.

## Provenance

Skills 01–30 retain the upstream `web-security-agent-skills` v2 testing hypotheses, technique
modules, test matrices, false-positive controls and references. Their execution instructions are
adapted to the canonical Hunt API; there is no separate upstream action schema or policy compiler.
The shared [execution guide](core/02-tool-execution-safety.md) documents current operation limits.
Core guides are ShakerScan runtime guidance, not an additional approval/budget engine.

Skill 31 is the local edge/origin methodology. Skill 32 adds native service/device investigation
through the existing library and capabilities; arbitrary protocol exchanges remain an explicit gap.
The historical `skills/web` installation location now includes this native service methodology;
its declared target kinds and ID distinguish it from web-interface knowledge.

Frontmatter declares real planner-visible capabilities, missing implementations and advisory
budget hints. Server-enforced labels describe responsibilities, not planner-callable operations.
The methodology never grants authority or changes the Hunt's saved resource limits.

## Support levels

| Level | Meaning |
|---|---|
| `supported` | Every required capability exists and is planner-visible. Bindable. |
| `partial` | Some techniques lack a declared executor. Bindable for existing capabilities; gaps remain explicit. |
| `reference` | Describes authority the server holds, not a procedure a planner selects. |

The `partial` level exists so a gap is visible before a run starts rather than discovered when the
planner reaches for a capability that was never there. `missing_capabilities` names the exact gap.

A `supported` skill may still carry `deferred_techniques`: parts of its methodology this runtime
cannot execute, each naming what it would need. Skill 14 supports bounded SQL verification while
explicitly deferring OOB, LDAP, and unsupported query-language mutations. Skill 31's direct-origin
work requires separately admitted direct-origin authority; binding the skill never supplies it.

## Service applicability

Web/API methodology can be read and bound for a network or device target's web interface without
changing the asset kind or granting web capabilities. Suggestions require an HTTP/application
surface signal or an explicit web-oriented objective; an asset label alone does not invent one.
A missing GraphQL, upload, or realtime executor is a technique gap, not a reason to hide all the
methodology. Capability names in `missing_capabilities` are not callable API operations.

## Two rules that do not bend

1. **Only deterministic proof contracts mark a finding verified.** A skill produces candidates.
2. **A skill never grants authority.** Active testing, credentials, mutation, network discovery and
   out-of-band interaction come from the hunt's policy and its approval receipt, never from binding
   a skill that mentions them.

## Updating

Do not overwrite the adapted execution guidance when importing upstream techniques. Update
frontmatter against the live capability registry, preserve useful investigation content, and run
`python scripts/check_hunt_methodologies.py` plus the Hunt methodology tests. The loader validates every declaration at startup: an unknown capability, a server-only
one, or a `supported` skill with a missing requirement fails closed rather than being published.
