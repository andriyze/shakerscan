# Hunt authorization and target scope

These notes describe the existing ShakerScan execution model. They do not define a second
policy format, matching engine, approval system, or set of skill-specific traffic limits.

## Start and continue

Read `GET /hunts/contract` and the run's context. Reuse valid standing target authorization.
When no standing authorization exists, obtain explicit target-specific consent once before
requesting active authority; a clear authorization already supplied by the operator counts.
Do not invent an approval receipt or ask the operator to repeat an existing grant.

Submit the objective, registered target, selected references and requested testing permissions
through the public Hunt start contract. The server resolves the target binding and approval.
A methodology never grants or removes capabilities and its budget hints do not resize the run.
For missing permission, explain the affected operation and continue already-authorized work.

## Assets and services

Use the actual registered asset and the selected service scheme, host and port. HTTP,
self-signed HTTPS and nonstandard ports are legitimate inputs under existing authorization.
An alternate port on the same admitted asset is not automatically a new consent ceremony.
An unrelated host, principal or tenant is not authorized merely because a page mentions it.

Workers retain frozen addresses and target identity. Do not independently re-resolve a hostname,
rewrite the Host header, reinterpret a CIDR, or substitute a different target to bypass an
execution error. Use the returned capability schema and report actual binding errors.

Selected same-asset credential reuse follows the saved Hunt authority before decryption;
a redirect cannot select another credential destination. Anonymous NSE discovery has a separate,
documented exception: it may follow HTTP(S) redirects on the same frozen asset without loading
credentials or changing the saved service selection. Foreign-host redirects remain observations.

## Limits and changes

Use remaining run budgets and the capability's reported request cost, not minimums copied from
methodology documents. A skipped optional operation is a coverage gap, not a vulnerability or
proof that the whole investigation must fail. Explicit zero limits remain meaningful.

Do not silently enlarge an exhausted budget or attach another principal. Use the live API when
it supports an operator-requested amendment; otherwise state that continuation capability is
missing and preserve the current evidence. Cancellation, revoked authority and run-wide health
freezes still apply. Record a final debrief rather than losing useful partial work.
