# Hunt AISVS boundary follow-up

**Status:** Implemented trust projection and opt-in ingress; deployment isolation is external.

Stacked on PR #296 at `14f0c649e2ec32f92641bbbaf9aa1c5969552825`. This is an
engineering verification profile, not an AISVS conformance claim. Default-on
metadata editing, operator opt-outs, standing target authorization, same-asset
service reuse and canonical execution/proof remain intact.

## Audit of the new #296 commits

- `1a58843e`: default-on metadata with opt-outs; lightweight authority helpers no
  longer import HTTP routers; installer closure repaired; CI starts through the
  supported launcher and waits for network readiness within a fixed deadline.
- `172098e`: removing metadata confirmation prompts does not let those registry
  entries acquire binaries, network placement or network budget dimensions.
- `14f0c64`: hosted installer synchronized; DNS expectations use canonical address
  representation; CI contract tests now match launcher-based startup.

These changes address the earlier installer/readiness failures without treating
an unavailable network worker as ready. The two remaining boundaries addressed
here are persistence of instruction trust and external-planner API access.

## Operator instructions and advisory drafts

The existing `target_skill` record retains an `operator_snapshot` alongside the
latest editable revision. This is not a second target or methodology registry.
Hunt can create/update/delete advisory drafts without extra confirmation, subject
to the existing metadata opt-out. It cannot replace/delete operator directives.
Twenty-revision history churn cannot displace the operator snapshot.

New Hunts load operator-written instructions as `target_skill.skill`. A later
Hunt-written or unknown-origin draft contributes only an `advisory` reference:
revision, content digest and a validated source Hunt UUID. Its title/body are not
automatically inserted into another planner's context. `targets.skill.read`
retains useful drafts, labels their trust and returns operator instructions
separately. Editable revision and operator instruction version can differ.

The existing editor displays this distinction and permits explicit operator save
of an unchanged reviewed draft. The API derives writer identity; caller-supplied
writer/trust/baseline fields are rejected. Operator deletion clears the baseline
even after Hunt deleted its draft. Old unknown-origin text remains advisory;
already-saved Hunt snapshots are not retroactively rewritten.

This prevents automatic trust promotion, not every possible model response to an
explicitly read malicious draft. Hashes identify content; they are not signatures
against a database administrator or an unrestricted same-UID process.

## Optional scoped planner listener

`api/hunt/planner_gateway.py` is an authenticated ASGI ingress to the **existing
API**, not another executor. The default operator listener is unchanged. The
additional listener exposes one already-admitted Hunt using an expiring lease.
It permits existing run-scoped capability/query/candidate/skill/lifecycle routes,
while the canonical registry and runtime still validate all action parameters,
permissions, credentials, budgets and proof. It does not expose operator target
authorization, sharing, instruction promotion, budget increases, per-action
approval, unrelated Hunts or arbitrary future routes.

A server-owned lease file is revalidated on every request and again after body
upload. Removal, disablement, expiry or credential rotation revokes new ingress
requests. Dropping the bearer never falls back to operator access. Caller
credentials and role headers are stripped before dispatch; planner identity is
server-derived. Ingress logs contain IDs/status, not bearer values or bodies.
Bodies and upload duration are bounded. The grant file is owner-only, non-symlink,
size-limited data containing a bearer hash. No lease-issuing HTTP route exists.

### Deployment

Admit the Hunt through the trusted operator workflow. Under the listener service's
OS identity, create the lease (default eight hours; maximum 24 hours):

```bash
PYTHONPATH=api:scanner python -m hunt.planner_lease \
  --hunt-id "$HUNT_ID" \
  --grant-file /run/shakerscan/planner-grant.json \
  --token-file /secure-transfer/planner-token
```

The command prints no bearer. In the API environment, start the separate listener
with a certificate trusted by the planner client:

```bash
SHAKERSCAN_HUNT_PLANNER_GRANT_FILE=/run/shakerscan/planner-grant.json \
  uvicorn hunt.planner_gateway:create_app --factory \
  --host 0.0.0.0 --port 8444 --no-proxy-headers --no-access-log \
  --ssl-certfile /run/tls/server.pem --ssl-keyfile /run/tls/server-key.pem
```

Transfer **only the bearer file** to the isolated planner environment. The shipped
API helper uses `SHAKERSCAN_API_TOKEN_FILE` and the listener's HTTPS URL. Supply the
admitted Hunt ID; the planner does not start a second Hunt. Normal authorized
capabilities and metadata drafts need no new approval prompts.

**Required boundary:** the planner must not independently reach the ordinary
operator API, database, grant file, private keys, operator credentials or host
filesystem. Constrain planner egress to this listener and its selected model
provider. Do not mount the operator's connection configuration. Run the listener
outside the planner environment. The lease grants ingress access only, never
additional testing authority. Deleting it revokes new requests; use the existing
Hunt cancellation path for already-running work. Lease revocation does not stop
in-flight execution or an external model process.

This PR does not install a launcher sandbox or container/network isolation policy.
An unrestricted local coding agent remains part of the trusted operator
installation. The opt-in listener is not evidence that an arbitrary deployment
satisfies AISVS policy-decision isolation.

## Verification and standards mapping

| Property | Tests | AISVS reference |
| --- | --- | --- |
| Drafts cannot automatically become operator intent or erase operator directives | `test_target_instruction_trust.py`, `test_target_asset_instruction_trust_postgres.py`, four-kind admission regression | v1.0-C9.2.5; C8.2.3 analogy |
| Caller cannot claim operator provenance in instruction JSON | Strict model and negative writes | v1.0-C12.5.4, partial provenance |
| Scoped caller cannot issue approvals or use another Hunt | `test_hunt_planner_gateway.py` | v1.0-C9.5.1, v1.0-C9.5.3 |
| Expired/revoked leases cannot reach dispatch | Ingress tests, including revocation during upload | v1.0-C9.5.2, bounded delegation |
| Actual CLI uses HTTPS without self-authorization | `test_hunt_planner_gateway_https.py` | Ingress/transport acceptance |
| Unchanged drafts can be deliberately saved by the operator | UI state tests and `SKILL-007` browser test | v1.0-C9.2.5 |

The PostgreSQL tests exercise actual schema/writes and admission projections, not
an external model. The HTTPS test uses the shipped CLI and real TLS listener with
a counting backend, not a live vulnerability scan or deployment firewall test.
MCP component integrity, model/provider-change evaluation, complete process
shutdown and cryptographic audit chains remain outside this patch. Existing
security gates are not weakened.

Mappings use the released AISVS 1.0, not development guidance:
[C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md),
[C8](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C08-Memory-Embeddings-and-Vector-Database.md),
[C5](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C05-Access-Control-and-Identity.md),
[C12](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C12-Monitoring-and-Logging.md).
C8 is an analogy for structured target knowledge, not a claim to implement a
vector store. OWASP AISVS content is CC BY-SA 4.0; requirements are linked rather
than vendored here.
