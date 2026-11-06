# Target liveness

Every target in the Targets list says whether it can be reached right now: whether its name
resolves, whether a connection to its ports opens, and whether the service behind them answers.
This page describes what is checked, when, within which limits, and how it is shown.

## What is recorded

Liveness belongs to the target as the Targets list shows it (a host, a web app without a host,
or a connected device's address). A host's web apps are checked as part of the host. One record
per target holds:

| Field | Values |
|---|---|
| DNS | `resolves` (at least one address), `no_record` (the resolver answered that the name has no A/AAAA record), `error` (the resolver failed or timed out; says nothing about the name). An IP address target needs no lookup and counts as `resolves`. |
| Reachable | yes when a TCP connection to one of the target's ports opened; no when every attempt was refused, timed out or found no route |
| Live | yes when the service answered: an HTTP status line on a web port (any status, a redirect or an error page included; redirects are not followed), or the first bytes a non-web service sends on its own (SSH, FTP, SMTP and similar banners) |
| Status | one summary of the above (see below) |
| Addresses | the addresses the name resolved to (at most 8) |
| Ports | for each port tried: opened, refused, timed out or unreachable, and the HTTP status where one came back |
| Last checked | when the check finished, and what started it (added, before a Scan, schedule, or "Check now") |
| Reason | why the target is not live, in the engine's own words ("connection refused on port 443", "no answer to HTTP on port 8443 within 5 s", "the name has no address record") |

The summary status:

| Status | Meaning |
|---|---|
| Live | a service answered |
| Reachable | a port opened, but no service answered within the check's time |
| Unreachable | the name resolves, but no port opened |
| No DNS | the name has no address record |
| DNS error | the resolver could not answer; the check is repeated within an hour |
| Not checked (policy) | the target's scope is blocked, or every address it resolves to is outside the destination policy, so nothing was sent |
| Not checked | the target has not been checked yet |

Nothing the target sends is stored except the HTTP status code: no headers, body, banner text or
certificate fields. A banner only proves that a service answered.

## Which ports

In this order, at most four ports per check:

1. the web apps of the target (the URL's port, or 443/80 by scheme);
2. the target's port hints;
3. ports a previous network scan found open;
4. when none of the above exists, 443 and 80.

Web ports (from a web app, or 80, 443, 8080 and 8443) are asked for HTTP (TLS where the scheme or
port says so); other ports are only connected to and read for a banner.

## Limits

A check is a passive request, the same tier as a passive Scan's first request, and it stays inside
what the target is already allowed:

- nothing is sent when the target's scope is blocked or the target is archived;
- the name is resolved once, every address is classified by the same destination policy Scan
  admission applies for the target's environment, and connections go only to admitted addresses,
  by address (no second lookup);
- per check: at most 4 ports, at most 2 addresses per port, at most 8 TCP connections and at most
  4 HTTP requests (`GET /`, no body, no credentials, no cookies, redirects not followed); at most
  1 KiB is read from each connection;
- time: 3 s for the DNS answer, 3 s per connection, 5 s for the service to answer, 15 s for the
  whole check;
- a round checks at most 64 targets, 16 at a time, every 20 seconds.

## When a target is checked

- **On add:** a new target, or a new web app on an existing host, is checked in the next round,
  whatever added it (the Targets page, the API, the client, or discovery). A large import is worked
  through a round at a time; targets asked for (before a Scan, or added) go before scheduled ones.
- **Before a Scan:** submitting a Scan asks for a fresh check of its target when the last one is
  more than 10 minutes old. The Scan does not wait for it; the Scan's own first request decides
  whether the Scan can assess the target.
- **On a schedule:** every active target again 12 hours after its last check (an hour after a
  DNS error).
- **Check now:** the target page's button runs the check at once and shows the result. A target
  checked in the last 30 seconds returns that result instead.

The checks run in the API process that leads the liveness loop (one process at a time across
replicas), from the engine's own network position.

## Where it shows

- **Targets list:** a Liveness column with the status; hovering it shows the reason and when it
  was checked. The Liveness filter (Live, Reachable, Unreachable, No DNS, DNS error, Not checked)
  is applied by the server before paging and counting, so the page, the total and the facet counts
  agree.
- **Target page:** a Liveness card with DNS, reachable, live, the addresses and ports tried, the
  last check and its reason, and "Check now".
- **API:** each inventory row and the target's asset detail carry `liveness`;
  `GET /targets/inventory?liveness=<status>` filters; `POST /targets/{id}/liveness` checks now.

## Scans of an unreachable target

A Scan whose first request cannot reach the target ends without a grade and says that the target
could not be reached, with the attempts it made. Liveness does not change that rule, and a target
shown as unreachable can still be scanned: the Scan may run from another network position (a
remote worker) that can reach it.

## Retests of findings on private addresses

A retest that does not reproduce a finding on a private address (an intranet app) answers
"likely fixed" only when it shows that it reached the finding's origin: a connection and an HTTP
answer there, checked the way liveness checks a web port (a replay whose requests were all answered
counts). When that cannot be shown, the retest stays inconclusive and says why, because a request
that never arrived reproduces nothing.

## Known limits

- The check is made from the API's network position. A target that only a remote worker can reach
  shows as unreachable even when its Scans succeed.
- UDP services are not checked.
- A service that neither speaks HTTP nor sends a banner first (for example Redis) shows as
  Reachable, not Live.
