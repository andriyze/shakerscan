# Traffic attribution and adaptive pacing

**Status:** current operator guide for how ShakerScan identifies its own traffic and slows down
for a degrading target.

## Recognising ShakerScan traffic

Every request a Scan, a retest or a Hunt sends to a target carries a declared identification, so a
target's security team can tell authorized ShakerScan testing from an attacker's traffic:

| What | Value |
|---|---|
| Header | `X-ShakerScan-Run: scan:<id>` for a Scan or a retest, `hunt:<id>` for a Hunt |
| User-Agent | the engine's own HTTP clients append the token `ShakerScan`; external tools (Nuclei, katana, ffuf, Dalfox, sqlmap, httpx) keep their own User-Agent and carry the header |

The id is the engine's record id for the run. It names the run to whoever operates the engine and
carries nothing else: never a token, a credential or a target value.

**For a security team:** filter the web server or WAF logs on the `X-ShakerScan-Run` header, then
ask the engine's operator for that run. The operator looks it up with `GET /scans/<id>` or
`GET /hunts/<id>`, and lists every run that touched an asset with
`GET /targets/<target id>/traffic` (each run's first and last request, request count, answers that
were 5xx, 429 or errors, and the target addresses connected to; `?since=` limits the period).

**Turning it off.** `SHAKERSCAN_TRAFFIC_ATTRIBUTION=off` on the API and workers sends no header
for the whole install. One Scan sends none with `options.traffic_attribution: false` (an
authorized engagement that must not announce itself). `SHAKERSCAN_TRAFFIC_USER_AGENT_TOKEN`
replaces the User-Agent token; set it empty for none.

Known limits: browser-driven checks (Playwright: browser sign-in, DOM XSS proof) do not add the
header yet; the headless crawl does (katana passes it to its browser). Port and TLS posture tools
(nmap, naabu, tlsx) send no HTTP and carry nothing.

## Adaptive pacing

A Scan slows down, and pauses, when its target degrades, instead of keeping its full rate while
the target answers 503, times out or slows to a crawl. On a fragile production system that rate
would be part of the outage, and degraded answers test nothing anyway.

Before each external tool attempt the worker reads the target origin's recent answers from the
Scan's own request archive and sets the attempt's rate:

| State | When (last 5 minutes, at least 8 answers) | Rate |
|---|---|---|
| normal | under 20 % degraded, latency under 4x the Scan's baseline | as planned |
| slowed | 20 % or more degraded, or median latency 4x the baseline | 1/2 |
| slowed | 50 % or more degraded, or 30 % answered 429 | 1/4 |
| paused | 80 % or more degraded | nothing sent |

A degraded answer is a 5xx (except 501), a 429 or a transport error. A paused attempt sends
nothing and waits (at most half its time, at most 5 minutes) for the degraded answers to age out
of the window. When the target does not recover, the attempt ends as `target_degraded` and its
family is reported partial; the Scan itself goes on and never fails because of pacing.

The engine's own in-process checks keep their existing adaptive throttle for active testing.

Each change is recorded in the Scan's `execution_context.target_pacing` (`GET /scans/<id>`), per
origin: the current state, the reason, the rate factor, and how many attempts it slowed, paused
or stopped.
