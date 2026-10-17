# Browser capture: `shakerscan record`

**Status:** shipped in 2.11.0 (client `record` command and engine capture routes).

`shakerscan record` opens a browser on one of your targets and keeps what you do there. You
browse, sign in and walk through the flows a crawler does not reach; the ShakerScan instance you
are connected to (on the same machine or another) receives every in-scope request as you go. The
result is a **browser capture**: a request collection that Scans and Hunts use like an imported
HAR file, and that an agent can read while you are still browsing.

There is no proxy and no certificate to install. The client drives Chromium through the Chrome
DevTools Protocol, so it sees HTTPS traffic without intercepting TLS.

## Install

Recording needs Playwright, an optional part of the client:

```bash
pipx install --force 'shakerscan[record]'    # or: pipx inject shakerscan playwright
python -m playwright install chromium         # with the client's Python, once
```

Without it, `shakerscan record` prints these commands and exits.

## Record

```bash
shakerscan record <target> [--name NAME] [--start-url URL] [--include-assets] [--json]
```

- `<target>` is a target id, or a URL whose origin names exactly one target (several targets on
  one origin: pass the id).
- A Chromium window opens with a fresh in-memory profile (no profile directory and no disk cache:
  nothing of the session is written to disk), at `--start-url` or the target's URL.
- Close the browser or press Ctrl-C to finish: the client uploads what is left, closes the capture
  and prints a summary: requests uploaded, endpoints, what was dropped and why, the capture id, and
  the commands to scan or Hunt with it (or, if the close did not go through, the command that
  closes it). `--json` prints the same as JSON.

The connection is the client's usual one (`shakerscan connect`, or `--url` and `--token-file`).
Against ShakerScan Enterprise, viewers cannot create captures, and only the person who opened a
capture can add to it or close it. On an engine-only install the curl launcher's `shakerscan
record` hands the command to the client, or says how to install it.

## What is captured

- Every request the page makes to the capture's **allowed origins**: the target's exact origin
  (scheme, host and port). Requests to other origins, including other subdomains, are counted and
  never sent.
- Method, URL, request and response headers, status, timing, request bodies (at most 256 KiB),
  response bodies (at most 1 MiB; scripts at most 256 KiB), each with a truncation flag.
- WebSockets: the handshake, and at most 50 frames per socket as 4 KiB previews.
- Images, fonts, media and stylesheets are dropped unless `--include-assets`. Scripts are kept.

The client uploads in batches (every 2 seconds, every 50 requests, or before a batch body would
reach 16 MiB, measured as the exact bytes sent). Each batch carries a sequence number, so a retry
after a network error is applied once; a batch is retried with backoff and never skipped. A batch
the server or a gateway in front of it refuses as too large (413) is split and sent again; a single
request too large on its own is sent without its bodies, and the summary counts it. If the client dies, the capture stays
open and the server closes it after 30 minutes without a batch.

### What the server checks

The server decides scope itself: every uploaded request's origin is checked against the capture's
binding, and a request outside it is refused and counted, never stored. A capture holds at most
20,000 requests. Its encrypted document is bounded by the collection size limit (25 MiB, counted
in stored bytes); once it is full, further requests are kept without bodies (method, URL, status
and headers, with cookie and authorization values withheld), and the summary says how many. A
batch sent again with the same sequence number but other requests is refused.

Each batch is stored on its own, encrypted, as it arrives: a batch never rewrites the ones before
it. Closing the capture (or the server's idle close) assembles them into the capture's document. An API process
assembles one capture at a time; a close that would wait more than 20 seconds answers 503 with
`Retry-After`, and `shakerscan record` retries it.

## Masking and storage

The captured document is stored encrypted, like any request collection. Everything you can read
back (the collection library, the request list, the agent's `shakerscan_captures` tool and Hunt
`collections.*`) is the redacted request index: methods, URLs with query values, `;matrix`
parameters (`;jsessionid=`) and token-like path segments withheld, body
**field names** (never values) and labels such as `resource:xhr` and `status:200`. Cookie,
Set-Cookie and Authorization values, tokens in query strings and password or token fields in forms
and JSON never appear in an API or MCP answer, and bodies are never logged.

## Following a capture

```bash
shakerscan api GET '/request-collections/<capture-id>/requests?since_seq=0'
```

Each request has a `seq` (its position, from 1). Pass the answer's `last_seq` as `since_seq` to get
only what was recorded since; `cursor` and `limit` page a long answer. An agent does the same with
the MCP tool `shakerscan_captures` (`action: "list"` for a target's captures, `action: "read"` with
`since_seq` for one capture's requests).

## Using a capture

A capture is a request collection (format `capture`) bound to its target. A Scan or Hunt uses it
once it is **closed**: while it records, a selection, a Scan or a Hunt naming it is refused (409
`capture_open`, "close it first"). `shakerscan record` closes it when you finish; otherwise
`shakerscan api POST /request-collections/<capture-id>/capture-close`, or wait for the idle close.

- **Scan:** `shakerscan scan <target-url> --collection-selection <capture-id>` seeds the Scan with
  the capture's safe requests as known endpoints. Save a selection with a replay policy to replay
  requests.
- **Hunt:** `shakerscan hunt start --target-id <target-id> --collection-id <capture-id>` makes it
  available to `collections.*`.

The library labels it **Browser capture**, with Recording or Closed and its counts.

## Limitations

- **Captured credentials are not promoted.** Cookies, authorization headers and passwords you
  typed stay only in the encrypted document. They never become a credential profile or an
  authenticated session, and replay does not reuse them: Scans and Hunts sign in with the target's
  own credential profiles. Every replay of a capture (Scan, Hunt `collections.replay_*`) leaves out
  the recorded Cookie, Authorization, Proxy-Authorization, API-key, CSRF/XSRF and other token or
  session headers (signature headers included), `;jsessionid`-style path parameters and query
  parameters named like a credential or holding a token-like value, and empties password-, pass-,
  pwd-, PIN-, OTP-, token- and secret-named fields in JSON (nested objects and lists included),
  form and multipart bodies; a body it cannot parse that names such a field is not replayed at
  all. A recorded login form is replayed without the password you typed, and each replay request
  names what was left out (`captured_withheld`). A capture cannot be edited, relabelled or
  replaced through the collection or device routes. To test as the account you used, add it as a
  credential profile.
- Only the target's exact origin is captured; an application that calls an API on another origin
  needs that API as its own target and its own capture.
- Only Chromium is supported, and only browser traffic: applications that are not web pages are
  not captured.
- Capture never grants scope: everything replayed or tested from it still goes through the
  target's scope and authorization checks.
