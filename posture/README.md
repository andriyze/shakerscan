# ShakerScan posture engine

Bounded DNS, email, HTTP and TLS posture observations for a hostname or IP address. The same
engine answers `POST /v1/check` on the hosted service (`https://pub.shakerscan.com`) and
`POST /public/check` on a self-hosted OSS or Enterprise instance, so both return identical
schema-2 documents: factual `observations` with measured fields and probe scope, no pass/fail
judgments.

| | Hosted service | Self-hosted instance |
|---|---|---|
| Targets | Public DNS names and global IP addresses only | Any hostname or address the operator chooses, including internal ones |
| Government/military targets | Refused (`target_restricted`) | Not restricted |
| Quotas and cache | Per-caller limits; 10-minute cache | None |
| Resolver | DNS over HTTPS | DNS over HTTPS, or the system resolver with `SHAKERSCAN_POSTURE_RESOLVER=system` |
| IP ownership (IPinfo) | Always | With `SHAKERSCAN_POSTURE_IPINFO_TOKEN` |

`src/instance.ts` is the self-hosted entry point: the API image bundles it to
`/opt/shakerscan/posture/instance.cjs` with a pinned Node runtime, and `api/public_check.py`
runs one process per check with the JSON request on stdin. The hosted service wraps
`src/checks/service.ts` in its own Lambda handler with persistent stores.

```sh
npm ci
npm run typecheck
npm test
npm run build
echo '{"target":"example.com"}' | node dist/instance.cjs
```

## Check page (`web/`)

`web/` runs the same check from a browser and shows the schema-2 document the way
`shakerscan check` does: observations grouped into DNS, email, HTTP, TLS and IP network, each
with a one-line summary and, on demand, every measured fact and the probe's scope, plus the
CLI's short Review list. It also opens a result saved with `shakerscan check … --json` on the
viewer's own device. There is no build step, framework or third-party request: `view.js` turns a
document into plain values (`test/web.test.ts` runs it against engine output) and `app.js`
renders them with `textContent` only, because DNS, certificate and header values are chosen by
the checked target.

```sh
python3 -m http.server -d web 8000   # http://127.0.0.1:8000/?sample, or ?target=example.com
```

The endpoint is the `shakerscan-check-endpoint` meta tag (`https://pub.shakerscan.com/v1/check`
by default), and the meta Content-Security-Policy's `connect-src` must name the same origin; the
tests enforce both. There is deliberately no query parameter for the endpoint, so a shared link
cannot redirect what someone types to another host. `_headers` adds `frame-ancestors`, HSTS and
the other response headers on hosts that read it (Cloudflare, Netlify).

Deploying:

- **Page:** serve `web/` as static files from Cloudflare (Workers static assets or Pages) at
  `check.shakerscan.com`, beside the `install.shakerscan.com` Worker. Deploy from a release tag or
  a manual dispatch rather than on every merge, like the installer.
- **Hosted service:** the browser calls `pub.shakerscan.com` directly, so its API Gateway HTTP
  API needs a CORS configuration for exactly that origin: `POST`, request header `content-type`,
  exposed header `retry-after`, no credentials. API Gateway then answers preflights itself; the
  Lambda (which allows only `POST`) is unchanged, and the CLI and MCP send no `Origin`.
- **No proxy in front of the service:** quotas and the region check are keyed on the API Gateway
  source address and never trust forwarded headers. A same-origin proxy would put every visitor
  behind one shared quota and move the region check to the proxy's location.
- **Self-hosted instance:** set the endpoint to `https://<instance>/public/check`, add that origin
  to `connect-src`, and add the page's origin to `SHAKERSCAN_CORS_ALLOW_ORIGINS` (the API refuses
  browser POSTs from other origins). The page sends no credentials, so an instance that
  authenticates API calls answers it with a refusal; use the CLI or MCP there.

Check the preflight after changing CORS:

```sh
curl -si -X OPTIONS https://pub.shakerscan.com/v1/check -H 'Origin: https://check.shakerscan.com' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
```
