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
