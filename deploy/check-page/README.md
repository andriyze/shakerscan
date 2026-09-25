# check.shakerscan.com

**Status:** configured in the repository; the one-time setup below comes before the first publish.

The posture check page (`posture/web/`) served as Cloudflare Workers static assets on the
`shakerscan.com` zone. No Worker script runs: Cloudflare serves the six files and applies
`posture/web/_headers` (wrangler sends it as configuration and never serves it as a file).

```
browser ── GET ──> check.shakerscan.com         Cloudflare, static assets
   └────── POST ─> pub.shakerscan.com/v1/check  API Gateway HTTP API (us-east-1) -> Lambda posture engine
```

The page calls the hosted API directly from the visitor's browser, so per-caller quotas and the
region check keep seeing each visitor's own address. Nothing proxies the API.

## One-time setup

1. **Cloudflare API token.** Create a token from the *Edit Cloudflare Workers* template, limited
   to the ShakerScan account and the `shakerscan.com` zone, with an expiry you renew. Static
   assets need none of the template's KV or R2 permissions; remove them. In the zone's DNS, make
   sure no record exists for `check.shakerscan.com` itself (the wildcard is fine): a custom domain
   cannot take over an existing record.
2. **GitHub environment.** Settings → Environments → `check-page`:
   - required reviewers: at least one maintainer;
   - deployment branches and tags: selected, `main` and tags `v*`;
   - secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
3. **CORS on the hosted API.** `pub.shakerscan.com` is an API Gateway custom domain
   (`d-8tipr886ve.execute-api.us-east-1.amazonaws.com`) in front of an HTTP API whose Lambda sends
   no CORS headers and answers `OPTIONS` with 405, so browsers refuse every check until the API
   allows the page's origin. Set it where the API is defined (`CorsConfiguration` in
   CloudFormation or SAM, `corsPreflight` in CDK, `cors_configuration` in Terraform) or:

   ```sh
   api_id=$(aws apigatewayv2 get-api-mappings --region us-east-1 --domain-name pub.shakerscan.com \
     --query 'Items[0].ApiId' --output text)
   aws apigatewayv2 update-api --region us-east-1 --api-id "$api_id" --cors-configuration \
     '{"AllowOrigins":["https://check.shakerscan.com"],"AllowMethods":["POST"],"AllowHeaders":["content-type"],"ExposeHeaders":["retry-after"],"MaxAge":600,"AllowCredentials":false}'
   ```

   API Gateway then answers preflights itself; the Lambda is unchanged, and the CLI and MCP send
   no `Origin`. Redeploy the stage if it does not auto-deploy, then expect a 204 carrying
   `access-control-allow-origin: https://check.shakerscan.com` from:

   ```sh
   curl -si -X OPTIONS https://pub.shakerscan.com/v1/check -H 'Origin: https://check.shakerscan.com' \
     -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
   ```

## Publish

Actions → *Check page deploy* → *Run workflow*, choosing `main` or a `v*` tag under *Use workflow
from*. The run refuses anything not on `main`, tests the page against the engine, waits for the
environment reviewer, publishes with the wrangler version pinned in `package-lock.json`
(installed without install scripts; the token reaches only that step), then checks the live
page, its headers and the API's CORS answer.

The first publish creates a proxied DNS record and an edge certificate for
`check.shakerscan.com`. That record takes precedence over the zone's wildcard `*.shakerscan.com`
A record (DNS-only, to the server that also answers `install.shakerscan.com`), which catches
`check.shakerscan.com` today; nothing else in the zone changes. Keep `pub.shakerscan.com`
DNS-only: proxying it through Cloudflare would put every caller behind Cloudflare's addresses in
the API's quotas and region check.

## Roll back

Each publish is a Worker version tagged with its commit. From this directory, with the token:

```sh
npx wrangler versions list
npx wrangler rollback <version-id>
```

Or run the workflow again from an earlier tag.

## Maintain

`npx wrangler deploy --dry-run` validates the configuration and lists the assets without
uploading anything. To update wrangler, set the new version in `package.json` (prefer a release
at least a week old) and regenerate the lockfile with
`npm install --package-lock-only --ignore-scripts`.
