# http-api-authorizer

A reusable AWS API Gateway v2 (HTTP API) Lambda `REQUEST` authorizer, published as `@vln-devsecops/http-api-authorizer-lambda`.

It's a small, growing set of independent authorization checks that can be combined as needed, rather than a fixed single-purpose authorizer. Today it supports:

1. **Origin verification (always on):** rejects any request whose `X-Origin-Verify` header doesn't match `ORIGIN_VERIFY_SECRET`. Intended to be paired with a CDN (e.g. CloudFront) that injects this header as an origin custom header, so the API only accepts traffic that actually transited the CDN — direct calls to the API's own endpoint are rejected.
2. **JWT verification (opt-in via `REQUIRE_JWT=true`):** additionally verifies the `Authorization: Bearer <token>` header as a JWT against a caller-supplied issuer's JWKS (via [`jose`](https://github.com/panva/jose)), checking `iss`/`aud`, and forwards the string-valued claims named in `JWT_FORWARD_CLAIMS` into the authorizer's `context` (readable downstream via `event.requestContext.authorizer.lambda`). Provider-agnostic — works against any standards-compliant OIDC issuer (Cognito, Auth0, etc.), not just one identity provider.

More checks (e.g. API keys) are expected to land here over time, selectable independently and usable in combination — this isn't meant to be "the origin+JWT authorizer" permanently, just what it supports so far.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `ORIGIN_VERIFY_SECRET` | always | Shared secret expected in the `X-Origin-Verify` request header. |
| `REQUIRE_JWT` | no | Set to `"true"` to also require and verify a bearer JWT. Defaults to origin-check-only. |
| `JWT_ISSUER_URL` | when `REQUIRE_JWT=true` | The token issuer's base URL; JWKS is fetched from `<issuer>/.well-known/jwks.json`. |
| `JWT_AUDIENCE` | when `REQUIRE_JWT=true` | Expected `aud` claim. |
| `JWT_FORWARD_CLAIMS` | when `REQUIRE_JWT=true` | Comma-separated list of claim names to copy (as strings) into the authorizer context. |

## Consuming this package

This package ships a single bundled entry point at `dist/handler.js` (handler export `handler`), built the same way `node-vlinder-auth/packages/lambda-src` bundles its own Lambdas — see the `terraform-modules/modules/aws/http_api_authorizer` module for the Terraform side (which installs this package at `terraform apply` time and zips `dist/`), and `terraform-modules/modules/aws/http_api`'s `lambda_authorizer` variable for wiring an authorizer built from this package (or any other Lambda) onto an HTTP API's routes.

## Development

```sh
npm install
npm run build   # typecheck + esbuild bundle to dist/
npm test
npm run lint
```
