# Authio forward-auth worker template

Put Authio sign-in in front of ANY app — no SDK in the app itself.
Unauthenticated browsers are redirected to Authio's hosted Lobby; after
sign-in the worker exchanges the single-use handoff code, sets HttpOnly
session cookies, and passes `X-Authio-User-Id` / `X-Authio-Org-Id` to
your upstream. Access tokens refresh silently.

## Setup

1. Copy this directory, `npm install`.
2. Fill in `wrangler.toml`: `AUTHIO_PROJECT_ID`, and either a `routes`
   pattern (proxy mode) or `AUTHIO_MODE = "endpoint"`.
3. Register the callback as a redirect URI for your project — in the
   dashboard, or declaratively:

   ```yaml
   # authio.yaml
   redirect_uris:
     - uri: https://app.example.com/__authio/callback
   ```

   ```sh
   authio apply
   ```

4. `npm run deploy`.

## Modes

- **Proxy (Cloudflare route)** — the worker fronts your app on a CF
  route. Verified requests are fetched through to your origin with the
  identity headers set.
- **Endpoint (`AUTHIO_MODE = "endpoint"`)** — implements the Traefik
  `forwardAuth` / nginx `auth_request` contract: `200` + identity
  headers when signed in, `302` to the Lobby otherwise. The proxy must
  forward `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri`
  (Traefik does by default).

## Optional: instant revocation

Bind a KV namespace as `AUTHIO_DENYLIST`, set the
`AUTHIO_WEBHOOK_SECRET` secret, and subscribe a webhook endpoint for
`session.revoked` pointing at `https://app.example.com/__authio/webhook`.
Revoked sessions then stop passing immediately instead of at JWT expiry.
