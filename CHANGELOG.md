# Changelog

All notable changes to `@useauthio/cloudflare-workers` are documented here. This
project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-09-10

### Added

- `createForwardAuth` — forward-auth in front of any app: Lobby
  redirect with a CSRF nonce cookie, session-handoff code exchange at
  the callback, HttpOnly session/refresh cookies, silent refresh, and
  `X-Authio-User-Id` / `X-Authio-Org-Id` headers upstream. Two modes:
  Cloudflare route (full proxy) and Traefik `forwardAuth` / nginx
  `auth_request` endpoint. Optional KV denylist fed by a built-in
  `session.revoked` webhook receiver (HMAC-verified).
- `template/` — a deployable wrangler project wiring `createForwardAuth`
  from env vars and KV bindings.

## [0.2.0] — 2026-06-12

### Changed
- **Renamed npm package `@authio/cloudflare-workers` → `@useauthio/cloudflare-workers`.** The
  original `@authio` scope could not be claimed on npm, so every Authio
  SDK now publishes under the organization scope `@useauthio`. Install
  with `npm install @useauthio/cloudflare-workers` and update imports accordingly.
  The old `@authio/cloudflare-workers` name is retired; releases below this entry were
  published (or prepared) under the old name and are kept for history.

