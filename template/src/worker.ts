/**
 * Deployable Authio forward-auth Worker.
 *
 * Configure via wrangler.toml vars + bindings (see the README next to
 * this file), deploy on a route in front of your app (proxy mode) or
 * point Traefik/nginx at it (endpoint mode). No other Authio SDK is
 * needed in the app behind it — identity arrives as headers.
 */

import { createForwardAuth, type ForwardAuth } from "@useauthio/cloudflare-workers";

export interface Env {
  /** auth-core origin, e.g. https://identity.authio.com */
  AUTHIO_API_URL: string;
  /** Your project id (proj_…) — enforces tenant binding. */
  AUTHIO_PROJECT_ID: string;
  /** Hosted Lobby origin. Omit for Authio's default. */
  AUTHIO_LOBBY_URL?: string;
  /** "proxy" (default) or "endpoint" (Traefik forwardAuth / nginx auth_request). */
  AUTHIO_MODE?: "proxy" | "endpoint";
  /** Comma-separated path prefixes served without auth (proxy mode). */
  AUTHIO_PUBLIC_PATHS?: string;
  /** whsec_… secret for the session.revoked denylist webhook (optional). */
  AUTHIO_WEBHOOK_SECRET?: string;
  /** KV for the revoked-session denylist (optional). */
  AUTHIO_DENYLIST?: KVNamespace;
  /** KV for JWKS caching (optional but recommended). */
  AUTHIO_JWKS_CACHE?: KVNamespace;
}

let forwardAuth: ForwardAuth | null = null;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    forwardAuth ??= createForwardAuth({
      apiUrl: env.AUTHIO_API_URL,
      projectId: env.AUTHIO_PROJECT_ID,
      lobbyUrl: env.AUTHIO_LOBBY_URL,
      mode: env.AUTHIO_MODE ?? "proxy",
      publicPaths: env.AUTHIO_PUBLIC_PATHS
        ? env.AUTHIO_PUBLIC_PATHS.split(",").map((p) => p.trim())
        : undefined,
      kv: env.AUTHIO_JWKS_CACHE,
      denylistKv: env.AUTHIO_DENYLIST,
      webhookSecret: env.AUTHIO_WEBHOOK_SECRET,
    });
    return forwardAuth.fetch(request);
  },
};
