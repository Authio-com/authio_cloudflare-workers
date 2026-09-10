/**
 * Forward-auth for Cloudflare Workers.
 *
 * `createForwardAuth` turns a Worker into the auth layer in front of an
 * app that has no Authio SDK of its own: unauthenticated browsers are
 * redirected to Authio's hosted Lobby, the callback exchanges the
 * single-use session-handoff code server-side, first-party HttpOnly
 * cookies carry the session, and verified requests reach the upstream
 * with `X-Authio-User-Id` / `X-Authio-Org-Id` headers. Expired access
 * tokens are refreshed silently from the refresh cookie.
 *
 * Two modes:
 *
 * - `"proxy"` (default): deploy on a Cloudflare route in front of the
 *   app. Verified requests are fetched through to the origin with the
 *   identity headers attached.
 * - `"endpoint"`: the Traefik `forwardAuth` / nginx `auth_request`
 *   contract. Verified requests answer `200` with the identity headers
 *   for the proxy to copy upstream; unauthenticated ones answer `302`
 *   to the Lobby (Traefik forwards non-2xx responses, including their
 *   cookies, to the browser).
 *
 * Optional hardening: bind `denylistKv` and set `webhookSecret` to feed
 * a sid denylist from Authio's `session.revoked` webhook (Phase 1
 * signal), so revoked-but-unexpired JWTs stop passing immediately.
 */

import { AuthioWorker, type AuthioWorkerOptions, type WorkerSession } from "./index";

/** Authio's hosted sign-in Lobby. */
const DEFAULT_LOBBY_URL = "https://auth.authio.com/";
const DEFAULT_CALLBACK_PATH = "/__authio/callback";
const DEFAULT_WEBHOOK_PATH = "/__authio/webhook";
const NONCE_COOKIE = "authio_fa_nonce";
const SESSION_COOKIE = "authio_session";
const REFRESH_COOKIE = "authio_refresh";
/** 30 days — matches auth-core's refresh-token lifetime ceiling. */
const DEFAULT_REFRESH_MAX_AGE = 30 * 24 * 3600;
const DEFAULT_DENYLIST_PREFIX = "authio:denylist:";
/** Cover at least the access-token TTL; after that the JWT is expired anyway. */
const DEFAULT_DENYLIST_TTL_SECONDS = 3600;

export interface ForwardAuthOptions extends AuthioWorkerOptions {
  /**
   * Hosted Lobby origin browsers are sent to for sign-in. Defaults to
   * Authio's production Lobby; set it when using a custom auth domain.
   */
  lobbyUrl?: string;
  /**
   * Path this worker claims for the sign-in callback (must be a
   * registered redirect URI for the project — `authio apply` can
   * declare it). Default `/__authio/callback`.
   */
  callbackPath?: string;
  /** `"proxy"` (Cloudflare route, default) or `"endpoint"` (forwardAuth). */
  mode?: "proxy" | "endpoint";
  /**
   * Path prefixes served without authentication (health checks, public
   * assets). Only meaningful in proxy mode — an endpoint-mode proxy
   * should simply not send those routes here.
   */
  publicPaths?: string[];
  /**
   * Proxy-mode upstream origin override, e.g. `http://10.0.0.7:3000`.
   * By default the worker fetches the incoming URL unchanged (the
   * Cloudflare-route deployment, where that reaches the zone origin).
   * Set this when the app lives on a different hostname — including
   * `wrangler dev`, where same-URL fetches would loop back into the
   * worker itself.
   */
  upstream?: string;
  /**
   * Mark cookies `Secure` (default true). Turn off only for plain-HTTP
   * local development.
   */
  secureCookies?: boolean;
  /** Refresh-cookie Max-Age in seconds. Default 30 days. */
  refreshCookieMaxAge?: number;
  /** Upstream identity header names. */
  userIdHeader?: string;
  orgIdHeader?: string;
  /**
   * KV namespace holding revoked session ids. When set (with
   * `webhookSecret`), the worker also serves `webhookPath` as a
   * `session.revoked` webhook receiver that feeds the denylist.
   */
  denylistKv?: KVNamespace;
  /** Signing secret (`whsec_…`) for the denylist webhook receiver. */
  webhookSecret?: string;
  /** Webhook receiver path. Default `/__authio/webhook`. */
  webhookPath?: string;
  /** KV key prefix for denylisted sids. */
  denylistPrefix?: string;
  /** Seconds a revoked sid stays denylisted. Default 3600. */
  denylistTtlSeconds?: number;
  /** Extra headers on every auth-core call (e.g. test-routing headers). */
  apiHeaders?: Record<string, string>;
}

export interface ForwardAuth {
  /** The Worker fetch handler. */
  fetch(request: Request): Promise<Response>;
  /** The underlying verifier, for advanced composition. */
  worker: AuthioWorker;
}

interface SessionEnvelope {
  access_token?: string;
  refresh_token?: string;
}

export function createForwardAuth(opts: ForwardAuthOptions): ForwardAuth {
  const worker = new AuthioWorker(opts);
  const apiUrl = opts.apiUrl.replace(/\/$/, "");
  const lobbyUrl = (opts.lobbyUrl ?? DEFAULT_LOBBY_URL).replace(/\/$/, "");
  const callbackPath = opts.callbackPath ?? DEFAULT_CALLBACK_PATH;
  const webhookPath = opts.webhookPath ?? DEFAULT_WEBHOOK_PATH;
  const mode = opts.mode ?? "proxy";
  const userIdHeader = opts.userIdHeader ?? "X-Authio-User-Id";
  const orgIdHeader = opts.orgIdHeader ?? "X-Authio-Org-Id";
  const refreshMaxAge = opts.refreshCookieMaxAge ?? DEFAULT_REFRESH_MAX_AGE;
  const denylistPrefix = opts.denylistPrefix ?? DEFAULT_DENYLIST_PREFIX;
  const denylistTtl = opts.denylistTtlSeconds ?? DEFAULT_DENYLIST_TTL_SECONDS;
  const upstream = opts.upstream?.replace(/\/$/, "");
  const secureAttr = opts.secureCookies === false ? "" : " Secure;";

  function apiHeaders(): Record<string, string> {
    return { "content-type": "application/json", ...(opts.apiHeaders ?? {}) };
  }

  /**
   * The origin browsers see. Endpoint mode sits behind a proxy, so the
   * forwarded scheme/host (which Traefik/nginx always set) win over the
   * worker's own URL.
   */
  function publicOrigin(req: Request): string {
    const url = new URL(req.url);
    const proto = req.headers.get("x-forwarded-proto") ?? url.protocol.replace(":", "");
    const host = req.headers.get("x-forwarded-host") ?? url.host;
    return `${proto}://${host}`;
  }

  /** Requested path+query, for round-tripping through the Lobby `next`. */
  function requestedPath(req: Request): string {
    if (mode === "endpoint") {
      const uri = req.headers.get("x-forwarded-uri");
      if (uri && uri.startsWith("/")) return uri;
    }
    const url = new URL(req.url);
    return url.pathname + url.search;
  }

  /** Only same-origin path targets survive; anything else falls back to "/". */
  function safeNext(raw: string | null): string {
    if (!raw || !raw.startsWith("/") || raw.startsWith("//")) return "/";
    return raw;
  }

  function setCookie(
    headers: Headers,
    name: string,
    value: string,
    maxAge: number,
  ): void {
    headers.append(
      "Set-Cookie",
      `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly;${secureAttr} SameSite=Lax; Max-Age=${maxAge}`,
    );
  }

  function clearCookie(headers: Headers, name: string): void {
    headers.append(
      "Set-Cookie",
      `${name}=; Path=/; HttpOnly;${secureAttr} SameSite=Lax; Max-Age=0`,
    );
  }

  function readCookie(req: Request, name: string): string | null {
    const header = req.headers.get("cookie") ?? "";
    for (const part of header.split(";")) {
      const eq = part.indexOf("=");
      if (eq < 0) continue;
      if (part.slice(0, eq).trim() === name) {
        return decodeURIComponent(part.slice(eq + 1).trim());
      }
    }
    return null;
  }

  /** 302 to the Lobby with a fresh CSRF nonce cookie. */
  function redirectToLobby(req: Request): Response {
    const origin = publicOrigin(req);
    const nonce = crypto.randomUUID();
    const target = new URL(lobbyUrl + "/");
    if (opts.projectId) target.searchParams.set("project_id", opts.projectId);
    target.searchParams.set("redirect_uri", `${origin}${callbackPath}`);
    target.searchParams.set("client_state_nonce", nonce);
    const next = requestedPath(req);
    if (next !== "/") target.searchParams.set("next", next);
    const headers = new Headers({ Location: target.toString() });
    // SameSite=Lax so the cookie survives the cross-site GET coming
    // back from the Lobby; HttpOnly so page JS can't read it.
    setCookie(headers, NONCE_COOKIE, nonce, 600);
    return new Response(null, { status: 302, headers });
  }

  /** Exchange the handoff code, mint cookies, bounce to `next`. */
  async function handleCallback(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const code = url.searchParams.get("code");
    const urlNonce =
      url.searchParams.get("client_state_nonce") ?? url.searchParams.get("state");
    const cookieNonce = readCookie(req, NONCE_COOKIE);
    if (!code) return new Response("missing code", { status: 400 });
    // Login-CSRF gate: the callback must carry the nonce this browser
    // was given when the sign-in started, and it must match the cookie.
    if (!urlNonce || !cookieNonce || urlNonce !== cookieNonce) {
      return new Response("state mismatch", { status: 403 });
    }
    const origin = publicOrigin(req);
    let envelope: SessionEnvelope;
    try {
      const res = await fetch(`${apiUrl}/v1/auth/session-handoff/exchange`, {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({
          code,
          redirect_uri: `${origin}${callbackPath}`,
          client_state_nonce: urlNonce,
        }),
      });
      if (!res.ok) return new Response("exchange failed", { status: 401 });
      envelope = (await res.json().catch(() => ({}))) as SessionEnvelope;
    } catch {
      return new Response("exchange unreachable", { status: 502 });
    }
    if (!envelope.access_token) {
      return new Response("exchange failed", { status: 401 });
    }
    // Verify before persisting: proves the token came from Authio's
    // signer (and yields exp for the cookie TTL).
    const session = await worker.verify(envelope.access_token);
    if (!session) return new Response("invalid token", { status: 401 });

    const headers = new Headers({
      Location: `${origin}${safeNext(url.searchParams.get("next"))}`,
    });
    const accessTtl = Math.max(
      60,
      Math.floor((session.expiresAt - Date.now()) / 1000),
    );
    setCookie(headers, SESSION_COOKIE, envelope.access_token, accessTtl);
    if (envelope.refresh_token) {
      setCookie(headers, REFRESH_COOKIE, envelope.refresh_token, refreshMaxAge);
    }
    clearCookie(headers, NONCE_COOKIE);
    return new Response(null, { status: 302, headers });
  }

  /** Silent refresh from the refresh cookie. Null when it can't. */
  async function tryRefresh(
    req: Request,
  ): Promise<{ session: WorkerSession; envelope: SessionEnvelope } | null> {
    const refreshToken = readCookie(req, REFRESH_COOKIE);
    if (!refreshToken) return null;
    let envelope: SessionEnvelope;
    try {
      const res = await fetch(`${apiUrl}/v1/auth/refresh`, {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!res.ok) return null;
      envelope = (await res.json().catch(() => ({}))) as SessionEnvelope;
    } catch {
      return null;
    }
    if (!envelope.access_token) return null;
    const session = await worker.verify(envelope.access_token);
    if (!session) return null;
    return { session, envelope };
  }

  async function denylisted(session: WorkerSession): Promise<boolean> {
    if (!opts.denylistKv || !session.sessionId) return false;
    try {
      return (
        (await opts.denylistKv.get(denylistPrefix + session.sessionId)) !== null
      );
    } catch {
      // KV outage must not lock every user out; JWT verification and
      // expiry still stand.
      return false;
    }
  }

  /** `session.revoked` webhook receiver feeding the KV denylist. */
  async function handleWebhook(req: Request): Promise<Response> {
    if (!opts.denylistKv || !opts.webhookSecret) {
      return new Response("not found", { status: 404 });
    }
    if (req.method !== "POST") {
      return new Response("method not allowed", { status: 405 });
    }
    const body = await req.text();
    const ok = await verifySignature(
      body,
      req.headers.get("authio-signature"),
      opts.webhookSecret,
    );
    if (!ok) {
      return Response.json({ error: "invalid_signature" }, { status: 401 });
    }
    let event: {
      action?: string;
      target_type?: string;
      target_id?: string;
    };
    try {
      event = JSON.parse(body) as typeof event;
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }
    if (
      event.action === "session.revoked" &&
      event.target_type === "session" &&
      typeof event.target_id === "string" &&
      event.target_id
    ) {
      await opts.denylistKv.put(denylistPrefix + event.target_id, "1", {
        expirationTtl: denylistTtl,
      });
    }
    return Response.json({ received: true });
  }

  /** Answer for a verified request, per mode. */
  async function pass(
    req: Request,
    session: WorkerSession,
    freshEnvelope: SessionEnvelope | null,
  ): Promise<Response> {
    const mint = (headers: Headers) => {
      if (!freshEnvelope?.access_token) return;
      const ttl = Math.max(
        60,
        Math.floor((session.expiresAt - Date.now()) / 1000),
      );
      setCookie(headers, SESSION_COOKIE, freshEnvelope.access_token, ttl);
      if (freshEnvelope.refresh_token) {
        setCookie(headers, REFRESH_COOKIE, freshEnvelope.refresh_token, refreshMaxAge);
      }
    };

    if (mode === "endpoint") {
      const headers = new Headers();
      headers.set(userIdHeader, session.userId);
      if (session.orgId) headers.set(orgIdHeader, session.orgId);
      mint(headers);
      return new Response(null, { status: 200, headers });
    }

    const inUrl = new URL(req.url);
    const target = upstream
      ? `${upstream}${inUrl.pathname}${inUrl.search}`
      : req.url;
    const upstreamReq = new Request(target, req);
    upstreamReq.headers.set(userIdHeader, session.userId);
    if (session.orgId) upstreamReq.headers.set(orgIdHeader, session.orgId);
    else upstreamReq.headers.delete(orgIdHeader);
    const res = await fetch(upstreamReq);
    if (!freshEnvelope) return res;
    const withCookies = new Response(res.body, res);
    mint(withCookies.headers);
    return withCookies;
  }

  async function handle(request: Request): Promise<Response> {
    const path =
      mode === "endpoint"
        ? new URL(publicOrigin(request) + requestedPath(request)).pathname
        : new URL(request.url).pathname;

    if (path === callbackPath) return handleCallback(request);
    if (path === webhookPath) return handleWebhook(request);
    if (
      mode === "proxy" &&
      (opts.publicPaths ?? []).some((p) => path.startsWith(p))
    ) {
      if (!upstream) return fetch(request);
      const u = new URL(request.url);
      return fetch(new Request(`${upstream}${u.pathname}${u.search}`, request));
    }

    let session = await worker.verifyRequest(request);
    if (session && (await denylisted(session))) session = null;
    if (session) return pass(request, session, null);

    const refreshed = await tryRefresh(request);
    if (refreshed && !(await denylisted(refreshed.session))) {
      return pass(request, refreshed.session, refreshed.envelope);
    }

    // Only browsers can complete a Lobby sign-in; API callers get 401.
    const accepts = request.headers.get("accept") ?? "";
    if (request.method === "GET" && accepts.includes("text/html")) {
      return redirectToLobby(request);
    }
    const headers = new Headers();
    clearCookie(headers, SESSION_COOKIE);
    return new Response("unauthorized", { status: 401, headers });
  }

  return { fetch: handle, worker };
}

// ---------------------------------------------------------------------
// Webhook signature (Authio-Signature: t=<unix>,v1=<hex hmac-sha256>)
// — mirrors authio_webhooks/internal/signing/hmac.go.
// ---------------------------------------------------------------------

const encoder = new TextEncoder();

function timingSafeEqualHex(aHex: string, bHex: string): boolean {
  if (aHex.length !== bHex.length) return false;
  let diff = 0;
  for (let i = 0; i < aHex.length; i++) {
    diff |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  }
  return diff === 0;
}

async function verifySignature(
  body: string,
  header: string | null,
  secret: string,
  toleranceMs = 300_000,
): Promise<boolean> {
  if (!header || !secret) return false;
  let t = "";
  let v1 = "";
  for (const part of header.split(",")) {
    const p = part.trim();
    if (p.startsWith("t=")) t = p.slice(2);
    else if (p.startsWith("v1=")) v1 = p.slice(3);
  }
  if (!t || !v1) return false;
  const ts = Number(t);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Date.now() - ts * 1000) > toleranceMs) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(`${t}.${body}`));
  const hex = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return timingSafeEqualHex(hex, v1.toLowerCase());
}
