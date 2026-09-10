/**
 * Forward-auth tests — the whole flow inside workerd with a mocked
 * auth-core: Lobby redirect + CSRF nonce, handoff-code exchange +
 * cookie mint, identity header passthrough (endpoint + proxy modes),
 * silent refresh, KV denylist, and the session.revoked webhook feed.
 */

import { fetchMock } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { createForwardAuth, type ForwardAuthOptions } from "../src/index";
import { API_URL, AUDIENCE, ISSUER, makeSigner, mockJwks, type Signer } from "./helpers";

const APP = "https://app.test";
const PROJECT = "proj_forward";

let signer: Signer;

beforeAll(async () => {
  signer = await makeSigner();
  mockJwks(signer.jwks);
});

function fakeKV(): KVNamespace & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    get: async (k: string) => store.get(k) ?? null,
    put: async (k: string, v: string) => {
      store.set(k, v);
    },
  } as unknown as KVNamespace & { store: Map<string, string> };
}

function fa(overrides: Partial<ForwardAuthOptions> = {}) {
  return createForwardAuth({
    apiUrl: API_URL,
    issuer: ISSUER,
    audience: AUDIENCE,
    projectId: PROJECT,
    lobbyUrl: "https://lobby.test",
    ...overrides,
  });
}

function getCookies(res: Response): string[] {
  return res.headers.getSetCookie();
}

async function signHmac(body: string, secret: string, t: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${t}.${body}`),
  );
  const hex = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `t=${t},v1=${hex}`;
}

describe("createForwardAuth: sign-in redirect", () => {
  it("sends an unauthenticated browser to the Lobby with a nonce cookie", async () => {
    const res = await fa().fetch(
      new Request(`${APP}/reports?week=3`, {
        headers: { accept: "text/html,application/xhtml+xml" },
      }),
    );
    expect(res.status).toBe(302);
    const target = new URL(res.headers.get("location")!);
    expect(target.origin).toBe("https://lobby.test");
    expect(target.searchParams.get("project_id")).toBe(PROJECT);
    expect(target.searchParams.get("redirect_uri")).toBe(`${APP}/__authio/callback`);
    expect(target.searchParams.get("next")).toBe("/reports?week=3");
    const nonce = target.searchParams.get("client_state_nonce");
    expect(nonce).toBeTruthy();
    const cookie = getCookies(res).find((c) => c.startsWith("authio_fa_nonce="));
    expect(cookie).toContain(nonce!);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
  });

  it("answers 401 (not a redirect) for non-browser callers", async () => {
    const res = await fa().fetch(
      new Request(`${APP}/api/data`, { headers: { accept: "application/json" } }),
    );
    expect(res.status).toBe(401);
  });
});

describe("createForwardAuth: callback", () => {
  it("refuses a callback whose nonce does not match the cookie (login CSRF)", async () => {
    const res = await fa().fetch(
      new Request(
        `${APP}/__authio/callback?code=hoc_1&client_state_nonce=evil`,
        { headers: { cookie: "authio_fa_nonce=good" } },
      ),
    );
    expect(res.status).toBe(403);
  });

  it("refuses a callback with no nonce cookie at all", async () => {
    const res = await fa().fetch(
      new Request(`${APP}/__authio/callback?code=hoc_1&client_state_nonce=n1`),
    );
    expect(res.status).toBe(403);
  });

  it("exchanges the handoff code, mints cookies, and bounces to next", async () => {
    const accessToken = await signer.sign({
      sub: "user_cb",
      sid: "sess_cb",
      projectId: PROJECT,
    });
    fetchMock
      .get(API_URL)
      .intercept({ method: "POST", path: "/v1/auth/session-handoff/exchange" })
      .reply(
        200,
        JSON.stringify({ access_token: accessToken, refresh_token: "rt_cb_1" }),
        { headers: { "content-type": "application/json" } },
      );

    const res = await fa().fetch(
      new Request(
        `${APP}/__authio/callback?code=hoc_1&client_state_nonce=n1&next=/dashboard`,
        { headers: { cookie: "authio_fa_nonce=n1" } },
      ),
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${APP}/dashboard`);
    const cookies = getCookies(res);
    expect(cookies.some((c) => c.startsWith(`authio_session=${accessToken}`))).toBe(true);
    expect(cookies.some((c) => c.startsWith("authio_refresh=rt_cb_1"))).toBe(true);
    // Nonce cookie is single-use.
    expect(cookies.some((c) => c.startsWith("authio_fa_nonce=;"))).toBe(true);
  });

  it("does not follow an absolute next target", async () => {
    const accessToken = await signer.sign({ sub: "user_cb2", projectId: PROJECT });
    fetchMock
      .get(API_URL)
      .intercept({ method: "POST", path: "/v1/auth/session-handoff/exchange" })
      .reply(200, JSON.stringify({ access_token: accessToken }), {
        headers: { "content-type": "application/json" },
      });
    const res = await fa().fetch(
      new Request(
        `${APP}/__authio/callback?code=hoc_2&client_state_nonce=n2&next=${encodeURIComponent("https://evil.test/phish")}`,
        { headers: { cookie: "authio_fa_nonce=n2" } },
      ),
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${APP}/`);
  });

  it("surfaces a failed exchange as 401", async () => {
    fetchMock
      .get(API_URL)
      .intercept({ method: "POST", path: "/v1/auth/session-handoff/exchange" })
      .reply(401, JSON.stringify({ code: "handoff_not_found" }), {
        headers: { "content-type": "application/json" },
      });
    const res = await fa().fetch(
      new Request(`${APP}/__authio/callback?code=hoc_bad&client_state_nonce=n3`, {
        headers: { cookie: "authio_fa_nonce=n3" },
      }),
    );
    expect(res.status).toBe(401);
  });
});

describe("createForwardAuth: endpoint mode (forwardAuth contract)", () => {
  it("answers 200 with identity headers for a valid session cookie", async () => {
    const token = await signer.sign({
      sub: "user_ep",
      actOrg: "org_ep",
      sid: "sess_ep",
      projectId: PROJECT,
    });
    const res = await fa({ mode: "endpoint" }).fetch(
      new Request(`${APP}/anything`, {
        headers: { cookie: `authio_session=${token}` },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("x-authio-user-id")).toBe("user_ep");
    expect(res.headers.get("x-authio-org-id")).toBe("org_ep");
  });

  it("uses X-Forwarded-* for the Lobby redirect target", async () => {
    const res = await fa({ mode: "endpoint" }).fetch(
      new Request("https://worker.internal/", {
        headers: {
          accept: "text/html",
          "x-forwarded-proto": "https",
          "x-forwarded-host": "app.customer.com",
          "x-forwarded-uri": "/team?tab=members",
        },
      }),
    );
    expect(res.status).toBe(302);
    const target = new URL(res.headers.get("location")!);
    expect(target.searchParams.get("redirect_uri")).toBe(
      "https://app.customer.com/__authio/callback",
    );
    expect(target.searchParams.get("next")).toBe("/team?tab=members");
  });

  it("silently refreshes from the refresh cookie when the access token is gone", async () => {
    const fresh = await signer.sign({
      sub: "user_rf",
      sid: "sess_rf",
      projectId: PROJECT,
    });
    fetchMock
      .get(API_URL)
      .intercept({ method: "POST", path: "/v1/auth/refresh" })
      .reply(
        200,
        JSON.stringify({ access_token: fresh, refresh_token: "rt_rotated" }),
        { headers: { "content-type": "application/json" } },
      );
    const res = await fa({ mode: "endpoint" }).fetch(
      new Request(`${APP}/page`, {
        headers: { cookie: "authio_refresh=rt_old" },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("x-authio-user-id")).toBe("user_rf");
    const cookies = getCookies(res);
    expect(cookies.some((c) => c.startsWith(`authio_session=${fresh}`))).toBe(true);
    expect(cookies.some((c) => c.startsWith("authio_refresh=rt_rotated"))).toBe(true);
  });
});

describe("createForwardAuth: proxy mode", () => {
  it("proxies verified requests to the origin", async () => {
    const token = await signer.sign({ sub: "user_px", projectId: PROJECT });
    fetchMock
      .get(APP)
      .intercept({ method: "GET", path: "/private" })
      .reply(200, "upstream says hi");
    const res = await fa().fetch(
      new Request(`${APP}/private`, {
        headers: { cookie: `authio_session=${token}` },
      }),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("upstream says hi");
  });

  it("rewrites the upstream origin when `upstream` is set (wrangler dev / internal host)", async () => {
    const token = await signer.sign({ sub: "user_up", projectId: PROJECT });
    fetchMock
      .get("http://origin.internal:3000")
      .intercept({ method: "GET", path: "/private?a=1" })
      .reply(200, "internal origin");
    const res = await fa({ upstream: "http://origin.internal:3000" }).fetch(
      new Request(`${APP}/private?a=1`, {
        headers: { cookie: `authio_session=${token}` },
      }),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("internal origin");
  });

  it("drops the Secure attribute when secureCookies is false", async () => {
    const res = await fa({ secureCookies: false }).fetch(
      new Request(`${APP}/page`, { headers: { accept: "text/html" } }),
    );
    const cookie = getCookies(res).find((c) => c.startsWith("authio_fa_nonce="));
    expect(cookie).toBeDefined();
    expect(cookie).not.toContain("Secure");
    expect(cookie).toContain("HttpOnly");
  });

  it("lets publicPaths through without a session", async () => {
    fetchMock
      .get(APP)
      .intercept({ method: "GET", path: "/healthz" })
      .reply(200, "ok");
    const res = await fa({ publicPaths: ["/healthz"] }).fetch(
      new Request(`${APP}/healthz`),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });
});

describe("createForwardAuth: KV denylist + webhook feed", () => {
  it("rejects a still-valid JWT whose sid was revoked", async () => {
    const kv = fakeKV();
    kv.store.set("authio:denylist:sess_dead", "1");
    const token = await signer.sign({
      sub: "user_dl",
      sid: "sess_dead",
      projectId: PROJECT,
    });
    const res = await fa({ mode: "endpoint", denylistKv: kv }).fetch(
      new Request(`${APP}/page`, {
        headers: { cookie: `authio_session=${token}`, accept: "application/json" },
      }),
    );
    expect(res.status).toBe(401);
  });

  it("feeds the denylist from a signed session.revoked webhook", async () => {
    const kv = fakeKV();
    const secret = "whsec_test";
    const body = JSON.stringify({
      action: "session.revoked",
      target_type: "session",
      target_id: "sess_hook",
    });
    const sig = await signHmac(body, secret, Math.floor(Date.now() / 1000));
    const res = await fa({
      denylistKv: kv,
      webhookSecret: secret,
    }).fetch(
      new Request(`${APP}/__authio/webhook`, {
        method: "POST",
        headers: { "authio-signature": sig },
        body,
      }),
    );
    expect(res.status).toBe(200);
    expect(kv.store.get("authio:denylist:sess_hook")).toBe("1");
  });

  it("rejects a webhook with a bad signature", async () => {
    const kv = fakeKV();
    const res = await fa({ denylistKv: kv, webhookSecret: "whsec_test" }).fetch(
      new Request(`${APP}/__authio/webhook`, {
        method: "POST",
        headers: { "authio-signature": "t=1,v1=deadbeef" },
        body: "{}",
      }),
    );
    expect(res.status).toBe(401);
    expect(kv.store.size).toBe(0);
  });
});
