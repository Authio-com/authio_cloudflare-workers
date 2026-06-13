/**
 * Integration tests — full verify path inside workerd against a mocked JWKS.
 *
 * Signs real EdDSA tokens with a generated key, serves the matching JWKS via
 * the runtime's fetchMock, and drives @useauthio/cloudflare-workers exactly as
 * a deployed Worker would: valid tokens resolve to a typed session; tamper,
 * expiry, wrong-issuer, and wrong-audience are rejected (null). Proves the SDK
 * works on its target runtime with no network and no live credentials.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { AuthioWorker } from "../src/index";
import {
  API_URL,
  AUDIENCE,
  ISSUER,
  makeSigner,
  mockJwks,
  tamper,
  type Signer,
} from "./helpers";

let signer: Signer;

beforeAll(async () => {
  signer = await makeSigner();
  mockJwks(signer.jwks);
});

function worker(overrides: { issuer?: string; audience?: string } = {}): AuthioWorker {
  return new AuthioWorker({
    apiUrl: API_URL,
    issuer: overrides.issuer ?? ISSUER,
    audience: overrides.audience ?? AUDIENCE,
  });
}

describe("AuthioWorker (integration, workerd + mocked JWKS)", () => {
  it("verifies a valid token and maps the claims to a WorkerSession", async () => {
    const token = await signer.sign({
      sub: "user_abc",
      actOrg: "org_xyz",
      actRole: "admin",
      sid: "sess_1",
    });
    const session = await worker().verify(token);
    expect(session).not.toBeNull();
    expect(session!.userId).toBe("user_abc");
    expect(session!.orgId).toBe("org_xyz");
    expect(session!.role).toBe("admin");
    expect(session!.sessionId).toBe("sess_1");
    expect(session!.expiresAt).toBeGreaterThan(Date.now());
  });

  it("maps a user with no active org to orgId/role null", async () => {
    const token = await signer.sign({ sub: "user_solo" });
    const session = await worker().verify(token);
    expect(session).not.toBeNull();
    expect(session!.userId).toBe("user_solo");
    expect(session!.orgId).toBeNull();
    expect(session!.role).toBeNull();
  });

  it("rejects a tampered signature", async () => {
    const token = await signer.sign({ sub: "user_abc" });
    expect(await worker().verify(tamper(token))).toBeNull();
  });

  it("rejects an expired token", async () => {
    const token = await signer.sign({ sub: "user_abc", exp: Math.floor(Date.now() / 1000) - 60 });
    expect(await worker().verify(token)).toBeNull();
  });

  it("rejects a token with the wrong issuer", async () => {
    const token = await signer.sign({ sub: "user_abc", issuer: "https://evil.test" });
    expect(await worker().verify(token)).toBeNull();
    // And a correct token under a verifier that expects a different issuer.
    const good = await signer.sign({ sub: "user_abc" });
    expect(await worker({ issuer: "https://other.test" }).verify(good)).toBeNull();
  });

  it("rejects a token with the wrong audience", async () => {
    const token = await signer.sign({ sub: "user_abc", audience: "someone-else" });
    expect(await worker().verify(token)).toBeNull();
  });

  it("verifyRequest resolves a session from the Authorization header", async () => {
    const token = await signer.sign({ sub: "user_hdr", actOrg: "org_1", actRole: "member" });
    const req = new Request("https://app.test/api", {
      headers: { authorization: `Bearer ${token}` },
    });
    const session = await worker().verifyRequest(req);
    expect(session).not.toBeNull();
    expect(session!.userId).toBe("user_hdr");
    expect(session!.role).toBe("member");
  });

  it("verifyRequest resolves a session from the authio_session cookie", async () => {
    const token = await signer.sign({ sub: "user_cookie" });
    const req = new Request("https://app.test/api", {
      headers: { cookie: `authio_session=${token}` },
    });
    const session = await worker().verifyRequest(req);
    expect(session).not.toBeNull();
    expect(session!.userId).toBe("user_cookie");
  });
});
