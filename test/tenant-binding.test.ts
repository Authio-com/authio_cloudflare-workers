/**
 * Two properties, both inside workerd against a mocked JWKS.
 *
 * 1. Issuer and audience are ALWAYS checked. They used to be handed to
 *    jose as `undefined` whenever the caller omitted them, and jose
 *    skips a check for an undefined value — so with the documented
 *    usage (`{ apiUrl, kv }`) neither was ever actually verified.
 *
 * 2. A token minted for another Authio project is rejected. Every
 *    tenant shares one signing key, issuer and audience, so nothing
 *    else in the token tells them apart.
 */

import { beforeAll, describe, expect, it, vi } from "vitest";
import { AuthioWorker } from "../src/index";
import { API_URL, AUDIENCE, ISSUER, makeSigner, mockJwks, type Signer } from "./helpers";

/** Must match the SDK's built-in defaults. */
const PROD_ISSUER = "https://identity.authio.com";
const PROD_AUDIENCE = "authio";

let signer: Signer;

beforeAll(async () => {
  signer = await makeSigner();
  mockJwks(signer.jwks);
});

describe("AuthioWorker issuer/audience are always enforced", () => {
  it("rejects a foreign issuer when the caller configured neither", async () => {
    const auth = new AuthioWorker({ apiUrl: API_URL });
    // Signed by the right key, but issued by someone else. Before the
    // fix this verified, because issuer was undefined.
    const token = await signer.sign({ sub: "u1", issuer: "https://evil.test" });
    expect(await auth.verify(token)).toBeNull();
  });

  it("rejects a foreign audience when the caller configured neither", async () => {
    const auth = new AuthioWorker({ apiUrl: API_URL });
    const token = await signer.sign({
      sub: "u1",
      issuer: PROD_ISSUER,
      audience: "someone-else",
    });
    expect(await auth.verify(token)).toBeNull();
  });

  it("accepts a genuine production-issued token with no explicit config", async () => {
    const auth = new AuthioWorker({ apiUrl: API_URL });
    const token = await signer.sign({
      sub: "u1",
      sid: "s1",
      issuer: PROD_ISSUER,
      audience: PROD_AUDIENCE,
    });
    const session = await auth.verify(token);
    expect(session?.userId).toBe("u1");
  });

  it("refuses an explicitly empty issuer or audience rather than skipping", () => {
    expect(() => new AuthioWorker({ apiUrl: API_URL, issuer: "" })).toThrow(
      /issuer cannot be empty/,
    );
    expect(() => new AuthioWorker({ apiUrl: API_URL, audience: "" })).toThrow(
      /audience cannot be empty/,
    );
  });
});

describe("AuthioWorker tenant binding", () => {
  function worker(projectId?: string): AuthioWorker {
    return new AuthioWorker({
      apiUrl: API_URL,
      issuer: ISSUER,
      audience: AUDIENCE,
      projectId,
    });
  }

  it("rejects a token minted for another project", async () => {
    const token = await signer.sign({ sub: "user_attacker", projectId: "proj_attacker" });
    expect(await worker("proj_victim").verify(token)).toBeNull();
  });

  it("accepts a token minted for the configured project", async () => {
    const token = await signer.sign({
      sub: "user_real",
      sid: "s1",
      projectId: "proj_victim",
    });
    const session = await worker("proj_victim").verify(token);
    expect(session?.userId).toBe("user_real");
  });

  it("warns but accepts a token with no project_id claim", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const token = await signer.sign({ sub: "user_legacy", sid: "s1" });
    const session = await worker("proj_victim").verify(token);
    expect(session?.userId).toBe("user_legacy");
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/no project_id claim/));
    warn.mockRestore();
  });

  it("does not reject when no projectId is configured", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const token = await signer.sign({ sub: "user_x", projectId: "proj_anyone" });
    const session = await worker().verify(token);
    expect(session?.userId).toBe("user_x");
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/no projectId configured/));
    warn.mockRestore();
  });
});
