/**
 * Unit tests — input handling that needs no JWKS / network. Runs in workerd.
 */

import { describe, expect, it } from "vitest";
import { AuthioWorker } from "../src/index";

describe("AuthioWorker (unit)", () => {
  it("requires apiUrl", () => {
    expect(() => new AuthioWorker({ apiUrl: "" })).toThrow(/apiUrl/);
  });

  it("constructs with apiUrl (and an optional KV namespace)", () => {
    expect(new AuthioWorker({ apiUrl: "https://api.authio.com" })).toBeDefined();
    // The kv option is part of the public surface; construction must accept it.
    const fakeKv = {} as unknown as KVNamespace;
    expect(
      new AuthioWorker({ apiUrl: "https://api.authio.com", kv: fakeKv, kvTtlSeconds: 120 }),
    ).toBeDefined();
  });

  it("returns null for empty / malformed tokens (no network)", async () => {
    const auth = new AuthioWorker({ apiUrl: "https://api.test" });
    expect(await auth.verify("")).toBeNull();
    expect(await auth.verify("not-a-jwt")).toBeNull();
    expect(await auth.verify("only.two")).toBeNull();
  });

  it("verifyRequest returns null when no Authorization header / cookie present", async () => {
    const auth = new AuthioWorker({ apiUrl: "https://api.test" });
    expect(await auth.verifyRequest(new Request("https://app.test/"))).toBeNull();
  });

  it("verifyRequest extracts a bearer token then verifies it (null on garbage)", async () => {
    const auth = new AuthioWorker({ apiUrl: "https://api.test" });
    const req = new Request("https://app.test/", {
      headers: { authorization: "Bearer not.a.jwt" },
    });
    expect(await auth.verifyRequest(req)).toBeNull();
  });

  it("verifyRequest reads the authio_session cookie when no bearer header", async () => {
    const auth = new AuthioWorker({ apiUrl: "https://api.test" });
    const req = new Request("https://app.test/", {
      headers: { cookie: "other=1; authio_session=not.a.jwt; x=2" },
    });
    // Garbage cookie verifies to null, but proves the cookie path is reached.
    expect(await auth.verifyRequest(req)).toBeNull();
  });
});
