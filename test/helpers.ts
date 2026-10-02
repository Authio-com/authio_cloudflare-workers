/**
 * Hermetic test fixtures: a generated Ed25519 signing key, a JWKS document
 * served via a stubbed global fetch, and a token minter that mirrors the
 * shape auth-core signs (EdDSA, `kid`, sub/act_org/act_role/sid claims).
 */

import { vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";

export const API_URL = "https://auth.test";
export const JWKS_PATH = "/v1/auth/.well-known/jwks.json";
export const ISSUER = "https://issuer.test";
export const AUDIENCE = "authio";
const KID = "test-key-1";

export interface Signer {
  jwks: { keys: JWK[] };
  sign(opts?: {
    sub?: string;
    actOrg?: string;
    actRole?: string;
    sid?: string;
    /** The tenant claim auth-core stamps on every user token. */
    projectId?: string;
    issuer?: string;
    audience?: string;
    expiresIn?: string;
    /** Absolute exp (seconds). Overrides expiresIn — used to mint expired tokens. */
    exp?: number;
    alg?: string;
  }): Promise<string>;
}

/** Generate an Ed25519 keypair + JWKS and return a token minter. */
export async function makeSigner(): Promise<Signer> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = "EdDSA";
  jwk.use = "sig";
  const jwks = { keys: [jwk] };

  return {
    jwks,
    async sign(opts = {}) {
      const builder = new SignJWT({
        ...(opts.actOrg ? { act_org: opts.actOrg } : {}),
        ...(opts.actRole ? { act_role: opts.actRole } : {}),
        ...(opts.sid ? { sid: opts.sid } : {}),
        ...(opts.projectId ? { project_id: opts.projectId } : {}),
      })
        .setProtectedHeader({ alg: opts.alg ?? "EdDSA", kid: KID })
        .setSubject(opts.sub ?? "user_123")
        .setIssuer(opts.issuer ?? ISSUER)
        .setAudience(opts.audience ?? AUDIENCE)
        .setIssuedAt();
      if (opts.exp !== undefined) builder.setExpirationTime(opts.exp);
      else builder.setExpirationTime(opts.expiresIn ?? "1h");
      return builder.sign(privateKey);
    },
  };
}

/**
 * Intercept the JWKS fetch the SDK makes from inside workerd and reply with
 * `jwks`. Every call is answered so the (cached) remote-JWKS set may refetch
 * freely; any other outbound request fails, keeping the suite off the network.
 */
export function mockJwks(jwks: { keys: JWK[] }): void {
  const jwksUrl = new URL(JWKS_PATH, API_URL).href;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== jwksUrl) throw new Error(`unexpected outbound fetch: ${url}`);
    return new Response(JSON.stringify(jwks), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
}

/**
 * Forge a tampered token whose signature decodes to DIFFERENT bytes.
 * Mutating the FIRST signature char always changes byte 0; flipping the LAST
 * char of a 64-byte EdDSA signature only touches padding bits, so it can
 * decode to the identical signature and still verify.
 */
export function tamper(token: string): string {
  const parts = token.split(".");
  const sig = parts[2]!;
  parts[2] = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
  return parts.join(".");
}
