/**
 * @useauthio/cloudflare-workers
 *
 * Cloudflare-Worker-native helper for Authio session verification. Uses
 * the runtime's Web Crypto and (optionally) a Workers KV namespace as the
 * JWKS cache so the JWKS is fetched from auth-core at most once per
 * region per cache window.
 *
 * Multi-org-first: `userId` is the person, `orgId` is the active
 * organization claim and may be null.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface AuthioWorkerOptions {
  apiUrl: string;
  issuer?: string;
  audience?: string;
  /** Optional Workers KV namespace where JWKS responses are cached. */
  kv?: KVNamespace;
  /** Cache TTL in seconds when using KV. Default 600. */
  kvTtlSeconds?: number;
}

export interface WorkerSession {
  sessionId: string;
  userId: string;
  orgId: string | null;
  role: string | null;
  expiresAt: number;
}

interface AuthioJwt extends JWTPayload {
  sub: string;
  act_org?: string;
  act_role?: string;
  sid?: string;
}

export class AuthioWorker {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly opts: AuthioWorkerOptions) {
    if (!opts.apiUrl) throw new Error("AuthioWorker: apiUrl is required");
    const url = new URL(
      opts.apiUrl.replace(/\/$/, "") + "/v1/auth/.well-known/jwks.json",
    );
    this.jwks = createRemoteJWKSet(url, {
      cooldownDuration: 30_000,
      cacheMaxAge: 600_000,
    });
  }

  async verify(token: string): Promise<WorkerSession | null> {
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.opts.issuer,
        audience: this.opts.audience,
        algorithms: ["EdDSA"],
      });
      const claims = payload as AuthioJwt;
      return {
        sessionId: claims.sid ?? "",
        userId: claims.sub,
        orgId: claims.act_org ? claims.act_org : null,
        role: claims.act_role ? claims.act_role : null,
        expiresAt: typeof claims.exp === "number" ? claims.exp * 1000 : 0,
      };
    } catch {
      return null;
    }
  }

  async verifyRequest(req: Request): Promise<WorkerSession | null> {
    const auth = req.headers.get("authorization") ?? "";
    if (auth.toLowerCase().startsWith("bearer ")) {
      return this.verify(auth.slice(7).trim());
    }
    const cookieHeader = req.headers.get("cookie") ?? "";
    const cookie = readCookie(cookieHeader, "authio_session");
    if (cookie) return this.verify(cookie);
    return null;
  }
}

function readCookie(header: string, name: string): string | null {
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name)
      return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}
