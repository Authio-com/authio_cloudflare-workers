import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

/**
 * Tests run inside REAL workerd (the same runtime Cloudflare runs in
 * production) via @cloudflare/vitest-pool-workers — not a Node shim. This is
 * the only way to prove @useauthio/cloudflare-workers behaves on its target
 * runtime (Web Crypto, the Workers fetch, no Node built-ins).
 *
 * The suite is hermetic: the JWKS fetch is intercepted with the runtime's
 * built-in `fetchMock` (cloudflare:test) and tokens are signed in-test with a
 * generated Ed25519 key, so it needs no network and no live credentials —
 * keeping the package green on every CI run.
 */
export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        miniflare: {
          compatibilityDate: "2024-11-12",
          compatibilityFlags: ["nodejs_compat"],
        },
      },
    },
  },
});
