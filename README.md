<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# @useauthio/cloudflare-workers

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Cloudflare Worker helper for Authio session verification. Uses Web Crypto + optional KV-based JWKS caching for maximum cold-start performance.

## Install

```bash
pnpm add @useauthio/cloudflare-workers
```

## Quick start

```ts
import { AuthioWorker } from "@useauthio/cloudflare-workers";

interface Env {
  AUTHIO_KV: KVNamespace;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const auth = new AuthioWorker({ apiUrl: "https://api.authio.com", kv: env.AUTHIO_KV });
    const session = await auth.verifyRequest(req);
    if (!session) return new Response("Unauthorized", { status: 401 });
    return Response.json({ userId: session.userId, orgId: session.orgId });
  },
};
```

## License

MIT
