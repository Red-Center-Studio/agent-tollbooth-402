---
name: install-tollbooth
description: >-
  Injects zero-dependency dual-rail HTTP 402 middleware (x402 V2 + <1ms Red Center Fiat Agent
  Wallet HMAC/Ed25519 receipt verification) into Cloudflare Workers, Hono apps, or MCP servers.
  Use when the user invokes /install-tollbooth or asks to add HTTP 402 paywalls to endpoints.
---

# Install Agent Tollbooth 402 Middleware

Wire dual-rail HTTP 402 monetization into a Cloudflare Worker, Hono application, or Streamable HTTP MCP server in under 60 seconds using `@redcenterstudio/agent-tollbooth-edge`.

## Step 1: Confirm Target & Guardrails

1. Review `rules/http-402-guardrails.md` before modifying any code.
2. Identify the target runtime:
   - **Cloudflare Worker** (`ExportedHandler.fetch`) -> use `withTollbooth(config, handler)`.
   - **Hono App** -> use `honoTollbooth(config)`.
   - **MCP Server (`/mcp`)** -> wrap `/mcp` or gate `tools/call` selectively while keeping `initialize` and `tools/list` free for agent discovery.
3. Confirm exempt routes (`/health`, `/readyz`, `/webhook/*`, `OPTIONS`) are listed in `exemptPaths`.

## Step 2: Install or Vendor the Zero-Dependency Middleware

- From npm (when published): install `@redcenterstudio/agent-tollbooth-edge` (0 runtime dependencies, pure Web Standard `Request`/`Response` + `crypto.subtle`).
- Inside this monorepo or offline workspace: depend on `"@redcenterstudio/agent-tollbooth-edge"` via workspace or copy `packages/edge-middleware/src/index.ts`.

## Step 3: Wire Dual-Rail Configuration

### Option A: Cloudflare Worker (`withTollbooth`)

```ts
import {
  D1NonceStore,
  usdToMicros,
  withTollbooth,
} from "@redcenterstudio/agent-tollbooth-edge";

interface Env {
  DB: D1Database;
  TOLLBOOTH_PAY_TO_ADDRESS: string;
  TOLLBOOTH_FACILITATOR_URL?: string;
  RECEIPT_SIGNING_SECRET?: string;
  RECEIPT_PUBLIC_KEY_ED25519?: string;
}

export default withTollbooth<Env>(
  (env) => ({
    payTo: env.TOLLBOOTH_PAY_TO_ADDRESS,
    facilitatorUrl:
      env.TOLLBOOTH_FACILITATOR_URL ?? "https://tollbooth.redcenterstudio.com",
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    proPass: false, // Set true with Tollbooth Pro Pass ($39 / $79 Agency) for `upto` + 3% fee
    exemptPaths: ["/health", "/readyz", "/webhook/*"],
    nonceStore: new D1NonceStore(env.DB),
    fiatWallet: {
      hmacSecret: env.RECEIPT_SIGNING_SECRET,
      ed25519PublicKey: env.RECEIPT_PUBLIC_KEY_ED25519,
      clearinghouseUrl: "https://tollbooth.redcenterstudio.com",
    },
    routes: [
      {
        pattern: "/api/v1/lookup",
        method: "GET",
        scheme: "exact",
        priceMicros: usdToMicros("0.005"), // $0.005 = 5,000 micros
        description: "Premium data lookup",
      },
    ],
  }),
  {
    async fetch(request, env, ctx) {
      return Response.json({ ok: true, data: "Paid response" });
    },
  },
);
```

### Option B: Hono Middleware (`honoTollbooth`)

```ts
import { Hono } from "hono";
import {
  MemoryNonceStore,
  honoTollbooth,
  usdToMicros,
} from "@redcenterstudio/agent-tollbooth-edge";

const app = new Hono();
const nonceStore = new MemoryNonceStore();

app.use(
  "/api/*",
  honoTollbooth({
    payTo: process.env.TOLLBOOTH_PAY_TO_ADDRESS ?? "0x000000000000000000000000000000000000dEaD",
    facilitatorUrl: process.env.TOLLBOOTH_FACILITATOR_URL ?? "https://tollbooth.redcenterstudio.com",
    nonceStore,
    fiatWallet: {
      hmacSecret: process.env.RECEIPT_SIGNING_SECRET,
    },
    routes: [
      {
        pattern: "/api/pro/summarize",
        method: "POST",
        scheme: "upto",
        priceMicros: usdToMicros("0.05"),
        proPass: true,
        meterUsage: async (_req, res, minAtomic, maxAtomic) => {
          const kb = BigInt(Math.max(1, Math.ceil((await res.clone().text()).length / 1024)));
          const metered = minAtomic + kb * 500n;
          return metered > maxAtomic ? maxAtomic : metered;
        },
      },
    ],
  }),
);
```

## Step 4: Configure Placeholder Env & D1 Nonce Table

1. Ensure `.env.example` (never `.env`) documents placeholders only:
   - `TOLLBOOTH_FACILITATOR_URL=https://tollbooth.redcenterstudio.com`
   - `TOLLBOOTH_PAY_TO_ADDRESS=0x000000000000000000000000000000000000dEaD`
   - `RECEIPT_SIGNING_SECRET=rcs_placeholder_hmac_secret_replace_in_production_32b`
2. If using `D1NonceStore`, confirm the D1 database contains the `used_nonces` table from `packages/clearinghouse-worker/migrations/0001_init.sql`.
3. **Never** write real API keys, Stripe secrets, or Cloudflare tokens into source or config files, and **never** run `wrangler deploy` automatically.

## Step 5: Verify Installation

1. Run TypeScript typechecking (`npm.cmd run typecheck` or `npx.cmd tsc --noEmit`).
2. Run `/test-agent` (`skills/test-agent/SKILL.md`) locally to verify `402` challenge -> signed payment -> `200 OK` -> replay rejection (`402`).
