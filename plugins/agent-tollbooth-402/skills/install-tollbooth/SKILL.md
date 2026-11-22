---
name: install-tollbooth
description: >-
  Auto-detects Cloudflare Workers, Hono, Next.js App Router, or Express apps, previews a clean diff,
  and injects zero-dependency HTTP 402 middleware that takes x402 USDC payments straight to the
  developer's own payTo wallet, on Base Sepolia testnet first. Use when the user invokes /install-tollbooth or asks to monetize routes.
---

# Install Agent Tollbooth 402 Middleware

Wrap existing API or MCP routes with `@redcenterstudio/agent-tollbooth-edge` using `withTollbooth(...)` or `honoTollbooth(...)` with safe defaults (`priceUsd: 0.01`, `mode: "x402"`, the developer's own `payTo` wallet, `network: "eip155:84532"` for Base Sepolia testing).

## Step 1: Auto-Detect Framework & Protect Exempt Routes

1. Inspect dependencies and entrypoints to identify the framework (`wrangler.jsonc` for Cloudflare Workers, `hono`, `app/api/**/route.ts` for Next.js App Router, or `express`).
2. Keep infrastructure routes (`/health`, `/readyz`, `/webhook/*`, `OPTIONS` preflight, and auth callbacks) bypassable (`exemptRoutes`).
3. Always preview the proposed diff with the user before writing changes.

## Step 2: Middleware Patterns

### Cloudflare Workers

```ts
import { withTollbooth } from "@redcenterstudio/agent-tollbooth-edge";

export default withTollbooth(
  { priceUsd: 0.01, mode: "x402", payTo: "0xYourBaseUSDCWallet", network: "eip155:84532" },
  async (request, env, ctx) => {
    return Response.json({ ok: true, message: "Paid endpoint unlocked" });
  },
);
```

### Hono

```ts
import { Hono } from "hono";
import { honoTollbooth } from "@redcenterstudio/agent-tollbooth-edge";

const app = new Hono();
app.use("/api/*", honoTollbooth({ priceUsd: 0.01, mode: "x402", payTo: process.env.TOLLBOOTH_PAY_TO_ADDRESS, network: "eip155:84532" }));
```

### Next.js App Router (`app/api/lookup/route.ts`)

```ts
import { withTollbooth } from "@redcenterstudio/agent-tollbooth-edge";

const gated = withTollbooth(
  { priceUsd: 0.01, mode: "x402", payTo: process.env.TOLLBOOTH_PAY_TO_ADDRESS, network: "eip155:84532" },
  async (request) => Response.json({ ok: true, url: request.url }),
);

export const GET = (request: Request) => gated.fetch(request);
```

## Step 3: Verify Locally

Run TypeScript validation (`tsc --noEmit`) and `/test-agent` sandbox verification (`mode: "sandbox"`), then summarize status (`[PASS]`, `[402 CHALLENGE]`, `[200 SETTLED]`, or `[ACTION NEEDED]`).

## Going Live on Base Mainnet

The default path pays the developer's own `payTo` wallet in USDC. Red Center Studio never holds the money and takes 0% of payments. Test free on Base Sepolia (`eip155:84532`) first.

To settle on Base mainnet (`eip155:8453`), either run your own facilitator, or buy a Pro Pass ($39 USD once, one project; Agency Pass $79 for multiple projects) for hosted mainnet settlement through tollbooth.redcenterstudio.com. The pass unlocks on the developer account whose `payoutAddress` equals your `payTo` address, so register with POST /developer/register using that wallet as the payout address.
