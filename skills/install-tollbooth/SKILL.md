---
name: install-tollbooth
description: >-
  Auto-detects Cloudflare Workers, Hono, Next.js App Router, or Express apps, previews a clean diff,
  and injects zero-dependency dual-rail HTTP 402 middleware (x402 V2 + <1ms Red Center Fiat Agent
  Wallet verification). Use when the user invokes /install-tollbooth or asks to monetize routes.
---

# Install Agent Tollbooth 402 Middleware (1-Step Setup)

Wrap existing API or MCP routes with `@redcenterstudio/agent-tollbooth-edge` in a single `withTollbooth(...)` or `honoTollbooth(...)` call with safe defaults (`priceUsd: 0.01`, `mode: "hybrid"`).

## Step 1: Auto-Detect Framework & Review Guardrails

1. Review `rules/http-402-guardrails.md` before modifying any file.
2. Inspect `package.json` and entrypoints to detect the user's framework automatically:
   - **Cloudflare Workers (`wrangler.jsonc` / `export default { fetch }`)**: wrap the handler in `withTollbooth(...)`.
   - **Hono (`"hono"` in dependencies / `new Hono()`)**: register `app.use("/api/*", honoTollbooth(...))`.
   - **Next.js App Router (`app/api/**/route.ts`)**: wrap exported `GET`/`POST` Web Request handlers with `withTollbooth({ priceUsd: 0.01, mode: "hybrid" }, handler).fetch`.
   - **Express (`"express"` in dependencies)**: bridge Express `req`/`res` to a Web `Request` passed into `withTollbooth(...).fetch(webReq)` and write back status, headers, and body.
3. Confirm exempt routes (`/health`, `/readyz`, `/webhook/*`, `OPTIONS`) remain bypassable.

## Step 2: Preview Diff or Create Backup Before Editing

Before editing any existing route file:
- Show the user a concise unified diff (or create a `.bak` backup if modifying files in place) clearly highlighting the exact `withTollbooth(...)` wrapper being added.
- Never overwrite existing secret management, and never write real API keys or Stripe secrets into code.

## Step 3: 1-Step Code Injection Templates

### Cloudflare Workers (1-Step Default)

```ts
import { withTollbooth } from "@redcenterstudio/agent-tollbooth-edge";

export default withTollbooth(
  { priceUsd: 0.01, mode: "hybrid", payTo: process.env.TOLLBOOTH_PAY_TO_ADDRESS },
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
app.use("/api/*", honoTollbooth({ priceUsd: 0.01, mode: "hybrid" }));
```

### Next.js App Router (`app/api/lookup/route.ts`)

```ts
import { withTollbooth } from "@redcenterstudio/agent-tollbooth-edge";

const gated = withTollbooth(
  { priceUsd: 0.01, mode: "hybrid" },
  async (request) => Response.json({ ok: true, url: request.url }),
);

export const GET = (request: Request) => gated.fetch(request);
```

### Express Adapter

```ts
import express from "express";
import { withTollbooth } from "@redcenterstudio/agent-tollbooth-edge";

const gated = withTollbooth(
  { priceUsd: 0.01, mode: "hybrid" },
  async () => Response.json({ ok: true, data: "Paid Express payload" }),
);

const app = express();
app.all("/api/*", async (req, res) => {
  const webReq = new Request(`http://${req.headers.host ?? "localhost"}${req.originalUrl}`, {
    method: req.method,
    headers: req.headers as Record<string, string>,
  });
  const out = await gated.fetch(webReq);
  res.status(out.status);
  out.headers.forEach((v, k) => res.setHeader(k, v));
  res.send(await out.text());
});
```

## Step 4: Placeholder `.env.example` Setup

Ensure `.env.example` (never `.env`) documents placeholders only:
- `TOLLBOOTH_PAY_TO_ADDRESS=0x000000000000000000000000000000000000dEaD`
- `TOLLBOOTH_FACILITATOR_URL=https://tollbooth.redcenterstudio.com`
- `RECEIPT_SIGNING_SECRET=rcs_placeholder_hmac_secret_replace_in_production_32b`

## Step 5: Verify & Print Uniform Status Table

Run TypeScript validation (`npm.cmd run typecheck`) and `/test-agent` (`npm.cmd run test:sandbox`), then summarize using this exact table:

| Check | Status | Details |
| :--- | :--- | :--- |
| Framework detection & diff | `[PASS]` | Wrapped target routes with `withTollbooth({ priceUsd: 0.01, mode: "hybrid" })` |
| TypeScript & secret hygiene | `[PASS]` | `tsc --noEmit` passed; placeholders in `.env.example` only |
| Local 402 smoke test | `[200 SETTLED]` | Verified `[402 CHALLENGE]` -> payment -> `[200 SETTLED]` via `/test-agent` |
| Production keys (optional) | `[ACTION NEEDED]` | Set `TOLLBOOTH_PAY_TO_ADDRESS` & `RECEIPT_SIGNING_SECRET` before deploy |
