---
name: scan-routes
description: >-
  Scans Cloudflare Workers, Hono, Next.js App Router, and MCP server routes to identify
  monetizable endpoints and propose dual-rail HTTP 402 pricing tiers. Use when the user
  invokes /scan-routes or asks to audit an API or MCP server for 402 monetization.
---

# Scan Routes & Propose HTTP 402 Pricing Tiers

Inspect the target repository to inventory every HTTP endpoint and MCP tool, separate exempt infrastructure routes from monetizable routes, and recommend concrete **x402 V2** (`exact` / `upto`) and **Red Center Fiat Agent Wallet** pricing tiers.

## Step 1: Discover Endpoints Across Supported Runtimes

Search the workspace for route and tool declarations without executing untrusted application code:

1. **Cloudflare Workers (`ExportedHandler.fetch`)**:
   - Inspect `wrangler.jsonc` / `wrangler.toml` to locate the `main` entrypoint.
   - Trace `url.pathname` checks, `switch (url.pathname)`, `URLPattern`, or `itty-router` handlers inside `fetch(request, env, ctx)`.
2. **Hono (`app.get`, `app.post`, `app.route`, `app.on`)**:
   - Search for `new Hono` instances and mounted sub-routers (`app.route("/v1", ...)`).
   - Record HTTP method, full resolved path, existing auth middleware, and response content type.
3. **Next.js App Router (`app/api/**/route.ts`)**:
   - Find `route.ts` / `route.js` files under `app/api/` or `src/app/api/` and extract exported HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`).
4. **MCP Servers (`tools/list`, `server.tool`, `setRequestHandler`)**:
   - Locate MCP tool registrations and JSON-RPC `POST /mcp` dispatchers.
   - Record each tool name, description, external API calls, or LLM token usage.

## Step 2: Classify Each Route & Assign Dual-Rail Pricing

Never propose `402` gating on `OPTIONS` preflight, `/health`, `/readyz`, `/webhook/*`, or OAuth callback routes. Classify every remaining endpoint into one of four buckets:

| Category | Signals in Code | Recommended Scheme | Suggested Price (USD / USDC) | Microdollars (`1 USD = 1,000,000`) |
| :--- | :--- | :--- | :--- | :--- |
| **Exempt** | `/health`, `/readyz`, `/webhook/*`, `OPTIONS`, auth callbacks | None (Bypass) | Free (`$0`) | `0` |
| **Lookup / Read** | Cached KV/D1 reads, DNS/WHOIS/metadata lookups, static queries | `exact` | `$0.001` – `$0.005` | `1,000` – `5,000` |
| **Compute / Mutation** | External API enrichment, PDF/HTML rendering, scraping, webhooks, write actions | `exact` | `$0.01` – `$0.10` | `10,000` – `100,000` |
| **Metered / LLM Stream** | Token generation, large payload transforms, variable-KB exports | `upto` *(Pro Pass)* | Ceiling `$0.05` – `$0.50` (bill per token/KB) | `50,000` – `500,000` |

For every monetized route, emit **both** rails in the recommendation:
- **Rail A (Open x402 V2 Standard):** Base64 `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` headers using USDC (`eip155:8453`, 6 decimals: `1 microdollar = 1 atomic unit`).
- **Rail B (Red Center Fiat Agent Wallet):** Sub-millisecond edge HMAC-SHA256 / Ed25519 receipt verification (`Authorization: Bearer rcs_receipt_...` or `X-Agent-Receipt`) with D1 nonce replay protection so Stripe-funded agents pay `$0.001–$0.10` without crypto wallets.

## Step 3: Present Tier & Net Payout Comparison

Include a concise route table and project developer net payouts across all 4 Red Center Studio tiers:

| Tier | Pricing | Fee Rate | Capabilities Unlocked |
| :--- | :--- | :--- | :--- |
| **Free / BYO x402 Mode** | `$0` | `0%` clearinghouse fee | Unlimited `/scan-routes`, local middleware injection, `/test-agent` simulator with any x402 facilitator (`exact` scheme). |
| **Hybrid Fiat + x402 Clearinghouse** | `$0/mo` | `7%` fee | Stripe-funded Fiat Agent Wallets (`rcs_receipt_...`) + automated Stripe Connect payouts via `tollbooth.redcenterstudio.com`. |
| **Tollbooth Pro Pass** | `$39` one-time (`$79` Agency) | `3%` fee | Drops clearinghouse fee to `3%`, unlocks `upto` dynamic per-token/per-KB metering, custom HTML 402 pages, and per-agent spend caps. |
| **Done-For-You Integration** | From `$399` | Custom | End-to-end custom MCP + HTTP 402 Tollbooth wrapping by Red Center Studio (`https://redcenterstudio.com`). |

## Step 4: Output Checklist & Next Action

End the scan report with:
1. Total routes inspected vs exempt vs monetizable.
2. Exact route-by-route table (Method, Path/Tool, Scheme, Suggested Price, Est. Net per 10k calls on Free vs Hybrid 7% vs Pro 3%).
3. Clear prompt offering to run `/install-tollbooth` (`skills/install-tollbooth/SKILL.md`) on the selected routes.
