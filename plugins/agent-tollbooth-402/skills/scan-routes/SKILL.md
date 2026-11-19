---
name: scan-routes
description: >-
  Scans Cloudflare Workers, Hono, Next.js App Router, Express, and MCP server routes to identify
  monetizable endpoints and propose dual-rail HTTP 402 pricing tiers. Use when the user
  invokes /scan-routes or asks to audit an API or MCP server for 402 monetization.
---

# Scan Routes & Propose HTTP 402 Pricing Tiers

Inspect the target repository to inventory every HTTP endpoint and MCP tool, separate exempt infrastructure routes from monetizable routes, and present uniform pricing recommendations.

## Step 1: Discover Endpoints Across Supported Frameworks

Search the workspace without executing untrusted application code:

1. **Cloudflare Workers (`ExportedHandler.fetch`)**:
   - Inspect `wrangler.jsonc` / `wrangler.toml` to locate the `main` entrypoint.
   - Trace `url.pathname` checks, `switch (url.pathname)`, `URLPattern`, or `itty-router` handlers inside `fetch(request, env, ctx)`.
2. **Hono (`app.get`, `app.post`, `app.route`, `app.on`)**:
   - Search for `new Hono` instances and mounted sub-routers (`app.route("/v1", ...)`).
3. **Next.js App Router (`app/api/**/route.ts`)**:
   - Find `route.ts` / `route.js` files under `app/api/` or `src/app/api/` and extract exported HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`).
4. **Express (`express()`, `router.get/post`)**:
   - Search for `express()` or `express.Router()` route definitions.
5. **MCP Servers (`tools/list`, `server.tool`, `setRequestHandler`)**:
   - Locate MCP tool registrations and `POST /mcp` JSON-RPC dispatchers.

## Step 2: Classify Each Route & Assign Dual-Rail Pricing

Never propose `402` gating on `OPTIONS` preflight, `/health`, `/readyz`, `/webhook/*`, or OAuth callback routes. Classify every remaining endpoint:

| Category | Signals in Code | Recommended Scheme | Suggested Price | Microdollars (`1 USD = 1,000,000`) |
| :--- | :--- | :--- | :--- | :--- |
| **Exempt** | `/health`, `/readyz`, `/webhook/*`, `OPTIONS`, auth callbacks | None (Bypass) | Free (`$0`) | `0` |
| **Lookup / Read** | Cached KV/D1 reads, DNS/WHOIS/metadata lookups, static queries | `exact` | `$0.001` – `$0.005` | `1,000` – `5,000` |
| **Compute / Mutation** | External API enrichment, PDF/HTML rendering, scraping, webhooks, write actions | `exact` | `$0.01` – `$0.10` | `10,000` – `100,000` |
| **Metered / LLM Stream** | Token generation, large payload transforms, variable-KB exports | `upto` *(Pro Pass)* | Ceiling `$0.05` – `$0.50` | `50,000` – `500,000` |

## Step 3: Present Tier & Net Payout Comparison

| Tier | Pricing | Clearinghouse Fee | Capabilities Unlocked |
| :--- | :--- | :--- | :--- |
| **Free / BYO x402 Mode** | `$0` | `0%` | Unlimited `/scan-routes`, local middleware injection, `/test-agent` simulator with any x402 facilitator (`exact`). |
| **Hybrid Fiat + x402 Clearinghouse** | `$0/mo` | `7%` | Stripe-funded Fiat Agent Wallets (`rcs_receipt_...` `<1ms` verification) + automated Stripe Connect payouts (`tollbooth.redcenterstudio.com`). |
| **Tollbooth Pro Pass** | `$39` one-time (`$79` Agency) | `3%` | Drops fee to `3%`, unlocks `upto` dynamic metering, custom HTML 402 pages, and per-agent spend caps. |
| **Done-For-You Integration** | From `$499` | Custom | End-to-end custom MCP + HTTP 402 Tollbooth wrapping by Red Center Studio (`https://redcenterstudio.com`). |

## Step 4: Uniform Markdown Output Format

Always conclude with a scannable status table using the standardized badges (`[PASS]`, `[ACTION NEEDED]`, `[402 CHALLENGE]`, `[200 SETTLED]`):

| Route / Tool | Status | Recommended Mode / Scheme | Suggested Price | Action / Next Step |
| :--- | :--- | :--- | :--- | :--- |
| `GET /health` | `[PASS]` | Exempt (Bypass) | `$0` | Keep unauthenticated and ungated |
| `GET /api/lookup` | `[ACTION NEEDED]` | `[402 CHALLENGE]` (`exact`) | `$0.01` | Run `/install-tollbooth` (`priceUsd: 0.01`) |
| `POST /api/generate` | `[ACTION NEEDED]` | `[402 CHALLENGE]` (`upto` Pro) | `$0.05` ceiling | Run `/install-tollbooth` with `proPass: true` |

Offer to run `/install-tollbooth` on the selected `[ACTION NEEDED]` routes.
