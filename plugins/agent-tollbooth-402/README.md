# Agent Tollbooth 402

**Dual-rail HTTP 402 monetization plugin (`x402 V2` + `<1ms` Fiat Agent Wallet) for Cloudflare Workers, Hono, Next.js App Router, Express, and MCP servers.**

Built by [Red Center Studio](https://redcenterstudio.com) · [Portal & Documentation](https://tollbooth.redcenterstudio.com/pay) · [Privacy Policy](https://redcenterstudio.com/privacy/)

## Install

```bash
/plugin install agent-tollbooth-402 --marketplace Red-Center-Studio/agent-tollbooth-402
```

---

## Included Capabilities

- **`/agent-tollbooth-402:scan-routes`**: Inspects HTTP handlers and MCP tool routers across Cloudflare Workers, Hono, Next.js App Router, and Express to identify billable endpoints and propose per-call microdollar prices.
- **`/agent-tollbooth-402:install-tollbooth`**: Wraps target endpoints with `@redcenterstudio/agent-tollbooth-edge` supporting open Base USDC (`x402 V2`, `0%` fee) and Red Center Fiat Agent Wallet bearer receipts (`<1ms` edge checks).
- **`/agent-tollbooth-402:test-agent`**: Validates HTTP `402` content negotiation (`application/json` headers + HTML payment card), `mode: "sandbox"` settlement, and nonce replay blocking.
- **Remote Streamable MCP (`https://tollbooth.redcenterstudio.com/mcp`)**: Exposes `tollbooth_pricing_quote`, `tollbooth_wallet_balance`, `tollbooth_verify_x402`, `tollbooth_create_topup_checkout`, `tollbooth_issue_receipt`, `tollbooth_register_wallet`, `tollbooth_ledger_history`, and `tollbooth_pass_status`.

---

## Pricing Tiers

| Tier | Fee / Developer Net | What You Get |
| :--- | :--- | :--- |
| **Free / BYO Crypto (`x402 V2`)** | **`0%` fee** (`100%` net) | Self-serve `payTo` USDC wallet on Base (`eip155:8453`), unlimited `/agent-tollbooth-402:scan-routes` & sandbox testing |
| **Hybrid Clearinghouse** | **`7%` fee** (`93%` net) | Hosted Stripe checkout links (`$10+`) and `<1ms` prepaid Fiat Agent Wallets |
| **Tollbooth Pro (`$39`) / Agency (`$79`)** | **`3%` fee** (`97%` net) | Cuts clearinghouse fee to `3%`, adds `upto` dynamic metering and per-agent spend caps |
| **Done-For-You Integration** | Custom (`From $499`) | Full custom MCP + HTTP 402 setup by [Red Center Studio](https://redcenterstudio.com/services/ai-tollbooth-setup/) |

---

## Support & Links

- Clearinghouse Portal & Live Demo: https://tollbooth.redcenterstudio.com/pay
- Source Repository: https://github.com/Red-Center-Studio/agent-tollbooth-402
- Privacy Policy: https://redcenterstudio.com/privacy/
- Support: hello@redcenterstudio.com
