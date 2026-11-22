# Agent Tollbooth 402

**HTTP 402 monetization plugin (`x402 V2` USDC paid straight to your own wallet) for Cloudflare Workers, Hono, Next.js App Router, Express, and MCP servers.**

Built by [Red Center Studio](https://redcenterstudio.com) · [Portal & Documentation](https://tollbooth.redcenterstudio.com/pay) · [Privacy Policy](https://redcenterstudio.com/privacy/)

## Install

```bash
/plugin install agent-tollbooth-402 --marketplace Red-Center-Studio/agent-tollbooth-402
```

---

## Included Capabilities

- **`/agent-tollbooth-402:scan-routes`**: Inspects HTTP handlers and MCP tool routers across Cloudflare Workers, Hono, Next.js App Router, and Express to identify billable endpoints and propose per-call microdollar prices.
- **`/agent-tollbooth-402:install-tollbooth`**: Wraps target endpoints with `@redcenterstudio/agent-tollbooth-edge` supporting open Base USDC (`x402 V2`, `0%` fee), paid straight to your own wallet.
- **`/agent-tollbooth-402:test-agent`**: Validates HTTP `402` content negotiation (`application/json` headers + HTML payment card), `mode: "sandbox"` settlement, and nonce replay blocking.
- **Remote Streamable MCP (`https://tollbooth.redcenterstudio.com/mcp`)**: Exposes `tollbooth_pricing_quote`, `tollbooth_wallet_balance`, `tollbooth_verify_x402`, `tollbooth_create_topup_checkout`, `tollbooth_issue_receipt`, `tollbooth_register_wallet`, `tollbooth_ledger_history`, and `tollbooth_pass_status`.

---

## Pricing Tiers

| Tier | Fee on your payments | What You Get |
| :--- | :--- | :--- |
| **Free (DIY)** | **`0%` fee** | Connector, plugin and skills, edge middleware, hosted settlement on Base Sepolia testnet, and Base mainnet through your own facilitator. Agents pay your `payTo` wallet directly |
| **Tollbooth Pro Pass (`$39` once, one project)** | **`0%` fee** | Hosted Base mainnet settlement (no Coinbase account or facilitator server of your own), up to 10,000 hosted settlements a month and earnings history. Payments still go straight to your wallet |
| **Agency Pass (`$79` once)** | **`0%` fee** | The same as Pro for multiple projects and client sites |
| **Done-For-You Integration** | Custom (`From $499`) | Full custom MCP + HTTP 402 setup by [Red Center Studio](https://redcenterstudio.com/services/ai-tollbooth-setup/) |

---

## Support & Links

- Clearinghouse Portal & Live Demo: https://tollbooth.redcenterstudio.com/pay
- Source Repository: https://github.com/Red-Center-Studio/agent-tollbooth-402
- Privacy Policy: https://redcenterstudio.com/privacy/
- Support: hello@redcenterstudio.com
