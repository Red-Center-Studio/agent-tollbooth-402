# @redcenterstudio/agent-tollbooth-edge

HTTP 402 middleware for Cloudflare Workers, Hono and any Web `Request` handler. AI agents pay per call in USDC over x402 V2, straight to your own Base wallet. Red Center Studio takes 0% of payments and never holds your money.

## Install

```sh
npm install @redcenterstudio/agent-tollbooth-edge
```

## Quick start (Cloudflare Worker)

```ts
import { withTollbooth } from '@redcenterstudio/agent-tollbooth-edge';

export default withTollbooth(
  {
    priceUsd: 0.01,
    mode: 'x402',
    payTo: '0xYourBaseWallet',
    network: 'eip155:84532', // Base Sepolia: free testing
  },
  async () => Response.json({ ok: true }),
);
```

Hono:

```ts
import { Hono } from 'hono';
import { honoTollbooth } from '@redcenterstudio/agent-tollbooth-edge';

const app = new Hono();
app.use('/api/*', honoTollbooth({ priceUsd: 0.01, mode: 'x402', payTo: '0xYourBaseWallet', network: 'eip155:84532' }));
```

Unpaid requests get a `402 Payment Required` challenge. Paid requests pass through to your handler. `/health`, `/readyz` and `/webhook/*` stay free. Use `mode: 'sandbox'` for offline local tests.

Payment settles only after your handler succeeds: if it answers with a 5xx or throws, the agent is not charged and can retry with the same authorization.

## Price an MCP server per tool

MCP clients send every call to one URL, so price by tool instead of by route. The handshake (`initialize`, `tools/list`, notifications) stays free, so clients can connect and see your tools before paying.

```ts
export default withTollbooth(
  {
    mode: 'x402',
    payTo: '0xYourBaseWallet',
    network: 'eip155:84532',
    routes: [
      {
        pattern: '/mcp',
        method: 'POST',
        priceUsd: 0.05, // any tool not listed below
        mcpToolPricesUsd: { search: 0.001, analyze: 0.02, ping: 0 }, // 0 = free
      },
    ],
  },
  mcpHandler,
);
```

A request that cannot be read as JSON-RPC pays the route price, and a batch pays the sum of its tool calls.

## Going live on Base mainnet

Set `network: 'eip155:8453'`, then either:

- settle through your own x402 facilitator (`facilitatorUrl`), free, or
- settle through the hosted facilitator at tollbooth.redcenterstudio.com with a Pro Pass ($39 USD once, one project) or Agency Pass ($79 USD once). Register a developer account whose payout address is your `payTo`. No Coinbase developer account or facilitator server of your own needed.

Either way, payments go straight to your wallet.

## Links

- Setup guide and passes: https://tollbooth.redcenterstudio.com
- Claude Code plugin and source: https://github.com/Red-Center-Studio/agent-tollbooth-402
- Done-for-you setup: https://redcenterstudio.com/services/ai-tollbooth-setup/

MIT licensed.
