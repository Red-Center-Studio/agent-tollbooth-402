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
