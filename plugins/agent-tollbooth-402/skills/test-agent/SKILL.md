---
name: test-agent
description: >-
  Runs a local HTTP 402 challenge, sandbox receipt verification, x402 simulation, 200 OK retry,
  HTML checkout card check, and nonce replay rejection check with zero external keys or wallets.
  Use when the user invokes /test-agent.
---

# Test Agent: Zero-Config HTTP 402 Verification

Verify any gated endpoint locally with **zero external configuration or wallets** using `mode: "sandbox"`.

## Sandbox Verification Flow

```ts
import {
  createSandboxReceipt,
  decodePaymentHeader,
  withTollbooth,
} from "@redcenterstudio/agent-tollbooth-edge";

const app = withTollbooth({ priceUsd: 0.01, mode: "sandbox" }, () =>
  Response.json({ ok: true, message: "Unlocked!" }),
);

// 1. Unpaid request -> HTTP 402 + actionable fix_hint
const unpaid = await app.fetch(new Request("https://sandbox.local/api/data"));

// 2. Retry with sandbox receipt -> HTTP 200 + PAYMENT-RESPONSE
const receiptToken = await createSandboxReceipt({ priceUsd: 0.01 });
const paid = await app.fetch(
  new Request("https://sandbox.local/api/data", {
    headers: { "X-Agent-Receipt": receiptToken },
  }),
);

// 3. Replaying the exact same receipt -> HTTP 402 NONCE_REPLAYED
const replay = await app.fetch(
  new Request("https://sandbox.local/api/data", {
    headers: { "X-Agent-Receipt": receiptToken },
  }),
);
```

## Uniform Output Table Format

| Step | Status | Details |
| :--- | :--- | :--- |
| 1. Unpaid JSON request | `[402 CHALLENGE]` | `HTTP 402` + Base64 `PAYMENT-REQUIRED` + `code=MISSING_PAYMENT` + `fix_hint` |
| 2. Browser `Accept: text/html` | `[PASS]` | Self-contained Red Center Studio `402` Checkout Card rendered |
| 3. Sandbox Receipt Retry | `[200 SETTLED]` | `HTTP 200` + Base64 `PAYMENT-RESPONSE` (local Web Crypto check) |
| 4. Nonce Replay Attempt | `[PASS]` | `HTTP 402` blocked with `NONCE_REPLAYED` and plain-English `fix_hint` |
| 5. Live Pricing / Wallet Tools | `[PASS]` | Use `tollbooth_pricing_quote` and `tollbooth_verify_x402` via MCP |
