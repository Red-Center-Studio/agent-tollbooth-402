---
name: test-agent
description: >-
  Runs an instant 30-second local HTTP 402 challenge, sandbox receipt signing or x402 simulation,
  200 OK retry, HTML checkout card check, and nonce replay rejection smoke test with zero API keys,
  zero crypto wallets, and zero Stripe setup. Use when the user invokes /test-agent.
---

# Test Agent — 30-Second Zero-Config HTTP 402 Smoke Test

Verify any gated endpoint locally in under 30 seconds with **zero API keys, zero crypto wallets, and zero Stripe setup** using `mode: "sandbox"` (or `mode: "mock"`).

## Option A: Instant 1-Command Sandbox Smoke Test

Run the bundled sandbox smoke runner from the plugin repository root:

```bash
npm run test:sandbox
```

This tests the complete loop entirely in memory (`createSandboxReceipt` + `createSandboxX402Header` + HTML content negotiation + nonce replay blocking) and outputs a scannable status table.

## Option B: Zero-Config Programmatic Smoke Test

```ts
import {
  createSandboxReceipt,
  decodePaymentHeader,
  withTollbooth,
} from "@redcenterstudio/agent-tollbooth-edge";

const app = withTollbooth({ priceUsd: 0.01, mode: "sandbox" }, () =>
  Response.json({ ok: true, secretData: "Unlocked!" }),
);

// 1. Unpaid request -> 402 Payment Required + actionable fix_hint
const unpaid = await app.fetch(new Request("https://sandbox.local/api/data"));
// unpaid.status === 402, JSON includes code: "MISSING_PAYMENT" and fix_hint

// 2. Sign a zero-config sandbox receipt & retry -> 200 OK + PAYMENT-RESPONSE
const token = await createSandboxReceipt({ priceUsd: 0.01 });
const paid = await app.fetch(
  new Request("https://sandbox.local/api/data", {
    headers: { Authorization: `Bearer ${token}` },
  }),
);
// paid.status === 200, decodePaymentHeader(paid.headers.get("PAYMENT-RESPONSE"))

// 3. Replay exact same token -> 402 NONCE_REPLAYED
const replay = await app.fetch(
  new Request("https://sandbox.local/api/data", {
    headers: { Authorization: `Bearer ${token}` },
  }),
);
// replay.status === 402, JSON includes code: "NONCE_REPLAYED" and fix_hint
```

## Full Vitest Suite

Run both the edge middleware and clearinghouse D1 worker test suites:

```bash
npm test
```

## Uniform Output Table Format

Report results to the user using these exact standardized status badges:

| Step | Status | Details |
| :--- | :--- | :--- |
| 1. Unpaid JSON request | `[402 CHALLENGE]` | `HTTP 402` + Base64 `PAYMENT-REQUIRED` + `code=MISSING_PAYMENT` + `fix_hint` |
| 2. Browser `Accept: text/html` | `[PASS]` | Self-contained Red Center Studio (`#24181a` Ironstone / `#d9622b` Ochre / `#f5efe6` Sand) 402 Checkout Card rendered |
| 3. Rail B Sandbox Receipt | `[200 SETTLED]` | `HTTP 200` + Base64 `PAYMENT-RESPONSE` (`<1ms` Web Crypto verification) |
| 4. Nonce Replay Attempt | `[PASS]` | `HTTP 402` blocked with `NONCE_REPLAYED` and plain-English `fix_hint` |
| 5. Rail A x402 V2 Flow | `[200 SETTLED]` | `/verify` -> handler -> `/settle` -> `HTTP 200` + `PAYMENT-RESPONSE` |
| Missing/expired configuration | `[ACTION NEEDED]` | Follow `fix_hint` in the JSON body or set `mode: "sandbox"` |
