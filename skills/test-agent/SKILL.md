---
name: test-agent
description: >-
  Runs a local HTTP 402 challenge, receipt signing or x402 signature simulation, 200 OK retry,
  and nonce replay rejection smoke test. Use when the user invokes /test-agent or wants to
  verify 402 tollbooth endpoints locally without hitting live blockchains or production Stripe.
---

# Test Agent — Local HTTP 402 Challenge & Retry Smoke Test

Validate a dual-rail HTTP 402 endpoint entirely in memory or against a local dev server without touching live blockchains, live Stripe accounts, or deployed Cloudflare infrastructure.

## Smoke Test Matrix

Every monetized endpoint MUST pass all four assertions:

1. **Unpaid Request -> `402 Payment Required` + Valid `PAYMENT-REQUIRED` Header**
   - Send request with no `PAYMENT-SIGNATURE`, `Authorization: Bearer rcs_receipt_...`, or `X-Agent-Receipt`.
   - Assert HTTP `402`.
   - Base64-decode the `PAYMENT-REQUIRED` header and verify JSON matches x402 V2:
     - `x402Version === 2`
     - `accepts` is a non-empty array containing `scheme` (`"exact"` or `"upto"`), `network`, `amount`, `asset`, `payTo`
     - `extensions.fiatAgentWallet` advertises `clearinghouseUrl` and accepted headers when Rail B is enabled.
2. **Rail B (Fiat Agent Wallet Receipt) -> `<1ms` Verification -> `200 OK`**
   - Sign a short-lived (`exp = now + 120`) test receipt via `signFiatReceipt(...)` from `@redcenterstudio/agent-tollbooth-edge` using a local test secret (`rcs_test_secret_not_for_prod`) or ephemeral Ed25519 key pair.
   - Retry request with `Authorization: Bearer rcs_receipt_hs256...` (or `X-Agent-Receipt`).
   - Assert HTTP `200` and Base64-decode `PAYMENT-RESPONSE` (`success === true`, `network === "rcs:fiat-wallet"`, `transaction === claims.jti`).
3. **Nonce Replay Attempt -> `402 Payment Required` (`nonce_replayed`)**
   - Re-send the **exact same** `rcs_receipt_...` header to the same endpoint.
   - Assert HTTP `402` and error reason `"nonce_replayed"`.
4. **Rail A (Open x402 V2 Signature) -> `/verify` -> `200 OK` -> `/settle`**
   - Encode an x402 V2 `PAYMENT-SIGNATURE` header with valid `validAfter`, `validBefore`, `to === payTo`, `value >= requiredAmount`, and unique `nonce`.
   - Mock or point `facilitatorUrl` to a local instance of `packages/clearinghouse-worker`.
   - Assert `/verify` returns `{ isValid: true }`, downstream handler runs once, `/settle` returns `{ success: true, txHash }`, and final HTTP response includes Base64 `PAYMENT-RESPONSE`.

## Running the Local Smoke Suites

From the repository root (`agent-tollbooth-402/`), run the Vitest suites covering both the edge middleware and the reference clearinghouse worker:

```bash
npm test
```

Or run targeted checks:

```bash
npx vitest run packages/edge-middleware/test/middleware.test.ts
npx vitest run packages/clearinghouse-worker/test/worker.test.ts
```

## Interpreting Failures

- **Missing `PAYMENT-REQUIRED` on `402`**: Verify the route pattern matches `routes[]` and is not shadowed by `exemptPaths`.
- **`nonce_replayed` on first attempt**: Ensure `MemoryNonceStore` or `D1NonceStore` receives a fresh `crypto.randomUUID()` `jti` / `nonce` per logical request.
- **`pro_pass_required_for_upto`**: Enable `proPass: true` on the middleware config or `tier = 'pro' | 'agency'` on the developer record in D1.
- **`5xx` Downstream Error**: Confirm neither `/settle` nor permanent wallet debit persisted so the agent can safely retry.
