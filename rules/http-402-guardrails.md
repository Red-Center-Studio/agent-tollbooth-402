---
trigger: model_decision
description: "Apply these HTTP 402 payment, replay-protection, idempotency, integer-ledger, and agent spend-cap guardrails strictly when designing, implementing, modifying, or reviewing API or MCP endpoint monetization (x402 V2 or Red Center Fiat Agent Wallet)."
---

# HTTP 402 Monetization & Clearinghouse Guardrails

Apply these mandatory engineering rules whenever modifying HTTP 402 paywalls, x402 V2 middleware, MCP tool monetization, or Fiat Agent Wallet ledger code.

## 1. Mandatory Bypass Exemptions
- NEVER gate `OPTIONS` (CORS preflight), `/health`, `/readyz`, `/webhook/*` (Stripe or facilitator webhooks), or OAuth/auth callback endpoints with `402 Payment Required`.
- Always expose payment headers in CORS responses:
  `Access-Control-Expose-Headers: PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Tollbooth-Rail`.

## 2. Constant-Time Web Crypto Verification
- Always verify Rail B bearer receipts (`Authorization: Bearer rcs_receipt_...` or `X-Agent-Receipt`) using `crypto.subtle.verify` (HMAC-SHA256 or Ed25519) **before** trusting or parsing claims for authorization.
- Never compare API secrets, webhook secrets, or HMAC tags with `===` / `!==`; compare fixed-length SHA-256 HMAC digests in constant time.

## 3. Nonce Replay Protection & Short TTL
- Every Rail B receipt (`jti`) and Rail A x402 V2 authorization (`nonce`) MUST enforce a short expiration (`exp` / `validBefore`, recommended `<= 300s` for edge receipts and `<= 60s` for x402 challenges) with bounded clock skew (`<= 30s`, the middleware default `DEFAULT_CLOCK_SKEW_SECONDS`).
- Consume nonces atomically in `used_nonces` (`PRIMARY KEY` / `INSERT OR IGNORE ...` checking `changes === 1`) **before** executing metered/paid business logic. Reject duplicates with `402` (`nonce_replayed`) or `409` on `/settle`.

## 4. Downstream-Safe Idempotency
- Honor `Idempotency-Key` headers on clearinghouse `/settle` and `/wallet/issue-receipt` endpoints so client retries never double-charge or double-debit.
- Never call `/settle` (Rail A) or finalize a debit when the downstream route handler throws an error or returns HTTP `>= 500`. On Rail B, release the consumed nonce on `5xx` so the caller can safely retry within the receipt TTL.

## 5. Zero Floating-Point Money Math
- Store and compute all fiat USD amounts in **integer microdollars** (`$1.00 = 1_000_000`, `$0.001 = 1_000`) and all on-chain token amounts in `BigInt` atomic units (e.g., 6-decimal USDC `1_000 = $0.001`).
- Enforce exact integer reconciliation on every clearinghouse ledger row:
  `platform_fee_micros + developer_net_micros === gross_micros`.
- Never use IEEE-754 floats in SQLite `CHECK` constraints, balance debits, or fee splits.

## 6. Spend Caps, `upto` Ceilings, and Secrets Hygiene
- On metered `upto` routes (Tollbooth Pro Pass / Agency), clamp settled charges so `settledAmount <= authorizedAmount` and reject `upto` usage when `proPass` is not enabled.
- Enforce per-agent spend limits (`perAgentSpendCapMicros` at the edge and `daily_spend_cap_micros` on `agent_wallets`) before issuing receipts or admitting traffic.
- Never hardcode Stripe keys, signing secrets, or API tokens in source files, `wrangler.jsonc`, or tests outside local test fixtures; read exclusively from `env.*` or `process.env` and document placeholders in `.env.example`.
