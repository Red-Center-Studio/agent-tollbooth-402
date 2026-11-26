import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';
import { createSqliteD1, MIGRATION_SQL } from './sqlite-d1.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import worker, {
  calculateClearinghouseFee,
  signStripeWebhookPayload,
  type Env,
} from '../src/index.js';
import {
  D1NonceStore,
  encodePaymentHeader,
  withTollbooth,
  type X402PaymentSignature,
} from '@redcenterstudio/agent-tollbooth-edge';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const TEST_ENV_SECRETS = {
  RECEIPT_SIGNING_SECRET: 'rcs_test_hmac_secret_value_not_for_production',
  CLEARINGHOUSE_API_KEY: 'rcs_test_clearinghouse_api_key_placeholder',
  FACILITATOR_HMAC_SECRET: 'rcs_test_facilitator_hmac_secret_placeholder',
  STRIPE_CONNECT_WEBHOOK_SECRET: 'whsec_test_placeholder_signing_secret',
  // The fiat-rail flows below pay these fixture developers, so they stand in for studio-owned accounts.
  STUDIO_DEVELOPER_IDS: 'dev_hybrid, dev_pro,dev_free',
};

const mockCtx = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
} as unknown as ExecutionContext;

function seedFixtures(raw: DatabaseSync) {
  const now = Math.floor(Date.now() / 1000);
  const today = new Date(now * 1000).toISOString().slice(0, 10);

  raw
    .prepare(
      'INSERT INTO developers (id, email, name, tier, stripe_account_id, payout_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
    .run(
      'dev_hybrid',
      'hybrid@example.com',
      'Hybrid Dev',
      'hybrid',
      'acct_hybrid',
      '0x1111111111111111111111111111111111111111',
      now,
    );

  raw
    .prepare(
      'INSERT INTO developers (id, email, name, tier, stripe_account_id, payout_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
    .run(
      'dev_pro',
      'pro@example.com',
      'Pro Dev',
      'pro',
      'acct_pro',
      '0x2222222222222222222222222222222222222222',
      now,
    );

  raw
    .prepare(
      'INSERT INTO developers (id, email, name, tier, stripe_account_id, payout_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
    .run(
      'dev_free',
      'free@example.com',
      'Free Dev',
      'free',
      null,
      '0x3333333333333333333333333333333333333333',
      now,
    );

  raw
    .prepare(
      'INSERT INTO agent_wallets (id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, stripe_customer_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .run('wallet_main', 'Agent Alpha', 100_000, 30_000, 0, today, 'cus_alpha', 'active', now, now);

  raw
    .prepare(
      'INSERT INTO agent_wallets (id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, stripe_customer_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .run('wallet_frozen', 'Frozen Agent', 100_000, 100_000, 0, today, 'cus_frozen', 'frozen', now, now);

  raw
    .prepare(
      'INSERT INTO agent_wallets (id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, stripe_customer_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .run(
      'wallet_yesterday',
      'Rollover Agent',
      50_000,
      20_000,
      20_000,
      '2020-01-01',
      'cus_roll',
      'active',
      now,
      now,
    );
}

describe('Clearinghouse integer fee math & D1 schema constraints', () => {
  it('computes exact 7% Hybrid vs 3% Pro/Agency fee splits across sub-cent and dollar charges', () => {
    // $0.001 = 1,000 micros
    expect(calculateClearinghouseFee(1_000, 'hybrid', 'fiat_wallet')).toEqual({
      grossMicros: 1_000,
      feeBps: 700,
      platformFeeMicros: 70,
      developerNetMicros: 930,
    });
    expect(calculateClearinghouseFee(1_000, 'pro', 'fiat_wallet')).toEqual({
      grossMicros: 1_000,
      feeBps: 300,
      platformFeeMicros: 30,
      developerNetMicros: 970,
    });

    // $0.05 = 50,000 micros
    expect(calculateClearinghouseFee(50_000, 'hybrid', 'fiat_wallet')).toEqual({
      grossMicros: 50_000,
      feeBps: 700,
      platformFeeMicros: 3_500,
      developerNetMicros: 46_500,
    });
    expect(calculateClearinghouseFee(50_000, 'agency', 'fiat_wallet')).toEqual({
      grossMicros: 50_000,
      feeBps: 300,
      platformFeeMicros: 1_500,
      developerNetMicros: 48_500,
    });

    // $1.00 = 1,000,000 micros
    expect(calculateClearinghouseFee(1_000_000, 'hybrid', 'x402')).toEqual({
      grossMicros: 1_000_000,
      feeBps: 700,
      platformFeeMicros: 70_000,
      developerNetMicros: 930_000,
    });
    expect(calculateClearinghouseFee(1_000_000, 'pro', 'x402')).toEqual({
      grossMicros: 1_000_000,
      feeBps: 300,
      platformFeeMicros: 30_000,
      developerNetMicros: 970_000,
    });

    // Free BYO x402 = 0%
    expect(calculateClearinghouseFee(10_000, 'free', 'x402')).toEqual({
      grossMicros: 10_000,
      feeBps: 0,
      platformFeeMicros: 0,
      developerNetMicros: 10_000,
    });
  });

  it('enforces D1 CHECK constraints on ledger reconciliation and non-negative balances', () => {
    const { raw } = createSqliteD1(MIGRATION_SQL);
    seedFixtures(raw);

    expect(() =>
      raw
        .prepare(
          'INSERT INTO ledger_entries (id, idempotency_key, wallet_id, developer_id, route_id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        )
        .run('bad_1', 'idem_bad', 'wallet_main', 'dev_hybrid', null, 'fiat_wallet', 'charge', 1000, 700, 70, 999, 'tx', null, 1),
    ).toThrow();

    expect(() =>
      raw.prepare('UPDATE agent_wallets SET balance_micros = -1 WHERE id = ?').run('wallet_main'),
    ).toThrow();
  });
});

describe('Clearinghouse HTTP endpoints & end-to-end Dual-Rail flows', () => {
  let env: Env;
  let raw: DatabaseSync;

  beforeEach(() => {
    const sqlite = createSqliteD1(MIGRATION_SQL);
    raw = sqlite.raw;
    seedFixtures(raw);
    // The legacy flows below use mock signatures, which only the test sandbox accepts.
    env = {
      DB: sqlite.d1,
      ...TEST_ENV_SECRETS,
      ENVIRONMENT: 'test-sandbox',
    };
  });

  it('GET /health returns 200 without payment', async () => {
    const res = await worker.fetch(new Request('https://tollbooth.redcenterstudio.com/health'), env, mockCtx);
    expect(res.status).toBe(200);
    expect((await res.json()) as { status: string }).toMatchObject({ status: 'ok' });
  });

  it('issues Rail B receipts with 7% Hybrid vs 3% Pro fees, idempotency, spend caps, and end-to-end edge verification', async () => {
    // Unauthorized rejected
    const unauth = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        body: JSON.stringify({}),
      }),
      env,
      mockCtx,
    );
    expect(unauth.status).toBe(401);

    // Hybrid 7% fee on $0.01 (10,000 micros)
    const issueHybrid = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem_hybrid_1',
        },
        body: JSON.stringify({
          walletId: 'wallet_main',
          developerId: 'dev_hybrid',
          audience: 'https://api.example.com/api/search',
          method: 'GET',
          amountMicros: 10_000,
        }),
      }),
      env,
      mockCtx,
    );
    expect(issueHybrid.status).toBe(200);
    const body1 = (await issueHybrid.json()) as {
      receipt: string;
      remainingBalanceMicros: number;
      feeBreakdown: { feeBps: number; platformFeeMicros: number; developerNetMicros: number };
    };
    expect(body1.receipt).toMatch(/^rcs_receipt_hs256\./);
    expect(body1.remainingBalanceMicros).toBe(90_000);
    expect(body1.feeBreakdown).toEqual({
      grossMicros: 10_000,
      feeBps: 700,
      platformFeeMicros: 700,
      developerNetMicros: 9_300,
    });

    // Idempotent retry returns identical receipt and does NOT double-debit wallet
    const retryHybrid = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem_hybrid_1',
        },
        body: JSON.stringify({
          walletId: 'wallet_main',
          developerId: 'dev_hybrid',
          audience: 'https://api.example.com/api/search',
          method: 'GET',
          amountMicros: 10_000,
        }),
      }),
      env,
      mockCtx,
    );
    expect(retryHybrid.status).toBe(200);
    const retryBody = (await retryHybrid.json()) as { receipt: string; idempotentReplay: boolean };
    expect(retryBody.idempotentReplay).toBe(true);
    expect(retryBody.receipt).toBe(body1.receipt);

    // Hybrid attempting `upto` rejected (403 pro_pass_required_for_upto)
    const hybridUpto = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletId: 'wallet_main',
          developerId: 'dev_hybrid',
          audience: 'https://api.example.com/api/llm',
          amountMicros: 5_000,
          scheme: 'upto',
        }),
      }),
      env,
      mockCtx,
    );
    expect(hybridUpto.status).toBe(403);

    // Pro Pass 3% fee on $0.01 (10,000 micros) with `upto` allowed
    const issuePro = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem_pro_1',
        },
        body: JSON.stringify({
          walletId: 'wallet_main',
          developerId: 'dev_pro',
          audience: 'https://api.example.com/api/llm',
          amountMicros: 10_000,
          scheme: 'upto',
        }),
      }),
      env,
      mockCtx,
    );
    expect(issuePro.status).toBe(200);
    const bodyPro = (await issuePro.json()) as {
      remainingBalanceMicros: number;
      feeBreakdown: { feeBps: number; platformFeeMicros: number; developerNetMicros: number };
    };
    expect(bodyPro.remainingBalanceMicros).toBe(80_000);
    expect(bodyPro.feeBreakdown).toEqual({
      grossMicros: 10_000,
      feeBps: 300,
      platformFeeMicros: 300,
      developerNetMicros: 9_700,
    });

    // Daily spend cap (30,000 cap, 20,000 spent today -> 15,000 fails 402)
    const capExceeded = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletId: 'wallet_main',
          developerId: 'dev_pro',
          audience: 'https://api.example.com/api/llm',
          amountMicros: 15_000,
        }),
      }),
      env,
      mockCtx,
    );
    expect(capExceeded.status).toBe(402);
    expect(((await capExceeded.json()) as { error: string }).error).toBe('daily_spend_cap_exceeded');

    // New UTC day resets daily spend window cleanly
    const rolloverOk = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletId: 'wallet_yesterday',
          developerId: 'dev_pro',
          audience: 'https://api.example.com/api/llm',
          amountMicros: 15_000,
        }),
      }),
      env,
      mockCtx,
    );
    expect(rolloverOk.status).toBe(200);

    // Frozen wallet rejected
    const frozenRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletId: 'wallet_frozen',
          developerId: 'dev_pro',
          audience: 'https://api.example.com/api/llm',
          amountMicros: 1_000,
        }),
      }),
      env,
      mockCtx,
    );
    expect(frozenRes.status).toBe(403);

    // End-to-end cross-package check: verify issued receipt against edge-middleware + D1NonceStore
    const merchantWorker = withTollbooth(
      {
        payTo: '0x1111111111111111111111111111111111111111',
        nonceStore: new D1NonceStore(env.DB),
        fiatWallet: { hmacSecret: env.RECEIPT_SIGNING_SECRET },
        routes: [{ pattern: '/api/search', method: 'GET', priceMicros: 10_000 }],
      },
      {
        async fetch() {
          return Response.json({ results: ['red center'] });
        },
      },
    );

    const firstEdgeCall = await merchantWorker.fetch(
      new Request('https://api.example.com/api/search', {
        headers: { Authorization: `Bearer ${body1.receipt}` },
      }),
      {},
      mockCtx,
    );
    expect(firstEdgeCall.status).toBe(200);

    const replayEdgeCall = await merchantWorker.fetch(
      new Request('https://api.example.com/api/search', {
        headers: { Authorization: `Bearer ${body1.receipt}` },
      }),
      {},
      mockCtx,
    );
    expect(replayEdgeCall.status).toBe(402);
  });

  it('handles x402 /verify and /settle with replay protection and Pro vs Hybrid ledger splits', async () => {
    const now = Math.floor(Date.now() / 1000);
    const nonce = `0x${'12'.repeat(16)}`;
    const payToPro = '0x2222222222222222222222222222222222222222';

    const paymentPayload: X402PaymentSignature = {
      x402Version: 2,
      scheme: 'upto',
      network: 'eip155:8453',
      accepted: { scheme: 'upto', network: 'eip155:8453' },
      payload: {
        signature: '0x' + 'cd'.repeat(65),
        authorization: {
          from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          to: payToPro,
          value: '50000',
          validAfter: String(now - 5),
          validBefore: String(now + 120),
          nonce,
        },
      },
    };
    const paymentRequirements = {
      scheme: 'upto' as const,
      network: 'eip155:8453',
      amount: '10000',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo: payToPro,
      resource: 'https://api.example.com/api/llm',
      maxTimeoutSeconds: 60,
    };

    const verify1 = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements }),
      }),
      env,
      mockCtx,
    );
    expect(verify1.status).toBe(200);
    expect((await verify1.json()) as { isValid: boolean }).toEqual({
      isValid: true,
      invalidReason: null,
    });

    // Settle metered amount 20,000 <= 50,000 authorized for Pro developer (3% = 600 micros)
    const settle1 = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/settle', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem_settle_1',
        },
        body: JSON.stringify({
          x402Version: 2,
          paymentPayload,
          paymentRequirements,
          settleAmount: '20000',
        }),
      }),
      env,
      mockCtx,
    );
    expect(settle1.status).toBe(200);
    const settle1Json = (await settle1.json()) as {
      success: boolean;
      settledAmount: string;
      platformFeeMicros: number;
      developerNetMicros: number;
      txHash: string;
    };
    expect(settle1Json).toMatchObject({
      success: true,
      settledAmount: '20000',
      // Rail A pays the developer's wallet directly: no clearinghouse fee.
      platformFeeMicros: 0,
      developerNetMicros: 20_000,
    });
    expect(settle1Json.txHash).toMatch(/^0x[0-9a-f]{64}$/);

    // Replay same nonce with DIFFERENT Idempotency-Key -> 409 nonce_replayed
    const replaySettle = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/settle', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem_settle_replay',
        },
        body: JSON.stringify({
          x402Version: 2,
          paymentPayload,
          paymentRequirements,
          settleAmount: '20000',
        }),
      }),
      env,
      mockCtx,
    );
    expect(replaySettle.status).toBe(409);
    expect(((await replaySettle.json()) as { errorReason: string }).errorReason).toBe('nonce_replayed');

    // /verify now reports nonce_already_used
    const verifyAfter = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements }),
      }),
      env,
      mockCtx,
    );
    expect((await verifyAfter.json()) as { isValid: boolean; invalidReason: string; code: string; fix_hint: string }).toMatchObject({
      isValid: false,
      invalidReason: 'nonce_already_used',
      code: 'NONCE_REPLAYED',
    });

    // Edge-middleware integrated directly against clearinghouse worker over fetchImpl
    const edgeWithClearinghouse = withTollbooth(
      {
        payTo: '0x1111111111111111111111111111111111111111',
        facilitatorUrl: 'https://tollbooth.redcenterstudio.com',
        fetchImpl: (input, init) => worker.fetch(new Request(input, init), env, mockCtx),
        routes: [{ pattern: '/api/data', priceMicros: 10_000 }],
      },
      {
        async fetch() {
          return Response.json({ ok: true });
        },
      },
    );

    const e2eX402: X402PaymentSignature = {
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      accepted: { scheme: 'exact', network: 'eip155:8453' },
      payload: {
        signature: '0x' + 'ef'.repeat(65),
        authorization: {
          from: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          to: '0x1111111111111111111111111111111111111111',
          value: '10000',
          validAfter: String(now - 5),
          validBefore: String(now + 120),
          nonce: `0x${'99'.repeat(16)}`,
        },
      },
    };
    const e2eRes = await edgeWithClearinghouse.fetch(
      new Request('https://api.example.com/api/data', {
        headers: { 'PAYMENT-SIGNATURE': encodePaymentHeader(e2eX402) },
      }),
      {},
      mockCtx,
    );
    expect(e2eRes.status).toBe(200);
  });

  it('serves Streamable HTTP MCP JSON-RPC 2.0 on /mcp', async () => {
    const initRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      }),
      env,
      mockCtx,
    );
    expect(initRes.status).toBe(200);
    const initJson = (await initRes.json()) as {
      result: { serverInfo: { name: string }; protocolVersion: string };
    };
    expect(initJson.result.serverInfo.name).toBe('agent-tollbooth-402-clearinghouse');

    const listRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      }),
      env,
      mockCtx,
    );
    const listJson = (await listRes.json()) as {
      result: { tools: Array<{ name: string }> };
    };
    expect(listJson.result.tools.map((t) => t.name)).toEqual([
      'tollbooth_pricing_quote',
      'tollbooth_wallet_balance',
      'tollbooth_issue_receipt',
      'tollbooth_verify_x402',
      'tollbooth_create_topup_checkout',
      'tollbooth_register_wallet',
      'tollbooth_ledger_history',
      'tollbooth_pass_status',
    ]);

    const quoteRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: {
            name: 'tollbooth_pricing_quote',
            arguments: { priceMicros: 5000, callsPerMonth: 10000 },
          },
        }),
      }),
      env,
      mockCtx,
    );
    const quoteJson = (await quoteRes.json()) as {
      result: {
        structuredContent: {
          monthlyGrossMicros: number;
          x402: { platformFeeMicros: number; developerNetMicros: number };
          passes: { proPassUsd: number; agencyPassUsd: number };
        };
      };
    };
    expect(quoteJson.result.structuredContent.monthlyGrossMicros).toBe(50_000_000);
    expect(quoteJson.result.structuredContent.x402.platformFeeMicros).toBe(0);
    expect(quoteJson.result.structuredContent.x402.developerNetMicros).toBe(50_000_000);
    expect(quoteJson.result.structuredContent.passes).toMatchObject({ proPassUsd: 39, agencyPassUsd: 79 });

    // Authenticated wallet balance tool
    const balRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/mcp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: {
            name: 'tollbooth_wallet_balance',
            arguments: { walletId: 'wallet_main' },
          },
        }),
      }),
      env,
      mockCtx,
    );
    const balJson = (await balRes.json()) as {
      result: { structuredContent: { balanceMicros: number; status: string } };
    };
    expect(balJson.result.structuredContent).toMatchObject({
      balanceMicros: 100_000,
      status: 'active',
    });
  });

  it('prevents concurrent double-spends on atomic wallet debits and honors 30s x402 clock skew', async () => {
    const now = Math.floor(Date.now() / 1000);
    const today = new Date(now * 1000).toISOString().slice(0, 10);

    // Seed wallet with $0.10 (100,000 micros) balance & $0.20 daily cap
    raw
      .prepare(
        'INSERT INTO agent_wallets (id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, stripe_customer_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      )
      .run('wallet_race', 'Concurrent Agent', 100_000, 200_000, 0, today, 'cus_race', 'active', now, now);

    // Fire two simultaneous $0.08 (80,000 micros) debit requests -> total 160k > 100k balance
    const makeDebitReq = (idemKey: string) =>
      worker.fetch(
        new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': idemKey,
          },
          body: JSON.stringify({
            walletId: 'wallet_race',
            developerId: 'dev_pro',
            audience: 'https://api.example.com/api/race',
            amountMicros: 80_000,
          }),
        }),
        env,
        mockCtx,
      );

    const [resA, resB] = await Promise.all([makeDebitReq('race_1'), makeDebitReq('race_2')]);
    const statuses = [resA.status, resB.status].sort((a, b) => a - b);
    expect(statuses).toEqual([200, 402]);

    const failedResp = resA.status === 402 ? resA : resB;
    const failedBody = (await failedResp.json()) as { code: string; fix_hint: string };
    expect(failedBody.code).toBe('INSUFFICIENT_FUNDS');
    expect(failedBody.fix_hint.length).toBeGreaterThan(10);

    // Verify exact post-race balance in D1 is 20,000 micros (no negative or double debit)
    const walletRow = raw
      .prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?')
      .get('wallet_race') as { balance_micros: number };
    expect(walletRow.balance_micros).toBe(20_000);

    // Verify 30-second clock skew tolerance on /verify
    const skewedX402: X402PaymentSignature = {
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      accepted: { scheme: 'exact', network: 'eip155:8453' },
      payload: {
        signature: '0x' + 'ab'.repeat(65),
        authorization: {
          from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          to: '0x2222222222222222222222222222222222222222',
          value: '10000',
          validAfter: String(now + 20), // 20s ahead (within 30s skew)
          validBefore: String(now - 20), // 20s expired (within 30s skew)
          nonce: `0x${'77'.repeat(16)}`,
        },
      },
    };
    const skewVerify = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          x402Version: 2,
          paymentPayload: skewedX402,
          paymentRequirements: {
            scheme: 'exact',
            network: 'eip155:8453',
            amount: '10000',
            asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
            payTo: '0x2222222222222222222222222222222222222222',
          },
        }),
      }),
      env,
      mockCtx,
    );
    expect(skewVerify.status).toBe(200);
    expect((await skewVerify.json()) as { isValid: boolean }).toEqual({
      isValid: true,
      invalidReason: null,
    });
    expect(skewVerify.headers.get('Access-Control-Expose-Headers')).toContain('PAYMENT-REQUIRED');
  });

  it('handles Stripe webhook wallet top-ups, tier upgrades, signature rejection, /wallet/topup, /pay portal, and MCP checkout', async () => {
    const now = Math.floor(Date.now() / 1000);
    const webhookSecret = env.STRIPE_CONNECT_WEBHOOK_SECRET!;

    // 1) Valid Stripe checkout.session.completed wallet top-up ($10.00 = 10,000,000 micros)
    const topupEvent = JSON.stringify({
      id: 'evt_topup_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_topup_1',
          amount_total: 1000,
          metadata: {
            kind: 'wallet_topup',
            wallet_id: 'wallet_main',
          },
        },
      },
    });
    const topupSig = await signStripeWebhookPayload(topupEvent, webhookSecret, now);
    const topupRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/webhook/stripe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': topupSig,
        },
        body: topupEvent,
      }),
      env,
      mockCtx,
    );
    expect(topupRes.status).toBe(200);
    expect((await topupRes.json()) as { kind: string; creditedMicros: number }).toMatchObject({
      kind: 'wallet_topup',
      creditedMicros: 10_000_000,
    });

    const afterTopupWallet = raw
      .prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?')
      .get('wallet_main') as { balance_micros: number };
    expect(afterTopupWallet.balance_micros).toBe(10_100_000);

    // Replay same Stripe event -> idempotentReplay: true and NO double-credit
    const topupReplay = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/webhook/stripe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': topupSig,
        },
        body: topupEvent,
      }),
      env,
      mockCtx,
    );
    expect(topupReplay.status).toBe(200);
    expect((await topupReplay.json()) as { idempotentReplay: boolean }).toMatchObject({
      idempotentReplay: true,
    });
    const afterReplayWallet = raw
      .prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?')
      .get('wallet_main') as { balance_micros: number };
    expect(afterReplayWallet.balance_micros).toBe(10_100_000);

    // 2) Tampered signature and expired (>300s) webhook rejected with 400 INVALID_SIGNATURE + fix_hint
    const badSigRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/webhook/stripe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': `${topupSig.slice(0, -4)}0000`,
        },
        body: topupEvent,
      }),
      env,
      mockCtx,
    );
    expect(badSigRes.status).toBe(400);
    expect((await badSigRes.json()) as { code: string; fix_hint: string }).toMatchObject({
      code: 'INVALID_SIGNATURE',
    });

    const oldSig = await signStripeWebhookPayload(topupEvent, webhookSecret, now - 400);
    const expiredSigRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/webhook/stripe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': oldSig,
        },
        body: topupEvent,
      }),
      env,
      mockCtx,
    );
    expect(expiredSigRes.status).toBe(400);
    expect((await expiredSigRes.json()) as { error: string; code: string }).toMatchObject({
      error: 'stripe_signature_expired',
      code: 'INVALID_SIGNATURE',
    });

    // 3) Stripe Pro Pass tier upgrade drops dev_hybrid fee from 7% to 3%
    const upgradeEvent = JSON.stringify({
      id: 'evt_upgrade_pro_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_pro_1',
          amount_total: 3900,
          metadata: {
            kind: 'tier_upgrade',
            developer_id: 'dev_hybrid',
            target_tier: 'pro',
          },
        },
      },
    });
    const upgradeSig = await signStripeWebhookPayload(upgradeEvent, webhookSecret, now);
    const upgradeRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/webhook/stripe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': upgradeSig,
        },
        body: upgradeEvent,
      }),
      env,
      mockCtx,
    );
    expect(upgradeRes.status).toBe(200);
    expect((await upgradeRes.json()) as { tier: string }).toMatchObject({ tier: 'pro' });

    const receiptAfterUpgrade = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/issue-receipt', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CLEARINGHOUSE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletId: 'wallet_main',
          developerId: 'dev_hybrid',
          audience: 'https://api.example.com/api/pro',
          amountMicros: 10_000,
          scheme: 'upto',
        }),
      }),
      env,
      mockCtx,
    );
    expect(receiptAfterUpgrade.status).toBe(200);
    expect(
      (
        (await receiptAfterUpgrade.json()) as {
          feeBreakdown: { feeBps: number; platformFeeMicros: number };
        }
      ).feeBreakdown,
    ).toMatchObject({ feeBps: 300, platformFeeMicros: 300 });

    // 4) POST /wallet/topup sandbox checkout + GET /pay Industrial portal + MCP tool
    const checkoutRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/topup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletId: 'wallet_main', amountUsd: 10 }),
      }),
      env,
      mockCtx,
    );
    expect(checkoutRes.status).toBe(200);
    expect((await checkoutRes.json()) as { mode: string; amountMicros: number }).toMatchObject({
      mode: 'sandbox',
      amountMicros: 10_000_000,
    });

    const portalRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/pay'),
      env,
      mockCtx,
    );
    expect(portalRes.status).toBe(200);
    const portalHtml = await portalRes.text();
    expect(portalHtml).toContain('#24181a');
    expect(portalHtml).toContain('#d9622b');
    expect(portalHtml).toContain('#e3a23c');
    expect(portalHtml).toContain('#f5efe6');
    expect(portalHtml).toContain('Fund Agent Wallet');

    const mcpCheckoutRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 99,
          method: 'tools/call',
          params: {
            name: 'tollbooth_create_topup_checkout',
            arguments: { developerId: 'dev_hybrid', passTier: 'pro' },
          },
        }),
      }),
      env,
      mockCtx,
    );
    const mcpCheckoutJson = (await mcpCheckoutRes.json()) as {
      result: { structuredContent: { amountMicros: number; kind: string } };
    };
    expect(mcpCheckoutJson.result.structuredContent).toMatchObject({
      amountMicros: 39_000_000,
      kind: 'tier_upgrade',
    });

    // 5) Hosted Payment Link resolution when STRIPE_PAYMENT_LINK_* env vars are configured
    const envWithLinks: Env = {
      ...env,
      STRIPE_PAYMENT_LINK_TOPUP_10: 'https://buy.stripe.com/test_topup10',
      STRIPE_PAYMENT_LINK_PRO_PASS: 'https://buy.stripe.com/test_pro39',
      STRIPE_PAYMENT_LINK_AGENCY_PASS: 'https://buy.stripe.com/test_agency79',
      PAID_SALES_OPEN: 'true',
    };

    // Sales closed (the default): no payment link is shown or returned, and a checkout with no account id is refused.
    const envClosed: Env = { ...envWithLinks, PAID_SALES_OPEN: undefined };
    const closedPortalHtml = await (
      await worker.fetch(new Request('https://tollbooth.redcenterstudio.com/pay'), envClosed, mockCtx)
    ).text();
    expect(closedPortalHtml).not.toContain('buy.stripe.com');
    expect(closedPortalHtml).toContain('Opens soon');
    const closedTopupRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/topup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletId: 'wallet_main', amountUsd: 10 }),
      }),
      envClosed,
      mockCtx,
    );
    expect(closedTopupRes.status).toBe(409);
    const anonTopupRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/topup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amountUsd: 10 }),
      }),
      envWithLinks,
      mockCtx,
    );
    expect(anonTopupRes.status).toBe(400);

    const linkTopupRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/topup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletId: 'wallet_main', amountUsd: 10 }),
      }),
      envWithLinks,
      mockCtx,
    );
    expect(linkTopupRes.status).toBe(200);
    expect((await linkTopupRes.json()) as { mode: string; checkoutUrl: string }).toMatchObject({
      mode: 'payment_link',
      checkoutUrl: 'https://buy.stripe.com/test_topup10?client_reference_id=wallet_main',
    });

    const linkProRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/wallet/topup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ developerId: 'dev_hybrid', passTier: 'pro' }),
      }),
      envWithLinks,
      mockCtx,
    );
    expect((await linkProRes.json()) as { mode: string; checkoutUrl: string }).toMatchObject({
      mode: 'payment_link',
      checkoutUrl: 'https://buy.stripe.com/test_pro39?client_reference_id=dev_hybrid',
    });

    const portalWithLinks = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/pay'),
      envWithLinks,
      mockCtx,
    );
    const portalWithLinksHtml = await portalWithLinks.text();
    expect(portalWithLinksHtml).toContain('https://buy.stripe.com/test_topup10');
    expect(portalWithLinksHtml).toContain('https://buy.stripe.com/test_pro39');
    expect(portalWithLinksHtml).toContain('https://buy.stripe.com/test_agency79');
    expect(portalWithLinksHtml).toContain('Free (DIY)');
    expect(portalWithLinksHtml).toContain('DIY setup in 4 steps');
    expect(portalWithLinksHtml).not.toContain('7% fee');
    expect(portalWithLinksHtml).not.toContain('3% fee');
    expect(portalWithLinksHtml).toContain('From $499');
    expect(portalWithLinksHtml).toContain('@media (max-width: 640px)');

    // 6) GET /demo/402 renders mobile-ready HTML 402 checkout card & JSON challenge
    const demoHtmlRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/demo/402', {
        headers: { Accept: 'text/html' },
      }),
      envWithLinks,
      mockCtx,
    );
    expect(demoHtmlRes.status).toBe(402);
    expect(demoHtmlRes.headers.get('PAYMENT-REQUIRED')).toBeTruthy();
    const demoHtml = await demoHtmlRes.text();
    expect(demoHtml).toContain('@media (max-width: 640px)');
    expect(demoHtml).toContain('How AI agents pay');
    expect(demoHtml).not.toContain('Simulate');
    expect(demoHtml).not.toContain('Fund Agent Wallet');

    const demoJsonRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/demo/402', {
        headers: { Accept: 'application/json' },
      }),
      envWithLinks,
      mockCtx,
    );
    expect(demoJsonRes.status).toBe(402);
    expect((await demoJsonRes.json()) as { code: string; priceUsd: string }).toMatchObject({
      code: 'MISSING_PAYMENT',
      priceUsd: '0.01',
    });

    // 7) Organic SEO / GEO / AI Crawler discovery routes (/pay metadata, /llms.txt, /.well-known/mcp.json, /robots.txt, /sitemap.xml)
    expect(portalHtml).toContain('<script type="application/ld+json">');
    expect(portalHtml).toContain('SoftwareApplication');
    expect(portalHtml).toContain('FAQPage');
    expect(portalHtml).toContain('rel="canonical"');
    expect(portalHtml).toContain('property="og:image"');

    const llmsRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/llms.txt'),
      env,
      mockCtx,
    );
    expect(llmsRes.status).toBe(200);
    expect(llmsRes.headers.get('Content-Type')).toContain('text/plain');
    const llmsText = await llmsRes.text();
    expect(llmsText).toContain('/agent-tollbooth-402:scan-routes');
    expect(llmsText).toContain('https://tollbooth.redcenterstudio.com/mcp');
    expect(llmsText).toContain('tollbooth_pricing_quote');

    const wellKnownRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/.well-known/mcp.json'),
      env,
      mockCtx,
    );
    expect(wellKnownRes.status).toBe(200);
    const wellKnownJson = (await wellKnownRes.json()) as {
      name: string;
      transport: string;
      endpoint: string;
      tools: unknown[];
    };
    expect(wellKnownJson).toMatchObject({
      name: 'io.github.Red-Center-Studio/agent-tollbooth-402',
      transport: 'streamable-http',
      endpoint: 'https://tollbooth.redcenterstudio.com/mcp',
    });
    expect(wellKnownJson.tools).toHaveLength(8);

    const robotsRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/robots.txt'),
      env,
      mockCtx,
    );
    expect(robotsRes.status).toBe(200);
    expect(await robotsRes.text()).toContain('Sitemap: https://tollbooth.redcenterstudio.com/sitemap.xml');

    const sitemapRes = await worker.fetch(
      new Request('https://tollbooth.redcenterstudio.com/sitemap.xml'),
      env,
      mockCtx,
    );
    expect(sitemapRes.status).toBe(200);
    expect(sitemapRes.headers.get('Content-Type')).toContain('application/xml');
    const sitemapText = await sitemapRes.text();
    // Google indexes the root as the canonical home; /pay serves the same page and points to it.
    expect(sitemapText).toContain('<loc>https://tollbooth.redcenterstudio.com/</loc>');
    expect(sitemapText).not.toContain('<loc>https://tollbooth.redcenterstudio.com/pay</loc>');
    expect(sitemapText).toMatch(/<lastmod>\d{4}-\d{2}-\d{2}<\/lastmod>/);
    expect(portalHtml).toContain('<link rel="canonical" href="https://tollbooth.redcenterstudio.com/" />');
    const title = /<title>([^<]*)<\/title>/.exec(portalHtml)?.[1] ?? '';
    expect(title.length).toBeLessThanOrEqual(60);
    expect(portalHtml).toContain('"@type":"Organization"');
    expect(portalHtml).toContain('"@type":"WebSite"');

    const indexNow = await worker.fetch(new Request('https://tollbooth.redcenterstudio.com/bb248c92ca11417d89331a559758f87f.txt'), env, mockCtx);
    expect(indexNow.status).toBe(200);
    expect(await indexNow.text()).toBe('bb248c92ca11417d89331a559758f87f');

    // Crawlers, link checkers and uptime monitors send HEAD: same status and type as GET, no body.
    for (const p of ['/', '/pay', '/sitemap.xml', '/robots.txt', '/llms.txt']) {
      const head = await worker.fetch(new Request(`https://tollbooth.redcenterstudio.com${p}`, { method: 'HEAD' }), env, mockCtx);
      expect(head.status, `HEAD ${p}`).toBe(200);
      expect(await head.text()).toBe('');
    }
    // The demo answers 402 on purpose, so search engines cannot index it: it stays out of the sitemap.
    expect(sitemapText).not.toContain('https://tollbooth.redcenterstudio.com/demo/402');
    expect(sitemapText).toContain('https://tollbooth.redcenterstudio.com/llms.txt');

    for (const glamaPath of ['/.well-known/glama.json', '/mcp/.well-known/glama.json']) {
      const glamaClaimRes = await worker.fetch(
        new Request(`https://tollbooth.redcenterstudio.com${glamaPath}`),
        env,
        mockCtx,
      );
      expect(glamaClaimRes.status).toBe(200);
      expect((await glamaClaimRes.json()) as { $schema: string; claim: string }).toMatchObject({
        $schema: 'https://glama.ai/mcp/schemas/connector.json',
        claim: 'glama_claim_cyMUBGX_WjP7q4T153TkuepupDjd91bT',
      });
    }
  });
});
