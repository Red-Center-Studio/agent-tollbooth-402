import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import worker, { calculateClearinghouseFee, type Env } from '../src/index.js';
import {
  D1NonceStore,
  encodePaymentHeader,
  withTollbooth,
  type X402PaymentSignature,
} from '@redcenterstudio/agent-tollbooth-edge';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATION_SQL = readFileSync(
  path.resolve(__dirname, '../migrations/0001_init.sql'),
  'utf8',
);

const TEST_ENV_SECRETS = {
  RECEIPT_SIGNING_SECRET: 'rcs_test_hmac_secret_value_not_for_production',
  CLEARINGHOUSE_API_KEY: 'rcs_test_clearinghouse_api_key_placeholder',
  FACILITATOR_HMAC_SECRET: 'rcs_test_facilitator_hmac_secret_placeholder',
};

const mockCtx = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
} as unknown as ExecutionContext;

function createSqliteD1(migrationSql: string): { d1: D1Database; raw: DatabaseSync } {
  const raw = new DatabaseSync(':memory:');
  raw.exec('PRAGMA foreign_keys = ON;');
  raw.exec(migrationSql);

  const buildStmt = (query: string) => {
    let bound: Array<string | number | bigint | Uint8Array | null> = [];
    const stmt: D1PreparedStatement = {
      bind(...values: unknown[]) {
        bound = values.map((v) =>
          v === undefined ? null : (v as string | number | bigint | Uint8Array | null),
        );
        return stmt;
      },
      async first<T = unknown>(colName?: string): Promise<T | null> {
        const row = raw.prepare(query).get(...bound) as Record<string, unknown> | undefined;
        if (!row) {
          return null;
        }
        if (colName !== undefined) {
          return (row[colName] ?? null) as T | null;
        }
        return row as unknown as T;
      },
      async run<T = Record<string, unknown>>() {
        const info = raw.prepare(query).run(...bound);
        return {
          results: [] as T[],
          success: true,
          meta: {
            duration: 0,
            size_after: 0,
            rows_read: 0,
            rows_written: Number(info.changes),
            last_row_id: Number(info.lastInsertRowid),
            changed_db: Number(info.changes) > 0,
            changes: Number(info.changes),
          },
        };
      },
      async all<T = Record<string, unknown>>() {
        const rows = raw.prepare(query).all(...bound) as T[];
        return {
          results: rows,
          success: true,
          meta: {
            duration: 0,
            size_after: 0,
            rows_read: rows.length,
            rows_written: 0,
            last_row_id: 0,
            changed_db: false,
            changes: 0,
          },
        };
      },
      raw: (async <T = unknown[]>(options?: { columnNames?: boolean }) => {
        const rows = raw.prepare(query).all(...bound) as Array<Record<string, unknown>>;
        const values = rows.map((r) => Object.values(r)) as T[];
        if (options?.columnNames) {
          const cols = rows[0] ? Object.keys(rows[0]) : [];
          return [cols, ...values] as [string[], ...T[]];
        }
        return values;
      }) as D1PreparedStatement['raw'],
    };
    return stmt;
  };

  const d1 = {
    prepare(query: string) {
      return buildStmt(query);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]) {
      const results = [];
      for (const s of statements) {
        results.push(await s.all<T>());
      }
      return results;
    },
    async exec(query: string) {
      raw.exec(query);
      return { count: 1, duration: 0 };
    },
    withSession() {
      return d1 as unknown as D1DatabaseSession;
    },
    async dump() {
      return new ArrayBuffer(0);
    },
  } as unknown as D1Database;

  return { d1, raw };
}

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
    env = {
      DB: sqlite.d1,
      ...TEST_ENV_SECRETS,
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
      platformFeeMicros: 600,
      developerNetMicros: 19_400,
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
          hybrid7Percent: { platformFeeMicros: number };
          proPass3Percent: { platformFeeMicros: number };
        };
      };
    };
    expect(quoteJson.result.structuredContent.monthlyGrossMicros).toBe(50_000_000);
    expect(quoteJson.result.structuredContent.hybrid7Percent.platformFeeMicros).toBe(3_500_000);
    expect(quoteJson.result.structuredContent.proPass3Percent.platformFeeMicros).toBe(1_500_000);

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
});
