import { describe, expect, it, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { DatabaseSync } from 'node:sqlite';
import worker, { signStripeWebhookPayload, type Env } from '../src/index.js';
import { verifyFiatReceipt } from '@redcenterstudio/agent-tollbooth-edge';
import { createSqliteD1, MIGRATION_SQL } from './sqlite-d1.js';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;
const BASE = 'https://tollbooth.redcenterstudio.com';

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

function makeSandboxEnv(): { env: Env; raw: DatabaseSync } {
  const { d1, raw } = createSqliteD1(MIGRATION_SQL);
  const now = Math.floor(Date.now() / 1000);
  raw
    .prepare(
      'INSERT INTO developers (id, email, name, tier, stripe_account_id, payout_address, created_at) VALUES (?, ?, ?, ?, NULL, ?, ?)',
    )
    .run('dev_studio', 'studio@example.com', 'Studio', 'pro', '0x1111111111111111111111111111111111111111', now);

  const env: Env = {
    DB: d1,
    RECEIPT_SIGNING_SECRET: 'rcs_redteam_local_hmac_secret_32bytes',
    CLEARINGHOUSE_API_KEY: 'rcs_redteam_admin_key',
    STRIPE_CONNECT_WEBHOOK_SECRET: 'whsec_redteam_test_secret',
    STUDIO_DEVELOPER_IDS: 'dev_studio',
    ENVIRONMENT: 'test-sandbox',
  };
  return { env, raw };
}

describe('Red-Team Round 1: Vector 2 — Auth, IDOR & Direct API Abuse', () => {
  it('Attack 1A/1B: blocks cross-tenant Idempotency-Key receipt theft and unauthenticated /settle ledger disclosure', async () => {
    const { env, raw } = makeSandboxEnv();

    const victimReg = (await (await worker.fetch(post('/wallet/register', { label: 'Victim' }), env, ctx)).json()) as {
      walletId: string;
      walletKey: string;
    };
    const attackerReg = (await (
      await worker.fetch(post('/wallet/register', { label: 'Attacker' }), env, ctx)
    ).json()) as {
      walletId: string;
      walletKey: string;
    };
    raw.prepare('UPDATE agent_wallets SET balance_micros = 500000 WHERE id = ?').run(victimReg.walletId);

    const sharedKey = 'shared_idem_victim_1';
    const victimRes = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        {
          walletId: victimReg.walletId,
          developerId: 'dev_studio',
          audience: 'https://api.example.com/secret',
          amountMicros: 10_000,
        },
        {
          Authorization: `Bearer ${victimReg.walletKey}`,
          'Idempotency-Key': sharedKey,
        },
      ),
      env,
      ctx,
    );
    expect(victimRes.status).toBe(200);
    const victimData = (await victimRes.json()) as { receipt: string; claims: { sub: string; jti: string } };
    expect(victimData.claims.sub).toBe(victimReg.walletId);

    // Attack 1A: Attacker reuses the exact same Idempotency-Key for their own empty wallet.
    // MUST NOT receive victim's signed receipt!
    const attackerRes = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        {
          walletId: attackerReg.walletId,
          developerId: 'dev_studio',
          audience: 'https://api.example.com/secret',
          amountMicros: 10_000,
        },
        {
          Authorization: `Bearer ${attackerReg.walletKey}`,
          'Idempotency-Key': sharedKey,
        },
      ),
      env,
      ctx,
    );
    const attackerBody = (await attackerRes.json()) as { receipt?: string; claims?: { sub?: string }; error?: string };
    expect(attackerRes.status).toBe(402);
    expect(attackerBody.receipt).toBeUndefined();
    expect(attackerBody.claims?.sub).not.toBe(victimReg.walletId);

    // Confirm verified receipt belongs only to victim, not attacker replay
    const checked = await verifyFiatReceipt(victimData.receipt, {
      hmacSecret: env.RECEIPT_SIGNING_SECRET,
      expectedAudience: 'https://api.example.com/secret',
      expectedMethod: 'GET',
      requiredMicros: 10_000,
    });
    expect(checked.valid).toBe(true);

    // Attack 1B: Unauthenticated POST /settle with empty {} body and victim's Idempotency-Key
    // MUST NOT disclose victim's jti/amount with 200 OK!
    const settleProbe = await worker.fetch(
      post('/settle', {}, { 'Idempotency-Key': sharedKey }),
      env,
      ctx,
    );
    expect(settleProbe.status).toBe(400);
    const settleBody = (await settleProbe.json()) as { success?: boolean; txHash?: string | null };
    expect(settleBody.success).toBe(false);
    expect(settleBody.txHash).toBeNull();
  });

  it('Attack 1E: rejects unregistered payTo on scheme=upto, tampered bearer tokens, and wrong HTTP methods', async () => {
    const { env } = makeSandboxEnv();
    const now = Math.floor(Date.now() / 1000);

    // Unregistered payTo claiming upto MUST be rejected with pro_pass_required_for_upto
    const verifyRes = await worker.fetch(
      post('/verify', {
        x402Version: 2,
        paymentPayload: {
          x402Version: 2,
          scheme: 'upto',
          network: 'eip155:84532',
          accepted: { scheme: 'upto', network: 'eip155:84532' },
          payload: {
            signature: `0x${'ab'.repeat(65)}`,
            authorization: {
              from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              to: '0x9999999999999999999999999999999999999999',
              value: '50000',
              validAfter: String(now - 5),
              validBefore: String(now + 120),
              nonce: `0x${'11'.repeat(32)}`,
            },
          },
        },
        paymentRequirements: {
          scheme: 'upto',
          network: 'eip155:84532',
          amount: '10000',
          asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
          payTo: '0x9999999999999999999999999999999999999999',
        },
      }),
      env,
      ctx,
    );
    const verifyJson = (await verifyRes.json()) as { isValid: boolean; invalidReason: string | null };
    expect(verifyJson.isValid).toBe(false);
    expect(verifyJson.invalidReason).toBe('pro_pass_required_for_upto');

    // Tampered tokens and unsupported HTTP methods
    const badAuth = await worker.fetch(
      post('/keys/rotate', {}, { Authorization: 'Bearer rcs_wk_tampered_invalid_key_1234567890' }),
      env,
      ctx,
    );
    expect(badAuth.status).toBe(401);

    const getMcp = await worker.fetch(new Request(`${BASE}/mcp`, { method: 'GET' }), env, ctx);
    expect(getMcp.status).toBe(405);

    const delReceipt = await worker.fetch(
      new Request(`${BASE}/wallet/issue-receipt`, { method: 'DELETE' }),
      env,
      ctx,
    );
    expect(delReceipt.status).toBe(404);

    const putSettle = await worker.fetch(
      new Request(`${BASE}/settle`, { method: 'PUT' }),
      env,
      ctx,
    );
    expect(putSettle.status).toBe(404);

    const postHealth = await worker.fetch(
      new Request(`${BASE}/health`, { method: 'POST' }),
      env,
      ctx,
    );
    expect(postHealth.status).toBe(404);
  });
});

function withD1Latency(db: D1Database, delayMs = 5): D1Database {
  const tick = () => new Promise((r) => setTimeout(r, delayMs));
  const rawMap = new WeakMap<D1PreparedStatement, D1PreparedStatement>();
  const wrapStmt = (stmt: D1PreparedStatement): D1PreparedStatement => {
    let latestRaw = stmt;
    const wrapped: D1PreparedStatement = {
      bind: (...vals: unknown[]) => {
        latestRaw = stmt.bind(...vals);
        return wrapStmt(latestRaw);
      },
      first: async <T = unknown>(col?: string) => {
        await tick();
        return col !== undefined ? stmt.first<T>(col) : stmt.first<T>();
      },
      run: async <T = Record<string, unknown>>() => {
        await tick();
        return stmt.run<T>();
      },
      all: async <T = Record<string, unknown>>() => {
        await tick();
        return stmt.all<T>();
      },
      raw: (async <T = unknown[]>(opts?: { columnNames?: boolean }) => {
        await tick();
        return opts?.columnNames ? stmt.raw<T>({ columnNames: true }) : stmt.raw<T>();
      }) as D1PreparedStatement['raw'],
    };
    rawMap.set(wrapped, stmt);
    return wrapped;
  };
  return {
    prepare: (q: string) => wrapStmt(db.prepare(q)),
    batch: async <T = unknown>(stmts: D1PreparedStatement[]) => {
      await tick();
      return db.batch<T>(stmts.map((s) => rawMap.get(s) ?? s));
    },
    exec: async (q: string) => {
      await tick();
      return db.exec(q);
    },
    withSession: () => db.withSession(),
    dump: () => db.dump(),
  } as unknown as D1Database;
}

describe('Red-Team Round 2: Vector 1 — Concurrency & Race Conditions', () => {
  it('Attack 2A: prevents double-credit and 500 errors on parallel duplicate Stripe webhooks', async () => {
    const { env: baseEnv, raw } = makeSandboxEnv();
    const env: Env = { ...baseEnv, DB: withD1Latency(baseEnv.DB, 5) };
    const { walletId } = (await (await worker.fetch(post('/wallet/register', {}), env, ctx)).json()) as {
      walletId: string;
    };

    const payload = JSON.stringify({
      id: 'evt_parallel_topup_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_parallel_topup_1',
          amount_total: 1000,
          payment_status: 'paid',
          metadata: { kind: 'wallet_topup', wallet_id: walletId },
        },
      },
    });
    const sig = await signStripeWebhookPayload(payload, env.STRIPE_CONNECT_WEBHOOK_SECRET!, Math.floor(Date.now() / 1000));

    const sendHook = () =>
      worker.fetch(
        new Request(`${BASE}/webhook/stripe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Stripe-Signature': sig },
          body: payload,
        }),
        env,
        ctx,
      );

    const [resA, resB] = await Promise.all([sendHook(), sendHook()]);
    expect([resA.status, resB.status]).toEqual([200, 200]);

    const bodies = await Promise.all([resA.json(), resB.json()]) as Array<{ idempotentReplay?: boolean }>;
    expect(bodies.filter((b) => b.idempotentReplay === true)).toHaveLength(1);

    const row = raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId) as {
      balance_micros: number;
    };
    expect(row.balance_micros).toBe(10_000_000);
  });

  it('Attack 2B: allows strictly one winner on parallel /keys/rotate and revokes the old key', async () => {
    const { env, raw } = makeSandboxEnv();
    const { walletId, walletKey } = (await (await worker.fetch(post('/wallet/register', {}), env, ctx)).json()) as {
      walletId: string;
      walletKey: string;
    };

    const rotate = () => worker.fetch(post('/keys/rotate', {}, { Authorization: `Bearer ${walletKey}` }), env, ctx);
    const [r1, r2] = await Promise.all([rotate(), rotate()]);
    const statuses = [r1.status, r2.status].sort((a, b) => a - b);
    expect(statuses).toEqual([200, 409]);

    const activeCount = raw
      .prepare('SELECT COUNT(*) AS n FROM api_keys WHERE wallet_id = ? AND revoked_at IS NULL')
      .get(walletId) as { n: number };
    expect(activeCount.n).toBe(1);
  });

  it('Attack 2C: prevents parallel duplicate email/payout registration and payout squatting races', async () => {
    const { env, raw } = makeSandboxEnv();
    const P1 = '0x' + 'aa'.repeat(20);
    const P2 = '0x' + 'bb'.repeat(20);

    // Parallel registration with same email -> strictly [201, 409], never 500
    const regEmail = () =>
      worker.fetch(
        post('/developer/register', { email: 'race@example.com', name: 'Race', payoutAddress: P1 }),
        env,
        ctx,
      );
    const [e1, e2] = await Promise.all([regEmail(), regEmail()]);
    expect([e1.status, e2.status].sort((a, b) => a - b)).toEqual([201, 409]);

    // Parallel registration with distinct emails claiming the SAME payoutAddress P2
    const [p1, p2] = await Promise.all([
      worker.fetch(post('/developer/register', { email: 'p1@example.com', name: 'P1', payoutAddress: P2 }), env, ctx),
      worker.fetch(post('/developer/register', { email: 'p2@example.com', name: 'P2', payoutAddress: P2 }), env, ctx),
    ]);
    expect([p1.status, p2.status].sort((a, b) => a - b)).toEqual([201, 409]);
    const p2Holders = raw
      .prepare('SELECT COUNT(*) AS n FROM developers WHERE LOWER(payout_address) = LOWER(?)')
      .get(P2) as { n: number };
    expect(p2Holders.n).toBe(1);

    // Parallel POST /developer/payout race from two separate registered developers for the same unused wallet P3
    const P3 = '0x' + 'cc'.repeat(20);
    const d1 = (await (
      await worker.fetch(post('/developer/register', { email: 'd1@example.com', name: 'D1' }), env, ctx)
    ).json()) as { developerKey: string };
    const d2 = (await (
      await worker.fetch(post('/developer/register', { email: 'd2@example.com', name: 'D2' }), env, ctx)
    ).json()) as { developerKey: string };
    const [s1, s2] = await Promise.all([
      worker.fetch(post('/developer/payout', { payoutAddress: P3 }, { Authorization: `Bearer ${d1.developerKey}` }), env, ctx),
      worker.fetch(post('/developer/payout', { payoutAddress: P3 }, { Authorization: `Bearer ${d2.developerKey}` }), env, ctx),
    ]);
    expect([s1.status, s2.status].sort((a, b) => a - b)).toEqual([200, 409]);
    const p3Holders = raw
      .prepare('SELECT COUNT(*) AS n FROM developers WHERE LOWER(payout_address) = LOWER(?)')
      .get(P3) as { n: number };
    expect(p3Holders.n).toBe(1);
  });

  it('Attack 2D: handles parallel /settle with same Idempotency-Key and two nonces without 500 crash', async () => {
    const { env } = makeSandboxEnv();
    const now = Math.floor(Date.now() / 1000);
    const makeSettle = (nonceHex: string) =>
      worker.fetch(
        post(
          '/settle',
          {
            x402Version: 2,
            paymentPayload: {
              x402Version: 2,
              scheme: 'exact',
              network: 'eip155:84532',
              accepted: { scheme: 'exact', network: 'eip155:84532' },
              payload: {
                signature: `0x${'ab'.repeat(65)}`,
                authorization: {
                  from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                  to: '0x1111111111111111111111111111111111111111',
                  value: '10000',
                  validAfter: String(now - 5),
                  validBefore: String(now + 120),
                  nonce: nonceHex,
                },
              },
            },
            paymentRequirements: {
              scheme: 'exact',
              network: 'eip155:84532',
              amount: '10000',
              asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
              payTo: '0x1111111111111111111111111111111111111111',
            },
          },
          { 'Idempotency-Key': 'parallel_shared_settle' },
        ),
        env,
        ctx,
      );

    const [a, b] = await Promise.all([makeSettle(`0x${'11'.repeat(32)}`), makeSettle(`0x${'22'.repeat(32)}`)]);
    const statuses = [a.status, b.status].sort((x, y) => x - y);
    expect(statuses).toEqual([200, 409]);
  });
});

describe('Red-Team Round 3: Vector 3 — Hostile Payloads & Boundary Chaos', () => {
  it('Attack 3A: cleanly rejects JSON null, array, and string primitive bodies across all POST routes with 400 (never 500)', async () => {
    const { env } = makeSandboxEnv();
    const reg = (await (await worker.fetch(post('/wallet/register', {}), env, ctx)).json()) as {
      walletKey: string;
    };

    const routes: Array<{ path: string; headers?: Record<string, string> }> = [
      { path: '/verify' },
      { path: '/settle' },
      { path: '/wallet/register' },
      { path: '/developer/register' },
      { path: '/developer/payout', headers: { Authorization: `Bearer ${reg.walletKey}` } },
      { path: '/wallet/topup' },
      { path: '/wallet/issue-receipt', headers: { Authorization: `Bearer ${reg.walletKey}` } },
      { path: '/mcp' },
    ];

    for (const badBody of ['null', '[]', '"primitive"', '123']) {
      for (const route of routes) {
        const res = await worker.fetch(
          new Request(`${BASE}${route.path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...route.headers },
            body: badBody,
          }),
          env,
          ctx,
        );
        expect(res.status, `${route.path} with ${badBody}`).toBe(400);
      }

      const sig = await signStripeWebhookPayload(
        badBody,
        env.STRIPE_CONNECT_WEBHOOK_SECRET!,
        Math.floor(Date.now() / 1000),
      );
      const hookRes = await worker.fetch(
        new Request(`${BASE}/webhook/stripe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Stripe-Signature': sig },
          body: badBody,
        }),
        env,
        ctx,
      );
      expect(hookRes.status, `/webhook/stripe with ${badBody}`).toBe(400);
    }

    // Stdio MCP bridge must survive JSON null without crashing
    const stdio = spawnSync(
      process.execPath,
      [path.join(ROOT_DIR, 'scripts/mcp-stdio.mjs')],
      {
        input: 'null\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
        encoding: 'utf8',
      },
    );
    expect(stdio.status).toBe(0);
    const lines = stdio.stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toHaveLength(2);
    expect((lines[0]!.error as { code: number }).code).toBe(-32600);
    expect(lines[1]!.id).toBe(1);
  }, 15_000);

  it('Attack 3B: rejects integer overflows, boolean coercion, invalid ttlSeconds, bogus routeId, and non-string/float /verify bombs', async () => {
    const { env, raw } = makeSandboxEnv();
    const { walletId, walletKey } = (await (await worker.fetch(post('/wallet/register', {}), env, ctx)).json()) as {
      walletId: string;
      walletKey: string;
    };
    raw.prepare('UPDATE agent_wallets SET balance_micros = 500000 WHERE id = ?').run(walletId);

    // Overflow & boolean in tollbooth_pricing_quote
    const quoteOverflow = await worker.fetch(
      post('/mcp', {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'tollbooth_pricing_quote',
          arguments: { priceMicros: Number.MAX_SAFE_INTEGER, callsPerMonth: Number.MAX_SAFE_INTEGER },
        },
      }),
      env,
      ctx,
    );
    expect(quoteOverflow.status).toBe(200);
    expect(((await quoteOverflow.json()) as { error?: { code: number } }).error?.code).toBe(-32602);

    const quoteBool = await worker.fetch(
      post('/mcp', {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'tollbooth_pricing_quote',
          arguments: { priceMicros: true, callsPerMonth: true },
        },
      }),
      env,
      ctx,
    );
    expect(((await quoteBool.json()) as { error?: { code: number } }).error?.code).toBe(-32602);

    // Invalid ttlSeconds "abc" must return 400 and NOT debit wallet or produce exp: null
    const badTtl = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        {
          walletId,
          developerId: 'dev_studio',
          audience: 'https://api.example.com',
          amountMicros: 10_000,
          ttlSeconds: 'abc',
        },
        { Authorization: `Bearer ${walletKey}` },
      ),
      env,
      ctx,
    );
    expect(badTtl.status).toBe(400);
    expect((raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId) as { balance_micros: number }).balance_micros).toBe(500_000);

    // Non-existent routeId must return 400 invalid_route_id (never 409 idempotency_conflict) and leave balance intact
    const badRoute = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        {
          walletId,
          developerId: 'dev_studio',
          routeId: 'route_nonexistent',
          audience: 'https://api.example.com',
          amountMicros: 10_000,
        },
        { Authorization: `Bearer ${walletKey}` },
      ),
      env,
      ctx,
    );
    expect(badRoute.status).toBe(400);
    expect((raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId) as { balance_micros: number }).balance_micros).toBe(500_000);

    // Non-string paymentRequirements fields & unsafe validBefore overflow on /verify must return clean 400/200 isValid:false (never 500)
    const now = Math.floor(Date.now() / 1000);
    const badTypesVerify = await worker.fetch(
      post('/verify', {
        x402Version: 2,
        paymentPayload: {
          x402Version: 2,
          scheme: 'exact',
          network: 'eip155:84532',
          accepted: { scheme: 'exact', network: 'eip155:84532' },
          payload: {
            signature: `0x${'ab'.repeat(65)}`,
            authorization: {
              from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              to: '0x1111111111111111111111111111111111111111',
              value: '10000',
              validAfter: String(now - 5),
              validBefore: '99999999999999999999999999999',
              nonce: `0x${'44'.repeat(32)}`,
            },
          },
        },
        paymentRequirements: {
          scheme: 'exact',
          network: 'eip155:84532',
          amount: '10000',
          asset: null,
          payTo: 123,
        },
      }),
      env,
      ctx,
    );
    expect(badTypesVerify.status).toBeLessThan(500);
    const badTypesJson = (await badTypesVerify.json()) as { isValid: boolean };
    expect(badTypesJson.isValid).toBe(false);
  });

  it('Attack 3D/3E: blocks silent type coercion, RTL/100KB/SQLi/XSS injection, and default /wallet/ledger limit=null truncation', async () => {
    const { env, raw } = makeSandboxEnv();

    // Non-string label/email and boolean dailySpendCapUsd must be rejected with 400
    const coercedReg = await worker.fetch(
      post('/wallet/register', { dailySpendCapUsd: true, email: 12345, label: { evil: 1 } }),
      env,
      ctx,
    );
    expect(coercedReg.status).toBe(400);

    // Unicode RTL bidi override & control chars in name/label must be rejected with 400
    const rtlReg = await worker.fetch(
      post('/developer/register', {
        email: 'rtl@example.com',
        name: 'Safe\u202Eevil',
      }),
      env,
      ctx,
    );
    expect(rtlReg.status).toBe(400);

    // Huge 100KB name/label must not silently store corrupted truncated identity if maliciously oversized; accept clean 400
    const giantReg = await worker.fetch(
      post('/developer/register', {
        email: 'giant@example.com',
        name: 'A'.repeat(100_000),
      }),
      env,
      ctx,
    );
    expect(giantReg.status).toBe(400);

    // XSS / SQLi strings in SQL queries and HTML responses must remain parameterized and escaped
    const sqliReg = await worker.fetch(
      post('/developer/register', {
        email: "sqli+1@example.com",
        name: "' OR 1=1 -- <script>alert(1)</script>",
      }),
      env,
      ctx,
    );
    expect(sqliReg.status).toBe(201);

    // Seed 5 charges on a valid wallet and call GET /wallet/ledger WITHOUT ?limit (limit=null) -> MUST return all 5, not 1!
    const { walletId, walletKey } = (await (await worker.fetch(post('/wallet/register', { label: 'Ledger' }), env, ctx)).json()) as {
      walletId: string;
      walletKey: string;
    };
    raw.prepare('UPDATE agent_wallets SET balance_micros = 500000 WHERE id = ?').run(walletId);
    for (let i = 0; i < 5; i++) {
      const r = await worker.fetch(
        post(
          '/wallet/issue-receipt',
          {
            walletId,
            developerId: 'dev_studio',
            audience: 'https://api.example.com/item',
            amountMicros: 1_000,
          },
          { Authorization: `Bearer ${walletKey}`, 'Idempotency-Key': `k_${i}` },
        ),
        env,
        ctx,
      );
      expect(r.status).toBe(200);
    }

    const ledgerRes = await worker.fetch(
      new Request(`${BASE}/wallet/ledger`, { headers: { Authorization: `Bearer ${walletKey}` } }),
      env,
      ctx,
    );
    expect(ledgerRes.status).toBe(200);
    const ledgerJson = (await ledgerRes.json()) as { entries: Array<Record<string, unknown>> };
    expect(ledgerJson.entries).toHaveLength(5);

    // XSS attempt via /demo/402 URL & query
    const demoXss = await worker.fetch(
      new Request(`${BASE}/demo/402?q=<script>alert(1)</script>`, { headers: { Accept: 'text/html' } }),
      env,
      ctx,
    );
    expect(demoXss.status).toBe(402);
    expect(await demoXss.text()).not.toContain('<script>alert(1)</script>');
  });
});

describe('Red-Team Round 4: Vector 4 — State Desync & Mid-Flight Interruption', () => {
  it('Attack 4B: handles upstream Stripe network outage and non-JSON 502 HTML without returning HTTP 500', async () => {
    const { env: baseEnv, raw } = makeSandboxEnv();
    const now = Math.floor(Date.now() / 1000);
    const devRes = (await (
      await worker.fetch(
        post('/developer/register', {
          email: 'stripeout@example.com',
          name: 'Outage Dev',
          payoutAddress: '0x1212121212121212121212121212121212121212',
        }),
        baseEnv,
        ctx,
      )
    ).json()) as { developerId: string };

    const stripeEnv: Env = {
      ...baseEnv,
      STRIPE_SECRET_KEY: 'sk_test_redteam_local_0000',
      PAID_SALES_OPEN: 'true',
      ENVIRONMENT: 'production',
    };

    try {
      // 1) Network drop during Stripe fetch
      vi.stubGlobal('fetch', async () => {
        throw new TypeError('connect ECONNREFUSED api.stripe.com');
      });
      const dropRes = await worker.fetch(
        post('/wallet/topup', { developerId: devRes.developerId, passTier: 'pro' }),
        stripeEnv,
        ctx,
      );
      expect(dropRes.status).toBe(502);
      const dropJson = (await dropRes.json()) as { error: string; code: string };
      expect(dropJson.error).toBe('stripe_checkout_failed');

      // 2) Upstream returns HTML 502 Bad Gateway instead of JSON
      vi.stubGlobal('fetch', async () => new Response('<html>502 Bad Gateway</html>', { status: 502 }));
      const htmlRes = await worker.fetch(
        post('/wallet/topup', { developerId: devRes.developerId, passTier: 'pro' }),
        stripeEnv,
        ctx,
      );
      expect(htmlRes.status).toBe(502);
      expect(((await htmlRes.json()) as { error: string }).error).toBe('stripe_checkout_failed');

      // 3) Same over MCP tool returns structured JSON-RPC isError instead of HTTP 500
      const mcpDrop = await worker.fetch(
        post('/mcp', {
          jsonrpc: '2.0',
          id: 77,
          method: 'tools/call',
          params: {
            name: 'tollbooth_create_topup_checkout',
            arguments: { developerId: devRes.developerId, passTier: 'pro' },
          },
        }),
        stripeEnv,
        ctx,
      );
      expect(mcpDrop.status).toBe(200);
      const mcpJson = (await mcpDrop.json()) as { result: { isError: boolean; structuredContent: { error: string } } };
      expect(mcpJson.result.isError).toBe(true);
      expect(mcpJson.result.structuredContent.error).toBe('stripe_checkout_failed');
    } finally {
      vi.unstubAllGlobals();
    }
    expect(raw.prepare('SELECT COUNT(*) AS n FROM ledger_entries WHERE created_at >= ?').get(now)).toMatchObject({ n: 0 });
  });

  it('Attack 4D: protects Agency tier from out-of-order delayed Pro webhook downgrades', async () => {
    const { env, raw } = makeSandboxEnv();
    const { developerId } = (await (
      await worker.fetch(post('/developer/register', { email: 'order@example.com', name: 'Order' }), env, ctx)
    ).json()) as { developerId: string };

    const sendHook = async (id: string, tier: 'pro' | 'agency') => {
      const payload = JSON.stringify({
        id,
        type: 'checkout.session.completed',
        data: {
          object: {
            id: `cs_${id}`,
            payment_status: 'paid',
            metadata: { kind: 'tier_upgrade', developer_id: developerId, target_tier: tier },
          },
        },
      });
      const sig = await signStripeWebhookPayload(payload, env.STRIPE_CONNECT_WEBHOOK_SECRET!, Math.floor(Date.now() / 1000));
      return worker.fetch(
        new Request(`${BASE}/webhook/stripe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Stripe-Signature': sig },
          body: payload,
        }),
        env,
        ctx,
      );
    };

    expect((await sendHook('evt_agency_first', 'agency')).status).toBe(200);
    expect((await sendHook('evt_pro_delayed', 'pro')).status).toBe(200);
    expect(raw.prepare('SELECT tier FROM developers WHERE id = ?').get(developerId)).toMatchObject({ tier: 'agency' });
  });

  it('Attack 4E: ensures /pay inline script verifies rHealth.ok and wraps fetch/clipboard rejections safely', async () => {
    const { env } = makeSandboxEnv();
    const html = await (await worker.fetch(new Request(`${BASE}/pay`), env, ctx)).text();
    expect(html).toContain('rHealth.ok');
    expect(html).toContain('Network error');
    expect(html).toContain('.catch(');
    expect(html).toContain("e.key === 'Escape'");
  });

  it('Round 5 Layout Regression: /pay enforces mobile minmax(0,1fr) grids, notice wrapping, favicon, and table container bounds', async () => {
    const { env } = makeSandboxEnv();
    const res = await worker.fetch(new Request(`${BASE}/pay`), env, ctx);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('grid-template-columns: minmax(0, 1fr)');
    expect(html).toContain('.tb-notice { padding: 14px 0; font-weight: 600; overflow-wrap: anywhere; max-width: 100%; }');
    expect(html).toContain('.btn { max-width: 100%; white-space: normal; overflow-wrap: anywhere; }');
    expect(html).toContain('.map { width: 100%; min-width: 520px;');
    expect(html).toContain('rel="icon"');
    const fav = await worker.fetch(new Request(`${BASE}/favicon.ico`), env, ctx);
    expect(fav.status).toBe(204);
  });

  it('Round 8 Regression: registration script never overwrites a shown-once key with a later error', async () => {
    const { env } = makeSandboxEnv();
    const html = await (await worker.fetch(new Request(`${BASE}/pay`), env, ctx)).text();
    expect(html).toContain('let keyShown = false;');
    expect(html).toContain('keyShown ? out.textContent + NL + msg : msg');
    expect(html).toContain('keyShown = true;');
  });
});

describe('Red-Team Round 6: Vector 5 — Silent Failure & Persistence Audit', () => {
  it('verifies exact SQLite persistence, integer fee reconciliation, zero plaintext keys, and default ledger completeness', async () => {
    const { env, raw } = makeSandboxEnv();
    const PAYOUT = '0x9090909090909090909090909090909090909090';

    // 1) Wallet + Developer registration via HTTP & MCP
    const wReg = (await (
      await worker.fetch(
        post('/wallet/register', { label: 'AuditBot', email: 'AuditBot@Example.com', dailySpendCapUsd: 42 }),
        env,
        ctx,
      )
    ).json()) as { walletId: string; walletKey: string };

    const dReg = (await (
      await worker.fetch(
        post('/developer/register', { email: 'AuditDev@Example.com', name: 'Audit Studio', payoutAddress: PAYOUT }),
        env,
        ctx,
      )
    ).json()) as { developerId: string; developerKey: string };

    const wRow = raw.prepare('SELECT * FROM agent_wallets WHERE id = ?').get(wReg.walletId) as Record<string, unknown>;
    expect(wRow).toMatchObject({
      id: wReg.walletId,
      owner_label: 'AuditBot',
      owner_email: 'auditbot@example.com',
      balance_micros: 0,
      daily_spend_cap_micros: 42_000_000,
      daily_spent_micros: 0,
      status: 'active',
    });

    const dRow = raw.prepare('SELECT * FROM developers WHERE id = ?').get(dReg.developerId) as Record<string, unknown>;
    expect(dRow).toMatchObject({
      id: dReg.developerId,
      email: 'auditdev@example.com',
      name: 'Audit Studio',
      payout_address: PAYOUT,
    });

    const keyRows = raw.prepare('SELECT * FROM api_keys').all() as Array<{ key_hash: string; revoked_at: number | null }>;
    expect(JSON.stringify(keyRows)).not.toContain(wReg.walletKey);
    expect(JSON.stringify(keyRows)).not.toContain(dReg.developerKey);

    // 2) Stripe webhook top-up + upgrade + 5 charges + exact ledger & cron retention
    const hook = async (id: string, object: Record<string, unknown>) => {
      const payload = JSON.stringify({ id, type: 'checkout.session.completed', data: { object } });
      const sig = await signStripeWebhookPayload(payload, env.STRIPE_CONNECT_WEBHOOK_SECRET!, Math.floor(Date.now() / 1000));
      return worker.fetch(
        new Request(`${BASE}/webhook/stripe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Stripe-Signature': sig },
          body: payload,
        }),
        env,
        ctx,
      );
    };

    expect((await hook('evt_p_topup', { id: 'cs_p_topup', amount_total: 1000, payment_status: 'paid', metadata: { kind: 'wallet_topup', wallet_id: wReg.walletId } })).status).toBe(200);
    expect((await hook('evt_p_upgrade', { id: 'cs_p_up', amount_total: 7900, payment_status: 'paid', metadata: { kind: 'tier_upgrade', developer_id: dReg.developerId, target_tier: 'agency' } })).status).toBe(200);
    expect(raw.prepare('SELECT tier FROM developers WHERE id = ?').get(dReg.developerId)).toMatchObject({ tier: 'agency' });

    env.STUDIO_DEVELOPER_IDS = `dev_studio,${dReg.developerId}`;
    for (let i = 0; i < 5; i++) {
      const r = await worker.fetch(
        post(
          '/wallet/issue-receipt',
          { walletId: wReg.walletId, developerId: dReg.developerId, audience: 'https://api.example.com/a', amountMicros: 1_234 },
          { Authorization: `Bearer ${wReg.walletKey}`, 'Idempotency-Key': `audit_rcpt_${i}` },
        ),
        env,
        ctx,
      );
      expect(r.status).toBe(200);
    }

    const afterW = raw.prepare('SELECT balance_micros, daily_spent_micros FROM agent_wallets WHERE id = ?').get(wReg.walletId) as {
      balance_micros: number;
      daily_spent_micros: number;
    };
    expect(afterW.balance_micros).toBe(10_000_000 - 5 * 1_234);
    expect(afterW.daily_spent_micros).toBe(5 * 1_234);

    // Every ledger row strictly satisfies integer fee reconciliation
    const ledgerRows = raw.prepare('SELECT gross_micros, platform_fee_micros, developer_net_micros FROM ledger_entries').all() as Array<{
      gross_micros: number;
      platform_fee_micros: number;
      developer_net_micros: number;
    }>;
    expect(ledgerRows.length).toBeGreaterThanOrEqual(6);
    for (const lr of ledgerRows) {
      expect(lr.platform_fee_micros + lr.developer_net_micros).toBe(lr.gross_micros);
    }

    // Default /developer/ledger without ?limit returns all 5 earnings rows
    const devLedger = await worker.fetch(
      new Request(`${BASE}/developer/ledger`, { headers: { Authorization: `Bearer ${dReg.developerKey}` } }),
      env,
      ctx,
    );
    expect(devLedger.status).toBe(200);
    expect(((await devLedger.json()) as { entries: unknown[] }).entries).toHaveLength(5);

    // Cron pruning drops expired auth nonces while preserving 365d webhook nonces
    const now = Math.floor(Date.now() / 1000);
    raw
      .prepare("INSERT INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, 'x402', 'p', '*', ?, ?)")
      .run('expired_auth_nonce', now - 7200, now - 8000);
    await worker.scheduled({} as ScheduledController, env, ctx);
    expect(raw.prepare('SELECT nonce FROM used_nonces WHERE nonce = ?').get('expired_auth_nonce')).toBeUndefined();
    expect(raw.prepare('SELECT nonce FROM used_nonces WHERE nonce = ?').get('stripe_evt_evt_p_upgrade')).toBeTruthy();
    // Replaying upgrade webhook after cron stays idempotent
    const replayUpgrade = await hook('evt_p_upgrade', {
      id: 'cs_p_up',
      amount_total: 7900,
      payment_status: 'paid',
      metadata: { kind: 'tier_upgrade', developer_id: dReg.developerId, target_tier: 'agency' },
    });
    expect((await replayUpgrade.json()) as { idempotentReplay: boolean }).toMatchObject({ idempotentReplay: true });
  });

  it('leaves ZERO orphaned DB rows when db.batch fails mid-flight on registerWallet, registerDeveloper, or Stripe topup', async () => {
    const { env: baseEnv, raw } = makeSandboxEnv();
    const baseDevCount = (raw.prepare('SELECT COUNT(*) AS n FROM developers').get() as { n: number }).n;

    // Force DB batch failure
    const failingDb = {
      ...baseEnv.DB,
      batch: async () => {
        throw new Error('D1 batch storage write aborted mid-transaction');
      },
    } as unknown as D1Database;
    const failEnv: Env = { ...baseEnv, DB: failingDb };

    const regW = await worker.fetch(post('/wallet/register', { label: 'OrphanTest' }), failEnv, ctx);
    expect(regW.status).toBe(500);

    const regD = await worker.fetch(post('/developer/register', { email: 'orphan@example.com', name: 'Orphan' }), failEnv, ctx);
    expect(regD.status).toBe(500);

    // Create a clean wallet, then fail Stripe topup batch
    const { walletId } = (await (await worker.fetch(post('/wallet/register', {}), baseEnv, ctx)).json()) as { walletId: string };
    const topupPayload = JSON.stringify({
      id: 'evt_orphan_topup',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_orphan', amount_total: 1000, payment_status: 'paid', metadata: { kind: 'wallet_topup', wallet_id: walletId } } },
    });
    const sig = await signStripeWebhookPayload(topupPayload, baseEnv.STRIPE_CONNECT_WEBHOOK_SECRET!, Math.floor(Date.now() / 1000));
    const hookFail = await worker.fetch(
      new Request(`${BASE}/webhook/stripe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Stripe-Signature': sig },
        body: topupPayload,
      }),
      failEnv,
      ctx,
    );
    expect(hookFail.status).toBe(500);

    // Confirm zero orphaned wallets, developers, keys, ledger entries, or webhook nonces
    expect((raw.prepare('SELECT COUNT(*) AS n FROM developers').get() as { n: number }).n).toBe(baseDevCount);
    expect((raw.prepare('SELECT COUNT(*) AS n FROM agent_wallets').get() as { n: number }).n).toBe(1);
    expect((raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId) as { balance_micros: number }).balance_micros).toBe(0);
    expect((raw.prepare('SELECT COUNT(*) AS n FROM api_keys').get() as { n: number }).n).toBe(1);
    expect((raw.prepare('SELECT COUNT(*) AS n FROM ledger_entries').get() as { n: number }).n).toBe(0);
    expect((raw.prepare('SELECT COUNT(*) AS n FROM used_nonces').get() as { n: number }).n).toBe(0);
  });

  it('a transient D1 failure never swallows a paid Stripe event: the retry credits once, the next retry is a replay', async () => {
    const { env: baseEnv, raw } = makeSandboxEnv();
    const { walletId } = (await (await worker.fetch(post('/wallet/register', {}), baseEnv, ctx)).json()) as { walletId: string };
    const { developerId } = (await (
      await worker.fetch(post('/developer/register', { email: 'retry@example.com', name: 'Retry Dev' }), baseEnv, ctx)
    ).json()) as { developerId: string };

    // Fail every read made after the request starts (the wallet/developer lookup), as a flaky D1 would.
    const flakyDb = {
      ...baseEnv.DB,
      prepare: (q: string) => {
        const stmt = baseEnv.DB.prepare(q);
        if (/^\s*SELECT id(, tier)? FROM (agent_wallets|developers) WHERE id/i.test(q)) {
          return {
            ...stmt,
            bind: () => ({ first: async () => { throw new Error('D1_ERROR: Network connection lost'); } }),
          };
        }
        return stmt;
      },
    } as unknown as D1Database;
    const flakyEnv: Env = { ...baseEnv, DB: flakyDb };

    const deliver = async (payload: string, env: Env) => {
      const sig = await signStripeWebhookPayload(payload, baseEnv.STRIPE_CONNECT_WEBHOOK_SECRET!, Math.floor(Date.now() / 1000));
      return worker.fetch(
        new Request(`${BASE}/webhook/stripe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Stripe-Signature': sig },
          body: payload,
        }),
        env,
        ctx,
      );
    };

    const topup = JSON.stringify({
      id: 'evt_flaky_topup',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_flaky', amount_total: 1000, payment_status: 'paid', metadata: { kind: 'wallet_topup', wallet_id: walletId } } },
    });
    const upgrade = JSON.stringify({
      id: 'evt_flaky_upgrade',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_flaky_up', amount_total: 3900, payment_status: 'paid', metadata: { kind: 'tier_upgrade', developer_id: developerId, target_tier: 'pro' } } },
    });

    expect((await deliver(topup, flakyEnv)).status).toBe(500);
    expect((await deliver(upgrade, flakyEnv)).status).toBe(500);
    expect((raw.prepare('SELECT COUNT(*) AS n FROM used_nonces').get() as { n: number }).n).toBe(0);

    // Stripe retries: processed for real, not mistaken for a replay.
    const retryTopup = (await (await deliver(topup, baseEnv)).json()) as { creditedMicros?: number; idempotentReplay?: boolean };
    expect(retryTopup).toMatchObject({ creditedMicros: 10_000_000 });
    expect(retryTopup.idempotentReplay).toBeUndefined();
    expect((await (await deliver(upgrade, baseEnv)).json()) as { tier?: string }).toMatchObject({ tier: 'pro' });

    // A further retry is a replay and does not credit again.
    expect((await (await deliver(topup, baseEnv)).json()) as { idempotentReplay?: boolean }).toMatchObject({ idempotentReplay: true });
    expect((raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId) as { balance_micros: number }).balance_micros).toBe(10_000_000);
    expect((raw.prepare('SELECT tier FROM developers WHERE id = ?').get(developerId) as { tier: string }).tier).toBe('pro');
  });
});

describe('Red-Team Round 7: Vector 1 + Vector 2 Escalated Combined Siege', () => {
  it('survives 10-way concurrent wallet issue-receipt, 10-way key rotation, 5-way payout race, and method fuzzing', async () => {
    const { env: baseEnv, raw } = makeSandboxEnv();
    const env: Env = { ...baseEnv, DB: withD1Latency(baseEnv.DB, 3) };

    const wA = (await (await worker.fetch(post('/wallet/register', { label: 'SiegeA' }), baseEnv, ctx)).json()) as {
      walletId: string;
      walletKey: string;
    };
    const wB = (await (await worker.fetch(post('/wallet/register', { label: 'SiegeB' }), baseEnv, ctx)).json()) as {
      walletId: string;
      walletKey: string;
    };
    // Wallet A: $0.05 (50,000 micros), daily cap $0.04 (40,000 micros). Wallet B: $0.01 (10,000 micros).
    raw.prepare('UPDATE agent_wallets SET balance_micros = 50000, daily_spend_cap_micros = 40000 WHERE id = ?').run(wA.walletId);
    raw.prepare('UPDATE agent_wallets SET balance_micros = 10000, daily_spend_cap_micros = 50000 WHERE id = ?').run(wB.walletId);

    // 10-way mixed receipt flood ($0.015 per call, two keys share 'dup_key_1')
    const receiptCalls = [
      ...Array.from({ length: 6 }, (_, i) =>
        worker.fetch(
          post(
            '/wallet/issue-receipt',
            { walletId: wA.walletId, developerId: 'dev_studio', audience: 'https://api.example.com/r', amountMicros: 15_000 },
            { Authorization: `Bearer ${wA.walletKey}`, 'Idempotency-Key': i < 2 ? 'dup_key_1' : `uniq_a_${i}` },
          ),
          env,
          ctx,
        ),
      ),
      ...Array.from({ length: 2 }, (_, i) =>
        worker.fetch(
          post(
            '/wallet/issue-receipt',
            { walletId: wB.walletId, developerId: 'dev_studio', audience: 'https://api.example.com/r', amountMicros: 6_000 },
            { Authorization: `Bearer ${wB.walletKey}`, 'Idempotency-Key': `uniq_b_${i}` },
          ),
          env,
          ctx,
        ),
      ),
      // Cross-tenant attempts mixing A's Idempotency-Key and B's wallet
      worker.fetch(
        post(
          '/wallet/issue-receipt',
          { walletId: wA.walletId, developerId: 'dev_studio', audience: 'https://api.example.com/r', amountMicros: 15_000 },
          { Authorization: `Bearer ${wB.walletKey}`, 'Idempotency-Key': 'dup_key_1' },
        ),
        env,
        ctx,
      ),
      worker.fetch(
        post(
          '/wallet/issue-receipt',
          { walletId: wB.walletId, developerId: 'dev_studio', audience: 'https://api.example.com/r', amountMicros: 6_000 },
          { Authorization: `Bearer ${wA.walletKey}`, 'Idempotency-Key': 'uniq_b_0' },
        ),
        env,
        ctx,
      ),
    ];

    const receiptResults = await Promise.all(receiptCalls);
    expect(receiptResults.every((r) => r.status < 500)).toBe(true);
    // Wallet A max possible spend under 40,000 cap at 15,000/call = 2 calls = 30,000
    const rowA = raw.prepare('SELECT balance_micros, daily_spent_micros FROM agent_wallets WHERE id = ?').get(wA.walletId) as {
      balance_micros: number;
      daily_spent_micros: number;
    };
    expect(rowA.daily_spent_micros).toBeLessThanOrEqual(40_000);
    expect(rowA.balance_micros).toBe(50_000 - rowA.daily_spent_micros);
    // Wallet B balance = 10,000 at 6,000/call = strictly 1 call = 4,000 left
    const rowB = raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(wB.walletId) as {
      balance_micros: number;
    };
    expect(rowB.balance_micros).toBe(4_000);

    // 10-way key rotation siege
    const rotResults = await Promise.all(
      Array.from({ length: 10 }, () =>
        worker.fetch(post('/keys/rotate', {}, { Authorization: `Bearer ${wA.walletKey}` }), env, ctx),
      ),
    );
    const rotCodes = rotResults.map((r) => r.status).sort((a, b) => a - b);
    expect(rotCodes).toEqual([200, 409, 409, 409, 409, 409, 409, 409, 409, 409]);
    expect(raw.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE wallet_id = ? AND revoked_at IS NULL').get(wA.walletId)).toMatchObject({ n: 1 });
    // Old key rejected on both HTTP & MCP immediately
    expect((await worker.fetch(new Request(`${BASE}/wallet/ledger`, { headers: { Authorization: `Bearer ${wA.walletKey}` } }), env, ctx)).status).toBe(401);
    expect(
      (
        await worker.fetch(
          post(
            '/mcp',
            { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'tollbooth_wallet_balance', arguments: { walletId: wA.walletId } } },
            { Authorization: `Bearer ${wA.walletKey}` },
          ),
          env,
          ctx,
        )
      ).status,
    ).toBe(401);

    // 5-way developer payout squatting race
    const TARGET_PAYOUT = '0x' + 'dd'.repeat(20);
    const devs = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        worker.fetch(post('/developer/register', { email: `squat${i}@example.com`, name: `S${i}` }), baseEnv, ctx).then((r) => r.json() as Promise<{ developerKey: string }>),
      ),
    );
    const payoutRace = await Promise.all(
      devs.map((d) =>
        worker.fetch(post('/developer/payout', { payoutAddress: TARGET_PAYOUT }, { Authorization: `Bearer ${d.developerKey}` }), env, ctx),
      ),
    );
    expect(payoutRace.map((r) => r.status).sort((a, b) => a - b)).toEqual([200, 409, 409, 409, 409]);

    // Method fuzzing across sensitive endpoints -> zero 5xx
    for (const method of ['HEAD', 'PUT', 'DELETE', 'PATCH']) {
      for (const p of ['/verify', '/settle', '/wallet/issue-receipt', '/wallet/register', '/developer/register', '/keys/rotate', '/webhook/stripe']) {
        const res = await worker.fetch(new Request(`${BASE}${p}`, { method }), baseEnv, ctx);
        expect(res.status, `${method} ${p}`).toBeLessThan(500);
      }
    }
  });
});
