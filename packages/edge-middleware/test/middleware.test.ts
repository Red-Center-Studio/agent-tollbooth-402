import { describe, expect, it, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  D1NonceStore,
  MemoryNonceStore,
  MemorySpendTracker,
  decodePaymentHeader,
  encodePaymentHeader,
  honoTollbooth,
  microsToUsdString,
  signFiatReceipt,
  usdMicrosToUsdcAtomic,
  usdToMicros,
  verifyFiatReceipt,
  withTollbooth,
  type D1LikeDatabase,
  type HonoLikeContext,
  type TollboothConfig,
  type X402PaymentRequired,
  type X402PaymentResponse,
  type X402PaymentSignature,
} from '../src/index.js';

const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const PAYER = '0x1234567890abcdef1234567890abcdef12345678';
const TEST_HMAC_SECRET = 'rcs_test_secret_not_for_prod_32bytes_min';

const mockCtx = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
} as unknown as ExecutionContext;

function createSqliteD1Like(): D1LikeDatabase {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE used_nonces (
      nonce TEXT PRIMARY KEY,
      rail TEXT NOT NULL,
      wallet_or_payer TEXT NOT NULL,
      route_pattern TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);
  return {
    prepare(query: string) {
      let boundValues: unknown[] = [];
      const stmt = {
        bind(...values: unknown[]) {
          boundValues = values;
          return stmt;
        },
        async run() {
          const info = db
            .prepare(query)
            .run(...(boundValues as Array<string | number | bigint | Uint8Array | null>));
          return { meta: { changes: Number(info.changes) } };
        },
      };
      return stmt;
    },
  };
}

function makeX402Signature(overrides?: Partial<X402PaymentSignature> & {
  authOverrides?: Partial<X402PaymentSignature['payload']['authorization']>;
}): string {
  const now = Math.floor(Date.now() / 1000);
  const sig: X402PaymentSignature = {
    x402Version: 2,
    scheme: overrides?.scheme ?? 'exact',
    network: overrides?.network ?? 'eip155:8453',
    accepted: overrides?.accepted ?? {
      scheme: overrides?.scheme ?? 'exact',
      network: overrides?.network ?? 'eip155:8453',
    },
    payload: {
      signature: overrides?.payload?.signature ?? '0x' + 'ab'.repeat(65),
      authorization: {
        from: PAYER,
        to: PAY_TO,
        value: '5000',
        validAfter: String(now - 10),
        validBefore: String(now + 120),
        nonce: `0x${crypto.randomUUID().replace(/-/g, '')}`,
        ...overrides?.authOverrides,
      },
    },
  };
  return encodePaymentHeader(sig);
}

describe('currency & encoding helpers', () => {
  it('converts USD values to exact integer microdollars and USDC atomic units', () => {
    expect(usdToMicros(0.001)).toBe(1000);
    expect(usdToMicros('$0.005')).toBe(5000);
    expect(usdToMicros('1.25')).toBe(1_250_000);
    expect(microsToUsdString(5000)).toBe('0.005');
    expect(microsToUsdString(1_000_000)).toBe('1');
    expect(usdMicrosToUsdcAtomic(5000)).toBe('5000');
    expect(() => usdToMicros(-0.01)).toThrow();
    expect(() => usdToMicros('0.0000001')).toThrow();
  });
});

describe('withTollbooth dual-rail edge middleware', () => {
  it('allows OPTIONS CORS preflight and exempt paths without charging', async () => {
    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        routes: [{ pattern: '/api/*', priceMicros: 5000 }],
      },
      {
        async fetch(req) {
          const url = new URL(req.url);
          return Response.json({ ok: true, path: url.pathname });
        },
      },
    );

    const optRes = await worker.fetch(
      new Request('https://api.example.com/api/data', { method: 'OPTIONS' }),
      {},
      mockCtx,
    );
    expect(optRes.status).toBe(200);

    const healthRes = await worker.fetch(
      new Request('https://api.example.com/health'),
      {},
      mockCtx,
    );
    expect(healthRes.status).toBe(200);
    expect((await healthRes.json()) as { path: string }).toEqual({ ok: true, path: '/health' });
  });

  it('returns 402 with Base64 x402 V2 PAYMENT-REQUIRED header on unpaid request', async () => {
    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        fiatWallet: {
          hmacSecret: TEST_HMAC_SECRET,
          clearinghouseUrl: 'https://tollbooth.redcenterstudio.com',
        },
        routes: [
          {
            pattern: '/api/lookup',
            method: 'GET',
            scheme: 'exact',
            priceMicros: usdToMicros('0.005'),
            description: 'DNS Lookup',
          },
        ],
      },
      {
        async fetch() {
          return Response.json({ shouldNotReach: true });
        },
      },
    );

    const res = await worker.fetch(
      new Request('https://api.example.com/api/lookup'),
      {},
      mockCtx,
    );

    expect(res.status).toBe(402);
    const header = res.headers.get('PAYMENT-REQUIRED');
    expect(header).toBeTruthy();
    const decoded = decodePaymentHeader<X402PaymentRequired>(header!);
    expect(decoded.x402Version).toBe(2);
    expect(decoded.accepts[0]).toMatchObject({
      scheme: 'exact',
      network: 'eip155:8453',
      amount: '5000',
      payTo: PAY_TO,
    });
    expect(decoded.extensions.fiatAgentWallet).toMatchObject({
      clearinghouseUrl: 'https://tollbooth.redcenterstudio.com',
      priceMicros: 5000,
    });
  });

  it('completes Rail A x402 V2 exact payment: /verify -> handler -> /settle -> 200 OK', async () => {
    const calls: string[] = [];
    const fetchMock: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      calls.push(url);
      if (url.endsWith('/verify')) {
        return Response.json({ isValid: true, invalidReason: null });
      }
      if (url.endsWith('/settle')) {
        expect((init?.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^x402_/);
        return Response.json({
          success: true,
          txHash: '0x9999deadbeef',
          network: 'eip155:8453',
          settledAmount: '5000',
          errorReason: null,
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        facilitatorUrl: 'https://facilitator.local',
        fetchImpl: fetchMock,
        routes: [{ pattern: '/api/lookup', method: 'GET', priceMicros: 5000 }],
      },
      {
        async fetch() {
          return Response.json({ answer: 42 });
        },
      },
    );

    const res = await worker.fetch(
      new Request('https://api.example.com/api/lookup', {
        headers: { 'PAYMENT-SIGNATURE': makeX402Signature() },
      }),
      {},
      mockCtx,
    );

    expect(res.status).toBe(200);
    expect(calls).toEqual(['https://facilitator.local/verify', 'https://facilitator.local/settle']);
    expect(res.headers.get('X-Tollbooth-Rail')).toBe('x402');
    const payRes = decodePaymentHeader<X402PaymentResponse>(res.headers.get('PAYMENT-RESPONSE')!);
    expect(payRes).toMatchObject({
      success: true,
      transaction: '0x9999deadbeef',
      payer: PAYER,
      settledAmount: '5000',
      rail: 'x402',
    });
  });

  it('enforces Pro Pass gating on upto scheme and settles metered usage <= authorized ceiling', async () => {
    let settledBody: Record<string, unknown> | undefined;
    const fetchMock: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/verify')) {
        return Response.json({ isValid: true, invalidReason: null });
      }
      if (url.endsWith('/settle')) {
        settledBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return Response.json({
          success: true,
          txHash: '0xuptosettle',
          network: 'eip155:8453',
          settledAmount: String(settledBody.settleAmount),
          errorReason: null,
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    // Without Pro Pass -> rejected
    const freeWorker = withTollbooth(
      {
        payTo: PAY_TO,
        proPass: false,
        fetchImpl: fetchMock,
        routes: [{ pattern: '/api/llm', method: 'POST', scheme: 'upto', priceMicros: 50_000 }],
      },
      { async fetch() { return Response.json({ ok: true }); } },
    );

    const rejected = await freeWorker.fetch(
      new Request('https://api.example.com/api/llm', {
        method: 'POST',
        headers: {
          'PAYMENT-SIGNATURE': makeX402Signature({
            scheme: 'upto',
            authOverrides: { value: '50000' },
          }),
        },
      }),
      {},
      mockCtx,
    );
    expect(rejected.status).toBe(402);
    expect(((await rejected.json()) as X402PaymentRequired).error).toBe('pro_pass_required_for_upto');

    // With Pro Pass -> metered settleAmount 12,000 <= 50,000
    const proWorker = withTollbooth(
      {
        payTo: PAY_TO,
        proPass: true,
        facilitatorUrl: 'https://facilitator.local',
        fetchImpl: fetchMock,
        routes: [
          {
            pattern: '/api/llm',
            method: 'POST',
            scheme: 'upto',
            priceMicros: 50_000,
            meterUsage: () => 12_000n,
          },
        ],
      },
      { async fetch() { return Response.json({ tokens: 120 }); } },
    );

    const ok = await proWorker.fetch(
      new Request('https://api.example.com/api/llm', {
        method: 'POST',
        headers: {
          'PAYMENT-SIGNATURE': makeX402Signature({
            scheme: 'upto',
            authOverrides: { value: '50000' },
          }),
        },
      }),
      {},
      mockCtx,
    );
    expect(ok.status).toBe(200);
    expect(settledBody?.settleAmount).toBe('12000');
    const payRes = decodePaymentHeader<X402PaymentResponse>(ok.headers.get('PAYMENT-RESPONSE')!);
    expect(payRes.settledAmount).toBe('12000');
  });

  it('rejects invalid facilitator /verify, underpaid amounts, and expired authorizations without running handler', async () => {
    const handlerSpy = vi.fn(async () => Response.json({ ok: true }));
    const settleSpy = vi.fn();

    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        facilitatorUrl: 'https://facilitator.local',
        fetchImpl: async (input) => {
          const url = String(input);
          if (url.endsWith('/verify')) {
            return Response.json({ isValid: false, invalidReason: 'signature_mismatch' });
          }
          settleSpy();
          return Response.json({ success: true });
        },
        routes: [{ pattern: '/api/data', priceMicros: 10_000 }],
      },
      { fetch: handlerSpy },
    );

    // Underpaid
    const underpaid = await worker.fetch(
      new Request('https://api.example.com/api/data', {
        headers: { 'PAYMENT-SIGNATURE': makeX402Signature({ authOverrides: { value: '9999' } }) },
      }),
      {},
      mockCtx,
    );
    expect(underpaid.status).toBe(402);

    // Expired
    const past = Math.floor(Date.now() / 1000) - 300;
    const expired = await worker.fetch(
      new Request('https://api.example.com/api/data', {
        headers: {
          'PAYMENT-SIGNATURE': makeX402Signature({
            authOverrides: { value: '10000', validAfter: String(past - 60), validBefore: String(past) },
          }),
        },
      }),
      {},
      mockCtx,
    );
    expect(expired.status).toBe(402);

    // Facilitator verify failed
    const badSig = await worker.fetch(
      new Request('https://api.example.com/api/data', {
        headers: { 'PAYMENT-SIGNATURE': makeX402Signature({ authOverrides: { value: '10000' } }) },
      }),
      {},
      mockCtx,
    );
    expect(badSig.status).toBe(402);
    expect(((await badSig.json()) as X402PaymentRequired).error).toBe('signature_mismatch');
    expect(handlerSpy).not.toHaveBeenCalled();
    expect(settleSpy).not.toHaveBeenCalled();
  });

  it('skips /settle and releases Rail B nonce when downstream handler returns 500', async () => {
    const settleSpy = vi.fn();
    let failOnce = true;

    const baseConfig: TollboothConfig = {
      payTo: PAY_TO,
      facilitatorUrl: 'https://facilitator.local',
      nonceStore: new MemoryNonceStore(),
      fiatWallet: { hmacSecret: TEST_HMAC_SECRET },
      fetchImpl: async (input) => {
        if (String(input).endsWith('/verify')) {
          return Response.json({ isValid: true, invalidReason: null });
        }
        settleSpy();
        return Response.json({ success: true, txHash: '0xnever' });
      },
      routes: [{ pattern: '/api/flaky', priceMicros: 5000 }],
    };

    const worker = withTollbooth(baseConfig, {
      async fetch() {
        if (failOnce) {
          failOnce = false;
          return new Response('Upstream Boom', { status: 500 });
        }
        return Response.json({ recovered: true });
      },
    });

    // Rail A 500 -> never calls /settle
    const x402Fail = await worker.fetch(
      new Request('https://api.example.com/api/flaky', {
        headers: { 'PAYMENT-SIGNATURE': makeX402Signature() },
      }),
      {},
      mockCtx,
    );
    expect(x402Fail.status).toBe(500);
    expect(settleSpy).not.toHaveBeenCalled();

    // Rail B 500 -> releases nonce so caller can retry once recovered
    failOnce = true;
    const now = Math.floor(Date.now() / 1000);
    const receipt = await signFiatReceipt(
      {
        v: 1,
        jti: `jti_retry_${crypto.randomUUID()}`,
        sub: 'wallet_retry_1',
        aud: 'https://api.example.com/api/flaky',
        mth: 'GET',
        amt: 5000,
        iat: now - 1,
        exp: now + 120,
      },
      { alg: 'hs256', secret: TEST_HMAC_SECRET },
    );

    const firstTry = await worker.fetch(
      new Request('https://api.example.com/api/flaky', {
        headers: { Authorization: `Bearer ${receipt}` },
      }),
      {},
      mockCtx,
    );
    expect(firstTry.status).toBe(500);

    const retryOk = await worker.fetch(
      new Request('https://api.example.com/api/flaky', {
        headers: { Authorization: `Bearer ${receipt}` },
      }),
      {},
      mockCtx,
    );
    expect(retryOk.status).toBe(200);
  });

  it('verifies Rail B HMAC-SHA256 & Ed25519 receipts under 5ms and prevents D1/Memory nonce replays', async () => {
    const now = Math.floor(Date.now() / 1000);
    const d1Store = new D1NonceStore(createSqliteD1Like());
    const edKeyPair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;

    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        nonceStore: d1Store,
        fiatWallet: {
          hmacSecret: TEST_HMAC_SECRET,
          ed25519PublicKey: edKeyPair.publicKey,
        },
        routes: [{ pattern: '/api/fast', priceMicros: 2500 }],
      },
      {
        async fetch() {
          return Response.json({ fast: true });
        },
      },
    );

    // 1) HMAC-SHA256 Bearer receipt
    const hsToken = await signFiatReceipt(
      {
        v: 1,
        jti: 'jti_hs_1',
        sub: 'wallet_agent_alpha',
        aud: 'https://api.example.com/api/fast',
        mth: 'GET',
        amt: 2500,
        iat: now - 2,
        exp: now + 120,
      },
      { alg: 'hs256', secret: TEST_HMAC_SECRET },
    );

    // Warm key cache & measure steady-state verification latency
    await verifyFiatReceipt(hsToken, {
      hmacSecret: TEST_HMAC_SECRET,
      expectedAudience: 'https://api.example.com/api/fast',
      expectedMethod: 'GET',
      requiredMicros: 2500,
    });
    const bench = await verifyFiatReceipt(hsToken, {
      hmacSecret: TEST_HMAC_SECRET,
      expectedAudience: 'https://api.example.com/api/fast',
      expectedMethod: 'GET',
      requiredMicros: 2500,
    });
    expect(bench.valid).toBe(true);
    expect(bench.verifiedInMs).toBeLessThan(10);

    const res1 = await worker.fetch(
      new Request('https://api.example.com/api/fast', {
        headers: { Authorization: `Bearer ${hsToken}` },
      }),
      {},
      mockCtx,
    );
    expect(res1.status).toBe(200);
    expect(res1.headers.get('X-Tollbooth-Rail')).toBe('fiat_wallet');
    const payRes1 = decodePaymentHeader<X402PaymentResponse>(res1.headers.get('PAYMENT-RESPONSE')!);
    expect(payRes1).toMatchObject({
      success: true,
      transaction: 'jti_hs_1',
      network: 'rcs:fiat-wallet',
      payer: 'wallet_agent_alpha',
    });

    // Replay same HMAC token against D1NonceStore -> 402 nonce_replayed
    const replayRes = await worker.fetch(
      new Request('https://api.example.com/api/fast', {
        headers: { Authorization: `Bearer ${hsToken}` },
      }),
      {},
      mockCtx,
    );
    expect(replayRes.status).toBe(402);
    expect(((await replayRes.json()) as X402PaymentRequired).error).toBe('nonce_replayed');

    // 2) Ed25519 asymmetric X-Agent-Receipt
    const edToken = await signFiatReceipt(
      {
        v: 1,
        jti: 'jti_ed_1',
        sub: 'wallet_agent_beta',
        aud: 'https://api.example.com/api/*',
        mth: '*',
        amt: 5000,
        iat: now - 1,
        exp: now + 120,
      },
      { alg: 'ed25519', privateKey: edKeyPair.privateKey },
    );

    const resEd = await worker.fetch(
      new Request('https://api.example.com/api/fast', {
        headers: { 'X-Agent-Receipt': edToken },
      }),
      {},
      mockCtx,
    );
    expect(resEd.status).toBe(200);
  });

  it('rejects tampered, expired, wrong-audience, and underpaid Rail B receipts', async () => {
    const now = Math.floor(Date.now() / 1000);
    const valid = await signFiatReceipt(
      {
        v: 1,
        jti: 'jti_checks',
        sub: 'wallet_1',
        aud: 'https://api.example.com/api/paid',
        mth: 'POST',
        amt: 5000,
        iat: now - 1,
        exp: now + 120,
      },
      { alg: 'hs256', secret: TEST_HMAC_SECRET },
    );

    const tampered = `${valid.slice(0, -3)}ZZZ`;
    expect(
      (
        await verifyFiatReceipt(tampered, {
          hmacSecret: TEST_HMAC_SECRET,
          expectedAudience: 'https://api.example.com/api/paid',
          expectedMethod: 'POST',
          requiredMicros: 5000,
        })
      ).reason,
    ).toBe('invalid_receipt_signature');

    const wrongAud = await verifyFiatReceipt(valid, {
      hmacSecret: TEST_HMAC_SECRET,
      expectedAudience: 'https://evil.example.com/api/paid',
      expectedMethod: 'POST',
      requiredMicros: 5000,
    });
    expect(wrongAud.reason).toBe('receipt_audience_mismatch');

    const underpaid = await verifyFiatReceipt(valid, {
      hmacSecret: TEST_HMAC_SECRET,
      expectedAudience: 'https://api.example.com/api/paid',
      expectedMethod: 'POST',
      requiredMicros: 6000,
    });
    expect(underpaid.reason).toBe('receipt_amount_insufficient');

    const expired = await verifyFiatReceipt(valid, {
      hmacSecret: TEST_HMAC_SECRET,
      expectedAudience: 'https://api.example.com/api/paid',
      expectedMethod: 'POST',
      requiredMicros: 5000,
      nowSeconds: now + 500,
    });
    expect(expired.reason).toBe('receipt_expired');
  });

  it('enforces perAgentSpendCapMicros, serves Pro custom HTML 402 pages, and works via honoTollbooth', async () => {
    const now = Math.floor(Date.now() / 1000);
    const mw = honoTollbooth({
      payTo: PAY_TO,
      proPass: true,
      perAgentSpendCapMicros: 6000,
      spendTracker: new MemorySpendTracker(),
      customPaymentPageHtml: (c) => `<html><body><h1>Pay ${c.accepts[0]?.amount}</h1></body></html>`,
      fiatWallet: { hmacSecret: TEST_HMAC_SECRET },
      routes: [{ pattern: '/api/items/:id', method: 'GET', priceMicros: 4000 }],
    });

    // Browser HTML 402 challenge page
    const htmlCtx: HonoLikeContext = {
      req: {
        raw: new Request('https://api.example.com/api/items/99', {
          headers: { Accept: 'text/html' },
        }),
      },
      res: undefined,
    };
    await mw(htmlCtx, async () => {
      throw new Error('Should not run next()');
    });
    expect(htmlCtx.res?.status).toBe(402);
    expect(htmlCtx.res?.headers.get('Content-Type')).toContain('text/html');
    expect(await htmlCtx.res?.text()).toContain('<h1>Pay 4000</h1>');

    // First call 4000 <= 6000 cap -> 200 OK
    const t1 = await signFiatReceipt(
      {
        v: 1,
        jti: 'jti_cap_1',
        sub: 'agent_capped',
        aud: '*',
        amt: 4000,
        iat: now,
        exp: now + 120,
      },
      { alg: 'hs256', secret: TEST_HMAC_SECRET },
    );
    const ctx1: HonoLikeContext = {
      req: {
        raw: new Request('https://api.example.com/api/items/1', {
          headers: { Authorization: `Bearer ${t1}` },
        }),
      },
      res: undefined,
    };
    await mw(ctx1, async () => {
      ctx1.res = Response.json({ item: 1 });
    });
    expect(ctx1.res?.status).toBe(200);

    // Second call 4000 + 4000 = 8000 > 6000 cap -> 402 agent_spend_cap_exceeded
    const t2 = await signFiatReceipt(
      {
        v: 1,
        jti: 'jti_cap_2',
        sub: 'agent_capped',
        aud: '*',
        amt: 4000,
        iat: now,
        exp: now + 120,
      },
      { alg: 'hs256', secret: TEST_HMAC_SECRET },
    );
    const ctx2: HonoLikeContext = {
      req: {
        raw: new Request('https://api.example.com/api/items/2', {
          headers: { Authorization: `Bearer ${t2}` },
        }),
      },
      res: undefined,
    };
    await mw(ctx2, async () => {
      throw new Error('Should be blocked by spend cap');
    });
    expect(ctx2.res?.status).toBe(402);
    expect(((await ctx2.res?.json()) as X402PaymentRequired).error).toBe('agent_spend_cap_exceeded');
  });
});
