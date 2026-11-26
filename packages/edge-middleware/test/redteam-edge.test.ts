import { describe, expect, it, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  D1NonceStore,
  DEFAULT_PAYMENT_URL,
  MemoryNonceStore,
  MemorySpendTracker,
  encodePaymentHeader,
  honoTollbooth,
  renderDefault402HtmlPage,
  signFiatReceipt,
  usdToMicros,
  verifyFiatReceipt,
  withTollbooth,
  type D1LikeDatabase,
  type HonoLikeContext,
  type X402PaymentRequired,
} from '../src/index.js';

const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const SECRET = 'rcs_redteam_edge_secret_32bytes_min';

const mockCtx = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
} as unknown as ExecutionContext;

describe('Red-Team Round 1: Edge Middleware Auth, Path & XSS Attacks', () => {
  it('Attack 1C: blocks double-slash and encoded-slash paywall path bypasses', async () => {
    const handler = vi.fn(async () => Response.json({ leaked: true }));
    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        mode: 'sandbox',
        routes: [{ pattern: '/api/*', priceMicros: 10_000 }],
      },
      { fetch: handler },
    );

    const doubleSlash = await worker.fetch(new Request('https://api.example.com//api/secret'), {}, mockCtx);
    expect(doubleSlash.status).toBe(402);

    const middleDouble = await worker.fetch(new Request('https://api.example.com/api//secret'), {}, mockCtx);
    expect(middleDouble.status).toBe(402);

    const encodedSlash = await worker.fetch(new Request('https://api.example.com/%2Fapi/secret'), {}, mockCtx);
    expect(encodedSlash.status).toBe(402);

    expect(handler).not.toHaveBeenCalled();
  });

  it('Attack 1F: encoded dot-segments cannot turn a gated path into an exempt or ungated one', async () => {
    const handler = vi.fn(async () => Response.json({ leaked: true }));
    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        mode: 'sandbox',
        routes: [{ pattern: '/api/*', priceMicros: 10_000 }],
      },
      { fetch: handler },
    );

    // Routers such as Hono leave %2F encoded, so these still reach the /api/* handler downstream.
    for (const path of ['/api/..%2Fhealth', '/api/..%2Fwebhook%2Fstripe', '/api/..%2Ffree', '/api/%2E%2E%2Ffree']) {
      const res = await worker.fetch(new Request(`https://api.example.com${path}`), {}, mockCtx);
      expect(res.status, path).toBe(402);
    }
    expect(handler).not.toHaveBeenCalled();

    // Genuine exempt paths still pass through.
    const health = await worker.fetch(new Request('https://api.example.com/health'), {}, mockCtx);
    expect(health.status).toBe(200);
  });

  it('Attack 1D: blocks lookalike-domain wildcard suffix bypass on receipt audience', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signFiatReceipt(
      {
        v: 1,
        jti: `jti_aud_${now}`,
        sub: 'wallet_1',
        aud: 'https://api.example.com*',
        mth: 'GET',
        amt: 10_000,
        iat: now - 1,
        exp: now + 120,
      },
      { alg: 'hs256', secret: SECRET },
    );

    const spoofedDomain = await verifyFiatReceipt(token, {
      hmacSecret: SECRET,
      expectedAudience: 'https://api.example.com.evil.com/data',
      expectedMethod: 'GET',
      requiredMicros: 10_000,
    });
    expect(spoofedDomain.valid).toBe(false);
    expect(spoofedDomain.reason).toBe('receipt_audience_mismatch');

    // Legitimate prefix on same origin still works
    const legit = await verifyFiatReceipt(token, {
      hmacSecret: SECRET,
      expectedAudience: 'https://api.example.com/v1/data',
      expectedMethod: 'GET',
      requiredMicros: 10_000,
    });
    expect(legit.valid).toBe(true);
  });

  it('Attack 1E: sanitizes javascript: and data: paymentUrl injection in HTML 402 card', () => {
    const maliciousChallenge: X402PaymentRequired = {
      x402Version: 2,
      code: 'MISSING_PAYMENT',
      error: 'Payment required',
      fix_hint: 'Pay first',
      priceUsd: '0.01',
      priceMicros: 10_000,
      acceptedRails: ['x402-v2'],
      paymentUrl: 'javascript:alert(document.domain)',
      resource: {
        url: 'https://api.example.com/data',
        description: 'Protected',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          amount: '10000',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          payTo: PAY_TO,
          maxTimeoutSeconds: 60,
        },
      ],
      extensions: {},
    };

    const html = renderDefault402HtmlPage(maliciousChallenge, new Request('https://api.example.com/data'));
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain(`href="${DEFAULT_PAYMENT_URL}"`);
  });
});

describe('Red-Team Round 3: Edge Middleware Hostile Payloads & Boundary Chaos', () => {
  it('Attack 3C: cleanly rejects JSON null/primitive PAYMENT-SIGNATURE, signed null receipts, and boolean/array usdToMicros', async () => {
    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        mode: 'sandbox',
        routes: [{ pattern: '/api/*', priceMicros: 10_000 }],
      },
      async () => Response.json({ ok: true }),
    );

    // Base64 of "null" -> must return 402 JSON, never throw unhandled TypeError
    const resNull = await worker.fetch(
      new Request('https://api.example.com/api/data', {
        headers: { 'PAYMENT-SIGNATURE': 'bnVsbA==' },
      }),
      {},
      mockCtx,
    );
    expect(resNull.status).toBe(402);

    // Base64 of "[1,2,3]"
    const resArr = await worker.fetch(
      new Request('https://api.example.com/api/data', {
        headers: { 'PAYMENT-SIGNATURE': encodePaymentHeader([1, 2, 3]) },
      }),
      {},
      mockCtx,
    );
    expect(resArr.status).toBe(402);

    // Sign a literal JSON "null" receipt payload with the real HMAC secret
    const payloadB64 = Buffer.from('null', 'utf8').toString('base64url');
    const signingInput = `hs256.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
    const sigB64 = Buffer.from(sigBuf).toString('base64url');
    const forgedNullReceipt = `rcs_receipt_${signingInput}.${sigB64}`;

    const verifyRes = await verifyFiatReceipt(forgedNullReceipt, {
      hmacSecret: SECRET,
      expectedAudience: 'https://api.example.com/api/data',
      expectedMethod: 'GET',
      requiredMicros: 10_000,
    });
    expect(verifyRes.valid).toBe(false);
    expect(verifyRes.reason).toBe('invalid_receipt_claims_schema');

    // usdToMicros rejects booleans, arrays, objects
    expect(() => usdToMicros(true as unknown as number)).toThrow();
    expect(() => usdToMicros([1] as unknown as number)).toThrow();
  });
});

describe('Red-Team Round 4: Edge Middleware State Desync & Mid-Flight Exceptions', () => {
  it('Attack 4A: releases consumed nonce and rolls back spend cap when downstream handler throws in withTollbooth & honoTollbooth', async () => {
    const now = Math.floor(Date.now() / 1000);
    const nonceStore = new MemoryNonceStore();
    const spendTracker = new MemorySpendTracker();
    let shouldThrow = true;

    const handler = async () => {
      if (shouldThrow) {
        shouldThrow = false;
        throw new Error('Downstream DB connection crashed mid-flight');
      }
      return Response.json({ recovered: true });
    };

    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        nonceStore,
        spendTracker,
        perAgentSpendCapMicros: 5_000,
        fiatWallet: { hmacSecret: SECRET },
        routes: [{ pattern: '/api/op', priceMicros: 5_000 }],
      },
      handler,
    );

    const receipt = await signFiatReceipt(
      {
        v: 1,
        jti: `jti_crash_recover_${now}`,
        sub: 'agent_desync',
        aud: 'https://api.example.com/api/op',
        mth: 'GET',
        amt: 5_000,
        iat: now - 1,
        exp: now + 120,
      },
      { alg: 'hs256', secret: SECRET },
    );

    // First call throws downstream exception
    await expect(
      worker.fetch(
        new Request('https://api.example.com/api/op', {
          headers: { Authorization: `Bearer ${receipt}` },
        }),
        {},
        mockCtx,
      ),
    ).rejects.toThrow('Downstream DB connection crashed');

    // Retry with SAME receipt must succeed (nonce released AND spend cap rolled back)
    const retryRes = await worker.fetch(
      new Request('https://api.example.com/api/op', {
        headers: { Authorization: `Bearer ${receipt}` },
      }),
      {},
      mockCtx,
    );
    expect(retryRes.status).toBe(200);
    expect(await retryRes.json()).toEqual({ recovered: true });

    // Also verify honoTollbooth rolls back Rail A x402 nonce & spend cap on next() exception
    const honoNonce = new MemoryNonceStore();
    const honoSpend = new MemorySpendTracker();
    let failHono = true;
    const mw = honoTollbooth({
      payTo: PAY_TO,
      facilitatorUrl: 'https://facilitator.local',
      nonceStore: honoNonce,
      spendTracker: honoSpend,
      perAgentSpendCapMicros: 5_000,
      fetchImpl: async (url) => {
        if (String(url).endsWith('/verify')) {
          return Response.json({ isValid: true, invalidReason: null });
        }
        return Response.json({ success: true, txHash: '0xok' });
      },
      routes: [{ pattern: '/api/hono', priceMicros: 5_000 }],
    });

    const sigHeader = encodePaymentHeader({
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      accepted: { scheme: 'exact', network: 'eip155:8453' },
      payload: {
        signature: `0x${'ab'.repeat(65)}`,
        authorization: {
          from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          to: PAY_TO,
          value: '5000',
          validAfter: String(now - 5),
          validBefore: String(now + 120),
          nonce: `0x${'55'.repeat(32)}`,
        },
      },
    });

    const c1: HonoLikeContext = {
      req: { raw: new Request('https://api.example.com/api/hono', { headers: { 'PAYMENT-SIGNATURE': sigHeader } }) },
      res: undefined,
    };
    await expect(
      mw(c1, async () => {
        if (failHono) {
          failHono = false;
          throw new Error('Hono downstream boom');
        }
      }),
    ).rejects.toThrow('Hono downstream boom');

    const c2: HonoLikeContext = {
      req: { raw: new Request('https://api.example.com/api/hono', { headers: { 'PAYMENT-SIGNATURE': sigHeader } }) },
      res: undefined,
    };
    await mw(c2, async () => {
      c2.res = Response.json({ ok: true });
    });
    expect(c2.res?.status).toBe(200);
  });

  it('Attack 4E: 402 HTML card clipboard handler guards rejected clipboard promises', () => {
    const html = renderDefault402HtmlPage(
      {
        x402Version: 2,
        code: 'MISSING_PAYMENT',
        error: 'Pay',
        fix_hint: 'Pay',
        priceUsd: '0.01',
        priceMicros: 10_000,
        acceptedRails: ['x402-v2'],
        paymentUrl: DEFAULT_PAYMENT_URL,
        resource: { url: 'https://api.example.com/d', description: 'D', mimeType: 'application/json' },
        accepts: [
          {
            scheme: 'exact',
            network: 'eip155:8453',
            amount: '10000',
            asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
            payTo: PAY_TO,
            maxTimeoutSeconds: 60,
          },
        ],
        extensions: {},
      },
      new Request('https://api.example.com/d'),
    );
    expect(html).toContain('.catch(');
    expect(html).toContain('minmax(0, 1fr)');
    expect(html).toContain('overflow-wrap: anywhere');
    expect(html).toContain('flex-shrink: 0');
    expect(html).toContain('rel="icon"');
    // Round 8 regression: the single-rail grid must not use a bare 1fr track (min-content blowout at 320px).
    expect(html).toContain('.rails.one { grid-template-columns: minmax(0, 1fr); }');
    expect(html).not.toContain('.rails.one { grid-template-columns: 1fr; }');
  });
});

describe('Red-Team Round 7: Escalated Combined Siege â€” 10-Way Edge Concurrency & Path/Alg Fuzzing', () => {
  it('enforces strictly 1 winner out of 10 parallel Rail B D1NonceStore replay requests + blocks path/alg tricks', async () => {
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
    const d1Like: D1LikeDatabase = {
      prepare(query: string) {
        let vals: unknown[] = [];
        const stmt = {
          bind(...v: unknown[]) {
            vals = v;
            return stmt;
          },
          async run() {
            const info = db.prepare(query).run(...(vals as Array<string | number | bigint | null>));
            return { meta: { changes: Number(info.changes) } };
          },
        };
        return stmt;
      },
    };

    const edPair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
    const worker = withTollbooth(
      {
        payTo: PAY_TO,
        nonceStore: new D1NonceStore(d1Like),
        fiatWallet: { hmacSecret: SECRET, ed25519PublicKey: edPair.publicKey },
        exemptPaths: ['/health'],
        routes: [{ pattern: '/api/*', priceMicros: 5_000 }],
      },
      async () => Response.json({ ok: true }),
    );

    const now = Math.floor(Date.now() / 1000);
    const receipt = await signFiatReceipt(
      {
        v: 1,
        jti: `jti_10way_${now}`,
        sub: 'wallet_siege',
        aud: 'https://api.example.com/api/paid',
        mth: 'GET',
        amt: 5_000,
        iat: now - 1,
        exp: now + 120,
      },
      { alg: 'ed25519', privateKey: edPair.privateKey },
    );

    const hits = await Promise.all(
      Array.from({ length: 10 }, () =>
        worker.fetch(
          new Request('https://api.example.com/api/paid', {
            headers: { Authorization: `Bearer ${receipt}` },
          }),
          {},
          mockCtx,
        ),
      ),
    );
    const codes = hits.map((r) => r.status).sort((a, b) => a - b);
    expect(codes).toEqual([200, 402, 402, 402, 402, 402, 402, 402, 402, 402]);

    // Path normalization traversal tricks stay gated
    for (const p of ['//api//paid', '/api/%2Fpaid', '/health/%2e%2e/api/paid']) {
      expect((await worker.fetch(new Request(`https://api.example.com${p}`), {}, mockCtx)).status).toBe(402);
    }

    // Wrong-algorithm forged receipt check
    const hsAsEd = `rcs_receipt_ed25519.${receipt.split('.')[1]}.bad_sig_xyz`;
    const badVerify = await verifyFiatReceipt(hsAsEd, {
      hmacSecret: SECRET,
      ed25519PublicKey: edPair.publicKey,
      expectedAudience: 'https://api.example.com/api/paid',
      expectedMethod: 'GET',
      requiredMicros: 5_000,
    });
    expect(badVerify.valid).toBe(false);
  });
});
