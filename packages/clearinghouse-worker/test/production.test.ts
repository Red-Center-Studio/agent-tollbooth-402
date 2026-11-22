import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import type { DatabaseSync } from 'node:sqlite';
import worker, { signStripeWebhookPayload, type Env } from '../src/index.js';
import { transferWithAuthorizationDigest, USDC_DOMAINS } from '../src/evm.js';
import { verifyFiatReceipt } from '@redcenterstudio/agent-tollbooth-edge';
import { createSqliteD1, MIGRATION_SQL } from './sqlite-d1.js';

const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;
const BASE = 'https://tollbooth.redcenterstudio.com';
const WEBHOOK_SECRET = 'whsec_prod_test_secret';
const PAY_TO = '0x1111111111111111111111111111111111111111';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** A real payer: secp256k1 key and its Ethereum address. */
function makePayer() {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, false).slice(1);
  return { priv, address: `0x${hex(keccak_256(pub).slice(-20))}` };
}

function signedPayment(
  payer: { priv: Uint8Array; address: string },
  opts: { network?: string; value?: string; nonce?: string; tamperValue?: string } = {},
) {
  const network = opts.network ?? 'eip155:84532';
  const domain = USDC_DOMAINS[network]!;
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: payer.address,
    to: PAY_TO,
    value: opts.value ?? '10000',
    validAfter: String(now - 5),
    validBefore: String(now + 120),
    nonce: opts.nonce ?? `0x${hex(crypto.getRandomValues(new Uint8Array(32)))}`,
  };
  const digest = transferWithAuthorizationDigest(domain, authorization)!;
  const sig = secp256k1.sign(digest, payer.priv);
  const signature = `0x${hex(sig.toCompactRawBytes())}${(27 + sig.recovery).toString(16)}`;
  const body = {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      scheme: 'exact',
      network,
      accepted: { scheme: 'exact', network },
      payload: { signature, authorization: { ...authorization, value: opts.tamperValue ?? authorization.value } },
    },
    paymentRequirements: {
      scheme: 'exact',
      network,
      amount: '10000',
      asset: domain.verifyingContract,
      payTo: PAY_TO,
      resource: 'https://api.example.com/data',
      maxTimeoutSeconds: 60,
    },
  };
  return { body, nonce: authorization.nonce };
}

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

const mcp = (name: string, args: Record<string, unknown>, key?: string) =>
  post(
    '/mcp',
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
    key ? { Authorization: `Bearer ${key}` } : {},
  );

describe('Production mode: real x402 verification and settlement', () => {
  let env: Env;
  let raw: DatabaseSync;

  beforeEach(() => {
    const db = createSqliteD1(MIGRATION_SQL);
    raw = db.raw;
    env = {
      DB: db.d1,
      RECEIPT_SIGNING_SECRET: 'unused_in_this_suite',
      CLEARINGHOUSE_API_KEY: 'rcs_admin_test_key',
      STRIPE_CONNECT_WEBHOOK_SECRET: WEBHOOK_SECRET,
      ENVIRONMENT: 'production',
    };
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('accepts a real EIP-712 signature and rejects tampered, mock and upto payments', async () => {
    const payer = makePayer();
    const good = signedPayment(payer);
    const ok = (await (await worker.fetch(post('/verify', good.body), env, ctx)).json()) as { isValid: boolean };
    expect(ok.isValid).toBe(true);

    const tampered = signedPayment(payer, { tamperValue: '20000' });
    const bad = (await (await worker.fetch(post('/verify', tampered.body), env, ctx)).json()) as {
      isValid: boolean;
      invalidReason: string;
    };
    expect(bad).toMatchObject({ isValid: false, invalidReason: 'signature_mismatch' });

    const mock = signedPayment(payer);
    mock.body.paymentPayload.payload.signature = '0x' + 'cd'.repeat(65);
    const mockRes = (await (await worker.fetch(post('/verify', mock.body), env, ctx)).json()) as { isValid: boolean };
    expect(mockRes.isValid).toBe(false);

    const hmac = signedPayment(payer);
    hmac.body.paymentPayload.payload.signature = 'hmac_sha256:' + 'ab'.repeat(32);
    const hmacRes = (await (await worker.fetch(post('/verify', hmac.body), env, ctx)).json()) as { isValid: boolean };
    expect(hmacRes.isValid).toBe(false);

    const upto = signedPayment(payer);
    upto.body.paymentRequirements.scheme = 'upto';
    upto.body.paymentPayload.scheme = 'upto';
    upto.body.paymentPayload.accepted.scheme = 'upto';
    const uptoRes = (await (await worker.fetch(post('/verify', upto.body), env, ctx)).json()) as { invalidReason: string };
    expect(uptoRes.invalidReason).toBe('upto_not_supported_onchain');
  });

  it('settles mainnet only for pass holders, and spends no nonce when it refuses', async () => {
    const now = Math.floor(Date.now() / 1000);
    const addDev = (id: string, tier: string, payout: string) =>
      raw
        .prepare(
          "INSERT INTO developers (id, email, name, tier, stripe_account_id, payout_address, created_at) VALUES (?, ?, ?, ?, NULL, ?, ?)",
        )
        .run(id, `${id}@example.com`, id, tier, payout, now);

    // Unknown payTo: no developer account, no pass.
    const unknown = await worker.fetch(post('/settle', signedPayment(makePayer(), { network: 'eip155:8453' }).body), env, ctx);
    expect(unknown.status).toBe(402);
    expect(((await unknown.json()) as { errorReason: string; code: string })).toMatchObject({
      errorReason: 'pass_required_for_mainnet_settlement',
      code: 'PRO_PASS_REQUIRED',
    });

    // A registered developer without a pass is refused too.
    addDev('dev_nopass', 'hybrid', PAY_TO);
    const noPass = await worker.fetch(post('/settle', signedPayment(makePayer(), { network: 'eip155:8453' }).body), env, ctx);
    expect(noPass.status).toBe(402);
    expect(raw.prepare('SELECT COUNT(*) AS n FROM used_nonces').get()).toMatchObject({ n: 0 });

    // With a Pro Pass the pass gate opens; the next check is the facilitator itself.
    raw.prepare("UPDATE developers SET tier = 'pro' WHERE id = 'dev_nopass'").run();
    const res = await worker.fetch(post('/settle', signedPayment(makePayer(), { network: 'eip155:8453' }).body), env, ctx);
    expect(res.status).toBe(503);
    expect(((await res.json()) as { errorReason: string }).errorReason).toBe('settlement_not_configured');
    expect(raw.prepare('SELECT COUNT(*) AS n FROM used_nonces').get()).toMatchObject({ n: 0 });

    // The monthly allowance: 10,000 hosted mainnet settlements this UTC month. Testnet and last month do not count.
    const insert = raw.prepare(
      "INSERT INTO ledger_entries (id, idempotency_key, wallet_id, developer_id, route_id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json, created_at) VALUES (?, ?, NULL, 'dev_nopass', NULL, 'x402', 'settlement', 10000, 0, 0, 10000, 'tx', ?, ?)",
    );
    const mainnetMeta = JSON.stringify({ network: 'eip155:8453', payer: '0x0', sandbox: false });
    const testnetMeta = JSON.stringify({ network: 'eip155:84532', payer: '0x0', sandbox: false });
    const lastMonth = now - 40 * 86400;
    raw.exec('BEGIN');
    for (let i = 0; i < 9_999; i++) insert.run(`led_m${i}`, `idem_m${i}`, mainnetMeta, now);
    for (let i = 0; i < 50; i++) insert.run(`led_t${i}`, `idem_t${i}`, testnetMeta, now);
    for (let i = 0; i < 50; i++) insert.run(`led_o${i}`, `idem_o${i}`, mainnetMeta, lastMonth);
    raw.exec('COMMIT');
    const under = await worker.fetch(post('/settle', signedPayment(makePayer(), { network: 'eip155:8453' }).body), env, ctx);
    expect(under.status).toBe(503); // 9,999 used: still allowed, reaches the facilitator check
    insert.run('led_m_last', 'idem_m_last', mainnetMeta, now);
    const over = await worker.fetch(post('/settle', signedPayment(makePayer(), { network: 'eip155:8453' }).body), env, ctx);
    expect(over.status).toBe(429);
    expect(((await over.json()) as { errorReason: string; code: string })).toMatchObject({
      errorReason: 'monthly_hosted_allowance_reached',
      code: 'ALLOWANCE_REACHED',
    });
    expect(raw.prepare('SELECT COUNT(*) AS n FROM used_nonces').get()).toMatchObject({ n: 0 });
  });

  it('settles Base Sepolia through the upstream facilitator and records the real transaction', async () => {
    const tx = `0x${'ab'.repeat(32)}`;
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init.body)) });
      return Response.json({ success: true, transaction: tx, network: 'eip155:84532' });
    });
    const p = signedPayment(makePayer());
    const res = await worker.fetch(post('/settle', p.body), env, ctx);
    const json = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(json).toMatchObject({ success: true, txHash: tx, settledAmount: '10000', platformFeeMicros: 0 });
    expect(calls[0]?.url).toBe('https://x402.org/facilitator/settle');
    const sent = calls[0]!.body as {
      paymentRequirements: { extra: { name: string } };
      paymentPayload: { accepted: { payTo: string } };
    };
    expect(sent.paymentRequirements.extra.name).toBe('USDC');
    expect(sent.paymentPayload.accepted.payTo).toBe(PAY_TO);
    expect(raw.prepare('SELECT tx_reference FROM ledger_entries').get()).toMatchObject({ tx_reference: tx });
  });

  it('frees the nonce when the facilitator rejects, so the payer can retry', async () => {
    vi.stubGlobal('fetch', async () => Response.json({ success: false, errorReason: 'insufficient_funds' }, { status: 400 }));
    const p = signedPayment(makePayer());
    const res = await worker.fetch(post('/settle', p.body), env, ctx);
    expect(res.status).toBe(502);
    expect(((await res.json()) as { errorReason: string }).errorReason).toBe('insufficient_funds');
    expect(raw.prepare('SELECT COUNT(*) AS n FROM used_nonces').get()).toMatchObject({ n: 0 });
    expect(raw.prepare('SELECT COUNT(*) AS n FROM ledger_entries').get()).toMatchObject({ n: 0 });
  });

  it('sends CORS headers and prunes expired nonces on the hourly cron', async () => {
    const res = await worker.fetch(new Request(`${BASE}/health`), env, ctx);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    const now = Math.floor(Date.now() / 1000);
    const ins = raw.prepare(
      "INSERT INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, 'x402', 'p', '*', ?, ?)",
    );
    ins.run('old', now - 7200, now - 7300);
    ins.run('fresh', now + 60, now);
    await worker.scheduled({} as ScheduledController, env, ctx);
    const left = raw.prepare('SELECT nonce FROM used_nonces').all() as Array<{ nonce: string }>;
    expect(left.map((r) => r.nonce)).toEqual(['fresh']);
  });
});

describe('Production mode: self-serve accounts, scoped keys and Ed25519 receipts', () => {
  let env: Env;
  let raw: DatabaseSync;

  beforeEach(async () => {
    const db = createSqliteD1(MIGRATION_SQL);
    raw = db.raw;
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    env = {
      DB: db.d1,
      RECEIPT_SIGNING_SECRET: 'hs256_fallback_secret',
      CLEARINGHOUSE_API_KEY: 'rcs_admin_test_key',
      STRIPE_CONNECT_WEBHOOK_SECRET: WEBHOOK_SECRET,
      RECEIPT_ED25519_PRIVATE_JWK: JSON.stringify(jwk),
      ENVIRONMENT: 'production',
    };
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('registers a wallet, scopes its key, signs Ed25519 receipts and rotates the key', async () => {
    const reg = await worker.fetch(post('/wallet/register', { label: 'Research agent', email: 'Owner@Example.com' }), env, ctx);
    expect(reg.status).toBe(201);
    const { walletId, walletKey } = (await reg.json()) as { walletId: string; walletKey: string };
    expect(walletKey).toMatch(/^rcs_wk_/);
    // Only the hash is stored.
    expect(JSON.stringify(raw.prepare('SELECT * FROM api_keys').all())).not.toContain(walletKey);

    const other = (await (await worker.fetch(post('/wallet/register', {}), env, ctx)).json()) as { walletKey: string };

    const bal = (await (await worker.fetch(mcp('tollbooth_wallet_balance', { walletId }, walletKey), env, ctx)).json()) as {
      result: { structuredContent: { balanceMicros: number } };
    };
    expect(bal.result.structuredContent.balanceMicros).toBe(0);
    const denied = await worker.fetch(mcp('tollbooth_wallet_balance', { walletId }, other.walletKey), env, ctx);
    expect(denied.status).toBe(401);

    // Fund it and spend through a developer.
    raw.prepare('UPDATE agent_wallets SET balance_micros = 5000000 WHERE id = ?').run(walletId);
    const dev = (await (
      await worker.fetch(post('/developer/register', { email: 'dev@example.com', name: 'Dev Co' }), env, ctx)
    ).json()) as { developerId: string; developerKey: string };

    // A self-registered developer is not studio-owned: the card-funded wallet cannot pay them, and nothing is debited.
    const notStudio = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        { walletId, developerId: dev.developerId, audience: 'https://api.example.com', amountMicros: 10_000 },
        { Authorization: `Bearer ${walletKey}` },
      ),
      env,
      ctx,
    );
    expect(notStudio.status).toBe(403);
    expect((await notStudio.json()) as { error: string; code: string }).toMatchObject({
      error: 'fiat_wallet_studio_routes_only',
      code: 'RAIL_NOT_AVAILABLE',
    });
    const afterRefusal = raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId) as {
      balance_micros: number;
    };
    expect(afterRefusal.balance_micros).toBe(5_000_000);
    expect(raw.prepare('SELECT COUNT(*) AS n FROM ledger_entries').get()).toEqual({ n: 0 });

    env.STUDIO_DEVELOPER_IDS = dev.developerId;
    const issue = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        { walletId, developerId: dev.developerId, audience: 'https://api.example.com', amountMicros: 10_000 },
        { Authorization: `Bearer ${walletKey}` },
      ),
      env,
      ctx,
    );
    expect(issue.status).toBe(200);
    const { receipt } = (await issue.json()) as { receipt: string };
    expect(receipt.startsWith('rcs_receipt_ed25519.')).toBe(true);

    // A wallet key cannot spend from another wallet.
    const cross = await worker.fetch(
      post(
        '/wallet/issue-receipt',
        { walletId, developerId: dev.developerId, audience: 'https://api.example.com', amountMicros: 10_000 },
        { Authorization: `Bearer ${other.walletKey}` },
      ),
      env,
      ctx,
    );
    expect(cross.status).toBe(403);

    // Merchants verify with the public JWKS only.
    const jwks = (await (await worker.fetch(new Request(`${BASE}/.well-known/tollbooth-jwks.json`), env, ctx)).json()) as {
      keys: Array<{ x: string; crv: string }>;
    };
    expect(jwks.keys[0]?.crv).toBe('Ed25519');
    expect(JSON.stringify(jwks)).not.toContain('"d"');
    const verified = await verifyFiatReceipt(receipt, {
      ed25519PublicKey: jwks.keys[0]!.x,
      expectedAudience: 'https://api.example.com',
      expectedMethod: 'GET',
      requiredMicros: 10_000,
    });
    expect(verified.valid).toBe(true);

    // Ledger history for the wallet and the developer.
    const wl = (await (await worker.fetch(mcp('tollbooth_ledger_history', { walletId }, walletKey), env, ctx)).json()) as {
      result: { structuredContent: { entries: Array<{ type: string }> } };
    };
    expect(wl.result.structuredContent.entries[0]?.type).toBe('charge');
    const dl = await worker.fetch(new Request(`${BASE}/developer/ledger`, { headers: { Authorization: `Bearer ${dev.developerKey}` } }), env, ctx);
    expect(dl.status).toBe(200);

    // Rotation revokes the old key.
    const rot = (await (
      await worker.fetch(post('/keys/rotate', {}, { Authorization: `Bearer ${walletKey}` }), env, ctx)
    ).json()) as { walletKey: string };
    expect(rot.walletKey).not.toBe(walletKey);
    expect((await worker.fetch(mcp('tollbooth_wallet_balance', { walletId }, walletKey), env, ctx)).status).toBe(401);
    expect((await worker.fetch(mcp('tollbooth_wallet_balance', { walletId }, rot.walletKey), env, ctx)).status).toBe(200);
  });

  it('refuses a duplicate developer email and reports pass status to the key holder only', async () => {
    const first = (await (
      await worker.fetch(post('/developer/register', { email: 'a@example.com', name: 'A' }), env, ctx)
    ).json()) as { developerId: string; developerKey: string };
    const dup = await worker.fetch(post('/developer/register', { email: 'A@example.com', name: 'A again' }), env, ctx);
    expect(dup.status).toBe(409);
    const status = (await (
      await worker.fetch(mcp('tollbooth_pass_status', { developerId: first.developerId }, first.developerKey), env, ctx)
    ).json()) as { result: { structuredContent: Record<string, unknown> } };
    expect(status.result.structuredContent).toMatchObject({ tier: 'free', hostedMainnetSettlement: false });
    expect(status.result.structuredContent).not.toHaveProperty('fiatWalletFeeBps');
    expect((await worker.fetch(mcp('tollbooth_pass_status', { developerId: first.developerId }), env, ctx)).status).toBe(401);
  });

  it('keeps each payout wallet on one account and lets the owner set or correct it', async () => {
    const W1 = '0x' + '1a'.repeat(20);
    const W2 = '0x' + '2b'.repeat(20);
    const a = (await (
      await worker.fetch(post('/developer/register', { email: 'w1@example.com', name: 'W1', payoutAddress: W1 }), env, ctx)
    ).json()) as { developerId: string; developerKey: string; payoutAddress: string };
    expect(a.payoutAddress).toBe(W1);

    // Same wallet, any letter case, on a second account: refused.
    const squat = await worker.fetch(
      post('/developer/register', { email: 'w2@example.com', name: 'W2', payoutAddress: W1.toUpperCase().replace('0X', '0x') }),
      env,
      ctx,
    );
    expect(squat.status).toBe(409);
    expect(((await squat.json()) as { error: string }).error).toBe('payout_address_in_use');

    const b = (await (
      await worker.fetch(post('/developer/register', { email: 'w3@example.com', name: 'W3' }), env, ctx)
    ).json()) as { developerId: string; developerKey: string };
    // Needs the account's own developer key.
    expect((await worker.fetch(post('/developer/payout', { payoutAddress: W2 }), env, ctx)).status).toBe(401);
    // Cannot take a wallet another account holds.
    const taken = await worker.fetch(post('/developer/payout', { payoutAddress: W1 }, { Authorization: `Bearer ${b.developerKey}` }), env, ctx);
    expect(taken.status).toBe(409);
    const bad = await worker.fetch(post('/developer/payout', { payoutAddress: '0x123' }, { Authorization: `Bearer ${b.developerKey}` }), env, ctx);
    expect(bad.status).toBe(400);
    const set = await worker.fetch(post('/developer/payout', { payoutAddress: W2 }, { Authorization: `Bearer ${b.developerKey}` }), env, ctx);
    expect(set.status).toBe(200);
    const row = raw.prepare('SELECT payout_address FROM developers WHERE id = ?').get(b.developerId) as { payout_address: string };
    expect(row.payout_address).toBe(W2);
    // The owner may re-save their own wallet.
    expect(
      (await worker.fetch(post('/developer/payout', { payoutAddress: W1 }, { Authorization: `Bearer ${a.developerKey}` }), env, ctx)).status,
    ).toBe(200);
  });

  it('fulfils Payment Link sessions from client_reference_id and waits for unpaid ones', async () => {
    const { walletId } = (await (await worker.fetch(post('/wallet/register', {}), env, ctx)).json()) as { walletId: string };
    const { developerId } = (await (
      await worker.fetch(post('/developer/register', { email: 'p@example.com', name: 'P' }), env, ctx)
    ).json()) as { developerId: string };
    const send = async (id: string, object: Record<string, unknown>, type = 'checkout.session.completed') => {
      const payload = JSON.stringify({ id, type, data: { object } });
      const sig = await signStripeWebhookPayload(payload, WEBHOOK_SECRET, Math.floor(Date.now() / 1000));
      return worker.fetch(
        new Request(`${BASE}/webhook/stripe`, { method: 'POST', headers: { 'Stripe-Signature': sig }, body: payload }),
        env,
        ctx,
      );
    };
    const unpaid = await send('evt_1', { id: 'cs_unpaid_1', client_reference_id: walletId, amount_total: 1000, payment_status: 'unpaid' });
    expect(((await unpaid.json()) as { pending: boolean }).pending).toBe(true);
    const paid = await send(
      'evt_2',
      { id: 'cs_unpaid_1', client_reference_id: walletId, amount_total: 1000, payment_status: 'paid' },
      'checkout.session.async_payment_succeeded',
    );
    expect(paid.status).toBe(200);
    expect(raw.prepare('SELECT balance_micros FROM agent_wallets WHERE id = ?').get(walletId)).toMatchObject({
      balance_micros: 10_000_000,
    });
    const pass = await send('evt_3', { id: 'cs_pass_1', client_reference_id: developerId, amount_total: 3900, payment_status: 'paid' });
    expect(pass.status).toBe(200);
    expect(raw.prepare('SELECT tier FROM developers WHERE id = ?').get(developerId)).toMatchObject({ tier: 'pro' });

    // The return page confirms the credited top-up.
    const page = await (await worker.fetch(new Request(`${BASE}/pay?status=success&session_id=cs_unpaid_1`), env, ctx)).text();
    expect(page).toContain('$10.00 USD added to');
  });

  it('keeps checkout closed until sales open, then only for accounts that exist, with metadata', async () => {
    const withStripe: Env = { ...env, STRIPE_SECRET_KEY: 'sk_test_example_not_real_0000' };
    const { walletId } = (await (await worker.fetch(post('/wallet/register', {}), withStripe, ctx)).json()) as { walletId: string };

    const closed = await worker.fetch(post('/wallet/topup', { walletId, amountUsd: 10 }), withStripe, ctx);
    expect(closed.status).toBe(409);
    const closedPage = await (await worker.fetch(new Request(`${BASE}/pay`), withStripe, ctx)).text();
    expect(closedPage).toContain('Opens soon');
    expect(closedPage).not.toContain('id="buy"');

    // Sales open but no studio route accepts wallets yet: top-ups stay unsold and the page offers passes only.
    const passesOnly: Env = { ...withStripe, PAID_SALES_OPEN: 'true' };
    const noTopup = await worker.fetch(post('/wallet/topup', { walletId, amountUsd: 10 }), passesOnly, ctx);
    expect(noTopup.status).toBe(409);
    expect(((await noTopup.json()) as { error: string }).error).toBe('topups_not_open');
    const passPage = await (await worker.fetch(new Request(`${BASE}/pay`), passesOnly, ctx)).text();
    expect(passPage).toContain('Buy a pass.');
    expect(passPage).toContain('name="payout"');
    expect(passPage).toContain('<!--<form class="card tb-form" data-kind="topup">');
    expect(passPage).not.toContain('Opens soon');

    // A pass is never sold to an account without a payout wallet: it could not unlock anything.
    const noWallet = (await (
      await worker.fetch(post('/developer/register', { email: 'nowallet@example.com', name: 'No Wallet' }), passesOnly, ctx)
    ).json()) as { developerId: string };
    const refused = await worker.fetch(post('/wallet/topup', { developerId: noWallet.developerId, passTier: 'pro' }), passesOnly, ctx);
    expect(refused.status).toBe(409);
    expect(((await refused.json()) as { error: string }).error).toBe('payout_address_required');

    const open: Env = { ...withStripe, PAID_SALES_OPEN: 'true', STUDIO_DEVELOPER_IDS: 'dev_studio' };
    const missing = await worker.fetch(post('/wallet/topup', { walletId: 'wallet_00000000000000000000', amountUsd: 10 }), open, ctx);
    expect(missing.status).toBe(404);

    let sent = '';
    vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
      sent = String(init.body);
      return Response.json({ id: 'cs_test_1', url: 'https://checkout.stripe.com/c/pay/cs_test_1' });
    });
    const ok = await worker.fetch(
      post('/wallet/topup', { walletId, amountUsd: 10, successUrl: 'https://evil.example/' }),
      open,
      ctx,
    );
    expect(ok.status).toBe(200);
    const form = new URLSearchParams(sent);
    expect(form.get('client_reference_id')).toBe(walletId);
    expect(form.get('automatic_tax[enabled]')).toBe('true');
    expect(form.get('metadata[wallet_id]')).toBe(walletId);
    expect(form.get('success_url')).toBe(`${BASE}/pay?status=success&session_id={CHECKOUT_SESSION_ID}`);
    const openPage = await (await worker.fetch(new Request(`${BASE}/pay`), open, ctx)).text();
    expect(openPage).toContain('id="buy"');
  });
});
