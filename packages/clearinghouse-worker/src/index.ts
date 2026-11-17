import {
  CORS_ALLOW_HEADERS,
  CORS_EXPOSE_HEADERS,
  DEFAULT_CLOCK_SKEW_SECONDS,
  signFiatReceipt,
  type PaymentScheme,
  type RcsReceiptClaims,
  type X402PaymentSignature,
} from '@redcenterstudio/agent-tollbooth-edge';

export type DeveloperTier = 'free' | 'hybrid' | 'pro' | 'agency';
export type SettlementRail = 'fiat_wallet' | 'x402';

export interface Env {
  DB: D1Database;
  RECEIPT_SIGNING_SECRET: string;
  CLEARINGHOUSE_API_KEY: string;
  FACILITATOR_HMAC_SECRET?: string;
  PRO_PASS_URL?: string;
  ENVIRONMENT?: string;
}

export interface FeeBreakdown {
  grossMicros: number;
  feeBps: number;
  platformFeeMicros: number;
  developerNetMicros: number;
}

export interface PaymentRequirementsInput {
  scheme: PaymentScheme;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  resource?: string;
  maxTimeoutSeconds?: number;
}

export interface FacilitatorRequestBody {
  x402Version: number;
  paymentPayload: X402PaymentSignature;
  paymentRequirements: PaymentRequirementsInput;
  settleAmount?: string;
}

export interface IssueReceiptBody {
  walletId: string;
  developerId: string;
  routeId?: string;
  audience: string;
  method?: string;
  amountMicros: number;
  scheme?: PaymentScheme;
  ttlSeconds?: number;
}

interface DeveloperRow {
  id: string;
  email: string;
  name: string;
  tier: DeveloperTier;
  payout_address: string | null;
}

interface WalletRow {
  id: string;
  owner_label: string;
  balance_micros: number;
  daily_spend_cap_micros: number;
  daily_spent_micros: number;
  spend_window_day: string;
  status: 'active' | 'frozen';
}

interface ExistingLedgerRow {
  id: string;
  gross_micros: number;
  fee_bps: number;
  platform_fee_micros: number;
  developer_net_micros: number;
  tx_reference: string | null;
  metadata_json: string | null;
}

const textEncoder = new TextEncoder();

function resolveClearinghouseGuidance(reason: string): { code: string; fix_hint: string } {
  switch (reason) {
    case 'unauthorized':
      return {
        code: 'INVALID_SIGNATURE',
        fix_hint: 'Supply a valid Authorization: Bearer <CLEARINGHOUSE_API_KEY> header.',
      };
    case 'insufficient_wallet_balance':
    case 'insufficient_balance_or_cap_exceeded':
    case 'insufficient_authorized_amount':
      return {
        code: 'INSUFFICIENT_FUNDS',
        fix_hint: 'Top up the agent wallet balance or authorize an amount >= required payment.',
      };
    case 'daily_spend_cap_exceeded':
      return {
        code: 'SPEND_CAP_EXCEEDED',
        fix_hint: 'Agent wallet reached its UTC daily_spend_cap_micros limit; increase cap or wait for next UTC day.',
      };
    case 'authorization_expired':
      return {
        code: 'RECEIPT_EXPIRED',
        fix_hint: 'Authorization validAfter/validBefore window fell outside +/-30s clock skew; re-sign with current timestamps.',
      };
    case 'nonce_already_used':
    case 'nonce_replayed':
      return {
        code: 'NONCE_REPLAYED',
        fix_hint: 'This authorization nonce was already settled. Generate a fresh nonce and retry.',
      };
    case 'pro_pass_required_for_upto':
      return {
        code: 'PRO_PASS_REQUIRED',
        fix_hint: 'Upgrade developer tier to pro or agency to enable the metered upto scheme.',
      };
    case 'wallet_frozen':
      return {
        code: 'WALLET_FROZEN',
        fix_hint: 'Reactivate the agent wallet status before issuing receipts.',
      };
    case 'developer_not_found':
    case 'wallet_not_found':
      return {
        code: 'NOT_FOUND',
        fix_hint: 'Verify the developerId / walletId exists in the clearinghouse D1 database.',
      };
    case 'signature_mismatch':
    case 'missing_signature':
    case 'malformed_hmac_signature':
    case 'malformed_evm_signature':
    case 'recipient_mismatch':
    case 'network_mismatch':
    case 'scheme_mismatch':
    case 'malformed_authorization':
    case 'unsupported_x402_version':
    case 'invalid_x402_request':
      return {
        code: 'INVALID_SIGNATURE',
        fix_hint: `Verify x402 V2 signature, network, payTo, and scheme (${reason}).`,
      };
    default:
      return {
        code: 'INVALID_REQUEST',
        fix_hint: `Check request fields and try again (${reason}).`,
      };
  }
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Expose-Headers', CORS_EXPOSE_HEADERS);
  headers.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
  if (!headers.has('Access-Control-Allow-Methods')) {
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function jsonWithCors(payload: unknown, status = 200): Response {
  return withCors(Response.json(payload, { status }));
}

/**
 * Exact integer fee math (no floating-point currency calculations).
 * - Hybrid: 7% (700 bps)
 * - Pro / Agency: 3% (300 bps)
 * - Free BYO x402: 0% (0 bps)
 */
export function calculateClearinghouseFee(
  grossMicros: number,
  tier: DeveloperTier,
  rail: SettlementRail,
): FeeBreakdown {
  if (!Number.isSafeInteger(grossMicros) || grossMicros < 0) {
    throw new RangeError(`Invalid grossMicros integer: ${grossMicros}`);
  }
  if (tier === 'free' && rail === 'fiat_wallet') {
    throw new Error('Free tier does not support fiat_wallet clearinghouse settlement');
  }

  let feeBps = 0;
  if (tier === 'hybrid') {
    feeBps = 700;
  } else if (tier === 'pro' || tier === 'agency') {
    feeBps = 300;
  }

  const platformFeeMicros = Math.floor((grossMicros * feeBps + 5000) / 10000);
  const developerNetMicros = grossMicros - platformFeeMicros;
  return {
    grossMicros,
    feeBps,
    platformFeeMicros,
    developerNetMicros,
  };
}

/**
 * Constant-time string comparison using Web Crypto HMAC-SHA256 digests so
 * secret lengths and characters never leak via timing.
 */
async function timingSafeEqualString(a: string, b: string): Promise<boolean> {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const [macA, macB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, textEncoder.encode(a)),
    crypto.subtle.sign('HMAC', key, textEncoder.encode(b)),
  ]);
  const bytesA = new Uint8Array(macA);
  const bytesB = new Uint8Array(macB);
  let diff = 0;
  for (let i = 0; i < bytesA.length; i++) {
    diff |= (bytesA[i] ?? 0) ^ (bytesB[i] ?? 0);
  }
  return diff === 0;
}

async function isAuthorizedAdminRequest(request: Request, env: Env): Promise<boolean> {
  const auth = request.headers.get('Authorization');
  if (!auth || !env.CLEARINGHOUSE_API_KEY) {
    return false;
  }
  const match = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!match?.[1]) {
    return false;
  }
  return timingSafeEqualString(match[1], env.CLEARINGHOUSE_API_KEY);
}

function utcDayString(nowSeconds: number): string {
  return new Date(nowSeconds * 1000).toISOString().slice(0, 10);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function computeSettlementTxHash(seed: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(seed));
  return `0x${toHex(new Uint8Array(digest))}`;
}

function decodeHexBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    return null;
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function verifyX402Signature(
  body: FacilitatorRequestBody,
  env: Env,
): Promise<{ ok: boolean; reason?: string }> {
  const sig = body.paymentPayload.payload.signature;
  if (typeof sig !== 'string' || sig.length === 0) {
    return { ok: false, reason: 'missing_signature' };
  }

  if (sig.startsWith('hmac_sha256:')) {
    if (!env.FACILITATOR_HMAC_SECRET) {
      return { ok: false, reason: 'facilitator_hmac_not_configured' };
    }
    const sigBytes = decodeHexBytes(sig.slice('hmac_sha256:'.length));
    if (!sigBytes) {
      return { ok: false, reason: 'malformed_hmac_signature' };
    }
    const auth = body.paymentPayload.payload.authorization;
    const canonical = `${auth.from}:${auth.to}:${auth.value}:${auth.validAfter}:${auth.validBefore}:${auth.nonce}`;
    const key = await crypto.subtle.importKey(
      'raw',
      textEncoder.encode(env.FACILITATOR_HMAC_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const sigBuf = sigBytes.buffer.slice(
      sigBytes.byteOffset,
      sigBytes.byteOffset + sigBytes.byteLength,
    ) as ArrayBuffer;
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, textEncoder.encode(canonical));
    return valid ? { ok: true } : { ok: false, reason: 'signature_mismatch' };
  }

  if (!/^0x[0-9a-fA-F]{64,}$/.test(sig)) {
    return { ok: false, reason: 'malformed_evm_signature' };
  }
  return { ok: true };
}

async function verifyX402Payload(
  body: FacilitatorRequestBody,
  env: Env,
): Promise<{
  isValid: boolean;
  invalidReason: string | null;
  developer?: DeveloperRow | null;
}> {
  if (!body || body.x402Version !== 2 || !body.paymentPayload || !body.paymentRequirements) {
    return { isValid: false, invalidReason: 'invalid_x402_request' };
  }

  const { paymentPayload, paymentRequirements } = body;
  if (paymentPayload.x402Version !== 2) {
    return { isValid: false, invalidReason: 'unsupported_x402_version' };
  }

  const reqScheme = paymentRequirements.scheme;
  const sigScheme = paymentPayload.accepted?.scheme ?? paymentPayload.scheme;
  const sigNetwork = paymentPayload.accepted?.network ?? paymentPayload.network;

  if (sigScheme !== reqScheme) {
    return { isValid: false, invalidReason: 'scheme_mismatch' };
  }
  if (sigNetwork !== paymentRequirements.network) {
    return { isValid: false, invalidReason: 'network_mismatch' };
  }

  const auth = paymentPayload.payload?.authorization;
  if (
    !auth ||
    typeof auth.from !== 'string' ||
    typeof auth.to !== 'string' ||
    typeof auth.nonce !== 'string' ||
    auth.nonce.length === 0 ||
    !/^\d+$/.test(String(auth.value)) ||
    !/^\d+$/.test(String(paymentRequirements.amount)) ||
    !/^\d+$/.test(String(auth.validAfter)) ||
    !/^\d+$/.test(String(auth.validBefore))
  ) {
    return { isValid: false, invalidReason: 'malformed_authorization' };
  }

  if (auth.to.toLowerCase() !== paymentRequirements.payTo.toLowerCase()) {
    return { isValid: false, invalidReason: 'recipient_mismatch' };
  }

  const now = Math.floor(Date.now() / 1000);
  const validAfter = Number(auth.validAfter);
  const validBefore = Number(auth.validBefore);
  const clockSkew = DEFAULT_CLOCK_SKEW_SECONDS;
  if (now < validAfter - clockSkew || now > validBefore + clockSkew) {
    return { isValid: false, invalidReason: 'authorization_expired' };
  }

  if (BigInt(auth.value) < BigInt(paymentRequirements.amount)) {
    return { isValid: false, invalidReason: 'insufficient_authorized_amount' };
  }

  const developer = await env.DB.prepare(
    'SELECT id, email, name, tier, payout_address FROM developers WHERE LOWER(payout_address) = LOWER(?) LIMIT 1',
  )
    .bind(paymentRequirements.payTo)
    .first<DeveloperRow>();

  if (reqScheme === 'upto' && developer && developer.tier !== 'pro' && developer.tier !== 'agency') {
    return { isValid: false, invalidReason: 'pro_pass_required_for_upto', developer };
  }

  const used = await env.DB.prepare('SELECT nonce FROM used_nonces WHERE nonce = ? LIMIT 1')
    .bind(auth.nonce)
    .first<{ nonce: string }>();
  if (used) {
    return { isValid: false, invalidReason: 'nonce_already_used', developer };
  }

  const sigCheck = await verifyX402Signature(body, env);
  if (!sigCheck.ok) {
    return { isValid: false, invalidReason: sigCheck.reason ?? 'signature_mismatch', developer };
  }

  return { isValid: true, invalidReason: null, developer };
}

async function handleVerify(request: Request, env: Env): Promise<Response> {
  let body: FacilitatorRequestBody;
  try {
    body = (await request.json()) as FacilitatorRequestBody;
  } catch {
    const g = resolveClearinghouseGuidance('invalid_json');
    return jsonWithCors(
      { isValid: false, invalidReason: 'invalid_json', ...g },
      400,
    );
  }

  const result = await verifyX402Payload(body, env);
  if (result.isValid) {
    return jsonWithCors({
      isValid: true,
      invalidReason: null,
    });
  }

  const g = resolveClearinghouseGuidance(result.invalidReason ?? 'invalid_x402_request');
  return jsonWithCors({
    isValid: false,
    invalidReason: result.invalidReason,
    ...g,
  });
}

async function handleSettle(request: Request, env: Env): Promise<Response> {
  let body: FacilitatorRequestBody;
  try {
    body = (await request.json()) as FacilitatorRequestBody;
  } catch {
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'invalid_json',
        ...resolveClearinghouseGuidance('invalid_json'),
      },
      400,
    );
  }

  const nonce = body.paymentPayload?.payload?.authorization?.nonce ?? '';
  const idempotencyKey = request.headers.get('Idempotency-Key') ?? `settle_${nonce}`;

  const existing = await env.DB.prepare(
    'SELECT id, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json FROM ledger_entries WHERE idempotency_key = ? LIMIT 1',
  )
    .bind(idempotencyKey)
    .first<ExistingLedgerRow>();

  if (existing) {
    const meta = existing.metadata_json
      ? (JSON.parse(existing.metadata_json) as { network?: string })
      : {};
    return jsonWithCors({
      success: true,
      txHash: existing.tx_reference,
      network: meta.network ?? body.paymentRequirements?.network ?? 'eip155:8453',
      settledAmount: String(existing.gross_micros),
      platformFeeMicros: existing.platform_fee_micros,
      developerNetMicros: existing.developer_net_micros,
      idempotentReplay: true,
      errorReason: null,
    });
  }

  const verification = await verifyX402Payload(body, env);
  if (!verification.isValid) {
    const reason =
      verification.invalidReason === 'nonce_already_used'
        ? 'nonce_replayed'
        : (verification.invalidReason ?? 'invalid_x402_request');
    const status = reason === 'nonce_replayed' ? 409 : 400;
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: reason,
        ...resolveClearinghouseGuidance(reason),
      },
      status,
    );
  }

  const auth = body.paymentPayload.payload.authorization;
  const req = body.paymentRequirements;
  const authorizedBig = BigInt(auth.value);
  let settleBig = BigInt(req.amount);

  if (req.scheme === 'upto') {
    const requestedSettle = body.settleAmount ?? req.amount;
    if (!/^\d+$/.test(requestedSettle)) {
      return jsonWithCors(
        {
          success: false,
          txHash: null,
          errorReason: 'invalid_settle_amount',
          ...resolveClearinghouseGuidance('invalid_settle_amount'),
        },
        400,
      );
    }
    settleBig = BigInt(requestedSettle);
    if (settleBig > authorizedBig) {
      return jsonWithCors(
        {
          success: false,
          txHash: null,
          errorReason: 'settle_amount_exceeds_authorization',
          ...resolveClearinghouseGuidance('settle_amount_exceeds_authorization'),
        },
        400,
      );
    }
  }

  const grossMicros = Number(settleBig);
  if (!Number.isSafeInteger(grossMicros) || grossMicros < 0) {
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'settle_amount_out_of_range',
        ...resolveClearinghouseGuidance('settle_amount_out_of_range'),
      },
      400,
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const consumeResult = await env.DB.prepare(
    'INSERT OR IGNORE INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  )
    .bind(
      auth.nonce,
      'x402',
      auth.from,
      req.resource ?? '*',
      Number(auth.validBefore),
      now,
    )
    .run();

  if ((consumeResult.meta?.changes ?? 0) !== 1) {
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'nonce_replayed',
        ...resolveClearinghouseGuidance('nonce_replayed'),
      },
      409,
    );
  }

  const tier: DeveloperTier = verification.developer?.tier ?? 'free';
  const feeBreakdown = calculateClearinghouseFee(grossMicros, tier, 'x402');
  const txHash = await computeSettlementTxHash(`${auth.nonce}:${req.network}:${grossMicros}:${now}`);

  await env.DB.prepare(
    'INSERT INTO ledger_entries (id, idempotency_key, wallet_id, developer_id, route_id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json, created_at) VALUES (?, ?, NULL, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(
      `led_${crypto.randomUUID()}`,
      idempotencyKey,
      verification.developer?.id ?? null,
      'x402',
      'settlement',
      feeBreakdown.grossMicros,
      feeBreakdown.feeBps,
      feeBreakdown.platformFeeMicros,
      feeBreakdown.developerNetMicros,
      txHash,
      JSON.stringify({ network: req.network, payer: auth.from }),
      now,
    )
    .run();

  return jsonWithCors({
    success: true,
    txHash,
    network: req.network,
    settledAmount: String(grossMicros),
    platformFeeMicros: feeBreakdown.platformFeeMicros,
    developerNetMicros: feeBreakdown.developerNetMicros,
    errorReason: null,
  });
}

async function issueWalletReceiptInternal(
  body: IssueReceiptBody,
  idempotencyKey: string,
  env: Env,
): Promise<{ status: number; payload: Record<string, unknown> }> {
  if (
    !body.walletId ||
    !body.developerId ||
    !body.audience ||
    !Number.isSafeInteger(body.amountMicros) ||
    body.amountMicros <= 0
  ) {
    return {
      status: 400,
      payload: {
        error: 'invalid_issue_receipt_request',
        ...resolveClearinghouseGuidance('invalid_issue_receipt_request'),
      },
    };
  }

  const existing = await env.DB.prepare(
    'SELECT id, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json FROM ledger_entries WHERE idempotency_key = ? LIMIT 1',
  )
    .bind(idempotencyKey)
    .first<ExistingLedgerRow>();

  if (existing?.metadata_json) {
    const cached = JSON.parse(existing.metadata_json) as Record<string, unknown>;
    return {
      status: 200,
      payload: {
        ...cached,
        idempotentReplay: true,
      },
    };
  }

  const developer = await env.DB.prepare(
    'SELECT id, email, name, tier, payout_address FROM developers WHERE id = ? LIMIT 1',
  )
    .bind(body.developerId)
    .first<DeveloperRow>();

  if (!developer) {
    return {
      status: 404,
      payload: {
        error: 'developer_not_found',
        ...resolveClearinghouseGuidance('developer_not_found'),
      },
    };
  }
  if (developer.tier === 'free') {
    return {
      status: 403,
      payload: {
        error: 'fiat_wallet_requires_hybrid_or_pro',
        ...resolveClearinghouseGuidance('fiat_wallet_requires_hybrid_or_pro'),
      },
    };
  }

  const scheme: PaymentScheme = body.scheme ?? 'exact';
  if (scheme === 'upto' && developer.tier !== 'pro' && developer.tier !== 'agency') {
    return {
      status: 403,
      payload: {
        error: 'pro_pass_required_for_upto',
        ...resolveClearinghouseGuidance('pro_pass_required_for_upto'),
      },
    };
  }

  const wallet = await env.DB.prepare(
    'SELECT id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, status FROM agent_wallets WHERE id = ? LIMIT 1',
  )
    .bind(body.walletId)
    .first<WalletRow>();

  if (!wallet) {
    return {
      status: 404,
      payload: {
        error: 'wallet_not_found',
        ...resolveClearinghouseGuidance('wallet_not_found'),
      },
    };
  }
  if (wallet.status !== 'active') {
    return {
      status: 403,
      payload: {
        error: 'wallet_frozen',
        ...resolveClearinghouseGuidance('wallet_frozen'),
      },
    };
  }

  const now = Math.floor(Date.now() / 1000);
  const today = utcDayString(now);
  const spentToday = wallet.spend_window_day === today ? wallet.daily_spent_micros : 0;

  if (spentToday + body.amountMicros > wallet.daily_spend_cap_micros) {
    return {
      status: 402,
      payload: {
        error: 'daily_spend_cap_exceeded',
        ...resolveClearinghouseGuidance('daily_spend_cap_exceeded'),
      },
    };
  }
  if (wallet.balance_micros < body.amountMicros) {
    return {
      status: 402,
      payload: {
        error: 'insufficient_wallet_balance',
        ...resolveClearinghouseGuidance('insufficient_wallet_balance'),
      },
    };
  }

  const feeBreakdown = calculateClearinghouseFee(body.amountMicros, developer.tier, 'fiat_wallet');
  const ttl = Math.min(300, Math.max(10, body.ttlSeconds ?? 120));
  const claims: RcsReceiptClaims = {
    v: 1,
    jti: `rcpt_${crypto.randomUUID()}`,
    sub: wallet.id,
    aud: body.audience,
    mth: body.method ?? '*',
    amt: body.amountMicros,
    iat: now,
    exp: now + ttl,
    tier: developer.tier,
  };

  const receipt = await signFiatReceipt(claims, {
    alg: 'hs256',
    secret: env.RECEIPT_SIGNING_SECRET,
  });

  const debitRes = await env.DB.prepare(
    `UPDATE agent_wallets
     SET balance_micros = balance_micros - ?,
         daily_spent_micros = CASE WHEN spend_window_day = ? THEN daily_spent_micros + ? ELSE ? END,
         spend_window_day = ?,
         updated_at = ?
     WHERE id = ?
       AND status = 'active'
       AND balance_micros >= ?
       AND (CASE WHEN spend_window_day = ? THEN daily_spent_micros ELSE 0 END) + ? <= daily_spend_cap_micros`,
  )
    .bind(
      body.amountMicros,
      today,
      body.amountMicros,
      body.amountMicros,
      today,
      now,
      wallet.id,
      body.amountMicros,
      today,
      body.amountMicros,
    )
    .run();

  if ((debitRes.meta?.changes ?? 0) !== 1) {
    return {
      status: 402,
      payload: {
        error: 'insufficient_balance_or_cap_exceeded',
        ...resolveClearinghouseGuidance('insufficient_balance_or_cap_exceeded'),
      },
    };
  }

  const updatedWallet = await env.DB.prepare(
    'SELECT balance_micros FROM agent_wallets WHERE id = ? LIMIT 1',
  )
    .bind(wallet.id)
    .first<{ balance_micros: number }>();

  const remainingBalanceMicros =
    updatedWallet?.balance_micros ?? wallet.balance_micros - body.amountMicros;
  const responsePayload = {
    receipt,
    claims,
    remainingBalanceMicros,
    feeBreakdown,
  };

  try {
    await env.DB.prepare(
      'INSERT INTO ledger_entries (id, idempotency_key, wallet_id, developer_id, route_id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
      .bind(
        `led_${crypto.randomUUID()}`,
        idempotencyKey,
        wallet.id,
        developer.id,
        body.routeId ?? null,
        'fiat_wallet',
        'charge',
        feeBreakdown.grossMicros,
        feeBreakdown.feeBps,
        feeBreakdown.platformFeeMicros,
        feeBreakdown.developerNetMicros,
        claims.jti,
        JSON.stringify(responsePayload),
        now,
      )
      .run();
  } catch {
    // Concurrent duplicate idempotency_key lost the INSERT race: roll back the duplicate debit.
    await env.DB.prepare(
      `UPDATE agent_wallets
       SET balance_micros = balance_micros + ?,
           daily_spent_micros = MAX(0, daily_spent_micros - ?),
           updated_at = ?
       WHERE id = ?`,
    )
      .bind(body.amountMicros, body.amountMicros, now, wallet.id)
      .run();

    const winner = await env.DB.prepare(
      'SELECT metadata_json FROM ledger_entries WHERE idempotency_key = ? LIMIT 1',
    )
      .bind(idempotencyKey)
      .first<{ metadata_json: string | null }>();
    if (winner?.metadata_json) {
      return {
        status: 200,
        payload: {
          ...(JSON.parse(winner.metadata_json) as Record<string, unknown>),
          idempotentReplay: true,
        },
      };
    }
    return {
      status: 409,
      payload: {
        error: 'idempotency_conflict',
        ...resolveClearinghouseGuidance('idempotency_conflict'),
      },
    };
  }

  return { status: 200, payload: responsePayload };
}

async function handleIssueReceipt(request: Request, env: Env): Promise<Response> {
  if (!(await isAuthorizedAdminRequest(request, env))) {
    return jsonWithCors(
      {
        error: 'unauthorized',
        ...resolveClearinghouseGuidance('unauthorized'),
      },
      401,
    );
  }

  let body: IssueReceiptBody;
  try {
    body = (await request.json()) as IssueReceiptBody;
  } catch {
    return jsonWithCors(
      {
        error: 'invalid_json',
        ...resolveClearinghouseGuidance('invalid_json'),
      },
      400,
    );
  }

  const idempotencyKey = request.headers.get('Idempotency-Key') ?? `rcpt_${crypto.randomUUID()}`;
  const result = await issueWalletReceiptInternal(body, idempotencyKey, env);
  return jsonWithCors(result.payload, result.status);
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const MCP_TOOLS = [
  {
    name: 'tollbooth_pricing_quote',
    description:
      'Compute clearinghouse fee and developer net payout across Free BYO x402 (0%), Hybrid (7%), and Tollbooth Pro/Agency (3%) tiers in integer USD microdollars.',
    inputSchema: {
      type: 'object',
      properties: {
        priceMicros: { type: 'integer', minimum: 1 },
        callsPerMonth: { type: 'integer', minimum: 1 },
      },
      required: ['priceMicros', 'callsPerMonth'],
    },
  },
  {
    name: 'tollbooth_wallet_balance',
    description: 'Inspect an agent wallet balance, status, and remaining UTC daily spend cap.',
    inputSchema: {
      type: 'object',
      properties: {
        walletId: { type: 'string' },
      },
      required: ['walletId'],
    },
  },
  {
    name: 'tollbooth_issue_receipt',
    description:
      'Issue a short-lived Rail B rcs_receipt_hs256 bearer token debited atomically from a prepaid agent wallet.',
    inputSchema: {
      type: 'object',
      properties: {
        walletId: { type: 'string' },
        developerId: { type: 'string' },
        audience: { type: 'string' },
        method: { type: 'string' },
        amountMicros: { type: 'integer', minimum: 1 },
        scheme: { type: 'string', enum: ['exact', 'upto'] },
        idempotencyKey: { type: 'string' },
      },
      required: ['walletId', 'developerId', 'audience', 'amountMicros'],
    },
  },
  {
    name: 'tollbooth_verify_x402',
    description: 'Verify an x402 V2 paymentPayload against paymentRequirements and D1 used_nonces.',
    inputSchema: {
      type: 'object',
      properties: {
        x402Version: { type: 'integer' },
        paymentPayload: { type: 'object' },
        paymentRequirements: { type: 'object' },
      },
      required: ['x402Version', 'paymentPayload', 'paymentRequirements'],
    },
  },
] as const;

function jsonRpcOk(id: string | number | null | undefined, result: unknown): Response {
  return jsonWithCors({
    jsonrpc: '2.0',
    id: id ?? null,
    result,
  });
}

function jsonRpcErr(
  id: string | number | null | undefined,
  code: number,
  message: string,
  status = 200,
): Response {
  return jsonWithCors(
    {
      jsonrpc: '2.0',
      id: id ?? null,
      error: { code, message },
    },
    status,
  );
}

async function handleMcp(request: Request, env: Env): Promise<Response> {
  if (request.method === 'OPTIONS') {
    return withCors(new Response(null, { status: 204 }));
  }
  if (request.method !== 'POST') {
    return jsonRpcErr(null, -32600, 'Method Not Allowed: use POST for Streamable HTTP MCP', 405);
  }

  let rpc: JsonRpcRequest;
  try {
    rpc = (await request.json()) as JsonRpcRequest;
  } catch {
    return jsonRpcErr(null, -32700, 'Parse error', 400);
  }

  if (rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string') {
    return jsonRpcErr(rpc.id, -32600, 'Invalid Request', 400);
  }

  if (rpc.method === 'notifications/initialized') {
    return withCors(new Response(null, { status: 202 }));
  }

  if (rpc.method === 'ping') {
    return jsonRpcOk(rpc.id, {});
  }

  if (rpc.method === 'initialize') {
    return jsonRpcOk(rpc.id, {
      protocolVersion: '2025-03-26',
      capabilities: {
        tools: { listChanged: false },
      },
      serverInfo: {
        name: 'agent-tollbooth-402-clearinghouse',
        version: '1.0.0',
      },
    });
  }

  if (rpc.method === 'tools/list') {
    return jsonRpcOk(rpc.id, { tools: MCP_TOOLS });
  }

  if (rpc.method === 'tools/call') {
    const params = rpc.params ?? {};
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;

    if (toolName === 'tollbooth_pricing_quote') {
      const priceMicros = Number(args.priceMicros);
      const callsPerMonth = Number(args.callsPerMonth);
      if (
        !Number.isSafeInteger(priceMicros) ||
        priceMicros <= 0 ||
        !Number.isSafeInteger(callsPerMonth) ||
        callsPerMonth <= 0
      ) {
        return jsonRpcErr(rpc.id, -32602, 'priceMicros and callsPerMonth must be positive safe integers');
      }
      const monthlyGross = priceMicros * callsPerMonth;
      const quote = {
        monthlyGrossMicros: monthlyGross,
        freeByoX402: calculateClearinghouseFee(monthlyGross, 'free', 'x402'),
        hybrid7Percent: calculateClearinghouseFee(monthlyGross, 'hybrid', 'fiat_wallet'),
        proPass3Percent: calculateClearinghouseFee(monthlyGross, 'pro', 'fiat_wallet'),
      };
      return jsonRpcOk(rpc.id, {
        content: [{ type: 'text', text: JSON.stringify(quote) }],
        structuredContent: quote,
      });
    }

    if (toolName === 'tollbooth_verify_x402') {
      const verification = await verifyX402Payload(args as unknown as FacilitatorRequestBody, env);
      const out = {
        isValid: verification.isValid,
        invalidReason: verification.invalidReason,
      };
      return jsonRpcOk(rpc.id, {
        content: [{ type: 'text', text: JSON.stringify(out) }],
        structuredContent: out,
      });
    }

    if (toolName === 'tollbooth_wallet_balance' || toolName === 'tollbooth_issue_receipt') {
      if (!(await isAuthorizedAdminRequest(request, env))) {
        return jsonRpcErr(rpc.id, -32001, 'Unauthorized: Bearer CLEARINGHOUSE_API_KEY required', 401);
      }

      if (toolName === 'tollbooth_wallet_balance') {
        const walletId = typeof args.walletId === 'string' ? args.walletId : '';
        const wallet = await env.DB.prepare(
          'SELECT id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, status FROM agent_wallets WHERE id = ? LIMIT 1',
        )
          .bind(walletId)
          .first<WalletRow>();
        if (!wallet) {
          return jsonRpcErr(rpc.id, -32004, 'Wallet not found');
        }
        const today = utcDayString(Math.floor(Date.now() / 1000));
        const spentToday = wallet.spend_window_day === today ? wallet.daily_spent_micros : 0;
        const summary = {
          walletId: wallet.id,
          ownerLabel: wallet.owner_label,
          status: wallet.status,
          balanceMicros: wallet.balance_micros,
          dailySpendCapMicros: wallet.daily_spend_cap_micros,
          dailySpentMicros: spentToday,
          remainingDailyCapMicros: Math.max(0, wallet.daily_spend_cap_micros - spentToday),
        };
        return jsonRpcOk(rpc.id, {
          content: [{ type: 'text', text: JSON.stringify(summary) }],
          structuredContent: summary,
        });
      }

      const idempotencyKey =
        typeof args.idempotencyKey === 'string' && args.idempotencyKey.length > 0
          ? args.idempotencyKey
          : `mcp_${crypto.randomUUID()}`;
      const issued = await issueWalletReceiptInternal(
        args as unknown as IssueReceiptBody,
        idempotencyKey,
        env,
      );
      return jsonRpcOk(rpc.id, {
        isError: issued.status >= 400,
        content: [{ type: 'text', text: JSON.stringify(issued.payload) }],
        structuredContent: issued.payload,
      });
    }

    return jsonRpcErr(rpc.id, -32601, `Unknown tool: ${toolName}`);
  }

  return jsonRpcErr(rpc.id, -32601, `Method not found: ${rpc.method}`);
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (request.method === 'OPTIONS') {
        return withCors(new Response(null, { status: 204 }));
      }

      if (request.method === 'GET' && url.pathname === '/health') {
        return jsonWithCors({
          status: 'ok',
          service: 'agent-tollbooth-402-clearinghouse',
          version: '1.0.0',
          timestamp: Math.floor(Date.now() / 1000),
        });
      }

      if (url.pathname === '/mcp') {
        return handleMcp(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/verify') {
        return handleVerify(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/settle') {
        return handleSettle(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/wallet/issue-receipt') {
        return handleIssueReceipt(request, env);
      }

      return jsonWithCors(
        {
          error: 'not_found',
          code: 'NOT_FOUND',
          fix_hint: 'Supported routes: GET /health, POST /verify, POST /settle, POST /wallet/issue-receipt, POST /mcp.',
        },
        404,
      );
    } catch {
      return jsonWithCors(
        {
          error: 'internal_error',
          code: 'INTERNAL_ERROR',
          fix_hint: 'An internal clearinghouse error occurred. Retry safely with the same Idempotency-Key.',
        },
        500,
      );
    }
  },
};
