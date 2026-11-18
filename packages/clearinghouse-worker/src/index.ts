import {
  CORS_ALLOW_HEADERS,
  CORS_EXPOSE_HEADERS,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DEFAULT_NETWORK,
  DEFAULT_PAY_TO,
  DEFAULT_USDC_BASE_ASSET,
  encodePaymentHeader,
  microsToUsdString,
  renderDefault402HtmlPage,
  signFiatReceipt,
  usdToMicros,
  type PaymentScheme,
  type RcsReceiptClaims,
  type X402PaymentRequired,
  type X402PaymentSignature,
} from '@redcenterstudio/agent-tollbooth-edge';

export type DeveloperTier = 'free' | 'hybrid' | 'pro' | 'agency';
export type SettlementRail = 'fiat_wallet' | 'x402';

export interface Env {
  DB: D1Database;
  RECEIPT_SIGNING_SECRET: string;
  CLEARINGHOUSE_API_KEY: string;
  FACILITATOR_HMAC_SECRET?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_CONNECT_WEBHOOK_SECRET?: string;
  STRIPE_PUBLISHABLE_KEY?: string;
  STRIPE_WEBHOOK_ENDPOINT_ID?: string;
  STRIPE_PRICE_TOPUP_10?: string;
  STRIPE_PRICE_PRO_PASS?: string;
  STRIPE_PRICE_AGENCY_PASS?: string;
  STRIPE_PAYMENT_LINK_TOPUP_10?: string;
  STRIPE_PAYMENT_LINK_PRO_PASS?: string;
  STRIPE_PAYMENT_LINK_AGENCY_PASS?: string;
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

const STRIPE_WEBHOOK_TOLERANCE_SECONDS = 300;

/**
 * Generate a valid Stripe-Signature header (`t=<ts>,v1=<hmac_sha256_hex>`) via Web Crypto.
 */
export async function signStripeWebhookPayload(
  rawBody: string,
  secret: string,
  timestampSeconds = Math.floor(Date.now() / 1000),
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signedPayload = `${timestampSeconds}.${rawBody}`;
  const sigBuf = await crypto.subtle.sign('HMAC', key, textEncoder.encode(signedPayload));
  return `t=${timestampSeconds},v1=${toHex(new Uint8Array(sigBuf))}`;
}

async function verifyStripeWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
  secret: string | undefined,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<{ ok: boolean; reason?: string }> {
  if (!secret) {
    return { ok: false, reason: 'stripe_webhook_secret_not_configured' };
  }
  if (!signatureHeader) {
    return { ok: false, reason: 'missing_stripe_signature' };
  }

  let timestampStr: string | undefined;
  const v1Sigs: string[] = [];
  for (const part of signatureHeader.split(',')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) {
      continue;
    }
    const k = part.slice(0, eqIdx).trim();
    const v = part.slice(eqIdx + 1).trim();
    if (k === 't') {
      timestampStr = v;
    } else if (k === 'v1') {
      v1Sigs.push(v);
    }
  }

  if (!timestampStr || !/^\d+$/.test(timestampStr) || v1Sigs.length === 0) {
    return { ok: false, reason: 'malformed_stripe_signature' };
  }

  const timestamp = Number(timestampStr);
  if (Math.abs(nowSeconds - timestamp) > STRIPE_WEBHOOK_TOLERANCE_SECONDS) {
    return { ok: false, reason: 'stripe_signature_expired' };
  }

  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const signedBytes = textEncoder.encode(`${timestamp}.${rawBody}`);

  for (const candidateHex of v1Sigs) {
    const sigBytes = decodeHexBytes(candidateHex);
    if (!sigBytes) {
      continue;
    }
    const sigBuf = sigBytes.buffer.slice(
      sigBytes.byteOffset,
      sigBytes.byteOffset + sigBytes.byteLength,
    ) as ArrayBuffer;
    if (await crypto.subtle.verify('HMAC', key, sigBuf, signedBytes)) {
      return { ok: true };
    }
  }

  return { ok: false, reason: 'stripe_signature_mismatch' };
}

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

export interface TopupCheckoutBody {
  walletId?: string;
  amountUsd?: number | string;
  developerId?: string;
  passTier?: 'pro' | 'agency';
  successUrl?: string;
  cancelUrl?: string;
}

interface StripeEvent {
  id: string;
  type: string;
  data?: {
    object?: {
      id?: string;
      amount_total?: number;
      metadata?: Record<string, string | undefined>;
    };
  };
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.text();
  const sigCheck = await verifyStripeWebhookSignature(
    rawBody,
    request.headers.get('Stripe-Signature'),
    env.STRIPE_CONNECT_WEBHOOK_SECRET,
  );

  if (!sigCheck.ok) {
    return jsonWithCors(
      {
        error: sigCheck.reason ?? 'stripe_signature_mismatch',
        code: 'INVALID_SIGNATURE',
        fix_hint:
          'Verify Stripe-Signature header (t=...,v1=...) against STRIPE_CONNECT_WEBHOOK_SECRET within 300s timestamp tolerance.',
      },
      400,
    );
  }

  let event: StripeEvent;
  try {
    event = JSON.parse(rawBody) as StripeEvent;
  } catch {
    return jsonWithCors(
      {
        error: 'invalid_json',
        code: 'INVALID_REQUEST',
        fix_hint: 'Send a valid JSON Stripe webhook event payload.',
      },
      400,
    );
  }

  if (!event.id || !event.type) {
    return jsonWithCors(
      {
        error: 'invalid_stripe_event',
        code: 'INVALID_REQUEST',
        fix_hint: 'Stripe event must include id and type fields.',
      },
      400,
    );
  }

  const eventIdemKey = `stripe_evt_${event.id}`;
  const existingLedger = await env.DB.prepare(
    'SELECT id FROM ledger_entries WHERE idempotency_key = ? LIMIT 1',
  )
    .bind(eventIdemKey)
    .first<{ id: string }>();
  const existingNonce = await env.DB.prepare(
    'SELECT nonce FROM used_nonces WHERE nonce = ? LIMIT 1',
  )
    .bind(eventIdemKey)
    .first<{ nonce: string }>();

  if (existingLedger || existingNonce) {
    return jsonWithCors({ received: true, idempotentReplay: true, eventId: event.id });
  }

  if (event.type !== 'checkout.session.completed') {
    return jsonWithCors({ received: true, ignored: true, type: event.type });
  }

  const session = event.data?.object ?? {};
  const meta = session.metadata ?? {};
  const now = Math.floor(Date.now() / 1000);

  if (meta.kind === 'tier_upgrade' && meta.developer_id) {
    const targetTier = meta.target_tier === 'agency' ? 'agency' : meta.target_tier === 'pro' ? 'pro' : null;
    if (!targetTier) {
      return jsonWithCors(
        {
          error: 'invalid_target_tier',
          code: 'INVALID_REQUEST',
          fix_hint: 'metadata.target_tier must be "pro" or "agency".',
        },
        400,
      );
    }

    const devUpdate = await env.DB.prepare('UPDATE developers SET tier = ? WHERE id = ?')
      .bind(targetTier, meta.developer_id)
      .run();

    if ((devUpdate.meta?.changes ?? 0) !== 1) {
      return jsonWithCors(
        {
          error: 'developer_not_found',
          ...resolveClearinghouseGuidance('developer_not_found'),
        },
        404,
      );
    }

    await env.DB.prepare(
      'INSERT OR IGNORE INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    )
      .bind(eventIdemKey, 'fiat_wallet', meta.developer_id, '/webhook/stripe', now + 86_400, now)
      .run();

    return jsonWithCors({
      received: true,
      kind: 'tier_upgrade',
      developerId: meta.developer_id,
      tier: targetTier,
    });
  }

  const walletId = meta.wallet_id;
  if (!walletId) {
    return jsonWithCors(
      {
        error: 'missing_wallet_id_metadata',
        code: 'INVALID_REQUEST',
        fix_hint: 'Provide metadata.wallet_id for wallet_topup or metadata.developer_id for tier_upgrade.',
      },
      400,
    );
  }

  const creditMicros =
    meta.amount_micros && /^\d+$/.test(String(meta.amount_micros))
      ? Number(meta.amount_micros)
      : Number(session.amount_total ?? 0) * 10_000;

  if (!Number.isSafeInteger(creditMicros) || creditMicros <= 0) {
    return jsonWithCors(
      {
        error: 'invalid_topup_amount',
        code: 'INVALID_REQUEST',
        fix_hint: 'Provide positive amount_total (cents) or metadata.amount_micros.',
      },
      400,
    );
  }

  const walletUpdate = await env.DB.prepare(
    'UPDATE agent_wallets SET balance_micros = balance_micros + ?, updated_at = ? WHERE id = ?',
  )
    .bind(creditMicros, now, walletId)
    .run();

  if ((walletUpdate.meta?.changes ?? 0) !== 1) {
    return jsonWithCors(
      {
        error: 'wallet_not_found',
        ...resolveClearinghouseGuidance('wallet_not_found'),
      },
      404,
    );
  }

  await env.DB.prepare(
    'INSERT INTO ledger_entries (id, idempotency_key, wallet_id, developer_id, route_id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json, created_at) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, 0, 0, ?, ?, ?, ?)',
  )
    .bind(
      `led_${crypto.randomUUID()}`,
      eventIdemKey,
      walletId,
      'fiat_wallet',
      'topup',
      creditMicros,
      creditMicros,
      session.id ?? event.id,
      JSON.stringify({ eventId: event.id, sessionId: session.id ?? null }),
      now,
    )
    .run();

  return jsonWithCors({
    received: true,
    kind: 'wallet_topup',
    walletId,
    creditedMicros: creditMicros,
  });
}

async function createTopupCheckoutInternal(
  body: TopupCheckoutBody,
  env: Env,
): Promise<{ status: number; payload: Record<string, unknown> }> {
  let amountMicros: number;
  let kind: 'wallet_topup' | 'tier_upgrade';
  let productName: string;
  let stripePriceId: string | undefined;

  if (body.passTier === 'pro' || body.passTier === 'agency') {
    kind = 'tier_upgrade';
    amountMicros = body.passTier === 'agency' ? 79_000_000 : 39_000_000;
    productName =
      body.passTier === 'agency'
        ? 'Agent Tollbooth 402 — Agency Pass'
        : 'Agent Tollbooth 402 — Pro Pass';
    stripePriceId =
      body.passTier === 'agency' ? env.STRIPE_PRICE_AGENCY_PASS : env.STRIPE_PRICE_PRO_PASS;
  } else {
    kind = 'wallet_topup';
    try {
      amountMicros = usdToMicros(body.amountUsd ?? 10);
    } catch {
      return {
        status: 400,
        payload: {
          error: 'invalid_amount_usd',
          code: 'INVALID_REQUEST',
          fix_hint: 'Supply a valid positive amountUsd >= 1.00.',
        },
      };
    }
    if (amountMicros < 1_000_000) {
      return {
        status: 400,
        payload: {
          error: 'minimum_topup_one_dollar',
          code: 'INVALID_REQUEST',
          fix_hint: 'Minimum Fiat Agent Wallet top-up is $1.00 USD (1,000,000 microdollars).',
        },
      };
    }
    productName = 'Red Center Fiat Agent Wallet Top-Up';
    if (amountMicros === 10_000_000) {
      stripePriceId = env.STRIPE_PRICE_TOPUP_10;
    }
  }

  const hasLiveOrTestStripeKey = Boolean(
    env.STRIPE_SECRET_KEY &&
      (env.STRIPE_SECRET_KEY.startsWith('sk_') || env.STRIPE_SECRET_KEY.startsWith('rk_')) &&
      !env.STRIPE_SECRET_KEY.includes('placeholder'),
  );

  const paymentLinkBase =
    body.passTier === 'pro'
      ? env.STRIPE_PAYMENT_LINK_PRO_PASS
      : body.passTier === 'agency'
        ? env.STRIPE_PAYMENT_LINK_AGENCY_PASS
        : amountMicros === 10_000_000
          ? env.STRIPE_PAYMENT_LINK_TOPUP_10
          : undefined;

  const successUrl = body.successUrl ?? 'https://tollbooth.redcenterstudio.com/pay?status=success';
  const cancelUrl = body.cancelUrl ?? 'https://tollbooth.redcenterstudio.com/pay?status=cancelled';

  if (hasLiveOrTestStripeKey && env.STRIPE_SECRET_KEY) {
    const form = new URLSearchParams();
    form.set('mode', 'payment');
    form.set('success_url', successUrl);
    form.set('cancel_url', cancelUrl);
    if (stripePriceId) {
      form.set('line_items[0][price]', stripePriceId);
      form.set('line_items[0][quantity]', '1');
    } else {
      const unitAmountCents = Math.round(amountMicros / 10_000);
      form.set('line_items[0][price_data][currency]', 'usd');
      form.set('line_items[0][price_data][unit_amount]', String(unitAmountCents));
      form.set('line_items[0][price_data][product_data][name]', productName);
      form.set('line_items[0][quantity]', '1');
    }
    form.set('metadata[kind]', kind);
    form.set('metadata[amount_micros]', String(amountMicros));
    if (body.walletId) {
      form.set('metadata[wallet_id]', body.walletId);
    }
    if (body.developerId) {
      form.set('metadata[developer_id]', body.developerId);
    }
    if (body.passTier) {
      form.set('metadata[target_tier]', body.passTier);
    }

    const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
    });
    const stripeJson = (await stripeRes.json()) as {
      id?: string;
      url?: string;
      error?: { message?: string };
    };
    if (!stripeRes.ok || !stripeJson.url) {
      return {
        status: 502,
        payload: {
          error: 'stripe_checkout_failed',
          code: 'FACILITATOR_ERROR',
          fix_hint: stripeJson.error?.message ?? 'Check STRIPE_SECRET_KEY and Stripe API status.',
        },
      };
    }
    return {
      status: 200,
      payload: {
        checkoutUrl: stripeJson.url,
        sessionId: stripeJson.id,
        amountMicros,
        amountUsd: microsToUsdString(amountMicros),
        kind,
        mode: 'stripe',
      },
    };
  }

  if (paymentLinkBase) {
    const clientRef = body.walletId ?? body.developerId;
    const checkoutUrl = clientRef
      ? `${paymentLinkBase}${paymentLinkBase.includes('?') ? '&' : '?'}client_reference_id=${encodeURIComponent(clientRef)}`
      : paymentLinkBase;
    return {
      status: 200,
      payload: {
        checkoutUrl,
        paymentLinkUrl: paymentLinkBase,
        sessionId: null,
        amountMicros,
        amountUsd: microsToUsdString(amountMicros),
        kind,
        productName,
        mode: 'payment_link',
      },
    };
  }

  const sandboxSessionId = `cs_sandbox_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  return {
    status: 200,
    payload: {
      checkoutUrl: `https://tollbooth.redcenterstudio.com/pay?sandbox_session=${sandboxSessionId}&kind=${kind}`,
      sessionId: sandboxSessionId,
      amountMicros,
      amountUsd: microsToUsdString(amountMicros),
      kind,
      productName,
      mode: 'sandbox',
    },
  };
}

async function handleWalletTopup(request: Request, env: Env): Promise<Response> {
  let body: TopupCheckoutBody;
  try {
    body = (await request.json()) as TopupCheckoutBody;
  } catch {
    return jsonWithCors(
      {
        error: 'invalid_json',
        ...resolveClearinghouseGuidance('invalid_json'),
      },
      400,
    );
  }
  const result = await createTopupCheckoutInternal(body, env);
  return jsonWithCors(result.payload, result.status);
}

function escapeHtmlAttr(val: string): string {
  return val
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function buildDemo402Challenge(request: Request): X402PaymentRequired {
  return {
    x402Version: 2,
    code: 'MISSING_PAYMENT',
    error: 'PAYMENT-SIGNATURE or rcs_receipt bearer header is required',
    fix_hint:
      'Attach an x402 V2 Base64 PAYMENT-SIGNATURE header or an Authorization: Bearer rcs_receipt_... token for $0.01 USD (10000 microdollars).',
    priceUsd: '0.01',
    priceMicros: 10_000,
    acceptedRails: ['x402-v2', 'rcs-fiat-wallet'],
    paymentUrl: 'https://tollbooth.redcenterstudio.com/pay',
    resource: {
      url: 'https://tollbooth.redcenterstudio.com/api/v1/lookup',
      description: 'Sample paywalled API route (GET /api/v1/lookup)',
      mimeType: 'application/json',
    },
    accepts: [
      {
        scheme: 'exact',
        network: DEFAULT_NETWORK,
        amount: '10000',
        asset: DEFAULT_USDC_BASE_ASSET,
        payTo: DEFAULT_PAY_TO,
        maxTimeoutSeconds: 60,
        extra: { name: 'USDC', version: '2' },
      },
    ],
    extensions: {
      fiatAgentWallet: {
        clearinghouseUrl: 'https://tollbooth.redcenterstudio.com',
        headers: ['Authorization: Bearer rcs_receipt_...', 'X-Agent-Receipt'],
        priceMicros: 10_000,
        currency: 'USD_MICROS',
      },
    },
  };
}

function renderClearinghousePortalHtml(env: Env): string {
  const topupAction = env.STRIPE_PAYMENT_LINK_TOPUP_10
    ? `<a class="btn" href="${escapeHtmlAttr(env.STRIPE_PAYMENT_LINK_TOPUP_10)}" rel="noopener noreferrer">Fund Agent Wallet ($10)</a>`
    : `<button class="btn" type="button" onclick="fetch('/wallet/topup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({amountUsd:10})}).then(r=>r.json()).then(d=>{if(d.checkoutUrl)location.href=d.checkoutUrl})">Fund Agent Wallet ($10)</button>`;

  const proAction = env.STRIPE_PAYMENT_LINK_PRO_PASS
    ? `<a class="btn" href="${escapeHtmlAttr(env.STRIPE_PAYMENT_LINK_PRO_PASS)}" rel="noopener noreferrer">Unlock Pro Pass ($39)</a>`
    : `<button class="btn" type="button" onclick="fetch('/wallet/topup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passTier:'pro'})}).then(r=>r.json()).then(d=>{if(d.checkoutUrl)location.href=d.checkoutUrl})">Unlock Pro Pass ($39)</button>`;

  const agencyAction = env.STRIPE_PAYMENT_LINK_AGENCY_PASS
    ? `<a class="btn btn-secondary" href="${escapeHtmlAttr(env.STRIPE_PAYMENT_LINK_AGENCY_PASS)}" rel="noopener noreferrer">Agency Pass ($79)</a>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Tollbooth 402 — Red Center Studio</title>
  <style>
    :root {
      --bg: #1F2937;
      --surface: #111827;
      --amber: #D97706;
      --emerald: #10B981;
      --text: #F9FAFB;
      --muted: #9CA3AF;
    }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0;
      padding: 28px 20px 44px;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }
    .wrap { max-width: 1080px; margin: 0 auto; }
    .header {
      background: var(--surface);
      border: 1px solid #374151;
      border-top: 3px solid var(--amber);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 18px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: rgba(16, 185, 129, 0.12);
      color: var(--emerald);
      border: 1px solid rgba(16, 185, 129, 0.5);
      margin-bottom: 12px;
    }
    .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--emerald); display: inline-block; }
    h1 { margin: 0 0 8px; font-size: 25px; letter-spacing: -0.01em; }
    h2 { margin: 0 0 6px; font-size: 17px; }
    p { margin: 0; color: var(--muted); line-height: 1.5; font-size: 14px; }
    .setup-panel {
      background: var(--surface);
      border: 1px solid #374151;
      border-radius: 10px;
      padding: 20px 24px;
      margin-bottom: 18px;
    }
    .setup-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 14px;
    }
    .setup-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }
    .cmd-box {
      background: #0B111B;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 10px;
    }
    .cmd-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
    }
    .cmd-code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      color: #E5E7EB;
      overflow-wrap: anywhere;
      line-height: 1.45;
    }
    .cmd-foot {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }
    .copy-mini {
      background: #1F2937;
      color: var(--text);
      border: 1px solid #4B5563;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      padding: 5px 10px;
      cursor: pointer;
    }
    .sim-row {
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px solid #1F2937;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px;
    }
    .sim-out {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }
    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
    .card {
      background: var(--surface);
      border: 1px solid #374151;
      border-radius: 10px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .tier-tag {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--emerald);
      margin-bottom: 6px;
    }
    .price {
      font-size: 24px;
      font-weight: 800;
      color: #FBBF24;
      margin: 8px 0;
      font-variant-numeric: tabular-nums;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      margin-top: 16px;
      background: var(--amber);
      color: #111827;
      font-weight: 700;
      font-size: 14px;
      text-decoration: none;
      text-align: center;
      padding: 10px 16px;
      border-radius: 8px;
      border: 0;
      cursor: pointer;
      min-height: 44px;
    }
    .btn-secondary {
      background: #1F2937;
      color: #F9FAFB;
      border: 1px solid var(--amber);
      margin-top: 8px;
    }
    .btn-inline {
      width: auto;
      margin-top: 0;
      padding: 8px 14px;
      font-size: 13px;
      min-height: 38px;
    }
    .footer {
      margin-top: 22px;
      font-size: 13px;
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: space-between;
    }
    a { color: #FBBF24; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: break-word; }
    @media (max-width: 960px) {
      .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .setup-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 640px) {
      body { padding: 14px 12px 28px; overflow-x: hidden; }
      .header, .setup-panel, .card { padding: 18px 14px; }
      h1 { font-size: 21px; }
      .cards { grid-template-columns: 1fr; }
      .btn { min-height: 48px; }
      .btn-inline { width: 100%; min-height: 46px; }
      .footer { flex-direction: column; gap: 6px; align-items: flex-start; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="header">
      <span class="pill"><span class="dot"></span>DUAL-RAIL HTTP 402 CLEARINGHOUSE &middot; &lt;1ms EDGE</span>
      <h1>Agent Tollbooth 402</h1>
      <p>Gate any Cloudflare Worker, Hono route, Next.js handler, or MCP tool with HTTP 402. Accept self-hosted x402 V2 USDC crypto at 0% fee or Stripe-funded Fiat Agent Wallets.</p>
    </section>

    <section class="setup-panel">
      <div class="setup-head">
        <div>
          <h2>30-Second Install</h2>
          <p>Works in Claude Code, Google Antigravity, and TypeScript Workers.</p>
        </div>
        <a class="btn btn-secondary btn-inline" href="/demo/402">Preview 402 Checkout Card</a>
      </div>
      <div class="setup-grid">
        <div class="cmd-box">
          <div class="cmd-label">Claude Code Plugin</div>
          <div class="cmd-code" id="cmd-claude">/plugin install agent-tollbooth-402 --marketplace Red-Center-Studio/agent-tollbooth-402</div>
          <div class="cmd-foot">
            <span class="cmd-label">Skills + MCP</span>
            <button class="copy-mini" type="button" onclick="copyText('cmd-claude',this)">Copy</button>
          </div>
        </div>
        <div class="cmd-box">
          <div class="cmd-label">Edge Middleware (Zero Deps)</div>
          <div class="cmd-code" id="cmd-npm">npm install github:Red-Center-Studio/agent-tollbooth-402</div>
          <div class="cmd-foot">
            <span class="cmd-label">Workers / Hono / Next</span>
            <button class="copy-mini" type="button" onclick="copyText('cmd-npm',this)">Copy</button>
          </div>
        </div>
        <div class="cmd-box">
          <div class="cmd-label">Remote Streamable MCP</div>
          <div class="cmd-code" id="cmd-mcp">https://tollbooth.redcenterstudio.com/mcp</div>
          <div class="cmd-foot">
            <span class="cmd-label">Antigravity &amp; Claude</span>
            <button class="copy-mini" type="button" onclick="copyText('cmd-mcp',this)">Copy</button>
          </div>
        </div>
      </div>
      <div class="sim-row">
        <button id="sim-btn" class="btn btn-secondary btn-inline" type="button" onclick="runLiveCheck()">Run Live 402 &rarr; Health Check</button>
        <span id="sim-out" class="sim-out">Click to test live 402 challenge header + clearinghouse latency.</span>
      </div>
    </section>

    <section class="cards">
      <article class="card">
        <div>
          <div class="tier-tag">Tier 1 &middot; Self-Serve Crypto</div>
          <h2>Free / BYO Crypto x402</h2>
          <div class="price">$0 &middot; 0% fee</div>
          <p>Point <code>payTo</code> at your own Base USDC wallet (<code>eip155:8453</code>) with any x402 V2 facilitator. Unlimited <code>/scan-routes</code> and sandbox testing.</p>
        </div>
        <a class="btn btn-secondary" href="https://github.com/Red-Center-Studio/agent-tollbooth-402" rel="noopener noreferrer">Setup Free x402</a>
      </article>
      <article class="card">
        <div>
          <div class="tier-tag">Tier 2 &middot; Stripe Fiat Rail</div>
          <h2>Hybrid Clearinghouse</h2>
          <div class="price">$0/mo + 7% fee</div>
          <p>Hosted Stripe checkout and prepaid Fiat Agent Wallets on <code>tollbooth.redcenterstudio.com</code> with &lt;1ms <code>rcs_receipt_...</code> edge checks and 93% developer net.</p>
        </div>
        ${topupAction}
      </article>
      <article class="card">
        <div>
          <div class="tier-tag">Tier 3 &middot; Reduced Fee</div>
          <h2>Tollbooth Pro / Agency Pass</h2>
          <div class="price">$39 / $79 &middot; 3% fee</div>
          <p>Cuts clearinghouse fee from 7% to 3% (97% net), unlocks <code>upto</code> per-token metering, custom 402 pages, and spend caps.</p>
        </div>
        <div>
          ${proAction}
          ${agencyAction}
        </div>
      </article>
      <article class="card">
        <div>
          <div class="tier-tag">Tier 4 &middot; Concierge</div>
          <h2>Done-For-You Integration</h2>
          <div class="price">From $399</div>
          <p>Custom MCP + HTTP 402 Tollbooth wrapping, D1 ledger deployment, and verification by Red Center Studio.</p>
        </div>
        <a class="btn" href="https://redcenterstudio.com" rel="noopener noreferrer">Book Integration</a>
      </article>
    </section>
    <p class="footer">
      <span>Red Center Studio &middot; <a href="https://github.com/Red-Center-Studio/agent-tollbooth-402">GitHub</a> &middot; <a href="https://redcenterstudio.com/privacy">Privacy</a></span>
      <span>Health: <a href="/health">/health</a> &middot; Demo 402: <a href="/demo/402">/demo/402</a></span>
    </p>
  </main>
  <script>
    function copyText(id, btn) {
      var el = document.getElementById(id);
      if (!el || !navigator.clipboard) return;
      navigator.clipboard.writeText(el.textContent).then(function () {
        btn.textContent = 'COPIED';
        btn.style.borderColor = '#10B981';
        btn.style.color = '#10B981';
        setTimeout(function () {
          btn.textContent = 'Copy';
          btn.style.borderColor = '#4B5563';
          btn.style.color = '#F9FAFB';
        }, 1400);
      });
    }
    async function runLiveCheck() {
      var out = document.getElementById('sim-out');
      out.textContent = 'Checking /demo/402 and /health...';
      try {
        var t0 = performance.now();
        var r402 = await fetch('/demo/402', { headers: { Accept: 'application/json' } });
        var hdr = r402.headers.get('PAYMENT-REQUIRED') || '';
        var r200 = await fetch('/health');
        var ms = Math.round(performance.now() - t0);
        out.style.color = '#10B981';
        out.textContent = '[402 CHALLENGE] HTTP ' + r402.status + ' | PAYMENT-REQUIRED (' + hdr.length + 'b) -> [200 OK] /health in ' + ms + 'ms';
      } catch (e) {
        out.style.color = '#FBBF24';
        out.textContent = 'Check failed: ' + (e && e.message ? e.message : 'network error');
      }
    }
  </script>
</body>
</html>`;
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
  {
    name: 'tollbooth_create_topup_checkout',
    description:
      'Create a Stripe Checkout (or local sandbox) URL to fund an agent wallet ($1+) or upgrade a developer to Tollbooth Pro ($39) / Agency ($79).',
    inputSchema: {
      type: 'object',
      properties: {
        walletId: { type: 'string' },
        amountUsd: { type: 'number', minimum: 1 },
        developerId: { type: 'string' },
        passTier: { type: 'string', enum: ['pro', 'agency'] },
      },
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

    if (toolName === 'tollbooth_create_topup_checkout') {
      const checkout = await createTopupCheckoutInternal(args as unknown as TopupCheckoutBody, env);
      return jsonRpcOk(rpc.id, {
        isError: checkout.status >= 400,
        content: [{ type: 'text', text: JSON.stringify(checkout.payload) }],
        structuredContent: checkout.payload,
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

      if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/pay')) {
        return withCors(
          new Response(renderClearinghousePortalHtml(env), {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          }),
        );
      }

      if (request.method === 'GET' && url.pathname === '/demo/402') {
        const challenge = buildDemo402Challenge(request);
        const demoReq = new Request('https://tollbooth.redcenterstudio.com/api/v1/lookup', {
          method: 'GET',
        });
        const headers = new Headers({
          'PAYMENT-REQUIRED': encodePaymentHeader(challenge),
          'WWW-Authenticate': `x402, Bearer realm="agent-tollbooth-402", error="${challenge.code}"`,
          'Cache-Control': 'no-store',
        });
        const accept = request.headers.get('Accept') ?? '';
        if (accept.includes('application/json') && !accept.includes('text/html')) {
          headers.set('Content-Type', 'application/json; charset=utf-8');
          return withCors(new Response(JSON.stringify(challenge), { status: 402, headers }));
        }
        headers.set('Content-Type', 'text/html; charset=utf-8');
        return withCors(
          new Response(renderDefault402HtmlPage(challenge, demoReq), {
            status: 402,
            headers,
          }),
        );
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

      if (request.method === 'POST' && url.pathname === '/wallet/topup') {
        return handleWalletTopup(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/webhook/stripe') {
        return handleStripeWebhook(request, env);
      }

      return jsonWithCors(
        {
          error: 'not_found',
          code: 'NOT_FOUND',
          fix_hint:
            'Supported routes: GET /, GET /pay, GET /health, POST /verify, POST /settle, POST /wallet/issue-receipt, POST /wallet/topup, POST /webhook/stripe, POST /mcp.',
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
