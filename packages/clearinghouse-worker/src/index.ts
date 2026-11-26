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
import MCP_TOOLS from '../mcp-tools.json';
import { verifyEip3009 } from './evm.js';
import {
  bearerToken,
  isUniqueConstraintError,
  ledgerHistory,
  receiptJwks,
  receiptSigningKey,
  registerDeveloper,
  registerWallet,
  resolveScopedKey,
  rotateKey,
  scopeAllows,
  setPayoutAddress,
  type Ed25519Env,
  type KeyScope,
} from './accounts.js';
import { callUpstream, facilitatorFor, upstreamBody, type UpstreamEnv } from './upstream.js';

export type DeveloperTier = 'free' | 'hybrid' | 'pro' | 'agency';
export type SettlementRail = 'fiat_wallet' | 'x402';

export interface Env extends UpstreamEnv, Ed25519Env {
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
  /** 'true' opens paid checkout. Any other value keeps wallet top-ups and passes closed. */
  PAID_SALES_OPEN?: string;
  /** Comma-separated developer ids owned by Red Center Studio. Fiat Agent Wallets pay only these. */
  STUDIO_DEVELOPER_IDS?: string;
  STRIPE_PAYMENT_LINK_TOPUP_10?: string;
  STRIPE_PAYMENT_LINK_PRO_PASS?: string;
  STRIPE_PAYMENT_LINK_AGENCY_PASS?: string;
  PRO_PASS_URL?: string;
  ENVIRONMENT?: string;
}

/** Mock signatures and fake settlement hashes are accepted only in the test sandbox, never in production. */
function isSandboxEnv(env: Env): boolean {
  return env.ENVIRONMENT === 'test-sandbox' || env.ENVIRONMENT === 'development';
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
        fix_hint: 'Supply Authorization: Bearer <key>, using the wallet or developer key issued at registration.',
      };
    case 'settlement_not_configured':
      return {
        code: 'FACILITATOR_ERROR',
        fix_hint: 'On-chain settlement is not switched on for this network yet. Use Base Sepolia (eip155:84532) to test, or settle Base mainnet through your own facilitator.',
      };
    case 'upto_not_supported_onchain':
      return {
        code: 'INVALID_REQUEST',
        fix_hint: 'x402 on-chain payments use the exact scheme (EIP-3009). Use the exact scheme with a fixed price per call.',
      };
    case 'unsupported_network':
    case 'asset_mismatch':
      return {
        code: 'INVALID_REQUEST',
        fix_hint: 'Pay in USDC on Base (eip155:8453) or Base Sepolia (eip155:84532), with the USDC contract address as asset.',
      };
    case 'smart_wallet_signature_needs_facilitator':
      return {
        code: 'INVALID_SIGNATURE',
        fix_hint: 'Smart-contract wallet signatures are checked by the on-chain facilitator, which is not available for this network yet. Sign with an EOA wallet.',
      };
    case 'facilitator_settlement_failed':
      return {
        code: 'FACILITATOR_ERROR',
        fix_hint: 'The on-chain transfer did not go through (often low USDC balance or an expired authorization). Nothing was charged; sign a new payment and retry.',
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
    case 'insufficient_funds':
      return {
        code: 'INSUFFICIENT_FUNDS',
        fix_hint: 'The paying wallet does not hold enough USDC on this network. Nothing was charged; fund the wallet and sign a new payment.',
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
        fix_hint: 'No account has that developer or wallet ID. Check it, or create an account first.',
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
    case 'pass_required_for_mainnet_settlement':
      return {
        code: 'PRO_PASS_REQUIRED',
        fix_hint:
          'Hosted Base mainnet settlement needs a Pro or Agency Pass on the developer account whose payout address is payTo (https://tollbooth.redcenterstudio.com/pay). Base Sepolia stays free, or settle mainnet through your own facilitator.',
      };
    case 'monthly_hosted_allowance_reached':
      return {
        code: 'ALLOWANCE_REACHED',
        fix_hint:
          'This pass has used its 10,000 hosted Base mainnet settlements for this month. Nothing was charged. Settle through your own facilitator until the 1st of next month (UTC), or email hello@redcenterstudio.com for a larger plan.',
      };
    case 'fiat_wallet_studio_routes_only':
      return {
        code: 'RAIL_NOT_AVAILABLE',
        fix_hint:
          'Fiat Agent Wallets pay only for Red Center Studio routes. Accept x402 USDC on Base instead: set payTo to your own wallet and agents pay you directly, 0% fee.',
      };
    default:
      return {
        code: 'INVALID_REQUEST',
        fix_hint: `Check request fields and try again (${reason}).`,
      };
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readJsonObject(
  request: Request,
): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false }> {
  try {
    const parsed: unknown = await request.json();
    if (!isPlainObject(parsed)) {
      return { ok: false };
    }
    return { ok: true, data: parsed };
  } catch {
    return { ok: false };
  }
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  // Every authenticated call uses a bearer key, never cookies, so any origin may call (browser MCP inspectors, dashboards).
  headers.set('Access-Control-Allow-Origin', '*');
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
 * x402 USDC payments settle straight to the developer's payTo wallet: 0% (0 bps), for every tier.
 * The percentages below apply only to the Fiat Agent Wallet rail, which pays Red Center Studio's own routes only.
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

/** Admin when the master key is presented, the wallet or developer for a scoped key, otherwise null. */
async function requestScope(request: Request, env: Env): Promise<KeyScope | null> {
  if (await isAuthorizedAdminRequest(request, env)) {
    return { kind: 'admin' };
  }
  const token = bearerToken(request);
  return token ? resolveScopedKey(env.DB, token) : null;
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

  if (!isSandboxEnv(env)) {
    const reqs = body.paymentRequirements;
    if (reqs.scheme !== 'exact') {
      return { ok: false, reason: 'upto_not_supported_onchain' };
    }
    const auth = body.paymentPayload.payload.authorization;
    const check = verifyEip3009(reqs.network, reqs.asset, auth, sig);
    if (check.ok) {
      return { ok: true };
    }
    if (check.reason === 'smart_wallet_signature_needs_facilitator') {
      const facilitator = facilitatorFor(reqs.network, env);
      if (!facilitator) {
        return { ok: false, reason: 'settlement_not_configured' };
      }
      const up = await callUpstream(
        facilitator,
        'verify',
        upstreamBody({ ...reqs, signature: sig, authorization: { ...auth } }),
      );
      return up.ok && up.json.isValid === true
        ? { ok: true }
        : { ok: false, reason: String(up.json.invalidReason ?? 'signature_mismatch') };
    }
    return { ok: false, reason: check.reason };
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
  if (
    !isPlainObject(body) ||
    body.x402Version !== 2 ||
    !isPlainObject(body.paymentPayload) ||
    !isPlainObject(body.paymentRequirements)
  ) {
    return { isValid: false, invalidReason: 'invalid_x402_request' };
  }

  const { paymentPayload, paymentRequirements } = body;
  if (paymentPayload.x402Version !== 2) {
    return { isValid: false, invalidReason: 'unsupported_x402_version' };
  }

  if (
    typeof paymentRequirements.scheme !== 'string' ||
    typeof paymentRequirements.network !== 'string' ||
    typeof paymentRequirements.asset !== 'string' ||
    typeof paymentRequirements.payTo !== 'string' ||
    (typeof paymentRequirements.amount !== 'string' && typeof paymentRequirements.amount !== 'number')
  ) {
    return { isValid: false, invalidReason: 'invalid_x402_request' };
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

  if (!isPlainObject(paymentPayload.payload) || typeof paymentPayload.payload.signature !== 'string') {
    return { isValid: false, invalidReason: 'malformed_authorization' };
  }
  const auth = paymentPayload.payload.authorization;
  if (
    !isPlainObject(auth) ||
    typeof auth.from !== 'string' ||
    typeof auth.to !== 'string' ||
    typeof auth.nonce !== 'string' ||
    auth.nonce.length === 0 ||
    auth.nonce.length > 256 ||
    (typeof auth.value !== 'string' && typeof auth.value !== 'number') ||
    (typeof auth.validAfter !== 'string' && typeof auth.validAfter !== 'number') ||
    (typeof auth.validBefore !== 'string' && typeof auth.validBefore !== 'number') ||
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
  if (!Number.isSafeInteger(validAfter) || !Number.isSafeInteger(validBefore)) {
    return { isValid: false, invalidReason: 'malformed_authorization' };
  }
  const clockSkew = DEFAULT_CLOCK_SKEW_SECONDS;
  if (now < validAfter - clockSkew || now > validBefore + clockSkew) {
    return { isValid: false, invalidReason: 'authorization_expired' };
  }

  if (BigInt(auth.value) < BigInt(paymentRequirements.amount)) {
    return { isValid: false, invalidReason: 'insufficient_authorized_amount' };
  }

  const developer = await env.DB.prepare(
    "SELECT id, email, name, tier, payout_address FROM developers WHERE LOWER(payout_address) = LOWER(?) ORDER BY CASE WHEN tier IN ('pro', 'agency') THEN 0 ELSE 1 END, created_at LIMIT 1",
  )
    .bind(paymentRequirements.payTo)
    .first<DeveloperRow>();

  if (reqScheme === 'upto') {
    if (!isSandboxEnv(env)) {
      return { isValid: false, invalidReason: 'upto_not_supported_onchain', developer };
    }
    if (!developer || (developer.tier !== 'pro' && developer.tier !== 'agency')) {
      return { isValid: false, invalidReason: 'pro_pass_required_for_upto', developer };
    }
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
  const parsed = await readJsonObject(request);
  if (!parsed.ok) {
    const g = resolveClearinghouseGuidance('invalid_json');
    return jsonWithCors(
      { isValid: false, invalidReason: 'invalid_json', ...g },
      400,
    );
  }
  const body = parsed.data as unknown as FacilitatorRequestBody;

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
  const parsed = await readJsonObject(request);
  if (!parsed.ok) {
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
  const body = parsed.data as unknown as FacilitatorRequestBody;

  const authNonce = body?.paymentPayload?.payload?.authorization?.nonce;
  if (
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body) ||
    body.x402Version !== 2 ||
    !body.paymentPayload ||
    !body.paymentRequirements ||
    typeof authNonce !== 'string' ||
    authNonce.length === 0
  ) {
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'invalid_x402_request',
        ...resolveClearinghouseGuidance('invalid_x402_request'),
      },
      400,
    );
  }

  const rawIdempotencyKey = request.headers.get('Idempotency-Key') ?? `settle_${authNonce}`;
  const idempotencyKey = `x402:${rawIdempotencyKey}`;

  const existing = await env.DB.prepare(
    "SELECT id, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json FROM ledger_entries WHERE idempotency_key = ? AND rail = 'x402' AND entry_type = 'settlement' LIMIT 1",
  )
    .bind(idempotencyKey)
    .first<ExistingLedgerRow>();

  if (existing) {
    const meta = existing.metadata_json
      ? (JSON.parse(existing.metadata_json) as { network?: string; nonce?: string })
      : {};
    if (meta.nonce && meta.nonce !== authNonce) {
      return jsonWithCors(
        {
          success: false,
          txHash: null,
          errorReason: 'idempotency_conflict',
          ...resolveClearinghouseGuidance('idempotency_conflict'),
        },
        409,
      );
    }
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
    const requestedSettle = body.settleAmount ?? String(req.amount);
    if (typeof requestedSettle !== 'string' || !/^\d+$/.test(requestedSettle)) {
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

  if (req.scheme === 'exact') {
    // EIP-3009 moves exactly the authorized value on chain.
    settleBig = authorizedBig;
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

  // Hosted settlement of real money (Base mainnet) is what the Pro and Agency Pass buy. Testnet stays free, and
  // anyone can settle mainnet through their own facilitator. The payment itself always goes straight to payTo.
  if (MAINNET_NETWORKS.has(req.network) && !hasHostedMainnetAccess(verification.developer ?? null, env)) {
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'pass_required_for_mainnet_settlement',
        ...resolveClearinghouseGuidance('pass_required_for_mainnet_settlement'),
      },
      402,
    );
  }

  // Each pass includes a monthly allowance of hosted mainnet settlements: the studio pays the facilitator per
  // settlement, and a pass is paid once. Studio-owned accounts are not limited.
  if (MAINNET_NETWORKS.has(req.network) && verification.developer && !studioDeveloperIds(env).has(verification.developer.id)) {
    const used = await hostedMainnetSettlementsThisMonth(env, verification.developer.id);
    if (used >= HOSTED_MONTHLY_ALLOWANCE) {
      return jsonWithCors(
        {
          success: false,
          txHash: null,
          errorReason: 'monthly_hosted_allowance_reached',
          ...resolveClearinghouseGuidance('monthly_hosted_allowance_reached'),
        },
        429,
      );
    }
  }

  const sandbox = isSandboxEnv(env);
  const facilitator = sandbox ? null : facilitatorFor(req.network, env);
  if (!sandbox && !facilitator) {
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'settlement_not_configured',
        ...resolveClearinghouseGuidance('settlement_not_configured'),
      },
      503,
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

  // Rail A pays the developer's own wallet directly on chain, so the clearinghouse takes no fee.
  const feeBreakdown = calculateClearinghouseFee(grossMicros, 'free', 'x402');
  let txHash: string;
  if (facilitator) {
    const up = await callUpstream(
      facilitator,
      'settle',
      upstreamBody({
        network: req.network,
        asset: req.asset,
        amount: req.amount,
        payTo: req.payTo,
        maxTimeoutSeconds: req.maxTimeoutSeconds,
        resource: req.resource,
        signature: body.paymentPayload.payload.signature,
        authorization: { ...auth },
      }),
    );
    const tx = typeof up.json.transaction === 'string' ? up.json.transaction : '';
    if (!up.ok || up.json.success !== true || !tx) {
      // Nothing settled: free the nonce so the payer can retry. The USDC contract still refuses a reused nonce.
      await env.DB.prepare('DELETE FROM used_nonces WHERE nonce = ?').bind(auth.nonce).run();
      const reason = String(up.json.errorReason ?? 'facilitator_settlement_failed');
      return jsonWithCors(
        { success: false, txHash: null, errorReason: reason, ...resolveClearinghouseGuidance(reason) },
        502,
      );
    }
    txHash = tx;
  } else {
    txHash = await computeSettlementTxHash(`sandbox:${auth.nonce}:${req.network}:${grossMicros}:${now}`);
  }

  try {
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
        JSON.stringify({ network: req.network, payer: auth.from, nonce: auth.nonce, sandbox }),
        now,
      )
      .run();
  } catch (err) {
    if (!isUniqueConstraintError(err)) {
      throw err;
    }
    const winner = await env.DB.prepare(
      "SELECT id, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json FROM ledger_entries WHERE idempotency_key = ? AND rail = 'x402' AND entry_type = 'settlement' LIMIT 1",
    )
      .bind(idempotencyKey)
      .first<ExistingLedgerRow>();
    const winnerMeta = winner?.metadata_json
      ? (JSON.parse(winner.metadata_json) as { network?: string; nonce?: string })
      : {};
    if (winner && winnerMeta.nonce === auth.nonce) {
      return jsonWithCors({
        success: true,
        txHash: winner.tx_reference,
        network: winnerMeta.network ?? req.network,
        settledAmount: String(winner.gross_micros),
        platformFeeMicros: winner.platform_fee_micros,
        developerNetMicros: winner.developer_net_micros,
        idempotentReplay: true,
        errorReason: null,
      });
    }
    if (!facilitator) {
      await env.DB.prepare('DELETE FROM used_nonces WHERE nonce = ?').bind(auth.nonce).run();
    }
    return jsonWithCors(
      {
        success: false,
        txHash: null,
        errorReason: 'idempotency_conflict',
        ...resolveClearinghouseGuidance('idempotency_conflict'),
      },
      409,
    );
  }

  return jsonWithCors({
    success: true,
    txHash,
    network: req.network,
    settledAmount: String(grossMicros),
    platformFeeMicros: feeBreakdown.platformFeeMicros,
    developerNetMicros: feeBreakdown.developerNetMicros,
    ...(sandbox ? { sandbox: true } : {}),
    errorReason: null,
  });
}

async function issueWalletReceiptInternal(
  body: IssueReceiptBody,
  idempotencyKey: string,
  env: Env,
): Promise<{ status: number; payload: Record<string, unknown> }> {
  if (
    !isPlainObject(body) ||
    typeof body.walletId !== 'string' ||
    !body.walletId ||
    typeof body.developerId !== 'string' ||
    !body.developerId ||
    typeof body.audience !== 'string' ||
    body.audience.trim().length === 0 ||
    body.audience.length > 2048 ||
    /[\r\n\0]/.test(body.audience) ||
    (body.method !== undefined && (typeof body.method !== 'string' || !/^(\*|[A-Za-z]{1,16})$/.test(body.method))) ||
    (body.scheme !== undefined && body.scheme !== 'exact' && body.scheme !== 'upto') ||
    typeof body.amountMicros !== 'number' ||
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
  if (
    body.ttlSeconds !== undefined &&
    (typeof body.ttlSeconds !== 'number' ||
      !Number.isSafeInteger(body.ttlSeconds) ||
      body.ttlSeconds < 10 ||
      body.ttlSeconds > 300)
  ) {
    return {
      status: 400,
      payload: {
        error: 'invalid_ttl_seconds',
        code: 'INVALID_REQUEST',
        fix_hint: 'ttlSeconds must be an integer between 10 and 300.',
      },
    };
  }
  if (body.routeId !== undefined && (typeof body.routeId !== 'string' || body.routeId.trim().length === 0 || body.routeId.length > 128)) {
    return {
      status: 400,
      payload: {
        error: 'invalid_route_id',
        code: 'INVALID_REQUEST',
        fix_hint: 'routeId must belong to the specified developerId in the routes table.',
      },
    };
  }

  const scopedIdemKey = `rcpt:${body.walletId}:${idempotencyKey}`;

  const existing = await env.DB.prepare(
    "SELECT id, developer_id, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json FROM ledger_entries WHERE idempotency_key = ? AND wallet_id = ? AND rail = 'fiat_wallet' AND entry_type = 'charge' LIMIT 1",
  )
    .bind(scopedIdemKey, body.walletId)
    .first<ExistingLedgerRow & { developer_id?: string | null }>();

  if (existing?.metadata_json) {
    const cached = JSON.parse(existing.metadata_json) as { claims?: { aud?: string; amt?: number } } & Record<string, unknown>;
    if (
      existing.developer_id !== body.developerId ||
      cached.claims?.aud !== body.audience ||
      cached.claims?.amt !== body.amountMicros
    ) {
      return {
        status: 409,
        payload: {
          error: 'idempotency_conflict',
          ...resolveClearinghouseGuidance('idempotency_conflict'),
        },
      };
    }
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
  // Card-funded wallet money is held by Red Center Studio, and there is no way to pay it out to other developers
  // (Stripe Connect from an Australian platform reaches Australian accounts only). So the fiat rail only pays the
  // studio's own developer accounts; everyone else is paid directly on chain through x402.
  if (!studioDeveloperIds(env).has(developer.id)) {
    return {
      status: 403,
      payload: {
        error: 'fiat_wallet_studio_routes_only',
        ...resolveClearinghouseGuidance('fiat_wallet_studio_routes_only'),
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

  if (body.routeId !== undefined) {
    const routeRow = await env.DB.prepare('SELECT id FROM routes WHERE id = ? AND developer_id = ? LIMIT 1')
      .bind(body.routeId, developer.id)
      .first<{ id: string }>();
    if (!routeRow) {
      return {
        status: 400,
        payload: {
          error: 'invalid_route_id',
          code: 'INVALID_REQUEST',
          fix_hint: 'routeId does not exist for this developer.',
        },
      };
    }
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

  // Ed25519 when its key is set: merchants verify with the public key from /.well-known/tollbooth-jwks.json and
  // never hold a secret that could mint receipts. HS256 stays as the fallback for self-hosted single-tenant setups.
  const edKey = await receiptSigningKey(env);
  const receipt = edKey
    ? await signFiatReceipt(claims, { alg: 'ed25519', privateKey: edKey })
    : await signFiatReceipt(claims, { alg: 'hs256', secret: env.RECEIPT_SIGNING_SECRET });

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
        scopedIdemKey,
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
  } catch (err) {
    // Roll back the wallet debit if ledger insertion failed (whether race conflict or DB error).
    await env.DB.prepare(
      `UPDATE agent_wallets
       SET balance_micros = balance_micros + ?,
           daily_spent_micros = MAX(0, daily_spent_micros - ?),
           updated_at = ?
       WHERE id = ?`,
    )
      .bind(body.amountMicros, body.amountMicros, now, wallet.id)
      .run();

    if (!isUniqueConstraintError(err)) {
      console.error('issue_receipt_ledger_insert_failed', err);
      throw err;
    }

    const winner = await env.DB.prepare(
      "SELECT metadata_json FROM ledger_entries WHERE idempotency_key = ? AND wallet_id = ? AND rail = 'fiat_wallet' AND entry_type = 'charge' LIMIT 1",
    )
      .bind(scopedIdemKey, wallet.id)
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
      amount_subtotal?: number;
      payment_status?: string;
      client_reference_id?: string | null;
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

  if (!isPlainObject(event) || typeof event.id !== 'string' || !event.id || typeof event.type !== 'string' || !event.type) {
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

  if (event.type !== 'checkout.session.completed' && event.type !== 'checkout.session.async_payment_succeeded') {
    return jsonWithCors({ received: true, ignored: true, type: event.type });
  }

  const session = event.data?.object ?? {};
  // Bank debits and other delayed methods complete unpaid; they are fulfilled on async_payment_succeeded instead.
  if (event.type === 'checkout.session.completed' && session.payment_status === 'unpaid') {
    return jsonWithCors({ received: true, pending: true, sessionId: session.id ?? null });
  }
  const meta: Record<string, string | undefined> = isPlainObject(session.metadata)
    ? ({ ...session.metadata } as Record<string, string | undefined>)
    : {};
  // Payment Links carry no metadata: recover the account from client_reference_id and the amount paid.
  const clientRef = typeof session.client_reference_id === 'string' ? session.client_reference_id : '';
  if (!meta.kind && !meta.wallet_id && !meta.developer_id && clientRef) {
    if (clientRef.startsWith('wallet_')) {
      meta.kind = 'wallet_topup';
      meta.wallet_id = clientRef;
    } else if (clientRef.startsWith('dev_')) {
      const cents = Number(session.amount_subtotal ?? session.amount_total ?? 0);
      meta.kind = 'tier_upgrade';
      meta.developer_id = clientRef;
      meta.target_tier = cents === 7900 ? 'agency' : cents === 3900 ? 'pro' : '';
    }
  }
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

    const existingDev = await env.DB.prepare('SELECT id, tier FROM developers WHERE id = ? LIMIT 1')
      .bind(meta.developer_id)
      .first<{ id: string; tier: DeveloperTier }>();

    if (!existingDev) {
      return jsonWithCors(
        {
          error: 'developer_not_found',
          ...resolveClearinghouseGuidance('developer_not_found'),
        },
        404,
      );
    }

    // Never downgrade an Agency Pass holder to Pro if an older webhook arrives out of order.
    const effectiveTier: DeveloperTier =
      existingDev.tier === 'agency' && targetTier === 'pro' ? 'agency' : targetTier;

    // Claim the event and apply the tier in one atomic batch: a replay fails on the
    // used_nonces primary key and rolls back; any other failure leaves no claim behind,
    // so Stripe's retry is processed instead of being mistaken for a replay.
    try {
      await env.DB.batch([
        env.DB.prepare(
          'INSERT INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        ).bind(eventIdemKey, 'fiat_wallet', meta.developer_id, '/webhook/stripe', now + 365 * 86_400, now),
        env.DB.prepare(
          "UPDATE developers SET tier = CASE WHEN tier = 'agency' AND ? = 'pro' THEN 'agency' ELSE ? END WHERE id = ?",
        ).bind(targetTier, targetTier, meta.developer_id),
      ]);
    } catch (err) {
      if (isUniqueConstraintError(err)) {
        return jsonWithCors({ received: true, idempotentReplay: true, eventId: event.id });
      }
      throw err;
    }

    return jsonWithCors({
      received: true,
      kind: 'tier_upgrade',
      developerId: meta.developer_id,
      tier: effectiveTier,
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

  const existingWallet = await env.DB.prepare('SELECT id FROM agent_wallets WHERE id = ? LIMIT 1')
    .bind(walletId)
    .first<{ id: string }>();

  if (!existingWallet) {
    return jsonWithCors(
      {
        error: 'wallet_not_found',
        ...resolveClearinghouseGuidance('wallet_not_found'),
      },
      404,
    );
  }

  // The event claim, the credit and the ledger row commit together or not at all.
  const claimStmt = env.DB.prepare(
    'INSERT INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(eventIdemKey, 'fiat_wallet', walletId, '/webhook/stripe', now + 365 * 86_400, now);

  const updateWalletStmt = env.DB.prepare(
    'UPDATE agent_wallets SET balance_micros = balance_micros + ?, updated_at = ? WHERE id = ?',
  ).bind(creditMicros, now, walletId);

  const insertLedgerStmt = env.DB.prepare(
    'INSERT INTO ledger_entries (id, idempotency_key, wallet_id, developer_id, route_id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, metadata_json, created_at) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, 0, 0, ?, ?, ?, ?)',
  ).bind(
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
  );

  try {
    await env.DB.batch([claimStmt, updateWalletStmt, insertLedgerStmt]);
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      return jsonWithCors({ received: true, idempotentReplay: true, eventId: event.id });
    }
    throw err;
  }

  return jsonWithCors({
    received: true,
    kind: 'wallet_topup',
    walletId,
    creditedMicros: creditMicros,
  });
}

function hasRealStripeKey(env: Env): boolean {
  return Boolean(
    env.STRIPE_SECRET_KEY &&
      (env.STRIPE_SECRET_KEY.startsWith('sk_') || env.STRIPE_SECRET_KEY.startsWith('rk_')) &&
      !env.STRIPE_SECRET_KEY.includes('placeholder'),
  );
}

/** Hosted Base mainnet settlements included with a pass each UTC calendar month. */
const HOSTED_MONTHLY_ALLOWANCE = 10_000;

/** Successful hosted mainnet settlements for one developer since the start of this UTC month. */
async function hostedMainnetSettlementsThisMonth(env: Env, developerId: string): Promise<number> {
  const now = new Date();
  const monthStart = Math.floor(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) / 1000);
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM ledger_entries WHERE developer_id = ? AND rail = 'x402' AND entry_type = 'settlement'
       AND created_at >= ? AND metadata_json LIKE '%"network":"eip155:8453"%'`,
  )
    .bind(developerId, monthStart)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

/** Networks where hosted settlement moves real money and needs a Pro or Agency Pass. */
const MAINNET_NETWORKS = new Set(['eip155:8453']);

/** Pass holders, and the studio's own accounts, may settle mainnet payments through the hosted facilitator. */
function hasHostedMainnetAccess(developer: DeveloperRow | null, env: Env): boolean {
  if (!developer) return false;
  return developer.tier === 'pro' || developer.tier === 'agency' || studioDeveloperIds(env).has(developer.id);
}

/** Developer accounts owned by Red Center Studio: the only ones a Fiat Agent Wallet may pay. Empty means none. */
function studioDeveloperIds(env: Env): Set<string> {
  return new Set(
    (env.STUDIO_DEVELOPER_IDS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

/** Top-ups are only sold while a studio-owned route can actually be paid from a wallet. */
function topupsOpen(env: Env): boolean {
  return studioDeveloperIds(env).size > 0;
}

function paidSalesOpen(env: Env): boolean {
  return env.PAID_SALES_OPEN === 'true';
}

async function createTopupCheckoutInternal(
  body: TopupCheckoutBody,
  env: Env,
): Promise<{ status: number; payload: Record<string, unknown> }> {
  if (
    !isPlainObject(body) ||
    (body.walletId !== undefined && typeof body.walletId !== 'string') ||
    (body.developerId !== undefined && typeof body.developerId !== 'string')
  ) {
    return {
      status: 400,
      payload: { error: 'invalid_request', code: 'INVALID_REQUEST', fix_hint: 'Provide a JSON object with string account IDs.' },
    };
  }
  let amountMicros: number;
  let kind: 'wallet_topup' | 'tier_upgrade';
  let productName: string;
  let stripePriceId: string | undefined;

  if (body.passTier !== undefined && body.passTier !== 'pro' && body.passTier !== 'agency') {
    return {
      status: 400,
      payload: { error: 'invalid_pass_tier', code: 'INVALID_REQUEST', fix_hint: 'passTier must be "pro" or "agency".' },
    };
  }
  if (body.passTier === 'pro' || body.passTier === 'agency') {
    kind = 'tier_upgrade';
    amountMicros = body.passTier === 'agency' ? 79_000_000 : 39_000_000;
    productName =
      body.passTier === 'agency'
        ? 'Agent Tollbooth 402 Agency Pass'
        : 'Agent Tollbooth 402 Pro Pass';
    stripePriceId =
      body.passTier === 'agency' ? env.STRIPE_PRICE_AGENCY_PASS : env.STRIPE_PRICE_PRO_PASS;
  } else {
    kind = 'wallet_topup';
    if (!topupsOpen(env)) {
      return {
        status: 409,
        payload: {
          error: 'topups_not_open',
          code: 'RAIL_NOT_AVAILABLE',
          fix_hint:
            'Agent wallet top-ups open once Red Center Studio APIs accept them. Pay developers directly with x402 USDC instead.',
        },
      };
    }
    try {
      amountMicros = usdToMicros((body.amountUsd ?? 10) as number | string);
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
    if (amountMicros < 1_000_000 || amountMicros > 10_000_000_000) {
      return {
        status: 400,
        payload: {
          error: 'minimum_topup_one_dollar',
          code: 'INVALID_REQUEST',
          fix_hint: 'Fiat Agent Wallet top-up must be between $1.00 and $10,000.00 USD.',
        },
      };
    }
    productName = 'Red Center Fiat Agent Wallet Top-Up';
    if (amountMicros === 10_000_000) {
      stripePriceId = env.STRIPE_PRICE_TOPUP_10;
    }
  }

  const hasLiveOrTestStripeKey = hasRealStripeKey(env);

  const paymentLinkBase =
    body.passTier === 'pro'
      ? env.STRIPE_PAYMENT_LINK_PRO_PASS
      : body.passTier === 'agency'
        ? env.STRIPE_PAYMENT_LINK_AGENCY_PASS
        : amountMicros === 10_000_000
          ? env.STRIPE_PAYMENT_LINK_TOPUP_10
          : undefined;

  // Return only to this site, so a checkout link cannot be used to bounce buyers elsewhere.
  const sameSite = (u: unknown): u is string =>
    typeof u === 'string' && u.startsWith('https://tollbooth.redcenterstudio.com/');
  const successUrl = sameSite(body.successUrl)
    ? body.successUrl
    : 'https://tollbooth.redcenterstudio.com/pay?status=success&session_id={CHECKOUT_SESSION_ID}';
  const cancelUrl = sameSite(body.cancelUrl)
    ? body.cancelUrl
    : 'https://tollbooth.redcenterstudio.com/pay?status=cancelled';

  // Real money never moves unless the webhook can deliver what was bought. A Stripe Checkout Session carries the
  // wallet or developer id in its metadata; a hosted Payment Link carries none, so it stays behind PAID_SALES_OPEN.
  const takesRealMoney = hasLiveOrTestStripeKey || Boolean(paymentLinkBase);
  const fulfilmentId = kind === 'tier_upgrade' ? body.developerId : body.walletId;
  if (takesRealMoney && !fulfilmentId) {
    return {
      status: 400,
      payload: {
        error: 'checkout_requires_account_id',
        code: 'INVALID_REQUEST',
        fix_hint:
          kind === 'tier_upgrade'
            ? 'Pass developerId so the pass can be applied after payment.'
            : 'Pass walletId so the top-up can be credited after payment.',
      },
    };
  }
  if (takesRealMoney && !paidSalesOpen(env)) {
    return {
      status: 409,
      payload: {
        error: 'paid_sales_not_open',
        code: 'INVALID_REQUEST',
        fix_hint: 'Paid wallet top-ups and passes are not open yet. The sandbox and the free x402 rail work today.',
      },
    };
  }

  if (takesRealMoney && fulfilmentId) {
    const found =
      kind === 'tier_upgrade'
        ? await env.DB.prepare('SELECT id, payout_address FROM developers WHERE id = ? LIMIT 1')
            .bind(fulfilmentId)
            .first<{ id: string; payout_address?: string | null }>()
        : await env.DB.prepare("SELECT id FROM agent_wallets WHERE id = ? AND status = 'active' LIMIT 1")
            .bind(fulfilmentId)
            .first<{ id: string }>();
    if (!found) {
      const reason = kind === 'tier_upgrade' ? 'developer_not_found' : 'wallet_not_found';
      return { status: 404, payload: { error: reason, ...resolveClearinghouseGuidance(reason) } };
    }
    // The pass unlocks hosted settlement by matching payTo to the payout address, so never sell one without it.
    if (kind === 'tier_upgrade' && !(found as { payout_address?: string | null }).payout_address) {
      return {
        status: 409,
        payload: {
          error: 'payout_address_required',
          code: 'INVALID_REQUEST',
          fix_hint:
            'This developer account has no payout wallet, so a pass could not unlock anything. Create an account with the Base wallet you use as payTo, then buy the pass for that account.',
        },
      };
    }
  }

  if (hasLiveOrTestStripeKey && env.STRIPE_SECRET_KEY) {
    const form = new URLSearchParams();
    form.set('mode', 'payment');
    // Same as the studio's Payment Links: Stripe Tax decides what to collect from the buyer's location.
    form.set('automatic_tax[enabled]', 'true');
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
    if (fulfilmentId) {
      form.set('client_reference_id', fulfilmentId);
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

    let stripeRes: Response;
    let stripeJson: { id?: string; url?: string; error?: { message?: string } } = {};
    try {
      stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: form.toString(),
      });
      stripeJson = (await stripeRes.json().catch(() => ({}))) as {
        id?: string;
        url?: string;
        error?: { message?: string };
      };
    } catch (err) {
      console.error('stripe_checkout_network_error', err);
      return {
        status: 502,
        payload: {
          error: 'stripe_checkout_failed',
          code: 'FACILITATOR_ERROR',
          fix_hint:
            'Checkout could not open right now. Nothing was charged. Please try again in a minute, or email hello@redcenterstudio.com.',
        },
      };
    }
    if (!stripeRes.ok || !stripeJson.url) {
      console.error('stripe_checkout_failed', stripeRes.status, stripeJson.error?.message ?? '');
      return {
        status: 502,
        payload: {
          error: 'stripe_checkout_failed',
          code: 'FACILITATOR_ERROR',
          fix_hint:
            'Checkout could not open right now. Nothing was charged. Please try again in a minute, or email hello@redcenterstudio.com.',
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
  const parsed = await readJsonObject(request);
  if (!parsed.ok) {
    return jsonWithCors(
      {
        error: 'invalid_json',
        ...resolveClearinghouseGuidance('invalid_json'),
      },
      400,
    );
  }
  const result = await createTopupCheckoutInternal(parsed.data as unknown as TopupCheckoutBody, env);
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
      'Sign a USDC payment for $0.01 USD on Base and retry with an x402 V2 Base64 PAYMENT-SIGNATURE header.',
    priceUsd: '0.01',
    priceMicros: 10_000,
    acceptedRails: ['x402-v2'],
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

function renderPortalStructuredDataJsonLd(): string {
  const graph = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'Organization',
        '@id': 'https://redcenterstudio.com/#organization',
        name: 'Red Center Studio',
        url: 'https://redcenterstudio.com/',
        email: 'hello@redcenterstudio.com',
        sameAs: ['https://github.com/Red-Center-Studio'],
      },
      {
        '@type': 'WebSite',
        '@id': 'https://tollbooth.redcenterstudio.com/#website',
        name: 'Agent Tollbooth 402',
        url: 'https://tollbooth.redcenterstudio.com/',
        publisher: { '@id': 'https://redcenterstudio.com/#organization' },
      },
      {
        '@type': 'SoftwareApplication',
        '@id': 'https://tollbooth.redcenterstudio.com/#app',
        name: 'Agent Tollbooth 402',
        applicationCategory: 'DeveloperApplication',
        operatingSystem: 'Cloudflare Workers, Node.js, Any HTTP Edge',
        url: 'https://tollbooth.redcenterstudio.com/',
        softwareVersion: '1.2.2',
        isAccessibleForFree: true,
        publisher: { '@id': 'https://redcenterstudio.com/#organization' },
        sameAs: [
          'https://github.com/Red-Center-Studio/agent-tollbooth-402',
          'https://glama.ai/mcp/servers/Red-Center-Studio/agent-tollbooth-402',
        ],
        author: { '@id': 'https://redcenterstudio.com/#organization' },
        offers: [
          {
            '@type': 'Offer',
            name: 'Free (DIY)',
            price: '0',
            priceCurrency: 'USD',
          },
          {
            '@type': 'Offer',
            name: 'Tollbooth Pro Pass',
            price: '39',
            priceCurrency: 'USD',
          },
          {
            '@type': 'Offer',
            name: 'Agency Pass',
            price: '79',
            priceCurrency: 'USD',
          },
          {
            '@type': 'Offer',
            name: 'Done-For-You Setup',
            price: '499',
            priceCurrency: 'USD',
          },
        ],
      },
      {
        '@type': 'FAQPage',
        mainEntity: [
          {
            '@type': 'Question',
            name: 'Can I use x402 V2 without paying any platform fee?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'Yes. Set your own payTo wallet address on Base in the middleware config and agents pay your wallet directly in USDC. Red Center Studio never holds your money and takes 0% of payments.',
            },
          },
          {
            '@type': 'Question',
            name: 'What does the Pro Pass add?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'The Pro Pass is $39 USD once, for one project. It turns on hosted Base mainnet settlement through tollbooth.redcenterstudio.com, so you need no Coinbase developer account, keys or facilitator server of your own. Payments still go straight to your wallet. It includes up to 10,000 hosted settlements a month and adds earnings history. The Agency Pass is $79 USD once and covers multiple projects.',
            },
          },
          {
            '@type': 'Question',
            name: 'Is Base Sepolia testing free?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'Yes. Hosted settlement on Base Sepolia testnet is free. Base mainnet is free too if you settle through your own facilitator.',
            },
          },
          {
            '@type': 'Question',
            name: 'Can I test locally without a Stripe key or crypto wallet?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'Yes. Pass mode: "sandbox" or run /agent-tollbooth-402:test-agent to test 402 headers, signed receipts, browser checkout cards, and nonce replay blocking offline.',
            },
          },
        ],
      },
    ],
  };
  return JSON.stringify(graph).replace(/</g, '\\u003c');
}

function renderLlmsTxt(): string {
  const toolLines = MCP_TOOLS.map((t) => `- \`${t.name}\`: ${t.description}`).join('\n');
  return [
    '# Agent Tollbooth 402',
    '',
    '> HTTP 402 (x402 V2 Base USDC paid straight to your own wallet, 0% fee) billing middleware, remote MCP server, and Claude Code / Antigravity plugin by Red Center Studio.',
    '',
    '## Live Endpoints',
    '- Portal & Pricing: https://tollbooth.redcenterstudio.com/',
    '- Streamable HTTP MCP Endpoint: https://tollbooth.redcenterstudio.com/mcp',
    '- MCP Discovery Card: https://tollbooth.redcenterstudio.com/.well-known/mcp.json',
    '- Interactive HTTP 402 Demo (HTML & JSON): https://tollbooth.redcenterstudio.com/demo/402',
    '- Health Check: https://tollbooth.redcenterstudio.com/health',
    '',
    '## Plugin Installation & Skills (Claude Code & Antigravity)',
    '```',
    '/plugin marketplace add Red-Center-Studio/agent-tollbooth-402',
    '/plugin install agent-tollbooth-402@agent-tollbooth-402',
    '```',
    '- `/agent-tollbooth-402:scan-routes`: Scan Workers, Hono, Next.js App Router, Express, or MCP servers for monetizable routes.',
    '- `/agent-tollbooth-402:install-tollbooth`: Inject zero-dependency HTTP 402 middleware that pays your own wallet.',
    '- `/agent-tollbooth-402:test-agent`: Run a 30-second offline 402 challenge, receipt verification, and replay-guard smoke test.',
    '',
    '## Install the Edge Middleware',
    '```',
    `npm install ${EDGE_TARBALL_URL}`,
    '```',
    '',
    '## Quick Edge Middleware Snippet',
    '```ts',
    "import { withTollbooth } from '@redcenterstudio/agent-tollbooth-edge';",
    '',
    'export default withTollbooth({ priceUsd: 0.01, mode: "x402", payTo: "0xYourBaseUSDCWallet", network: "eip155:84532" }, async (request) => {',
    '  return Response.json({ ok: true, path: new URL(request.url).pathname });',
    '});',
    '```',
    '',
    '## Remote MCP Tools',
    toolLines,
    '',
    '## Accounts, Keys and Receipts',
    '- Self-serve accounts: POST /wallet/register returns a wallet key (rcs_wk_...), POST /developer/register returns a developer key (rcs_dk_...). Keys are shown once; only hashes are stored. POST /keys/rotate replaces a key. POST /developer/payout (developer key) sets or corrects the payout wallet.',
    '- A wallet key reads its own balance and ledger and requests receipts that spend from that wallet only.',
    '- Rail B receipts are Ed25519-signed. Verify them with the public key at https://tollbooth.redcenterstudio.com/.well-known/tollbooth-jwks.json (fetchTollboothPublicKey() in the middleware).',
    '',
    '## x402 Settlement',
    '- /verify recovers the EIP-712 TransferWithAuthorization signer and checks it is the payer, plus USDC asset, network, recipient, amount, expiry and replay.',
    '- /settle submits the transfer through an on-chain facilitator: x402.org for Base Sepolia (eip155:84532), free. Hosted Base mainnet (eip155:8453) needs a Pro or Agency Pass; without one, settle mainnet through your own facilitator. A settlement that cannot run is refused, never faked.',
    '',
    '## Clearinghouse Pricing',
    '- Free (DIY): $0 USD. The MCP server, plugin and skills, edge middleware, hosted settlement on Base Sepolia testnet, and Base mainnet through your own facilitator. 0% fee.',
    '- Tollbooth Pro Pass: $39 USD once, one project. Hosted Base mainnet settlement through tollbooth.redcenterstudio.com (no Coinbase developer account, keys or facilitator server of your own), up to 10,000 hosted settlements a month and earnings history. Needs the developer account payout address to equal your payTo address.',
    '- Agency Pass: $79 USD once. The same as Pro for multiple projects and client sites.',
    '- Payments always go straight to your own payTo wallet in USDC. Red Center Studio never holds your money and takes 0% of payments.',
    '- Done-For-You Setup: From $499 USD (custom Cloudflare Worker + D1 handover via https://redcenterstudio.com/services/ai-tollbooth-setup/)',
    '',
    '## Directory & Source Links',
    '- GitHub: https://github.com/Red-Center-Studio/agent-tollbooth-402',
    '- Glama Listing: https://glama.ai/mcp/servers/Red-Center-Studio/agent-tollbooth-402',
  ].join('\n');
}

function renderWellKnownMcpManifest(): Record<string, unknown> {
  return {
    $schema: 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json',
    name: 'io.github.Red-Center-Studio/agent-tollbooth-402',
    title: 'Agent Tollbooth 402',
    version: '1.2.2',
    description:
      'HTTP 402 & x402 V2 billing, pricing quotes, signed receipts, and earnings history for APIs & MCP. Agents pay your own wallet in USDC.',
    websiteUrl: 'https://tollbooth.redcenterstudio.com/',
    endpoint: 'https://tollbooth.redcenterstudio.com/mcp',
    transport: 'streamable-http',
    documentation: 'https://tollbooth.redcenterstudio.com/llms.txt',
    repository: 'https://github.com/Red-Center-Studio/agent-tollbooth-402',
    tools: MCP_TOOLS,
  };
}

function renderRobotsTxt(): string {
  return 'User-agent: *\nAllow: /\nSitemap: https://tollbooth.redcenterstudio.com/sitemap.xml\n';
}

/** Date the public pages last changed; bump with each release that changes /, /pay or llms.txt. */
const SITE_LASTMOD = '2026-11-26';

function renderSitemapXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://tollbooth.redcenterstudio.com/</loc>
    <lastmod>${SITE_LASTMOD}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://tollbooth.redcenterstudio.com/llms.txt</loc>
    <lastmod>${SITE_LASTMOD}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>
`;
}

/** The edge middleware on the npm registry. Not exported: Workers treat named exports of the entry as handlers. */
const EDGE_TARBALL_URL = '@redcenterstudio/agent-tollbooth-edge';

/** The banner shown when a buyer returns from Stripe, or null. Built from query params and the ledger only. */
async function portalNotice(url: URL, env: Env): Promise<{ tone: 'ok' | 'info'; text: string } | null> {
  const status = url.searchParams.get('status');
  if (url.searchParams.get('sandbox_session')) {
    return { tone: 'info', text: 'Sandbox checkout: no real payment was taken. Use a real Stripe key to test the full flow.' };
  }
  if (status === 'cancelled') {
    return { tone: 'info', text: 'Checkout cancelled. Nothing was charged.' };
  }
  if (status !== 'success') {
    return null;
  }
  const sessionId = url.searchParams.get('session_id') ?? '';
  if (/^cs_[A-Za-z0-9_]{8,200}$/.test(sessionId)) {
    const row = await env.DB.prepare(
      "SELECT wallet_id, gross_micros FROM ledger_entries WHERE tx_reference = ? AND entry_type = 'topup' LIMIT 1",
    )
      .bind(sessionId)
      .first<{ wallet_id: string; gross_micros: number }>();
    if (row) {
      return {
        tone: 'ok',
        text: `Payment received: $${(row.gross_micros / 1_000_000).toFixed(2)} USD added to ${row.wallet_id}.`,
      };
    }
  }
  return {
    tone: 'ok',
    text: 'Payment received. Your pass is active within a minute. Hosted Base mainnet settlement works for payments whose payTo is your account payout wallet. Check it with tollbooth_pass_status and your developer key.',
  };
}

function renderClearinghousePortalHtml(
  env: Env,
  notice: { tone: 'ok' | 'info'; text: string } | null = null,
): string {
  // Buy buttons show only when a purchase can be delivered: sales are open, or this is a sandbox with no Stripe key.
  const showBuy = paidSalesOpen(env) || (!hasRealStripeKey(env) && !env.STRIPE_PAYMENT_LINK_TOPUP_10);
  const closedNote = '<span class="btn btn-ghost" aria-disabled="true">Opens soon</span>';
  // With sales open and a real Stripe key, the buttons lead to the account form, which starts a Checkout Session
  // that carries the wallet or developer id, so every payment can be credited.
  const liveBuy = paidSalesOpen(env) && hasRealStripeKey(env);
  const noticeHtml = notice
    ? `<div class="tb-notice tb-${notice.tone}" role="status"><div class="wrap">${escapeHtmlAttr(notice.text)}</div></div>`
    : '';
  const buyPanel = liveBuy
    ? `<section id="buy" style="padding-top:0">
      <div class="wrap narrow">
        <span class="label">Buy</span>
        <h2>${topupsOpen(env) ? 'Fund a wallet or buy a pass.' : 'Buy a pass.'}</h2>
        <div class="grid g2">
          ${topupsOpen(env) ? '' : '<!--'}<form class="card tb-form" data-kind="topup">
            <h3>Agent wallet top-up (Red Center Studio APIs only)</h3>
            <label>Wallet ID <input name="account" placeholder="wallet_..." autocomplete="off" pattern="wallet_[0-9a-f]{20}"></label>
            <button class="btn btn-ghost" type="button" data-register="wallet">No wallet yet? Create one</button>
            <button class="btn btn-primary" type="submit">Pay $10 USD</button>
          </form>${topupsOpen(env) ? '' : '-->'}
          <form class="card tb-form" data-kind="pass">
            <h3>Pro or Agency pass</h3>
            <p><strong>1. New here? Create your developer account.</strong></p>
            <label>Email <input name="email" type="email" autocomplete="email"></label>
            <label>Name <input name="owner" autocomplete="name"></label>
            <label>Base wallet that receives payments (your payTo) <input name="payout" placeholder="0x..." autocomplete="off" pattern="0x[0-9a-fA-F]{40}"></label>
            <button class="btn btn-ghost" type="button" data-register="developer">Create my account</button>
            <p><strong>2. Choose your pass.</strong> Already have an account? Enter its developer ID.</p>
            <label>Developer ID <input name="account" placeholder="dev_..." autocomplete="off" pattern="dev_[0-9a-f]{20}" required></label>
            <label>Pass <select name="tier"><option value="pro">Pro &middot; $39 once</option><option value="agency">Agency &middot; $79 once</option></select></label>
            <button class="btn btn-primary" type="submit">Buy pass</button>
          </form>
        </div>
        <p class="tb-out" id="tb-out" role="status"></p>
      </div>
    </section>`
    : '';
  const topupAction = !topupsOpen(env) ? '' : !showBuy ? closedNote : liveBuy ? '<a class="btn btn-primary" href="#buy">Fund Agent Wallet ($10)</a>' : env.STRIPE_PAYMENT_LINK_TOPUP_10
    ? `<a class="btn btn-primary" href="${escapeHtmlAttr(env.STRIPE_PAYMENT_LINK_TOPUP_10)}" rel="noopener noreferrer">Fund Agent Wallet ($10)</a>`
    : `<button class="btn btn-primary" type="button" onclick="if(this.disabled)return;var b=this;b.disabled=true;fetch('/wallet/topup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({amountUsd:10})}).then(function(r){return r.json()}).then(function(d){if(d&&d.checkoutUrl)location.href=d.checkoutUrl;else b.disabled=false;}).catch(function(){b.disabled=false;})">Fund Agent Wallet ($10)</button>`;

  const proAction = !showBuy ? closedNote : liveBuy ? '<a class="btn btn-primary" href="#buy">Buy Pro Pass &middot; $39</a>' : env.STRIPE_PAYMENT_LINK_PRO_PASS
    ? `<a class="btn btn-primary" href="${escapeHtmlAttr(env.STRIPE_PAYMENT_LINK_PRO_PASS)}" rel="noopener noreferrer">Buy Pro Pass &middot; $39</a>`
    : `<button class="btn btn-primary" type="button" onclick="if(this.disabled)return;var b=this;b.disabled=true;fetch('/wallet/topup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passTier:'pro'})}).then(function(r){return r.json()}).then(function(d){if(d&&d.checkoutUrl)location.href=d.checkoutUrl;else b.disabled=false;}).catch(function(){b.disabled=false;})">Buy Pro Pass &middot; $39</button>`;

  const agencyAction = !showBuy ? '' : liveBuy ? '<a class="btn btn-ghost" href="#buy">Agency Pass &middot; $79</a>' : env.STRIPE_PAYMENT_LINK_AGENCY_PASS
    ? `<a class="btn btn-ghost" href="${escapeHtmlAttr(env.STRIPE_PAYMENT_LINK_AGENCY_PASS)}" rel="noopener noreferrer">Agency Pass &middot; $79</a>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#24181a" />
  <title>Charge AI Agents per Call with x402 | Agent Tollbooth 402</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 22 22'%3E%3CclipPath id='s'%3E%3Ccircle cx='11' cy='11' r='11'/%3E%3C/clipPath%3E%3Cg clip-path='url(%23s)'%3E%3Crect width='22' height='12.5' fill='%23d9622b'/%3E%3Crect y='14.5' width='22' height='2.5' fill='%23d9622b'/%3E%3Crect y='19' width='22' height='2.5' fill='%23a63d14'/%3E%3C/g%3E%3C/svg%3E" />
  <meta name="description" content="Charge AI agents per call with HTTP 402 and x402. USDC goes straight to your own wallet at 0% fee. Free DIY setup, go live on Base with a $39 Pro Pass." />
  <link rel="canonical" href="https://tollbooth.redcenterstudio.com/" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="Red Center Studio" />
  <meta property="og:title" content="Agent Tollbooth 402: Charge AI Agents with HTTP 402 and x402" />
  <meta property="og:description" content="Charge AI agents per call with HTTP 402 and x402. USDC goes straight to your own wallet at 0% fee. Free DIY setup, go live on Base with a $39 Pro Pass." />
  <meta property="og:url" content="https://tollbooth.redcenterstudio.com/" />
  <meta property="og:image" content="https://raw.githubusercontent.com/Red-Center-Studio/agent-tollbooth-402/main/assets/screenshots/clearinghouse-portal.png" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Agent Tollbooth 402: Charge AI Agents with HTTP 402 and x402" />
  <meta name="twitter:description" content="Charge AI agents per call with HTTP 402 and x402. USDC goes straight to your own wallet at 0% fee. Free DIY setup, go live on Base with a $39 Pro Pass." />
  <meta name="twitter:image" content="https://raw.githubusercontent.com/Red-Center-Studio/agent-tollbooth-402/main/assets/screenshots/clearinghouse-portal.png" />
  <script type="application/ld+json">${renderPortalStructuredDataJsonLd()}</script>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@700;800&family=IBM+Plex+Mono:wght@500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" />
  <style>
    :root {
      --ironstone: #24181a;
      --ironstone-2: #32211f;
      --ochre: #d9622b;
      --ochre-deep: #a63d14;
      --oxide: #7a2e1d;
      --spinifex: #e3a23c;
      --gum: #4f7f63;
      --sand: #f5efe6;
      --card: #fffcf8;
      --line: #e3d7c8;
      --ink: #2a1a16;
      --muted: #6b5a52;
      --on-dark: #f3e9de;
      --on-dark-muted: #cbb9ab;
      --display: "Archivo", "Helvetica Neue", Arial, sans-serif;
      --body: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
      --mono: "IBM Plex Mono", ui-monospace, Menlo, monospace;
      --wrap: 1120px;
    }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; scroll-behavior: smooth; max-width: 100%; overflow-x: hidden; }
    body { margin: 0; max-width: 100%; overflow-x: hidden; background: var(--sand); color: var(--ink); font: 400 17px/1.6 var(--body); }
    a { color: var(--ochre-deep); overflow-wrap: anywhere; }
    h1, h2, h3 { font-family: var(--display); font-weight: 800; letter-spacing: -0.02em; line-height: 1.08; margin: 0; text-wrap: balance; overflow-wrap: anywhere; }
    p { margin: 0; overflow-wrap: anywhere; }
    .wrap { max-width: var(--wrap); min-width: 0; margin: 0 auto; padding: 0 24px; }
    .narrow { max-width: 760px; min-width: 0; }
    .label { font: 500 12px/1.4 var(--mono); letter-spacing: 0.16em; text-transform: uppercase; color: var(--ochre-deep); }
    .dark .label { color: var(--spinifex); }
    .lede { color: var(--muted); max-width: 62ch; }
    .dark .lede { color: var(--on-dark-muted); }
    .meta { color: var(--muted); font-size: 15px; margin-top: 12px; }
    :focus-visible { outline: 3px solid var(--spinifex); outline-offset: 2px; }
    :not(pre) > code { font-family: var(--mono); font-size: 0.88em; overflow-wrap: anywhere; }

    @keyframes riseFade {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes dotPulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(227, 162, 60, 0.45); }
      50% { box-shadow: 0 0 0 5px rgba(227, 162, 60, 0); }
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      min-height: 46px;
      padding: 10px 20px;
      border: 1px solid transparent;
      border-radius: 2px;
      font: 600 15px/1.2 var(--body);
      text-decoration: none;
      cursor: pointer;
      white-space: nowrap;
      transition: background 0.15s, color 0.15s, border-color 0.15s, transform 0.15s;
    }
    .btn-primary { background: var(--ochre); color: #1e1412; }
    .btn-primary:hover { background: var(--spinifex); }
    .btn-ghost { background: transparent; color: var(--ink); border-color: var(--ink); }
    .tb-notice { padding: 14px 0; font-weight: 600; overflow-wrap: anywhere; max-width: 100%; }
    .tb-ok { background: #e3f0e1; color: #1d3b1a; }
    .tb-info { background: #f3e6cf; color: #4a3210; }
    .tb-form { display: flex; flex-direction: column; gap: 10px; }
    .tb-form label { display: flex; flex-direction: column; gap: 4px; font-size: 15px; }
    .tb-form input, .tb-form select { font: inherit; padding: 8px 10px; border: 1px solid var(--ink); border-radius: 6px; background: #fff; min-width: 0; }
    .tb-out { white-space: pre-wrap; word-break: break-all; margin-top: 16px; }
    .btn-ghost:hover { background: var(--ink); color: var(--sand); }
    .dark .btn-ghost { color: var(--on-dark); border-color: rgba(243, 233, 222, 0.55); }
    .dark .btn-ghost:hover { background: var(--on-dark); color: var(--ironstone); }

    /* Header */
    .dark { background: var(--ironstone); color: var(--on-dark); }
    .site-head .wrap { display: flex; align-items: center; gap: 16px; min-height: 76px; flex-wrap: wrap; padding-top: 12px; padding-bottom: 12px; }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      font: 500 13px/1 var(--mono);
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--on-dark);
      text-decoration: none;
      margin-right: auto;
    }
    .brand::before {
      content: "";
      width: 22px;
      height: 22px;
      flex: none;
      background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 22 22'%3E%3CclipPath id='s'%3E%3Ccircle cx='11' cy='11' r='11'/%3E%3C/clipPath%3E%3Cg clip-path='url(%23s)'%3E%3Crect width='22' height='12.5' fill='%23d9622b'/%3E%3Crect y='14.5' width='22' height='2.5' fill='%23d9622b'/%3E%3Crect y='19' width='22' height='2.5' fill='%23a63d14'/%3E%3C/g%3E%3C/svg%3E") center / contain no-repeat;
    }
    .site-nav { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
    .site-nav a.link { color: var(--on-dark); text-decoration: none; font: 600 15px/1 var(--body); padding: 12px 10px; }
    .site-nav a.link:hover, .site-nav a.link[aria-current] { color: var(--spinifex); }
    .site-nav a.link[aria-current] { text-decoration: underline; text-decoration-thickness: 2px; text-underline-offset: 8px; }
    .menu-btn, .nav-cta { display: none; }
    .head-cta { display: flex; gap: 8px; }

    /* Hero + Interactive Proof Player (matches redcenterstudio.com .has-proof) */
    .hero {
      position: relative;
      overflow: hidden;
      background:
        radial-gradient(ellipse 70% 90% at 88% 118%, rgba(217, 98, 43, 0.42), transparent 60%),
        radial-gradient(ellipse 50% 60% at 100% 100%, rgba(227, 162, 60, 0.22), transparent 60%),
        var(--ironstone);
    }
    .hero .wrap { padding-top: 52px; padding-bottom: 54px; display: flex; flex-direction: column; }
    .hero h1 { font-size: clamp(32px, 4.3vw, 50px); max-width: 17ch; margin: 14px 0 16px; color: #fff8f0; }
    .hero .lede { font-size: 17.5px; line-height: 1.55; }
    .crumbs { font-size: 14px; color: var(--on-dark-muted); margin-bottom: 14px; }
    .crumbs a { color: inherit; }
    .cta-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 24px; }
    .facts { display: flex; flex-wrap: wrap; gap: 18px 34px; margin: 28px 0 0; padding-top: 22px; border-top: 1px solid rgba(243, 233, 222, 0.14); }
    .facts > div { margin: 0; }
    .facts dt { margin: 0; }
    .facts dd { margin: 4px 0 0; font: 700 16px/1.3 var(--body); color: #fff8f0; }

    /* Proof Frame Walkthrough Player */
    .proof { margin: 28px 0 0; position: relative; isolation: isolate; min-width: 0; max-width: 100%; }
    .proof::before {
      content: "";
      position: absolute;
      z-index: -1;
      left: -8%;
      right: -8%;
      top: -12%;
      bottom: 4%;
      background: radial-gradient(closest-side, rgba(217, 98, 43, 0.34), rgba(227, 162, 60, 0.1) 60%, transparent);
      pointer-events: none;
    }
    .proof-frame {
      position: relative;
      border-radius: 12px;
      overflow: hidden;
      padding: 1.5px;
      background: linear-gradient(135deg, #e3a23c, rgba(217, 98, 43, 0.55) 35%, rgba(243, 233, 222, 0.14) 70%, rgba(227, 162, 60, 0.5));
      box-shadow: 0 34px 80px -30px rgba(217, 98, 43, 0.6), 0 20px 44px -22px rgba(0, 0, 0, 0.85);
    }
    .proof-inner {
      background: #191012;
      border-radius: 10.5px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .proof-chrome {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 14px;
      background: #201517;
      border-bottom: 1px solid rgba(243, 233, 222, 0.12);
    }
    .proof-dots { display: inline-flex; gap: 6px; align-items: center; }
    .proof-dots i { width: 8px; height: 8px; border-radius: 50%; background: rgba(243, 233, 222, 0.25); display: inline-block; }
    .proof-dots i:first-child { background: var(--ochre); }
    .proof-dots i:nth-child(2) { background: var(--spinifex); }
    .proof-dots i:nth-child(3) { background: var(--gum); }
    .proof-title {
      flex: 1 1 0;
      min-width: 0;
      font: 500 11.5px/1.2 var(--mono);
      letter-spacing: 0.08em;
      color: var(--on-dark-muted);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .proof-play {
      min-height: 44px;
      padding: 4px 10px;
      background: rgba(243, 233, 222, 0.08);
      color: var(--on-dark);
      border: 1px solid rgba(243, 233, 222, 0.24);
      border-radius: 2px;
      font: 500 11px/1 var(--mono);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      cursor: pointer;
    }
    .proof-play:hover { background: var(--spinifex); color: var(--ironstone); border-color: var(--spinifex); }
    .proof-tabs {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 4px;
      padding: 8px 12px;
      background: #1e1315;
      border-bottom: 1px solid rgba(243, 233, 222, 0.08);
    }
    .proof-tab {
      background: transparent;
      border: 1px solid transparent;
      border-radius: 2px;
      min-height: 44px;
      padding: 7px 6px;
      color: var(--on-dark-muted);
      font: 500 11.5px/1.25 var(--mono);
      cursor: pointer;
      text-align: center;
      transition: background 0.15s, color 0.15s, border-color 0.15s;
    }
    .proof-tab:hover { color: var(--on-dark); background: rgba(243, 233, 222, 0.05); }
    .proof-tab[aria-selected="true"] {
      background: rgba(217, 98, 43, 0.18);
      border-color: rgba(227, 162, 60, 0.45);
      color: #fff8f0;
    }
    .proof-stage {
      padding: 16px 16px 14px;
      min-height: 196px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 12px;
    }
    .proof-status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      align-self: flex-start;
      padding: 4px 9px;
      border-radius: 2px;
      font: 500 11px/1.2 var(--mono);
      letter-spacing: 0.1em;
      text-transform: uppercase;
      background: rgba(79, 127, 99, 0.16);
      color: #b7dec5;
      border: 1px solid rgba(79, 127, 99, 0.45);
    }
    .proof-status.challenge {
      background: rgba(217, 98, 43, 0.2);
      color: #ffd3b0;
      border-color: rgba(217, 98, 43, 0.6);
    }
    .proof-code {
      margin: 0;
      font: 500 12.5px/1.55 var(--mono);
      color: #f6ede2;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      animation: riseFade 0.22s ease-out both;
    }
    .proof-caption-bar {
      padding: 11px 14px 12px;
      background: #221618;
      border-top: 1px solid rgba(243, 233, 222, 0.1);
    }
    .proof-caption {
      font: 500 13.5px/1.4 var(--body);
      color: #fff8f0;
    }
    .proof-track {
      margin-top: 8px;
      height: 3px;
      background: rgba(243, 233, 222, 0.12);
      overflow: hidden;
      border-radius: 2px;
    }
    .proof-fill {
      height: 100%;
      width: 25%;
      background: linear-gradient(90deg, var(--ochre), var(--spinifex));
      transition: width 0.3s ease;
    }
    .proof figcaption { margin-top: 10px; font-size: 13.5px; line-height: 1.45; color: var(--on-dark-muted); }

    @media (min-width: 1000px) {
      .has-proof .wrap { display: grid; grid-template-columns: minmax(0, 1.02fr) minmax(0, 1fr); column-gap: 44px; row-gap: 0; align-items: start; }
      .has-proof .wrap > * { grid-column: 1; }
      .has-proof .wrap > .proof { grid-column: 2; grid-row: 1 / span 10; align-self: center; margin: 0; }
      .has-proof .wrap > .facts, .has-proof .wrap > .cta-row { order: 0; }
    }

    .strata {
      display: block;
      height: 10px;
      background: linear-gradient(to bottom, var(--oxide) 0 25%, var(--ochre-deep) 25% 50%, var(--ochre) 50% 75%, var(--spinifex) 75% 100%);
    }

    /* Sections & Cards */
    section { padding: 64px 0; }
    .sec-head h2 { font-size: clamp(26px, 3.4vw, 36px); margin: 12px 0 14px; }
    .grid { display: grid; gap: 18px; margin-top: 28px; }
    .g3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .g4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .g2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .card {
      min-width: 0;
      max-width: 100%;
      overflow-wrap: anywhere;
      background: var(--card);
      border: 1px solid var(--line);
      border-top: 3px solid var(--ochre);
      padding: 22px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      border-radius: 2px;
      transition: transform 0.16s ease, box-shadow 0.16s ease, border-color 0.16s ease;
    }
    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 12px 26px rgba(36, 24, 26, 0.08);
      border-color: #d6c4b0;
      border-top-color: var(--ochre);
    }
    .wd-pick {
      border-color: var(--ochre-deep);
      box-shadow: inset 0 4px 0 var(--ochre-deep), 0 10px 24px rgba(166, 61, 20, 0.08);
    }
    .wd-pick:hover { border-color: var(--ochre-deep); }
    .card-top-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
    .pop-pill {
      padding: 3px 8px;
      border-radius: 2px;
      background: #fbeee4;
      border: 1px solid var(--ochre-deep);
      color: var(--ochre-deep);
      font: 500 11px/1.2 var(--mono);
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .card h3 { font-size: 20.5px; }
    .card .price { font: 800 26px/1.1 var(--display); letter-spacing: -0.02em; color: var(--ink); font-variant-numeric: tabular-nums; }
    .card p { color: var(--muted); font-size: 15px; line-height: 1.5; }
    .tier-list { list-style: none; padding: 0; margin: 4px 0 0; display: flex; flex-direction: column; gap: 6px; font-size: 14px; color: var(--ink); }
    .tier-list li { padding-left: 18px; position: relative; line-height: 1.4; }
    .tier-list li::before { content: "\\2713"; position: absolute; left: 0; top: 0; color: var(--gum); font-weight: 700; }
    .card .spacer { flex: 1; min-height: 4px; }
    .card-actions { display: flex; flex-direction: column; gap: 8px; margin-top: 8px; }
    .card-actions .btn { width: 100%; font-size: 14.5px; padding: 10px 14px; }

    /* Table */
    .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; max-width: 100%; margin-top: 20px; }
    .map { width: 100%; min-width: 520px; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); font-size: 15px; }
    .map th, .map td { text-align: left; padding: 12px 16px; border-bottom: 1px solid var(--line); vertical-align: top; }
    .map th { font: 500 12px/1.4 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--ochre-deep); background: #faf4ec; }

    /* Code boxes & interactive check */
    .code-box { position: relative; margin-top: 8px; }
    .code-box pre {
      margin: 0;
      background: var(--ironstone);
      color: var(--on-dark);
      border-radius: 2px;
      padding: 60px 14px 14px;
      font: 500 12.5px/1.55 var(--mono);
      overflow-x: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .copy-btn {
      position: absolute;
      top: 8px;
      right: 8px;
      min-height: 44px;
      padding: 4px 13px;
      font-size: 12.5px;
      background: var(--card);
      color: var(--ink);
      border: 1px solid var(--line);
    }
    .copy-btn:hover { background: var(--spinifex); color: var(--ink); border-color: var(--spinifex); }
    .demo-panel {
      margin-top: 24px;
      min-width: 0;
      max-width: 100%;
      overflow-wrap: anywhere;
      background: var(--card);
      border: 1px solid var(--line);
      border-left: 3px solid var(--ochre);
      padding: 20px 22px;
      border-radius: 2px;
    }
    .demo-row { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 14px; margin-top: 12px; }
    .demo-out {
      font: 500 12.5px/1.5 var(--mono);
      color: var(--muted);
      padding: 8px 12px;
      background: var(--sand);
      border: 1px solid var(--line);
      border-radius: 2px;
      flex: 1 1 280px;
      overflow-wrap: anywhere;
    }
    .demo-out.ok { background: #eaf2ec; border-color: #b8d3c1; color: #214530; }
    .demo-out.err { background: #f8e6df; border-color: #e0b2a4; color: var(--oxide); }

    /* FAQ */
    .faq { border-top: 1px solid var(--line); margin-top: 16px; }
    .faq details { border-bottom: 1px solid var(--line); }
    .faq summary { cursor: pointer; list-style: none; padding: 18px 36px 18px 0; position: relative; font: 700 18px/1.35 var(--body); }
    .faq summary::-webkit-details-marker { display: none; }
    .faq summary::after { content: "+"; position: absolute; right: 4px; top: 14px; font: 500 24px/1 var(--mono); color: var(--ochre-deep); }
    .faq details[open] summary::after { content: "\\2212"; }
    .faq details p { color: var(--muted); padding: 0 0 20px; }

    /* Footer */
    .site-foot { padding: 0 0 40px; font-size: 15px; }
    .foot-grid { display: grid; grid-template-columns: 1.5fr repeat(3, 1fr); gap: 32px; }
    .foot-brand p { color: var(--on-dark-muted); margin-top: 14px; max-width: 32ch; }
    .foot-col { display: flex; flex-direction: column; gap: 10px; align-items: flex-start; }
    .foot-col a { color: var(--on-dark); text-decoration: none; font-weight: 600; }
    .foot-col a:hover { color: var(--spinifex); }
    .site-foot .legal-links { display: flex; flex-wrap: wrap; gap: 4px 24px; margin-top: 28px; }
    .site-foot .legal-links a { color: var(--on-dark); text-decoration: none; font-weight: 600; font-size: 15px; }
    .site-foot .legal-links a:hover { color: var(--spinifex); }
    .site-foot .legal-more { color: var(--on-dark-muted); font-size: 13px; line-height: 1.5; margin-top: 12px; max-width: 90ch; }

    @media (prefers-reduced-motion: reduce) { .proof-code, .card { animation: none; transition: none; } }
    @media (max-width: 1080px) {
      .g4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 900px) {
      .g3 { grid-template-columns: minmax(0, 1fr); }
      .foot-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 640px) {
      body { font-size: 16px; overflow-x: hidden; }
      .wrap { padding: 0 16px; }
      section { padding: 48px 0; }
      .g2, .g3, .g4 { grid-template-columns: minmax(0, 1fr); }
      .btn { max-width: 100%; white-space: normal; overflow-wrap: anywhere; }
      .hero .wrap { padding-top: 34px; padding-bottom: 40px; }
      .proof-tabs { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .proof-stage { min-height: 180px; padding: 14px; }
      .site-head { position: sticky; top: 0; z-index: 60; }
      .site-head .wrap { min-height: 60px; gap: 0 10px; padding-top: 6px; padding-bottom: 6px; }
      .site-head .head-cta { display: none; }
      .brand { font-size: 11.5px; letter-spacing: 0.11em; min-width: 0; }
      .menu-btn {
        display: inline-flex;
        align-items: center;
        flex: none;
        gap: 8px;
        min-height: 44px;
        padding: 8px 12px;
        background: transparent;
        color: var(--on-dark);
        border: 1px solid rgba(243, 233, 222, 0.55);
        border-radius: 2px;
        font: 600 14.5px/1 var(--body);
        cursor: pointer;
      }
      .menu-btn[aria-expanded="true"] { background: var(--on-dark); color: var(--ironstone); }
      .site-nav { display: none; width: 100%; }
      .site-nav.open {
        display: flex;
        flex-direction: column;
        align-items: stretch;
        gap: 0;
        padding: 8px 0 14px;
        border-top: 1px solid rgba(243, 233, 222, 0.14);
      }
      .site-nav.open a.link { min-height: 48px; display: flex; align-items: center; padding: 0; border-bottom: 1px solid rgba(243, 233, 222, 0.1); }
      .site-nav.open .nav-cta { display: inline-flex; margin-top: 12px; min-height: 48px; }
      .cta-row .btn, .demo-row .btn { width: 100%; min-height: 48px; }
      .foot-grid { grid-template-columns: minmax(0, 1fr); gap: 22px; }
      .foot-col a, .site-foot .legal-links a { min-height: 44px; display: inline-flex; align-items: center; }
      .map th, .map td { padding: 10px 12px; }
    }
  </style>
</head>
<body>
  <header class="site-head dark">
    <div class="wrap">
      <a class="brand" href="https://redcenterstudio.com/" rel="noopener noreferrer">Red Center Studio</a>
      <button class="menu-btn" type="button" aria-expanded="false" aria-controls="site-nav">Menu</button>
      <nav class="site-nav" id="site-nav" aria-label="Main">
        <a class="link" href="https://redcenterstudio.com/services/" rel="noopener noreferrer">Services</a>
        <a class="link" href="https://redcenterstudio.com/products/" rel="noopener noreferrer">Shop</a>
        <a class="link" href="https://redcenterstudio.com/claude-connectors/" aria-current="page" rel="noopener noreferrer">Claude connectors</a>
        <a class="link" href="https://redcenterstudio.com/tools/" rel="noopener noreferrer">Free tools</a>
        <a class="link" href="https://redcenterstudio.com/support/" rel="noopener noreferrer">Support</a>
        <a class="btn btn-primary nav-cta" href="https://redcenterstudio.com/start/" rel="noopener noreferrer">Start a project</a>
      </nav>
      <div class="head-cta">
        <a class="btn btn-primary" href="https://redcenterstudio.com/start/" rel="noopener noreferrer">Start a project</a>
      </div>
    </div>
  </header>

  <main id="main">
    ${noticeHtml}
    <div class="hero dark has-proof">
      <div class="wrap">
        <nav class="crumbs" aria-label="Breadcrumb">
          <a href="https://redcenterstudio.com/" rel="noopener noreferrer">Home</a> /
          <a href="https://redcenterstudio.com/products/" rel="noopener noreferrer">Shop</a> /
          <a href="https://redcenterstudio.com/claude-connectors/" rel="noopener noreferrer">Claude connectors</a> /
          <span aria-current="page">Agent Tollbooth 402</span>
        </nav>
        <span class="label">Shop &nbsp;/&nbsp; Claude Code &amp; Antigravity Plugin</span>
        <h1>Charge AI agents per call with HTTP 402 and x402.</h1>
        <p class="lede">Add pay-per-call HTTP 402 billing to any Cloudflare Worker, Hono route, Next.js App Router handler, or MCP server. Accept open x402 V2 USDC payments straight to your own wallet. Red Center Studio never holds your money and takes 0% of payments. Test free on Base Sepolia, then go live on Base mainnet.</p>
        <div class="cta-row">
          <a class="btn btn-primary" href="#connect">Install in 30 seconds</a>
          <a class="btn btn-ghost" href="#prices">See prices and passes</a>
          <a class="btn btn-ghost" href="/demo/402">Open live 402 demo</a>
        </div>
        <dl class="facts">
          <div><dt class="label">Free tier</dt><dd>$0 USD &middot; 0% fee (x402)</dd></div>
          <div><dt class="label">Go live</dt><dd>Pro Pass $39 once</dd></div>
          <div><dt class="label">Payouts</dt><dd>USDC to your wallet</dd></div>
        </dl>
        <figure class="proof">
          <div class="proof-frame">
            <div class="proof-inner">
              <div class="proof-chrome">
                <span class="proof-dots" aria-hidden="true"><i></i><i></i><i></i></span>
                <span class="proof-title">tollbooth.redcenterstudio.com: Setup &amp; 402 Flow</span>
                <button id="proof-toggle" class="proof-play" type="button">Pause</button>
              </div>
              <div class="proof-tabs" role="tablist" aria-label="Walkthrough steps">
                <button class="proof-tab" type="button" role="tab" aria-selected="true" data-step="0">1. Install</button>
                <button class="proof-tab" type="button" role="tab" aria-selected="false" data-step="1">2. Wrap Route</button>
                <button class="proof-tab" type="button" role="tab" aria-selected="false" data-step="2">3. 402 Challenge</button>
                <button class="proof-tab" type="button" role="tab" aria-selected="false" data-step="3">4. Paid</button>
              </div>
              <div class="proof-stage">
                <span id="proof-badge" class="proof-status">Step 1 &middot; Claude Code &amp; Antigravity</span>
                <pre id="proof-code" class="proof-code">$ /plugin marketplace add Red-Center-Studio/agent-tollbooth-402
$ /plugin install agent-tollbooth-402@agent-tollbooth-402

[PASS] 3 skills (/agent-tollbooth-402:scan-routes, /agent-tollbooth-402:install-tollbooth, /agent-tollbooth-402:test-agent)
[PASS] Remote MCP ready: https://tollbooth.redcenterstudio.com/mcp</pre>
              </div>
              <div class="proof-caption-bar">
                <div id="proof-caption" class="proof-caption">Add the plugin in one command or connect the remote MCP server directly.</div>
                <div class="proof-track"><div id="proof-fill" class="proof-fill"></div></div>
              </div>
            </div>
          </div>
          <figcaption>Interactive walkthrough: install the plugin, wrap a route, issue HTTP 402 challenges, and settle USDC to your wallet.</figcaption>
        </figure>
      </div>
      <span class="strata" aria-hidden="true"></span>
    </div>

    <section id="free">
      <div class="wrap">
        <div class="sec-head narrow">
          <span class="label">Start free</span>
          <h2>Three built-in plugin skills and a local sandbox.</h2>
          <p class="lede">Install the plugin once to scan your routes, inject zero-dependency HTTP 402 protection, and test replay guards locally before a dollar moves.</p>
        </div>
        <div class="grid g3">
          <article class="card">
            <span class="label">Free skill</span>
            <h3><code>/agent-tollbooth-402:scan-routes</code></h3>
            <p>Scans Workers, Hono, Next.js, Express, and MCP endpoints to pinpoint billable routes and propose per-call USD prices.</p>
          </article>
          <article class="card">
            <span class="label">Free skill</span>
            <h3><code>/agent-tollbooth-402:install-tollbooth</code></h3>
            <p>Injects <code>@redcenterstudio/agent-tollbooth-edge</code> with x402 V2 verification, payTo set to your own wallet, and CORS headers.</p>
          </article>
          <article class="card">
            <span class="label">Free skill</span>
            <h3><code>/agent-tollbooth-402:test-agent</code></h3>
            <p>Runs an instant local 402 challenge, sandbox receipt signing, 200 OK retry, HTML card check, and nonce replay rejection test.</p>
          </article>
        </div>
      </div>
    </section>

    <section id="prices" style="padding-top:0">
      <div class="wrap">
        <div class="sec-head">
          <span class="label">Prices and clearinghouse tiers</span>
          <h2>Free to build and test. One small pass to go live.</h2>
          <p class="lede">Agents pay your own Base wallet in USDC. Red Center Studio never holds your money and takes 0% of payments. The Pro Pass only pays for hosted Base mainnet settlement.</p>
        </div>

        <div class="table-wrap">
          <table class="map">
            <thead>
              <tr>
                <th>Tier</th>
                <th>Covers</th>
                <th>Fee on your payments</th>
                <th>Price</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Free (DIY)</strong></td>
                <td>The MCP server, plugin and skills, edge middleware, hosted settlement on Base Sepolia testnet (<code>eip155:84532</code>), and Base mainnet (<code>eip155:8453</code>) through your own facilitator</td>
                <td>0% fee</td>
                <td>$0 USD</td>
              </tr>
              <tr>
                <td><strong>Tollbooth Pro Pass</strong></td>
                <td>Hosted Base mainnet settlement through tollbooth.redcenterstudio.com, with no Coinbase developer account, keys or facilitator server of your own. Up to 10,000 settlements a month. Earnings history. One project</td>
                <td>0% fee</td>
                <td>$39 USD once</td>
              </tr>
              <tr>
                <td><strong>Agency Pass</strong></td>
                <td>The same as Pro for multiple projects and client sites</td>
                <td>0% fee</td>
                <td>$79 USD once</td>
              </tr>
              <tr>
                <td><strong>Done for you</strong></td>
                <td>Custom MCP + HTTP 402 integration, D1 ledger deployment, and handover by Red Center Studio</td>
                <td>Fixed quote</td>
                <td>From $499 USD</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="grid g4">
          <article class="card">
            <span class="label">Tier 1 &middot; DIY</span>
            <h3>Free (DIY)</h3>
            <div class="price">$0 &middot; 0% fee</div>
            <p>Build and test with everything included. Point <code>payTo</code> at your own Base USDC wallet.</p>
            <ul class="tier-list">
              <li>Connector, plugin and skills</li>
              <li>Free hosted testing on Base Sepolia</li>
              <li>Base mainnet through your own facilitator</li>
            </ul>
            <span class="spacer"></span>
            <div class="card-actions">
              <a class="btn btn-ghost" href="https://github.com/Red-Center-Studio/agent-tollbooth-402" rel="noopener noreferrer">Setup free x402</a>
            </div>
          </article>

          <article class="card wd-pick">
            <div class="card-top-row">
              <span class="label">Tier 2 &middot; Go live</span>
              <span class="pop-pill">Most popular</span>
            </div>
            <h3>Tollbooth Pro Pass</h3>
            <div class="price">$39 once &middot; 0% fee</div>
            <p>Hosted Base mainnet settlement for one project. Payments still go straight to your wallet.</p>
            <ul class="tier-list">
              <li>No Coinbase account or facilitator server</li>
              <li>Up to 10,000 hosted payments a month</li>
              <li>Earnings history for every payment</li>
              <li>Needs your payout address to equal <code>payTo</code></li>
            </ul>
            <span class="spacer"></span>
            <div class="card-actions">
              ${proAction}
            </div>
          </article>

          <article class="card">
            <span class="label">Tier 3 &middot; Multiple projects</span>
            <h3>Agency Pass</h3>
            <div class="price">$79 once &middot; 0% fee</div>
            <p>The same as Pro, for multiple projects and client sites.</p>
            <ul class="tier-list">
              <li>Hosted Base mainnet settlement, up to 10,000 payments a month</li>
              <li>Earnings history for every payment</li>
              <li>Payments go straight to each wallet</li>
            </ul>
            <span class="spacer"></span>
            <div class="card-actions">
              ${agencyAction}
            </div>
          </article>

          <article class="card">
            <span class="label">Tier 4 &middot; Concierge</span>
            <h3>Done-For-You Setup</h3>
            <div class="price">From $499</div>
            <p>Custom MCP and HTTP 402 Worker endpoints deployed in your Cloudflare account.</p>
            <ul class="tier-list">
              <li>Per-bot AI crawler policy</li>
              <li>Live Worker + D1 handover</li>
              <li>Source code in your repo</li>
            </ul>
            <span class="spacer"></span>
            <div class="card-actions">
              <a class="btn btn-ghost" href="https://redcenterstudio.com/services/ai-tollbooth-setup/" rel="noopener noreferrer">Book setup &middot; $499+</a>
            </div>
          </article>
        </div>

        <p class="lede" style="margin-top:20px">Prepaid agent wallets pay Red Center Studio&apos;s own APIs only. They are not a way for other developers to get paid. ${topupAction}</p>

        <div class="demo-panel" id="diy">
          <span class="label">DIY setup in 4 steps</span>
          <h3 style="margin-top:6px">From nothing to live payments.</h3>
          <ol class="tier-list" style="padding-left:0">
            <li><strong>Register.</strong> Create a developer account with your Base wallet as the payout address: <code>POST /developer/register</code>, or step 1 of the form below. Fix a wrong wallet later with <code>POST /developer/payout</code>.</li>
            <li><strong>Install.</strong> Run <code>/install-tollbooth</code> in Claude Code, or add the middleware by hand, with <code>payTo</code> set to that wallet.</li>
            <li><strong>Test free.</strong> Run <code>/test-agent</code> and settle on Base Sepolia. It costs nothing.</li>
            <li><strong>Go live.</strong> Buy a Pro Pass to settle on Base mainnet through the hosted facilitator.</li>
          </ol>
        </div>
      </div>
    </section>
    ${buyPanel}

    <section id="connect" style="padding-top:0">
      <div class="wrap">
        <div class="sec-head narrow">
          <span class="label">Connect it</span>
          <h2>Install in Claude Code, Antigravity, or your Worker in 30 seconds.</h2>
          <p class="lede">Copy one command below to add the plugin, connect the Streamable HTTP MCP server, or install the zero-dependency middleware package.</p>
        </div>

        <div class="grid g3">
          <div class="card">
            <span class="label">Claude Code Marketplace</span>
            <h3>Plugin bundle + skills</h3>
            <div class="code-box">
              <pre tabindex="0"><code id="cmd-claude">/plugin marketplace add Red-Center-Studio/agent-tollbooth-402
/plugin install agent-tollbooth-402@agent-tollbooth-402</code></pre>
              <button class="btn btn-ghost copy-btn" type="button" data-copy="cmd-claude">Copy</button>
            </div>
          </div>

          <div class="card">
            <span class="label">Remote Streamable MCP</span>
            <h3>Antigravity &amp; Claude connector</h3>
            <div class="code-box">
              <pre tabindex="0"><code id="cmd-mcp">https://tollbooth.redcenterstudio.com/mcp</code></pre>
              <button class="btn btn-ghost copy-btn" type="button" data-copy="cmd-mcp">Copy</button>
            </div>
          </div>

          <div class="card">
            <span class="label">Edge Middleware</span>
            <h3>Workers / Hono / Next.js</h3>
            <div class="code-box">
              <pre tabindex="0"><code id="cmd-npm">npm install ${EDGE_TARBALL_URL}</code></pre>
              <button class="btn btn-ghost copy-btn" type="button" data-copy="cmd-npm">Copy</button>
            </div>
          </div>
        </div>

        <div class="demo-panel">
          <span class="label">Interactive live probe</span>
          <h3 style="margin-top:6px">Test the live HTTP 402 challenge header and clearinghouse health.</h3>
          <div class="demo-row">
            <button id="run-demo-btn" class="btn btn-primary" type="button">Run Live 402 Check</button>
            <a class="btn btn-ghost" href="/demo/402">Open Browser 402 Card</a>
            <span id="demo-output" class="demo-out">Click to fetch /demo/402 (JSON) and /health on tollbooth.redcenterstudio.com.</span>
          </div>
        </div>
      </div>
    </section>

    <section id="tools" style="padding-top:0">
      <div class="wrap">
        <div class="sec-head narrow">
          <span class="label">Reference</span>
          <h2>Clearinghouse endpoints and remote MCP tools.</h2>
        </div>
        <div class="table-wrap">
          <table class="map">
            <thead>
              <tr>
                <th>Surface</th>
                <th>Name / Route</th>
                <th>Purpose</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_pricing_quote</code></td>
                <td>Estimate monthly earnings from x402 payments (0% fee) and see the pass prices.</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_wallet_balance</code></td>
                <td>Check remaining prepaid agent wallet credit balance in USD and integer micro-dollars (studio routes only).</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_issue_receipt</code></td>
                <td>Issue a short-lived signed <code>rcs_receipt_...</code> bearer token for agent requests.</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_verify_x402</code></td>
                <td>Inspect or verify an x402 V2 <code>PAYMENT-SIGNATURE</code> header payload.</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_create_topup_checkout</code></td>
                <td>Create a Stripe Checkout / Payment Link URL for wallet top-ups (studio routes only) or Pro/Agency Passes.</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_register_wallet</code></td>
                <td>Create an empty agent wallet and its wallet key (shown once).</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_ledger_history</code></td>
                <td>Recent top-ups, charges and settlements for a wallet or developer account.</td>
              </tr>
              <tr>
                <td>MCP Tool</td>
                <td><code>tollbooth_pass_status</code></td>
                <td>A developer account's tier and metering access.</td>
              </tr>
              <tr>
                <td>HTTP</td>
                <td><code>POST /wallet/register</code>, <code>POST /developer/register</code>, <code>POST /developer/payout</code>, <code>POST /keys/rotate</code></td>
                <td>Self-serve accounts with scoped keys. Only key hashes are stored.</td>
              </tr>
              <tr>
                <td>HTTP</td>
                <td><code>GET /.well-known/tollbooth-jwks.json</code></td>
                <td>Ed25519 public key for verifying Rail B receipts without any shared secret.</td>
              </tr>
              <tr>
                <td>HTTP Edge</td>
                <td><code>GET /health</code> &amp; <code>GET /demo/402</code></td>
                <td>Clearinghouse health probe and dual content-negotiated HTML/JSON 402 demo endpoint.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="faq" style="padding-top:0">
      <div class="wrap">
        <div class="narrow">
          <h2 style="font-size:clamp(26px,3.4vw,34px);margin:0 0 8px">Frequently asked questions</h2>
          <div class="faq">
            <details>
              <summary>Can I use x402 V2 without paying any platform fee?</summary>
              <p>Yes. Set your own <code>payTo</code> wallet address on Base in the middleware config and agents pay your wallet directly in USDC. Red Center Studio never holds your money and takes 0% of payments.</p>
            </details>
            <details>
              <summary>What does the Pro Pass add?</summary>
              <p>It is $39 USD once, for one project. It turns on hosted Base mainnet settlement, so you need no Coinbase developer account, keys or facilitator server of your own. Payments still go straight to your wallet. It includes up to 10,000 hosted settlements a month. The Agency Pass is $79 USD once for multiple projects.</p>
            </details>
            <details>
              <summary>Is testing free?</summary>
              <p>Yes. Hosted settlement on Base Sepolia testnet is free. Base mainnet is free too if you settle through your own facilitator.</p>
            </details>
            <details>
              <summary>Can I test locally without a crypto wallet?</summary>
              <p>Yes. Pass <code>mode: &quot;sandbox&quot;</code> or run <code>/agent-tollbooth-402:test-agent</code> to test 402 headers, signed receipts, browser checkout cards, and nonce replay blocking offline.</p>
            </details>
          </div>
        </div>
      </div>
    </section>
  </main>

  <footer class="site-foot dark">
    <span class="strata" aria-hidden="true" style="margin-bottom:36px"></span>
    <div class="wrap">
      <div class="foot-grid">
        <div class="foot-brand">
          <a class="brand" href="https://redcenterstudio.com/" rel="noopener noreferrer">Red Center Studio</a>
          <p>Custom platforms, fast websites, AI agents and HTTP 402 tollbooth tooling, built by an independent solo studio.</p>
        </div>
        <div class="foot-col">
          <span class="label">Plugin &amp; Clearinghouse</span>
          <a href="#connect">Install in 30 seconds</a>
          <a href="#prices">Pricing &amp; passes</a>
          <a href="/demo/402">Live 402 checkout demo</a>
          <a href="/health">Health status</a>
        </div>
        <div class="foot-col">
          <span class="label">Red Center Studio</span>
          <a href="https://redcenterstudio.com/services/ai-tollbooth-setup/" rel="noopener noreferrer">Done-for-you AI Tollbooth</a>
          <a href="https://redcenterstudio.com/claude-connectors/" rel="noopener noreferrer">Claude connectors</a>
          <a href="https://redcenterstudio.com/products/" rel="noopener noreferrer">Shop</a>
          <a href="https://github.com/Red-Center-Studio/agent-tollbooth-402" rel="noopener noreferrer">GitHub repository</a>
        </div>
        <div class="foot-col">
          <span class="label">Contact</span>
          <a href="mailto:hello@redcenterstudio.com">hello@redcenterstudio.com</a>
          <a href="https://redcenterstudio.com/start/" rel="noopener noreferrer">Start a project</a>
          <a href="https://redcenterstudio.com/support/" rel="noopener noreferrer">Support</a>
        </div>
      </div>
      <nav class="legal-links" aria-label="Legal">
        <a href="https://redcenterstudio.com/privacy/" rel="noopener noreferrer">Privacy Policy</a>
        <a href="https://redcenterstudio.com/terms/" rel="noopener noreferrer">Terms of Service</a>
        <a href="https://redcenterstudio.com/terms/#deposits-cancellations-and-refunds" rel="noopener noreferrer">Refunds</a>
      </nav>
      <p class="legal-more">Stripe and Claude are trademarks of their respective owners. Red Center Studio is an independent studio and is not affiliated with, endorsed by, or certified by them.</p>
    </div>
  </footer>

  <script>
  (() => {
    const out = document.getElementById('tb-out');
    if (!out) return;
    let keyShown = false;
    const NL = String.fromCharCode(10, 10);
    const post = async (path, body) => {
      try {
        const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        return [r.ok, await r.json().catch(() => ({}))];
      } catch {
        return [false, { fix_hint: 'Network error contacting clearinghouse. Please check your connection and retry.' }];
      }
    };
    document.querySelectorAll('[data-register]').forEach((b) => b.addEventListener('click', async () => {
      if (b.disabled) return;
      const form = b.closest('form');
      const isWallet = b.dataset.register === 'wallet';
      if (!isWallet && !/^0x[0-9a-fA-F]{40}$/.test(form.elements.payout.value.trim())) {
        out.textContent = 'Add the Base wallet address (0x followed by 40 characters) that will receive your payments.';
        out.scrollIntoView({ block: 'nearest' });
        return;
      }
      b.disabled = true;
      b.setAttribute('aria-busy', 'true');
      try {
        const body = isWallet ? {} : { email: form.elements.email.value, name: form.elements.owner.value, payoutAddress: form.elements.payout.value.trim() || undefined };
        const [ok, j] = await post(isWallet ? '/wallet/register' : '/developer/register', body);
        if (!ok) {
          const msg = j.fix_hint || 'Could not create the account.';
          out.textContent = keyShown ? out.textContent + NL + msg : msg;
          return;
        }
        form.elements.account.value = isWallet ? j.walletId : j.developerId;
        const created = (isWallet ? 'Wallet ' + j.walletId + '. Wallet key (shown once, save it now): ' + j.walletKey
          : 'Account created: ' + j.developerId + '. Developer key (shown once, save it now): ' + j.developerKey + '. Now choose your pass.');
        out.textContent = keyShown ? out.textContent + NL + created : created;
        keyShown = true;
        out.scrollIntoView({ block: 'nearest' });
      } finally {
        b.disabled = false;
        b.removeAttribute('aria-busy');
      }
    }));
    document.querySelectorAll('.tb-form').forEach((form) => form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = form.querySelector('[type="submit"]');
      if (submitBtn && submitBtn.disabled) return;
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.setAttribute('aria-busy', 'true');
      }
      try {
        const id = form.elements.account.value.trim();
        const body = form.dataset.kind === 'topup' ? { walletId: id, amountUsd: 10 } : { developerId: id, passTier: form.elements.tier.value };
        const [ok, j] = await post('/wallet/topup', body);
        if (ok && j.checkoutUrl) { location.href = j.checkoutUrl; return; }
        // Append, never replace: a wallet or developer key shown once above must survive a failed checkout.
        const msg = j.fix_hint || 'Checkout did not open. Please try again.';
        out.textContent = keyShown ? out.textContent + NL + msg : msg;
        out.scrollIntoView({ block: 'nearest' });
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.removeAttribute('aria-busy');
        }
      }
    }));
  })();
    (function () {
      var menuBtn = document.querySelector('.menu-btn');
      var nav = document.getElementById('site-nav');
      if (menuBtn && nav) {
        menuBtn.addEventListener('click', function () {
          var open = menuBtn.getAttribute('aria-expanded') !== 'true';
          menuBtn.setAttribute('aria-expanded', String(open));
          menuBtn.textContent = open ? 'Close' : 'Menu';
          nav.classList.toggle('open', open);
        });
        document.addEventListener('keydown', function (e) {
          if (e.key === 'Escape' && nav.classList.contains('open')) {
            menuBtn.setAttribute('aria-expanded', 'false');
            menuBtn.textContent = 'Menu';
            nav.classList.remove('open');
            menuBtn.focus();
          }
        });
      }
      var steps = [
        {
          badge: 'Step 1 \\u00b7 Claude Code & Antigravity',
          challenge: false,
          code: '$ /plugin marketplace add Red-Center-Studio/agent-tollbooth-402\\n$ /plugin install agent-tollbooth-402@agent-tollbooth-402\\n\\n[PASS] 3 skills (/agent-tollbooth-402:scan-routes, /agent-tollbooth-402:install-tollbooth, /agent-tollbooth-402:test-agent)\\n[PASS] Remote MCP ready: https://tollbooth.redcenterstudio.com/mcp',
          caption: 'Add the plugin in one command or connect the remote MCP server directly.'
        },
        {
          badge: 'Step 2 \\u00b7 Zero-Dependency Edge Guard',
          challenge: false,
          code: "import { withTollbooth } from '@redcenterstudio/agent-tollbooth-edge';\\n\\nexport default withTollbooth({\\n  priceUsd: 0.01,\\n  mode: 'x402',\\n  payTo: '0xYourBaseUSDCWallet',\\n  network: 'eip155:84532'\\n}, handler);",
          caption: 'Wrap Cloudflare Workers, Hono, Next.js, or MCP routes. Payments go to your own wallet.'
        },
        {
          badge: 'Step 3 \\u00b7 HTTP 402 Payment Challenge',
          challenge: true,
          code: 'GET /demo/402  ->  HTTP/1.1 402 Payment Required\\nPAYMENT-REQUIRED: eyJ4NDAyVmVyc2lvbiI6MiwiY29kZSI6Ik1JU1NJTkdf...\\n\\n{ "code": "MISSING_PAYMENT", "priceUsd": "0.01", "rails": ["x402-v2"] }',
          caption: 'AI agents receive strict x402 V2 JSON headers; browsers see a Red Center checkout card.'
        },
        {
          badge: 'Step 4 \\u00b7 Paid and settled',
          challenge: false,
          code: 'PAYMENT-SIGNATURE: eyJ4NDAyVmVyc2lvbiI6Miwic2NoZW1lIjoiZXhhY3Qi...\\n-> USDC authorization verified\\n-> settled on Base to your payTo wallet\\n\\nHTTP/1.1 200 OK  |  PAYMENT-RESPONSE: { "success": true }',
          caption: 'The agent retries with a signed USDC payment. It settles to your wallet, the nonce is spent, and the route answers 200.'
        }
      ];
      var activeStep = 0;
      var paused = false;
      var tabEls = document.querySelectorAll('.proof-tab');
      var badgeEl = document.getElementById('proof-badge');
      var codeEl = document.getElementById('proof-code');
      var capEl = document.getElementById('proof-caption');
      var fillEl = document.getElementById('proof-fill');
      var toggleEl = document.getElementById('proof-toggle');

      function renderStep(idx) {
        activeStep = idx % steps.length;
        var st = steps[activeStep];
        tabEls.forEach(function (t, i) { t.setAttribute('aria-selected', String(i === activeStep)); });
        if (badgeEl) {
          badgeEl.textContent = st.badge;
          badgeEl.className = st.challenge ? 'proof-status challenge' : 'proof-status';
        }
        if (codeEl) {
          codeEl.style.animation = 'none';
          void codeEl.offsetWidth;
          codeEl.style.animation = '';
          codeEl.textContent = st.code;
        }
        if (capEl) capEl.textContent = st.caption;
        if (fillEl) fillEl.style.width = ((activeStep + 1) * 25) + '%';
      }
      window.__setProofStep = renderStep;
      tabEls.forEach(function (t, i) {
        t.addEventListener('click', function () {
          paused = true;
          if (toggleEl) toggleEl.textContent = 'Play';
          renderStep(i);
        });
      });
      if (toggleEl) {
        toggleEl.addEventListener('click', function () {
          paused = !paused;
          toggleEl.textContent = paused ? 'Play' : 'Pause';
        });
      }
      setInterval(function () {
        if (!paused) renderStep(activeStep + 1);
      }, 3400);

      document.querySelectorAll('[data-copy]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var el = document.getElementById(btn.getAttribute('data-copy'));
          if (!el || !navigator.clipboard) return;
          navigator.clipboard.writeText(el.textContent).then(function () {
            btn.textContent = 'Copied';
            btn.style.borderColor = '#4f7f63';
            btn.style.color = '#2f5a41';
            setTimeout(function () {
              btn.textContent = 'Copy';
              btn.style.borderColor = '';
              btn.style.color = '';
            }, 1500);
          }).catch(function () {
            btn.textContent = 'Copy failed';
            setTimeout(function () {
              btn.textContent = 'Copy';
            }, 1500);
          });
        });
      });
      var demoBtn = document.getElementById('run-demo-btn');
      var out = document.getElementById('demo-output');
      if (demoBtn && out) {
        demoBtn.addEventListener('click', async function () {
          if (demoBtn.disabled) return;
          demoBtn.disabled = true;
          demoBtn.setAttribute('aria-busy', 'true');
          out.className = 'demo-out';
          out.textContent = 'Checking /demo/402 and /health...';
          try {
            var t0 = performance.now();
            var r402 = await fetch('/demo/402', { headers: { Accept: 'application/json' } });
            var hdr = r402.headers.get('PAYMENT-REQUIRED') || '';
            var rHealth = await fetch('/health');
            var ms = Math.round(performance.now() - t0);
            if (r402.status === 402 && hdr.length > 0 && rHealth.ok) {
              out.className = 'demo-out ok';
              out.textContent = '[402 CHALLENGE] HTTP ' + r402.status + ' | PAYMENT-REQUIRED (' + hdr.length + 'b) -> [' + rHealth.status + ' OK] /health in ' + ms + 'ms';
            } else {
              out.className = 'demo-out err';
              out.textContent = 'Unexpected probe response: /demo/402 HTTP ' + r402.status + ' (header ' + hdr.length + 'b), /health HTTP ' + rHealth.status + ' in ' + ms + 'ms';
            }
          } catch (e) {
            out.className = 'demo-out err';
            out.textContent = 'Check failed: ' + (e && e.message ? e.message : 'network error');
          } finally {
            demoBtn.disabled = false;
            demoBtn.removeAttribute('aria-busy');
          }
        });
      }
    })();
  </script>
</body>
</html>`;
}

async function handleIssueReceipt(request: Request, env: Env): Promise<Response> {
  const scope = await requestScope(request, env);
  if (!scope) {
    return jsonWithCors({ error: 'unauthorized', ...resolveClearinghouseGuidance('unauthorized') }, 401);
  }

  const parsed = await readJsonObject(request);
  if (!parsed.ok) {
    return jsonWithCors(
      {
        error: 'invalid_json',
        ...resolveClearinghouseGuidance('invalid_json'),
      },
      400,
    );
  }
  const body = parsed.data as unknown as IssueReceiptBody;

  // A wallet key may only spend from its own wallet.
  if (!scopeAllows(scope, { walletId: typeof body.walletId === 'string' ? body.walletId : undefined })) {
    return jsonWithCors({ error: 'unauthorized', ...resolveClearinghouseGuidance('unauthorized') }, 403);
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
    const rawRpc: unknown = await request.json();
    if (!isPlainObject(rawRpc)) {
      return jsonRpcErr(null, -32600, 'Invalid Request', 400);
    }
    rpc = rawRpc as unknown as JsonRpcRequest;
  } catch {
    return jsonRpcErr(null, -32700, 'Parse error', 400);
  }

  if (rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string') {
    return jsonRpcErr(rpc.id, -32600, 'Invalid Request', 400);
  }
  if (rpc.params !== undefined && !isPlainObject(rpc.params)) {
    return jsonRpcErr(rpc.id, -32602, 'Invalid params', 400);
  }

  if (rpc.method === 'notifications/initialized') {
    return withCors(new Response(null, { status: 202 }));
  }

  if (rpc.method === 'ping') {
    return jsonRpcOk(rpc.id, {});
  }

  if (rpc.method === 'initialize') {
    const requestedProtocol =
      typeof rpc.params?.protocolVersion === 'string' ? rpc.params.protocolVersion : '2025-03-26';
    return jsonRpcOk(rpc.id, {
      protocolVersion: requestedProtocol,
      capabilities: {
        tools: { listChanged: false },
        resources: { listChanged: false },
        prompts: { listChanged: false },
      },
      serverInfo: {
        name: 'agent-tollbooth-402-clearinghouse',
        version: '1.2.2',
      },
    });
  }

  if (rpc.method === 'tools/list') {
    return jsonRpcOk(rpc.id, { tools: MCP_TOOLS });
  }

  if (rpc.method === 'resources/list') {
    return jsonRpcOk(rpc.id, { resources: [] });
  }

  if (rpc.method === 'resources/templates/list') {
    return jsonRpcOk(rpc.id, { resourceTemplates: [] });
  }

  if (rpc.method === 'prompts/list') {
    return jsonRpcOk(rpc.id, { prompts: [] });
  }

  if (rpc.method === 'tools/call') {
    const params = rpc.params ?? {};
    const toolName = typeof params.name === 'string' ? params.name : '';
    if (params.arguments !== undefined && !isPlainObject(params.arguments)) {
      return jsonRpcErr(rpc.id, -32602, 'Tool arguments must be a JSON object');
    }
    const args = (params.arguments ?? {}) as Record<string, unknown>;

    if (toolName === 'tollbooth_pricing_quote') {
      const priceMicros = args.priceMicros;
      const callsPerMonth = args.callsPerMonth;
      if (
        typeof priceMicros !== 'number' ||
        typeof callsPerMonth !== 'number' ||
        !Number.isSafeInteger(priceMicros) ||
        priceMicros <= 0 ||
        !Number.isSafeInteger(callsPerMonth) ||
        callsPerMonth <= 0
      ) {
        return jsonRpcErr(rpc.id, -32602, 'priceMicros and callsPerMonth must be positive safe integers');
      }
      const monthlyGross = priceMicros * callsPerMonth;
      if (!Number.isSafeInteger(monthlyGross)) {
        return jsonRpcErr(rpc.id, -32602, 'monthly gross exceeds safe integer bounds');
      }
      const quote = {
        monthlyGrossMicros: monthlyGross,
        x402: calculateClearinghouseFee(monthlyGross, 'free', 'x402'),
        passes: {
          freeDiyUsd: 0,
          proPassUsd: 39,
          agencyPassUsd: 79,
          oneTime: true,
          note: 'x402 USDC goes straight to your payTo wallet with 0% Red Center fee. The Pro Pass ($39 once, one project) and Agency Pass ($79 once) pay for hosted Base mainnet settlement, not a share of your earnings. Base Sepolia testing is free.',
        },
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

    if (toolName === 'tollbooth_register_wallet') {
      const out = await registerWallet(env.DB, args);
      return jsonRpcOk(rpc.id, {
        isError: out.status >= 400,
        content: [{ type: 'text', text: JSON.stringify(out.payload) }],
        structuredContent: out.payload,
      });
    }

    if (toolName === 'tollbooth_ledger_history' || toolName === 'tollbooth_pass_status') {
      const scope = await requestScope(request, env);
      const walletId = typeof args.walletId === 'string' ? args.walletId : undefined;
      const developerId = typeof args.developerId === 'string' ? args.developerId : undefined;
      const target =
        toolName === 'tollbooth_pass_status' ? { developerId } : walletId ? { walletId } : { developerId };
      if (!scopeAllows(scope, target)) {
        return jsonRpcErr(rpc.id, -32001, 'Unauthorized: send Authorization: Bearer <wallet or developer key> for this account', 401);
      }
      let out: { status: number; payload: Record<string, unknown> };
      if (toolName === 'tollbooth_ledger_history') {
        out = await ledgerHistory(env.DB, target, args.limit);
      } else {
        const dev = await env.DB.prepare('SELECT id, tier FROM developers WHERE id = ? LIMIT 1')
          .bind(developerId)
          .first<{ id: string; tier: DeveloperTier }>();
        out = dev
          ? {
              status: 200,
              payload: {
                developerId: dev.id,
                tier: dev.tier === 'pro' || dev.tier === 'agency' ? dev.tier : 'free',
                hostedMainnetSettlement: dev.tier === 'pro' || dev.tier === 'agency',
              },
            }
          : { status: 404, payload: { error: 'developer_not_found', ...resolveClearinghouseGuidance('developer_not_found') } };
      }
      return jsonRpcOk(rpc.id, {
        isError: out.status >= 400,
        content: [{ type: 'text', text: JSON.stringify(out.payload) }],
        structuredContent: out.payload,
      });
    }

    if (toolName === 'tollbooth_wallet_balance' || toolName === 'tollbooth_issue_receipt') {
      const scope = await requestScope(request, env);
      if (!scopeAllows(scope, { walletId: typeof args.walletId === 'string' ? args.walletId : undefined })) {
        return jsonRpcErr(rpc.id, -32001, 'Unauthorized: send Authorization: Bearer <wallet key> for this wallet', 401);
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

async function handleRequest(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (request.method === 'OPTIONS') {
        return withCors(new Response(null, { status: 204 }));
      }

      if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/pay')) {
        return withCors(
          new Response(renderClearinghousePortalHtml(env, await portalNotice(url, env)), {
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
          version: '1.2.2',
          timestamp: Math.floor(Date.now() / 1000),
        });
      }

      if (request.method === 'GET' && url.pathname === '/llms.txt') {
        return withCors(
          new Response(renderLlmsTxt(), {
            status: 200,
            headers: {
              'Content-Type': 'text/plain; charset=utf-8',
              'Cache-Control': 'public, max-age=300',
            },
          }),
        );
      }

      if (request.method === 'GET' && url.pathname === '/.well-known/mcp.json') {
        return jsonWithCors(renderWellKnownMcpManifest());
      }

      if (
        request.method === 'GET' &&
        (url.pathname === '/.well-known/glama.json' || url.pathname === '/mcp/.well-known/glama.json')
      ) {
        return jsonWithCors({
          $schema: 'https://glama.ai/mcp/schemas/connector.json',
          claim: 'glama_claim_cyMUBGX_WjP7q4T153TkuepupDjd91bT',
          maintainers: [{ email: 'housesharingappjerome@gmail.com' }],
        });
      }

      if (request.method === 'GET' && url.pathname === '/favicon.ico') {
        return withCors(new Response(null, { status: 204, headers: { 'Cache-Control': 'public, max-age=86400' } }));
      }

      if (request.method === 'GET' && url.pathname === '/robots.txt') {
        return withCors(
          new Response(renderRobotsTxt(), {
            status: 200,
            headers: {
              'Content-Type': 'text/plain; charset=utf-8',
              'Cache-Control': 'public, max-age=3600',
            },
          }),
        );
      }

      if (request.method === 'GET' && url.pathname === '/sitemap.xml') {
        return withCors(
          new Response(renderSitemapXml(), {
            status: 200,
            headers: {
              'Content-Type': 'application/xml; charset=utf-8',
              'Cache-Control': 'public, max-age=3600',
            },
          }),
        );
      }

      if (url.pathname === '/mcp') {
        return await handleMcp(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/verify') {
        return await handleVerify(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/settle') {
        return await handleSettle(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/wallet/issue-receipt') {
        return await handleIssueReceipt(request, env);
      }

      if (request.method === 'GET' && url.pathname === '/.well-known/tollbooth-jwks.json') {
        return withCors(
          Response.json(await receiptJwks(env), { headers: { 'Cache-Control': 'public, max-age=300' } }),
        );
      }

      if (request.method === 'POST' && (url.pathname === '/wallet/register' || url.pathname === '/developer/register')) {
        const parsed = await readJsonObject(request);
        if (!parsed.ok) {
          return jsonWithCors({ error: 'invalid_json', ...resolveClearinghouseGuidance('invalid_json') }, 400);
        }
        const out =
          url.pathname === '/wallet/register'
            ? await registerWallet(env.DB, parsed.data)
            : await registerDeveloper(env.DB, parsed.data);
        return jsonWithCors(out.payload, out.status);
      }

      if (request.method === 'POST' && url.pathname === '/keys/rotate') {
        const token = bearerToken(request);
        const scope = token ? await resolveScopedKey(env.DB, token) : null;
        if (!token || !scope) {
          return jsonWithCors({ error: 'unauthorized', ...resolveClearinghouseGuidance('unauthorized') }, 401);
        }
        const out = await rotateKey(env.DB, token, scope);
        return jsonWithCors(out.payload, out.status);
      }

      if (request.method === 'POST' && url.pathname === '/developer/payout') {
        const token = bearerToken(request);
        const scope = token ? await resolveScopedKey(env.DB, token) : null;
        if (!token || !scope) {
          return jsonWithCors({ error: 'unauthorized', ...resolveClearinghouseGuidance('unauthorized') }, 401);
        }
        const parsed = await readJsonObject(request);
        if (!parsed.ok) {
          return jsonWithCors({ error: 'invalid_json', ...resolveClearinghouseGuidance('invalid_json') }, 400);
        }
        const out = await setPayoutAddress(env.DB, scope, parsed.data as { payoutAddress?: unknown });
        return jsonWithCors(out.payload, out.status);
      }

      if (request.method === 'GET' && (url.pathname === '/wallet/ledger' || url.pathname === '/developer/ledger')) {
        const scope = await requestScope(request, env);
        const own = scope?.kind === 'wallet' ? scope.walletId : scope?.kind === 'developer' ? scope.developerId : '';
        const id = url.searchParams.get('id') ?? own;
        const target = url.pathname === '/wallet/ledger' ? { walletId: id } : { developerId: id };
        if (!scopeAllows(scope, target)) {
          return jsonWithCors({ error: 'unauthorized', ...resolveClearinghouseGuidance('unauthorized') }, 401);
        }
        const out = await ledgerHistory(env.DB, target, url.searchParams.get('limit'));
        return jsonWithCors(out.payload, out.status);
      }

      if (request.method === 'POST' && url.pathname === '/wallet/topup') {
        return await handleWalletTopup(request, env);
      }

      if (request.method === 'POST' && url.pathname === '/webhook/stripe') {
        return await handleStripeWebhook(request, env);
      }

      return jsonWithCors(
        {
          error: 'not_found',
          code: 'NOT_FOUND',
          fix_hint:
            'Supported routes: GET /, GET /pay, GET /demo/402, GET /health, GET /llms.txt, GET /.well-known/mcp.json, GET /robots.txt, GET /sitemap.xml, GET /.well-known/tollbooth-jwks.json, POST /verify, POST /settle, POST /wallet/register, POST /developer/register, POST /developer/payout, POST /keys/rotate, GET /wallet/ledger, GET /developer/ledger, POST /wallet/issue-receipt, POST /wallet/topup, POST /webhook/stripe, POST /mcp.',
        },
        404,
      );
    } catch (err) {
      console.error('clearinghouse_unhandled_error', err);
      return jsonWithCors(
        {
          error: 'internal_error',
          code: 'INTERNAL_ERROR',
          fix_hint: 'An internal clearinghouse error occurred. Retry safely with the same Idempotency-Key.',
        },
        500,
      );
    }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Crawlers, link checkers and uptime monitors often send HEAD: answer it as GET, without a body.
    if (request.method === 'HEAD') {
      const res = await handleRequest(new Request(request.url, { method: 'GET', headers: request.headers }), env, ctx);
      return new Response(null, { status: res.status, statusText: res.statusText, headers: res.headers });
    }
    return handleRequest(request, env, ctx);
  },

  /** Hourly: drop spent nonces whose authorization or receipt has expired (an expired one is refused anyway). */
  async scheduled(_controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    const cutoff = Math.floor(Date.now() / 1000) - 3600;
    await env.DB.prepare('DELETE FROM used_nonces WHERE expires_at < ?').bind(cutoff).run();
  },
};
