/**
 * @redcenterstudio/agent-tollbooth-edge
 * Zero-dependency dual-rail HTTP 402 middleware for Cloudflare Workers, Fetch APIs, Next.js, and Hono.
 *
 * Rail A: Open x402 V2 standard (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`)
 * Rail B: Red Center Fiat Agent Wallet (`rcs_receipt_...` verified <1ms via Web Crypto + NonceStore)
 */

export type PaymentScheme = 'exact' | 'upto';
export type TollboothRail = 'x402' | 'fiat_wallet';
export type FiatReceiptAlg = 'hs256' | 'ed25519';
export type TollboothMode = 'sandbox' | 'mock' | 'hybrid' | 'x402';

export type TollboothErrorCode =
  | 'MISSING_PAYMENT'
  | 'INSUFFICIENT_FUNDS'
  | 'RECEIPT_EXPIRED'
  | 'NONCE_REPLAYED'
  | 'INVALID_SIGNATURE'
  | 'SPEND_CAP_EXCEEDED'
  | 'PRO_PASS_REQUIRED'
  | 'FACILITATOR_ERROR';

export const DEFAULT_FACILITATOR_URL = 'https://tollbooth.redcenterstudio.com';
export const DEFAULT_PAYMENT_URL = 'https://tollbooth.redcenterstudio.com';
export const DEFAULT_PAY_TO = '0x000000000000000000000000000000000000dEaD';
export const DEFAULT_NETWORK = 'eip155:8453';
export const DEFAULT_USDC_BASE_ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const DEFAULT_EXEMPT_PATHS = ['/health', '/readyz', '/webhook/*'] as const;
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;
export const DEFAULT_PRICE_USD = 0.01;
export const SANDBOX_HMAC_SECRET = 'rcs_sandbox_local_dev_secret_32bytes_deterministic';

export const CORS_EXPOSE_HEADERS =
  'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Agent-Receipt, WWW-Authenticate, X-Tollbooth-Rail';
export const CORS_ALLOW_HEADERS =
  'Content-Type, Authorization, PAYMENT-SIGNATURE, X-Agent-Receipt, Idempotency-Key';

export interface D1LikeRunResult {
  meta?: {
    changes?: number;
  };
}

export interface D1LikePreparedStatement {
  bind(...values: unknown[]): D1LikePreparedStatement;
  run(): Promise<D1LikeRunResult>;
}

export interface D1LikeDatabase {
  prepare(query: string): D1LikePreparedStatement;
}

export interface NonceConsumeMeta {
  walletOrPayer: string;
  route: string;
  expiresAt: number;
  rail?: TollboothRail;
}

export interface NonceStore {
  consume(nonce: string, meta: NonceConsumeMeta): Promise<boolean>;
  release?(nonce: string): Promise<void>;
}

export interface SpendTracker {
  checkAndRecord(
    agentId: string,
    amountMicros: number,
    capMicros: number,
  ): Promise<{ allowed: boolean; spentMicros: number }>;
  rollback?(agentId: string, amountMicros: number): Promise<void>;
}

export interface RcsReceiptClaims {
  v: 1;
  jti: string;
  sub: string;
  aud: string;
  mth?: string;
  amt: number;
  iat: number;
  exp: number;
  tier?: 'hybrid' | 'pro' | 'agency';
}

export type ReceiptSigningKey =
  | { alg: 'hs256'; secret: string }
  | { alg: 'ed25519'; privateKey: CryptoKey };

export interface FiatWalletConfig {
  hmacSecret?: string;
  ed25519PublicKey?: CryptoKey | string;
  clearinghouseUrl?: string;
  clockSkewSeconds?: number;
}

export interface FiatWalletVerifyOptions extends FiatWalletConfig {
  expectedAudience: string;
  expectedMethod: string;
  requiredMicros: number;
  nowSeconds?: number;
  perAgentSpendCapMicros?: number;
  spendTracker?: SpendTracker;
}

export interface FiatReceiptVerifyResult {
  valid: boolean;
  reason?: string;
  claims?: RcsReceiptClaims;
  alg?: FiatReceiptAlg;
  verifiedInMs?: number;
}

export interface X402AcceptOption {
  scheme: PaymentScheme;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

export interface X402PaymentRequired {
  x402Version: 2;
  code: TollboothErrorCode;
  error: string;
  fix_hint: string;
  priceUsd: string;
  priceMicros: number;
  acceptedRails: Array<'x402-v2' | 'rcs-fiat-wallet'>;
  paymentUrl: string;
  resource: {
    url: string;
    description: string;
    mimeType: string;
  };
  accepts: X402AcceptOption[];
  extensions: Record<string, unknown>;
}

export interface X402Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

export interface X402PaymentSignature {
  x402Version: 2;
  scheme?: PaymentScheme;
  network?: string;
  accepted?: {
    scheme: PaymentScheme;
    network: string;
  };
  payload: {
    signature: string;
    authorization: X402Authorization;
  };
}

export interface X402PaymentResponse {
  success: boolean;
  transaction: string | null;
  network: string;
  payer: string | null;
  settledAmount?: string;
  rail?: TollboothRail;
  errorReason: string | null;
}

export interface X402VerifyResponse {
  isValid: boolean;
  invalidReason: string | null;
}

export interface X402SettleResponse {
  success: boolean;
  txHash: string | null;
  network?: string;
  settledAmount?: string;
  errorReason: string | null;
}

export interface TollboothRouteConfig {
  pattern: string;
  method?: string | string[];
  scheme?: PaymentScheme;
  priceMicros?: number;
  priceUsd?: number | string;
  minPriceMicros?: number;
  proPass?: boolean;
  description?: string;
  mimeType?: string;
  network?: string;
  asset?: string;
  payTo?: string;
  maxTimeoutSeconds?: number;
  meterUsage?: (
    request: Request,
    response: Response,
    minAtomic: bigint,
    authorizedAtomic: bigint,
  ) => Promise<bigint> | bigint;
}

export interface TollboothConfig {
  payTo?: string;
  mode?: TollboothMode;
  priceUsd?: number | string;
  priceMicros?: number;
  facilitatorUrl?: string;
  paymentUrl?: string;
  network?: string;
  asset?: string;
  proPass?: boolean;
  clockSkewSeconds?: number;
  customPaymentPageHtml?:
    | string
    | ((challenge: X402PaymentRequired, request: Request) => string);
  perAgentSpendCapMicros?: number;
  spendTracker?: SpendTracker;
  exemptPaths?: string[];
  nonceStore?: NonceStore;
  fiatWallet?: FiatWalletConfig;
  routes?: TollboothRouteConfig[];
  fetchImpl?: typeof fetch;
  nowSeconds?: () => number;
}

export interface WorkerHandler<Env = unknown> {
  fetch(request: Request, env?: Env, ctx?: ExecutionContext): Promise<Response>;
}

export type WorkerFetchFn<Env = unknown> = (
  request: Request,
  env?: Env,
  ctx?: ExecutionContext,
) => Promise<Response> | Response;

export interface HonoLikeContext {
  req: {
    raw: Request;
  };
  res: Response | undefined;
}

export type HonoLikeNext = () => Promise<void>;
export type HonoLikeMiddleware = (
  c: HonoLikeContext,
  next: HonoLikeNext,
) => Promise<Response | void>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const hmacKeyCache = new Map<string, Promise<CryptoKey>>();
const ed25519KeyCache = new Map<string, Promise<CryptoKey>>();

/**
 * Convert a USD dollar value (e.g. `0.005` or `"$0.005"`) into integer microdollars (`1 USD = 1_000_000`).
 */
export function usdToMicros(usd: number | string): number {
  const cleaned =
    typeof usd === 'string' ? usd.trim().replace(/^\$/, '') : String(usd);
  if (!/^\d+(\.\d+)?$/.test(cleaned)) {
    throw new RangeError(`Invalid non-negative USD amount: "${usd}"`);
  }
  const [wholePart = '0', fracPart = ''] = cleaned.split('.');
  if (fracPart.length > 6) {
    throw new RangeError(`USD precision exceeds 6 decimal microdollars: "${usd}"`);
  }
  const micros = Number(wholePart) * 1_000_000 + Number(fracPart.padEnd(6, '0'));
  if (!Number.isSafeInteger(micros) || micros < 0) {
    throw new RangeError(`USD amount out of safe integer bounds: "${usd}"`);
  }
  return micros;
}

/**
 * Format integer microdollars into a trimmed USD string (e.g. `5000` -> `"0.005"`).
 */
export function microsToUsdString(micros: number): string {
  if (!Number.isSafeInteger(micros) || micros < 0) {
    throw new RangeError(`Invalid microdollars value: ${micros}`);
  }
  const whole = Math.floor(micros / 1_000_000);
  const frac = String(micros % 1_000_000).padStart(6, '0').replace(/0+$/, '');
  return frac.length > 0 ? `${whole}.${frac}` : String(whole);
}

/**
 * Convert USD microdollars to 6-decimal USDC atomic units (1 microdollar === 1 USDC atomic unit).
 */
export function usdMicrosToUsdcAtomic(micros: number): string {
  if (!Number.isSafeInteger(micros) || micros < 0) {
    throw new RangeError(`Invalid microdollars value: ${micros}`);
  }
  return String(micros);
}

/**
 * Web-standard Base64 encode for UTF-8 JSON payloads without Node Buffer dependency.
 */
export function encodePaymentHeader(payload: unknown): string {
  const bytes = textEncoder.encode(JSON.stringify(payload));
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/**
 * Web-standard Base64 decode for x402 V2 JSON header payloads.
 */
export function decodePaymentHeader<T>(encoded: string): T {
  const trimmed = encoded.trim();
  const binary = atob(trimmed);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return JSON.parse(textDecoder.decode(bytes)) as T;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input: string): Uint8Array {
  if (!/^[A-Za-z0-9\-_]+$/.test(input)) {
    throw new Error('Invalid base64url characters');
  }
  const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * In-memory TTL-pruning NonceStore suitable for local smoke tests and single-isolate development.
 */
export class MemoryNonceStore implements NonceStore {
  private readonly used = new Map<string, number>();

  async consume(nonce: string, meta: NonceConsumeMeta): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, exp] of this.used.entries()) {
      if (exp <= now) {
        this.used.delete(key);
      }
    }
    const existingExp = this.used.get(nonce);
    if (existingExp !== undefined && existingExp > now) {
      return false;
    }
    const ttlExp = Math.max(meta.expiresAt, now + 60);
    this.used.set(nonce, ttlExp);
    return true;
  }

  async release(nonce: string): Promise<void> {
    this.used.delete(nonce);
  }
}

/**
 * Durable edge NonceStore backed by Cloudflare D1 `used_nonces`.
 */
export class D1NonceStore implements NonceStore {
  private readonly db: D1LikeDatabase;

  constructor(db: D1LikeDatabase) {
    this.db = db;
  }

  async consume(nonce: string, meta: NonceConsumeMeta): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    const rail = meta.rail ?? 'fiat_wallet';
    const result = await this.db
      .prepare(
        'INSERT OR IGNORE INTO used_nonces (nonce, rail, wallet_or_payer, route_pattern, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      )
      .bind(nonce, rail, meta.walletOrPayer, meta.route, meta.expiresAt, now)
      .run();
    return (result.meta?.changes ?? 0) === 1;
  }

  async release(nonce: string): Promise<void> {
    await this.db.prepare('DELETE FROM used_nonces WHERE nonce = ?').bind(nonce).run();
  }
}

/**
 * In-memory per-agent spend cap tracker.
 */
export class MemorySpendTracker implements SpendTracker {
  private readonly spendByAgent = new Map<string, number>();

  async checkAndRecord(
    agentId: string,
    amountMicros: number,
    capMicros: number,
  ): Promise<{ allowed: boolean; spentMicros: number }> {
    const current = this.spendByAgent.get(agentId) ?? 0;
    const next = current + amountMicros;
    if (next > capMicros) {
      return { allowed: false, spentMicros: current };
    }
    this.spendByAgent.set(agentId, next);
    return { allowed: true, spentMicros: next };
  }

  async rollback(agentId: string, amountMicros: number): Promise<void> {
    const current = this.spendByAgent.get(agentId) ?? 0;
    const next = Math.max(0, current - amountMicros);
    this.spendByAgent.set(agentId, next);
  }
}

function getHmacKey(secret: string, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  const cacheKey = `${usage}:${secret}`;
  let pending = hmacKeyCache.get(cacheKey);
  if (!pending) {
    pending = crypto.subtle.importKey(
      'raw',
      textEncoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      [usage],
    );
    hmacKeyCache.set(cacheKey, pending);
  }
  return pending;
}

function decodePublicKeyBytes(raw: string): Uint8Array {
  const trimmed = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  return base64UrlDecode(trimmed);
}

function getEd25519VerifyKey(keyOrEncoded: CryptoKey | string): Promise<CryptoKey> {
  if (typeof keyOrEncoded !== 'string') {
    return Promise.resolve(keyOrEncoded);
  }
  let pending = ed25519KeyCache.get(keyOrEncoded);
  if (!pending) {
    const rawBytes = decodePublicKeyBytes(keyOrEncoded);
    pending = crypto.subtle.importKey(
      'raw',
      rawBytes.buffer.slice(rawBytes.byteOffset, rawBytes.byteOffset + rawBytes.byteLength) as ArrayBuffer,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    ed25519KeyCache.set(keyOrEncoded, pending);
  }
  return pending;
}

/**
 * Sign a Red Center Fiat Agent Wallet receipt (`rcs_receipt_<alg>.<payload>.<sig>`).
 */
export async function signFiatReceipt(
  claims: RcsReceiptClaims,
  keyMaterial: ReceiptSigningKey,
): Promise<string> {
  if (!Number.isSafeInteger(claims.amt) || claims.amt < 0) {
    throw new RangeError('Receipt amt must be a non-negative safe integer in microdollars');
  }
  const payloadB64 = base64UrlEncode(textEncoder.encode(JSON.stringify(claims)));
  const signingInput = `${keyMaterial.alg}.${payloadB64}`;
  const data = textEncoder.encode(signingInput);

  let sigBuffer: ArrayBuffer;
  if (keyMaterial.alg === 'hs256') {
    const key = await getHmacKey(keyMaterial.secret, 'sign');
    sigBuffer = await crypto.subtle.sign('HMAC', key, data);
  } else {
    sigBuffer = await crypto.subtle.sign('Ed25519', keyMaterial.privateKey, data);
  }

  const sigB64 = base64UrlEncode(new Uint8Array(sigBuffer));
  return `rcs_receipt_${signingInput}.${sigB64}`;
}

/**
 * Zero-config helper for local `mode: "sandbox"` / `"mock"` testing without API keys or Stripe.
 */
export async function createSandboxReceipt(
  overrides?: Partial<RcsReceiptClaims> & { priceUsd?: number | string; secret?: string },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const amt =
    overrides?.amt ??
    (overrides?.priceUsd !== undefined
      ? usdToMicros(overrides.priceUsd)
      : usdToMicros(DEFAULT_PRICE_USD));
  const claims: RcsReceiptClaims = {
    v: 1,
    jti: overrides?.jti ?? `rcpt_sandbox_${crypto.randomUUID()}`,
    sub: overrides?.sub ?? 'wallet_sandbox_agent',
    aud: overrides?.aud ?? '*',
    mth: overrides?.mth ?? '*',
    amt,
    iat: overrides?.iat ?? now,
    exp: overrides?.exp ?? now + 120,
    ...(overrides?.tier ? { tier: overrides.tier } : {}),
  };
  return signFiatReceipt(claims, {
    alg: 'hs256',
    secret: overrides?.secret ?? SANDBOX_HMAC_SECRET,
  });
}

/**
 * Zero-config helper generating a Base64-encoded x402 V2 `PAYMENT-SIGNATURE` header for local sandbox runs.
 */
export function createSandboxX402Header(overrides?: {
  priceUsd?: number | string;
  amount?: string;
  payTo?: string;
  from?: string;
  nonce?: string;
  scheme?: PaymentScheme;
  network?: string;
}): string {
  const now = Math.floor(Date.now() / 1000);
  const amount =
    overrides?.amount ??
    usdMicrosToUsdcAtomic(
      overrides?.priceUsd !== undefined
        ? usdToMicros(overrides.priceUsd)
        : usdToMicros(DEFAULT_PRICE_USD),
    );
  const scheme = overrides?.scheme ?? 'exact';
  const network = overrides?.network ?? DEFAULT_NETWORK;
  const sig: X402PaymentSignature = {
    x402Version: 2,
    scheme,
    network,
    accepted: { scheme, network },
    payload: {
      signature: `0x${'ab'.repeat(65)}`,
      authorization: {
        from: overrides?.from ?? '0x1234567890abcdef1234567890abcdef12345678',
        to: overrides?.payTo ?? DEFAULT_PAY_TO,
        value: amount,
        validAfter: String(now - 5),
        validBefore: String(now + 120),
        nonce: overrides?.nonce ?? `0x${crypto.randomUUID().replace(/-/g, '')}`,
      },
    },
  };
  return encodePaymentHeader(sig);
}

function matchesAudience(claimAud: string, expectedAudience: string): boolean {
  if (claimAud === '*') {
    return true;
  }
  if (claimAud === expectedAudience) {
    return true;
  }
  let expectedBase = expectedAudience;
  try {
    const reqUrl = new URL(expectedAudience);
    expectedBase = `${reqUrl.origin}${reqUrl.pathname}`;
  } catch {
    // non-URL audience string
  }
  if (claimAud.endsWith('/*')) {
    const dirBase = claimAud.slice(0, -2);
    const prefix = claimAud.slice(0, -1);
    return expectedBase === dirBase || expectedBase.startsWith(prefix);
  }
  if (claimAud.endsWith('*')) {
    const prefix = claimAud.slice(0, -1);
    return expectedBase.startsWith(prefix) || expectedAudience.startsWith(prefix);
  }
  try {
    const claimUrl = new URL(claimAud);
    const reqUrl = new URL(expectedAudience);
    return claimUrl.origin === reqUrl.origin && claimUrl.pathname === reqUrl.pathname;
  } catch {
    return false;
  }
}

/**
 * Verify a Rail B `rcs_receipt_...` bearer token in <1ms using Web Crypto `crypto.subtle.verify`.
 */
export async function verifyFiatReceipt(
  token: string,
  options: FiatWalletVerifyOptions,
): Promise<FiatReceiptVerifyResult> {
  const start = performance.now();
  const trimmed = token.trim();
  if (!trimmed.startsWith('rcs_receipt_')) {
    return { valid: false, reason: 'invalid_receipt_prefix' };
  }

  const body = trimmed.slice('rcs_receipt_'.length);
  const parts = body.split('.');
  if (parts.length !== 3) {
    return { valid: false, reason: 'malformed_receipt_format' };
  }

  const [algPart, payloadB64, sigB64] = parts as [string, string, string];
  if (algPart !== 'hs256' && algPart !== 'ed25519') {
    return { valid: false, reason: 'unsupported_receipt_algorithm' };
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(sigB64);
  } catch {
    return { valid: false, reason: 'invalid_receipt_signature_encoding' };
  }

  const signedBytes = textEncoder.encode(`${algPart}.${payloadB64}`);
  const sigArrayBuffer = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength,
  ) as ArrayBuffer;

  let signatureValid = false;
  try {
    if (algPart === 'hs256') {
      if (!options.hmacSecret) {
        return { valid: false, reason: 'hmac_verifier_not_configured' };
      }
      const key = await getHmacKey(options.hmacSecret, 'verify');
      signatureValid = await crypto.subtle.verify('HMAC', key, sigArrayBuffer, signedBytes);
    } else {
      if (!options.ed25519PublicKey) {
        return { valid: false, reason: 'ed25519_verifier_not_configured' };
      }
      const key = await getEd25519VerifyKey(options.ed25519PublicKey);
      signatureValid = await crypto.subtle.verify('Ed25519', key, sigArrayBuffer, signedBytes);
    }
  } catch {
    return { valid: false, reason: 'signature_verification_error' };
  }

  if (!signatureValid) {
    return { valid: false, reason: 'invalid_receipt_signature' };
  }

  let claims: RcsReceiptClaims;
  try {
    claims = JSON.parse(textDecoder.decode(base64UrlDecode(payloadB64))) as RcsReceiptClaims;
  } catch {
    return { valid: false, reason: 'malformed_receipt_claims' };
  }

  if (
    claims.v !== 1 ||
    typeof claims.jti !== 'string' ||
    claims.jti.length === 0 ||
    typeof claims.sub !== 'string' ||
    claims.sub.length === 0 ||
    typeof claims.aud !== 'string' ||
    !Number.isSafeInteger(claims.amt) ||
    !Number.isFinite(claims.iat) ||
    !Number.isFinite(claims.exp)
  ) {
    return { valid: false, reason: 'invalid_receipt_claims_schema' };
  }

  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  if (claims.exp <= now - skew) {
    return { valid: false, reason: 'receipt_expired' };
  }
  if (claims.iat > now + skew) {
    return { valid: false, reason: 'receipt_not_yet_valid' };
  }
  if (!matchesAudience(claims.aud, options.expectedAudience)) {
    return { valid: false, reason: 'receipt_audience_mismatch' };
  }
  if (claims.mth && claims.mth !== '*' && claims.mth.toUpperCase() !== options.expectedMethod.toUpperCase()) {
    return { valid: false, reason: 'receipt_method_mismatch' };
  }
  if (claims.amt < options.requiredMicros) {
    return { valid: false, reason: 'receipt_amount_insufficient' };
  }

  const verifiedInMs = performance.now() - start;
  return {
    valid: true,
    claims,
    alg: algPart,
    verifiedInMs,
  };
}

function resolveErrorGuidance(
  errorReason: string,
  requiredMicros: number,
  expectedAudience: string,
): { code: TollboothErrorCode; fix_hint: string } {
  const priceStr = `$${microsToUsdString(requiredMicros)} USD (${requiredMicros} microdollars)`;
  switch (errorReason) {
    case 'MISSING_PAYMENT':
    case 'PAYMENT-SIGNATURE or rcs_receipt bearer header is required':
      return {
        code: 'MISSING_PAYMENT',
        fix_hint: `Attach an x402 V2 Base64 PAYMENT-SIGNATURE header or an Authorization: Bearer rcs_receipt_... token for ${priceStr}.`,
      };
    case 'INSUFFICIENT_FUNDS':
    case 'receipt_amount_insufficient':
    case 'insufficient_payment_amount':
      return {
        code: 'INSUFFICIENT_FUNDS',
        fix_hint: `Payment amount is below the required ${priceStr}. Top up your agent wallet or authorize at least ${requiredMicros} atomic units.`,
      };
    case 'RECEIPT_EXPIRED':
    case 'receipt_expired':
    case 'receipt_not_yet_valid':
    case 'authorization_expired_or_not_yet_valid':
    case 'invalid_authorization_timestamps':
      return {
        code: 'RECEIPT_EXPIRED',
        fix_hint:
          'Receipt or x402 authorization timestamp is outside the allowed +/-30s window. Issue a fresh receipt or re-sign with current timestamps.',
      };
    case 'NONCE_REPLAYED':
    case 'nonce_replayed':
    case 'nonce_already_used':
      return {
        code: 'NONCE_REPLAYED',
        fix_hint:
          'This payment nonce/jti was already redeemed. Generate a new unique nonce or request a fresh receipt before retrying.',
      };
    case 'agent_spend_cap_exceeded':
      return {
        code: 'SPEND_CAP_EXCEEDED',
        fix_hint:
          'Per-agent spend cap reached. Increase perAgentSpendCapMicros or daily_spend_cap_micros on the wallet before retrying.',
      };
    case 'pro_pass_required_for_upto':
      return {
        code: 'PRO_PASS_REQUIRED',
        fix_hint:
          'The metered upto scheme requires Tollbooth Pro Pass. Set proPass: true (or switch the route scheme to "exact").',
      };
    case 'facilitator_verify_http_error':
    case 'facilitator_settlement_failed':
    case 'facilitator_settlement_rejected':
    case 'facilitator_unreachable':
    case 'fiat_wallet_not_enabled':
    case 'hmac_verifier_not_configured':
    case 'ed25519_verifier_not_configured':
    case 'signature_verification_error':
      return {
        code: 'FACILITATOR_ERROR',
        fix_hint:
          'Verify facilitatorUrl and RECEIPT_SIGNING_SECRET / ed25519PublicKey configuration, or pass mode: "sandbox" for zero-config local testing.',
      };
    default:
      return {
        code: 'INVALID_SIGNATURE',
        fix_hint: `Signature or payload validation failed (${errorReason}). Verify payload formatting, signing key, network, payTo, and audience (${expectedAudience}).`,
      };
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Self-contained Red Center Studio Industrial HTML 402 Checkout Card rendered when
 * a browser sends `Accept: text/html` to a gated endpoint.
 */
export function renderDefault402HtmlPage(
  challenge: X402PaymentRequired,
  request: Request,
): string {
  const url = new URL(request.url);
  const accept = challenge.accepts[0];
  const amountAtomic = accept?.amount ?? String(challenge.priceMicros);
  const payTo = accept?.payTo ?? DEFAULT_PAY_TO;
  const network = accept?.network ?? DEFAULT_NETWORK;
  const scheme = accept?.scheme ?? 'exact';
  const railsText = challenge.acceptedRails.includes('rcs-fiat-wallet')
    ? 'x402 V2 (USDC) + Red Center Fiat Wallet'
    : 'x402 V2 (USDC)';

  const safeCurl = `curl -H "PAYMENT-SIGNATURE: <base64_x402_v2>" "${request.url}"\ncurl -H "Authorization: Bearer rcs_receipt_..." "${request.url}"\n# payTo: ${payTo}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>402 Payment Required — Agent Tollbooth 402</title>
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
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }
    .card {
      width: 100%;
      max-width: 580px;
      background: var(--surface);
      border: 1px solid #374151;
      border-top: 3px solid var(--amber);
      border-radius: 10px;
      padding: 26px;
      box-shadow: 0 14px 34px rgba(0, 0, 0, 0.38);
    }
    .badges { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
    .badge {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 4px 10px;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .badge-amber { background: rgba(217, 119, 6, 0.16); color: #FBBF24; border: 1px solid var(--amber); }
    .badge-emerald { background: rgba(16, 185, 129, 0.12); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.55); }
    .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--emerald); display: inline-block; }
    h1 { margin: 0 0 6px; font-size: 20px; font-weight: 700; letter-spacing: -0.01em; color: var(--text); }
    p { margin: 0 0 18px; color: var(--muted); font-size: 14px; line-height: 1.5; }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-bottom: 16px;
      background: #1F2937;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 14px;
    }
    .label { font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.06em; }
    .val {
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      overflow-wrap: anywhere;
      margin-top: 3px;
      font-variant-numeric: tabular-nums;
    }
    .price { font-size: 20px; color: #FBBF24; font-variant-numeric: tabular-nums; }
    .hint {
      background: rgba(217, 119, 6, 0.09);
      border-left: 3px solid var(--amber);
      padding: 11px 14px;
      border-radius: 6px;
      font-size: 13px;
      line-height: 1.45;
      color: var(--text);
      margin-bottom: 16px;
      overflow-wrap: anywhere;
    }
    .code-wrap { position: relative; margin-bottom: 18px; }
    .code {
      background: #0B111B;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 12px 72px 12px 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      line-height: 1.5;
      color: #E5E7EB;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 0;
    }
    .copy-btn {
      position: absolute;
      top: 8px;
      right: 8px;
      background: #1F2937;
      color: var(--text);
      border: 1px solid #4B5563;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      padding: 5px 10px;
      cursor: pointer;
    }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: var(--amber);
      color: #111827;
      font-weight: 700;
      font-size: 14px;
      text-decoration: none;
      padding: 11px 18px;
      border-radius: 8px;
      min-height: 44px;
    }
    .brand { margin-left: auto; font-size: 12px; color: var(--muted); }
    @media (max-width: 640px) {
      body { padding: 14px; align-items: flex-start; }
      .card { padding: 20px 16px; }
      .grid { grid-template-columns: 1fr; gap: 12px; }
      .actions { flex-direction: column; align-items: stretch; }
      .btn { width: 100%; min-height: 48px; }
      .brand { margin-left: 0; text-align: center; }
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="badges">
      <span class="badge badge-amber">402 ${escapeHtml(challenge.code)}</span>
      <span class="badge badge-emerald"><span class="dot"></span>x402 V2 &middot; Fiat Wallet Ready</span>
    </div>
    <h1>Payment Required</h1>
    <p>${escapeHtml(challenge.resource.description)}</p>
    <div class="grid">
      <div>
        <div class="label">Endpoint</div>
        <div class="val">${escapeHtml(request.method.toUpperCase())} ${escapeHtml(url.pathname)}</div>
      </div>
      <div>
        <div class="label">Price (${escapeHtml(scheme)})</div>
        <div class="val price">$${escapeHtml(challenge.priceUsd)} USD</div>
      </div>
      <div>
        <div class="label">Accepted Rails</div>
        <div class="val">${escapeHtml(railsText)}</div>
      </div>
      <div>
        <div class="label">x402 Settlement</div>
        <div class="val">${escapeHtml(network)} &middot; ${escapeHtml(amountAtomic)} USDC</div>
      </div>
    </div>
    <div class="hint"><strong>Next step:</strong> ${escapeHtml(challenge.fix_hint)}</div>
    <div class="code-wrap">
      <pre class="code" id="curl-cmd">${escapeHtml(safeCurl)}</pre>
      <button class="copy-btn" type="button" onclick="var b=this;navigator.clipboard&&navigator.clipboard.writeText(document.getElementById('curl-cmd').textContent).then(function(){b.textContent='COPIED';b.style.borderColor='#10B981';b.style.color='#10B981';setTimeout(function(){b.textContent='Copy';b.style.borderColor='#4B5563';b.style.color='#F9FAFB';},1500);})">Copy</button>
    </div>
    <div class="actions">
      <a class="btn" href="${escapeHtml(challenge.paymentUrl)}" rel="noopener noreferrer">Fund Agent Wallet</a>
      <span class="brand">Red Center Studio &middot; tollbooth.redcenterstudio.com</span>
    </div>
  </main>
</body>
</html>`;
}

function matchPathPattern(pattern: string, pathname: string): boolean {
  if (pattern === '*' || pattern === '/*') {
    return true;
  }
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1);
    return pathname === pattern.slice(0, -2) || pathname.startsWith(prefix);
  }
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = pathname.split('/').filter(Boolean);
  if (patternParts.length !== pathParts.length) {
    return false;
  }
  for (let i = 0; i < patternParts.length; i++) {
    const seg = patternParts[i]!;
    if (seg === '*') {
      continue;
    }
    if (seg.startsWith(':')) {
      if (!pathParts[i]) {
        return false;
      }
      continue;
    }
    if (seg !== pathParts[i]) {
      return false;
    }
  }
  return true;
}

function isMethodMatch(routeMethod: string | string[] | undefined, reqMethod: string): boolean {
  if (!routeMethod) {
    return true;
  }
  const upper = reqMethod.toUpperCase();
  if (Array.isArray(routeMethod)) {
    return routeMethod.some((m) => m.toUpperCase() === upper || m === '*');
  }
  return routeMethod === '*' || routeMethod.toUpperCase() === upper;
}

function extractFiatReceiptToken(request: Request): string | null {
  const custom = request.headers.get('X-Agent-Receipt');
  if (custom) {
    const trimmed = custom.trim();
    if (trimmed.startsWith('rcs_receipt_')) {
      return trimmed;
    }
    const customBearer = /^Bearer\s+(rcs_receipt_\S+)$/i.exec(trimmed);
    if (customBearer?.[1]) {
      return customBearer[1];
    }
  }
  const auth = request.headers.get('Authorization');
  if (auth) {
    const match = /^Bearer\s+(rcs_receipt_\S+)$/i.exec(auth.trim());
    if (match?.[1]) {
      return match[1];
    }
  }
  return null;
}

interface NormalizedRoute extends TollboothRouteConfig {
  resolvedPriceMicros: number;
}

interface NormalizedConfig extends TollboothConfig {
  payTo: string;
  mode: TollboothMode;
  clockSkewSeconds: number;
  normalizedRoutes: NormalizedRoute[];
  fetchImpl?: typeof fetch;
}

function createSandboxFacilitatorFetch(): typeof fetch {
  return async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString();
    const rawBody = init?.body ? String(init.body) : '{}';
    const body = JSON.parse(rawBody) as {
      paymentPayload?: X402PaymentSignature;
      paymentRequirements?: { amount?: string; network?: string };
      settleAmount?: string;
    };
    if (url.endsWith('/verify')) {
      const ok =
        body.paymentPayload?.x402Version === 2 &&
        Boolean(body.paymentPayload?.payload?.signature) &&
        Boolean(body.paymentPayload?.payload?.authorization?.nonce);
      return Response.json({
        isValid: ok,
        invalidReason: ok ? null : 'invalid_sandbox_payload',
      });
    }
    if (url.endsWith('/settle')) {
      const nonce = body.paymentPayload?.payload?.authorization?.nonce ?? 'sandbox';
      return Response.json({
        success: true,
        txHash: `0xsandbox_${nonce.replace(/^0x/, '').slice(0, 32)}`,
        network: body.paymentRequirements?.network ?? DEFAULT_NETWORK,
        settledAmount: body.settleAmount ?? body.paymentRequirements?.amount ?? '10000',
        errorReason: null,
      });
    }
    return Response.json({ error: 'unsupported_sandbox_route' }, { status: 404 });
  };
}

function normalizeConfig(config: TollboothConfig): NormalizedConfig {
  const mode: TollboothMode = config.mode ?? 'hybrid';
  const defaultMicros =
    config.priceMicros ??
    (config.priceUsd !== undefined ? usdToMicros(config.priceUsd) : usdToMicros(DEFAULT_PRICE_USD));
  const payTo = config.payTo ?? DEFAULT_PAY_TO;
  const isSandbox = mode === 'sandbox' || mode === 'mock';

  const fiatWallet: FiatWalletConfig | undefined = isSandbox
    ? {
        clearinghouseUrl:
          config.fiatWallet?.clearinghouseUrl ??
          config.facilitatorUrl ??
          `${DEFAULT_FACILITATOR_URL}/sandbox`,
        clockSkewSeconds:
          config.fiatWallet?.clockSkewSeconds ??
          config.clockSkewSeconds ??
          DEFAULT_CLOCK_SKEW_SECONDS,
        ...config.fiatWallet,
        hmacSecret: config.fiatWallet?.hmacSecret ?? SANDBOX_HMAC_SECRET,
      }
    : config.fiatWallet;

  const rawRoutes =
    config.routes && config.routes.length > 0
      ? config.routes
      : [{ pattern: '/*', scheme: 'exact' as PaymentScheme, priceMicros: defaultMicros }];

  const normalizedRoutes: NormalizedRoute[] = rawRoutes.map((r) => ({
    ...r,
    resolvedPriceMicros:
      r.priceMicros ??
      (r.priceUsd !== undefined ? usdToMicros(r.priceUsd) : defaultMicros),
  }));

  return {
    ...config,
    payTo,
    mode,
    clockSkewSeconds: config.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS,
    fiatWallet,
    fetchImpl: config.fetchImpl ?? (isSandbox ? createSandboxFacilitatorFetch() : undefined),
    normalizedRoutes,
  };
}

function buildPaymentRequiredChallenge(
  request: Request,
  config: NormalizedConfig,
  route: NormalizedRoute,
  errorReason: string,
): X402PaymentRequired {
  const scheme: PaymentScheme = route.scheme ?? 'exact';
  const network = route.network ?? config.network ?? DEFAULT_NETWORK;
  const asset = route.asset ?? config.asset ?? DEFAULT_USDC_BASE_ASSET;
  const payTo = route.payTo ?? config.payTo;
  const maxTimeoutSeconds = route.maxTimeoutSeconds ?? 60;
  const priceMicros = route.resolvedPriceMicros;
  const amount = usdMicrosToUsdcAtomic(priceMicros);
  const paymentUrl = config.paymentUrl ?? DEFAULT_PAYMENT_URL;

  const guidance = resolveErrorGuidance(errorReason, priceMicros, request.url);
  const acceptedRails: Array<'x402-v2' | 'rcs-fiat-wallet'> = config.fiatWallet
    ? ['x402-v2', 'rcs-fiat-wallet']
    : ['x402-v2'];

  const extensions: Record<string, unknown> = {};
  if (config.fiatWallet) {
    extensions.fiatAgentWallet = {
      clearinghouseUrl:
        config.fiatWallet.clearinghouseUrl ?? config.facilitatorUrl ?? DEFAULT_FACILITATOR_URL,
      headers: ['Authorization: Bearer rcs_receipt_...', 'X-Agent-Receipt'],
      priceMicros,
      currency: 'USD_MICROS',
    };
  }

  return {
    x402Version: 2,
    code: guidance.code,
    error: errorReason,
    fix_hint: guidance.fix_hint,
    priceUsd: microsToUsdString(priceMicros),
    priceMicros,
    acceptedRails,
    paymentUrl,
    resource: {
      url: request.url,
      description:
        route.description ?? `Paid API resource (${request.method} ${new URL(request.url).pathname})`,
      mimeType: route.mimeType ?? 'application/json',
    },
    accepts: [
      {
        scheme,
        network,
        amount,
        asset,
        payTo,
        maxTimeoutSeconds,
        extra: {
          name: 'USDC',
          version: '2',
        },
      },
    ],
    extensions,
  };
}

function create402Response(
  request: Request,
  config: NormalizedConfig,
  challenge: X402PaymentRequired,
): Response {
  const encodedRequired = encodePaymentHeader(challenge);
  const headers = new Headers({
    'PAYMENT-REQUIRED': encodedRequired,
    'WWW-Authenticate': `x402, Bearer realm="agent-tollbooth-402", error="${challenge.code}"`,
    'Access-Control-Expose-Headers': CORS_EXPOSE_HEADERS,
    'Cache-Control': 'no-store',
  });

  const acceptHeader = request.headers.get('Accept') ?? '';
  if (acceptHeader.includes('text/html')) {
    const html =
      config.proPass && config.customPaymentPageHtml
        ? typeof config.customPaymentPageHtml === 'function'
          ? config.customPaymentPageHtml(challenge, request)
          : config.customPaymentPageHtml
        : renderDefault402HtmlPage(challenge, request);
    headers.set('Content-Type', 'text/html; charset=utf-8');
    return new Response(html, { status: 402, headers });
  }

  headers.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(challenge), { status: 402, headers });
}

function attachCorsExposeHeaders(response: Response, includePreflight = false): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Expose-Headers', CORS_EXPOSE_HEADERS);
  if (includePreflight) {
    if (!headers.has('Access-Control-Allow-Headers')) {
      headers.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
    }
    if (!headers.has('Access-Control-Allow-Methods')) {
      headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    }
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function cloneWithPaymentResponse(
  response: Response,
  paymentResponse: X402PaymentResponse,
  rail: TollboothRail,
): Response {
  const headers = new Headers(response.headers);
  headers.set('PAYMENT-RESPONSE', encodePaymentHeader(paymentResponse));
  headers.set('X-Tollbooth-Rail', rail);
  headers.set('Access-Control-Expose-Headers', CORS_EXPOSE_HEADERS);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function parseBigIntAmount(value: string): bigint | null {
  if (!/^\d+$/.test(value)) {
    return null;
  }
  return BigInt(value);
}

interface TollboothEvaluatorResult {
  isPreflight?: boolean;
  earlyResponse?: Response;
  finalizeResponse?: (downstreamResponse: Response) => Promise<Response>;
}

async function evaluateTollboothRequest(
  request: Request,
  rawConfig: TollboothConfig,
  defaultNonceStore: NonceStore,
  defaultSpendTracker: SpendTracker,
): Promise<TollboothEvaluatorResult> {
  if (request.method.toUpperCase() === 'OPTIONS') {
    return { isPreflight: true };
  }

  const config = normalizeConfig(rawConfig);
  const url = new URL(request.url);
  const exemptPaths = config.exemptPaths ?? [...DEFAULT_EXEMPT_PATHS];
  if (exemptPaths.some((pat) => matchPathPattern(pat, url.pathname))) {
    return {};
  }

  const route = config.normalizedRoutes.find(
    (r) => matchPathPattern(r.pattern, url.pathname) && isMethodMatch(r.method, request.method),
  );
  if (!route) {
    return {};
  }

  const scheme: PaymentScheme = route.scheme ?? 'exact';
  const proPassEnabled = route.proPass ?? config.proPass ?? false;

  if (scheme === 'upto' && !proPassEnabled) {
    const challenge = buildPaymentRequiredChallenge(
      request,
      config,
      route,
      'pro_pass_required_for_upto',
    );
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const nonceStore = config.nonceStore ?? defaultNonceStore;
  const spendTracker = config.spendTracker ?? defaultSpendTracker;
  const nowSec = config.nowSeconds ? config.nowSeconds() : Math.floor(Date.now() / 1000);
  const requiredMicros = route.resolvedPriceMicros;

  // Rail B: Red Center Fiat Agent Wallet (<1ms Web Crypto verification)
  const receiptToken = extractFiatReceiptToken(request);
  if (receiptToken) {
    if (!config.fiatWallet) {
      const challenge = buildPaymentRequiredChallenge(request, config, route, 'fiat_wallet_not_enabled');
      return { earlyResponse: create402Response(request, config, challenge) };
    }

    const verifyResult = await verifyFiatReceipt(receiptToken, {
      ...config.fiatWallet,
      clockSkewSeconds: config.fiatWallet.clockSkewSeconds ?? config.clockSkewSeconds,
      expectedAudience: request.url,
      expectedMethod: request.method,
      requiredMicros,
      nowSeconds: nowSec,
    });

    if (!verifyResult.valid || !verifyResult.claims) {
      const challenge = buildPaymentRequiredChallenge(
        request,
        config,
        route,
        verifyResult.reason ?? 'invalid_receipt_signature',
      );
      return { earlyResponse: create402Response(request, config, challenge) };
    }

    const claims = verifyResult.claims;
    const consumed = await nonceStore.consume(claims.jti, {
      walletOrPayer: claims.sub,
      route: route.pattern,
      expiresAt: claims.exp,
      rail: 'fiat_wallet',
    });
    if (!consumed) {
      const challenge = buildPaymentRequiredChallenge(request, config, route, 'nonce_replayed');
      return { earlyResponse: create402Response(request, config, challenge) };
    }

    let spendRecorded = false;
    if (config.perAgentSpendCapMicros !== undefined) {
      const capCheck = await spendTracker.checkAndRecord(
        claims.sub,
        requiredMicros,
        config.perAgentSpendCapMicros,
      );
      if (!capCheck.allowed) {
        if (nonceStore.release) {
          await nonceStore.release(claims.jti);
        }
        const challenge = buildPaymentRequiredChallenge(
          request,
          config,
          route,
          'agent_spend_cap_exceeded',
        );
        return { earlyResponse: create402Response(request, config, challenge) };
      }
      spendRecorded = true;
    }

    return {
      finalizeResponse: async (downstreamResponse: Response) => {
        if (downstreamResponse.status >= 500) {
          if (nonceStore.release) {
            await nonceStore.release(claims.jti);
          }
          if (spendRecorded && spendTracker.rollback) {
            await spendTracker.rollback(claims.sub, requiredMicros);
          }
          return downstreamResponse;
        }
        return cloneWithPaymentResponse(
          downstreamResponse,
          {
            success: true,
            transaction: claims.jti,
            network: 'rcs:fiat-wallet',
            payer: claims.sub,
            settledAmount: String(requiredMicros),
            rail: 'fiat_wallet',
            errorReason: null,
          },
          'fiat_wallet',
        );
      },
    };
  }

  // Rail A: Open x402 V2 Standard
  const paymentSigHeader = request.headers.get('PAYMENT-SIGNATURE');
  if (!paymentSigHeader) {
    const challenge = buildPaymentRequiredChallenge(
      request,
      config,
      route,
      'PAYMENT-SIGNATURE or rcs_receipt bearer header is required',
    );
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  let parsedSig: X402PaymentSignature;
  try {
    parsedSig = decodePaymentHeader<X402PaymentSignature>(paymentSigHeader);
  } catch {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'malformed_payment_signature');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const sigScheme = parsedSig.accepted?.scheme ?? parsedSig.scheme;
  const sigNetwork = parsedSig.accepted?.network ?? parsedSig.network;
  const expectedNetwork = route.network ?? config.network ?? DEFAULT_NETWORK;
  const expectedAsset = route.asset ?? config.asset ?? DEFAULT_USDC_BASE_ASSET;
  const expectedPayTo = route.payTo ?? config.payTo;
  const requiredAtomicStr = usdMicrosToUsdcAtomic(requiredMicros);
  const requiredAtomic = BigInt(requiredAtomicStr);

  if (parsedSig.x402Version !== 2 || !parsedSig.payload?.authorization || !parsedSig.payload?.signature) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'invalid_x402_payload');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  if (sigScheme !== scheme) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'scheme_mismatch');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  if (sigNetwork !== expectedNetwork) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'network_mismatch');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const auth = parsedSig.payload.authorization;
  if (
    typeof auth.from !== 'string' ||
    auth.from.length === 0 ||
    typeof auth.to !== 'string' ||
    typeof auth.nonce !== 'string' ||
    auth.nonce.length === 0
  ) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'invalid_x402_authorization_fields');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  if (auth.to.toLowerCase() !== expectedPayTo.toLowerCase()) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'recipient_mismatch');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  if (!/^\d+$/.test(String(auth.validAfter)) || !/^\d+$/.test(String(auth.validBefore))) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'invalid_authorization_timestamps');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const validAfter = Number(auth.validAfter);
  const validBefore = Number(auth.validBefore);
  const skew = config.clockSkewSeconds;
  if (
    !Number.isSafeInteger(validAfter) ||
    !Number.isSafeInteger(validBefore) ||
    nowSec < validAfter - skew ||
    nowSec > validBefore + skew
  ) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'authorization_expired_or_not_yet_valid');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const authorizedAtomic = parseBigIntAmount(auth.value);
  if (authorizedAtomic === null || authorizedAtomic < requiredAtomic) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'insufficient_payment_amount');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const facilitatorBase = (config.facilitatorUrl ?? DEFAULT_FACILITATOR_URL).replace(/\/+$/, '');
  const fetchFn = config.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const paymentRequirements = {
    scheme,
    network: expectedNetwork,
    amount: requiredAtomicStr,
    asset: expectedAsset,
    payTo: expectedPayTo,
    resource: request.url,
    maxTimeoutSeconds: route.maxTimeoutSeconds ?? 60,
  };

  let verifyResp: Response;
  try {
    verifyResp = await fetchFn(`${facilitatorBase}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        x402Version: 2,
        paymentPayload: parsedSig,
        paymentRequirements,
      }),
    });
  } catch {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_unreachable');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  if (!verifyResp.ok) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_verify_http_error');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  let verifyJson: X402VerifyResponse;
  try {
    verifyJson = (await verifyResp.json()) as X402VerifyResponse;
  } catch {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_verify_http_error');
    return { earlyResponse: create402Response(request, config, challenge) };
  }
  if (!verifyJson.isValid) {
    const challenge = buildPaymentRequiredChallenge(
      request,
      config,
      route,
      verifyJson.invalidReason ?? 'facilitator_verification_rejected',
    );
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const consumed = await nonceStore.consume(auth.nonce, {
    walletOrPayer: auth.from,
    route: route.pattern,
    expiresAt: Math.floor(validBefore),
    rail: 'x402',
  });
  if (!consumed) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'nonce_replayed');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  let spendRecorded = false;
  if (config.perAgentSpendCapMicros !== undefined) {
    const capCheck = await spendTracker.checkAndRecord(
      auth.from,
      requiredMicros,
      config.perAgentSpendCapMicros,
    );
    if (!capCheck.allowed) {
      if (nonceStore.release) {
        await nonceStore.release(auth.nonce);
      }
      const challenge = buildPaymentRequiredChallenge(request, config, route, 'agent_spend_cap_exceeded');
      return { earlyResponse: create402Response(request, config, challenge) };
    }
    spendRecorded = true;
  }

  return {
    finalizeResponse: async (downstreamResponse: Response) => {
      if (downstreamResponse.status >= 500) {
        if (nonceStore.release) {
          await nonceStore.release(auth.nonce);
        }
        if (spendRecorded && spendTracker.rollback) {
          await spendTracker.rollback(auth.from, requiredMicros);
        }
        return downstreamResponse;
      }

      let settleAtomic = requiredAtomic;
      if (scheme === 'upto') {
        if (route.meterUsage) {
          const minAtomic = BigInt(route.minPriceMicros ?? 0);
          const metered = await route.meterUsage(request, downstreamResponse, minAtomic, authorizedAtomic);
          if (metered < 0n) {
            settleAtomic = 0n;
          } else if (metered > authorizedAtomic) {
            settleAtomic = authorizedAtomic;
          } else {
            settleAtomic = metered;
          }
        } else {
          settleAtomic = authorizedAtomic;
        }
      }

      let settleResp: Response;
      try {
        settleResp = await fetchFn(`${facilitatorBase}/settle`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': `x402_${auth.nonce}`,
          },
          body: JSON.stringify({
            x402Version: 2,
            paymentPayload: parsedSig,
            paymentRequirements,
            settleAmount: settleAtomic.toString(),
          }),
        });
      } catch {
        if (nonceStore.release) {
          await nonceStore.release(auth.nonce);
        }
        if (spendRecorded && spendTracker.rollback) {
          await spendTracker.rollback(auth.from, requiredMicros);
        }
        const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_unreachable');
        return create402Response(request, config, challenge);
      }

      if (!settleResp.ok) {
        if (nonceStore.release) {
          await nonceStore.release(auth.nonce);
        }
        if (spendRecorded && spendTracker.rollback) {
          await spendTracker.rollback(auth.from, requiredMicros);
        }
        const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_settlement_failed');
        return create402Response(request, config, challenge);
      }

      let settleJson: X402SettleResponse;
      try {
        settleJson = (await settleResp.json()) as X402SettleResponse;
      } catch {
        if (nonceStore.release) {
          await nonceStore.release(auth.nonce);
        }
        if (spendRecorded && spendTracker.rollback) {
          await spendTracker.rollback(auth.from, requiredMicros);
        }
        const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_settlement_failed');
        return create402Response(request, config, challenge);
      }

      if (!settleJson.success) {
        if (nonceStore.release) {
          await nonceStore.release(auth.nonce);
        }
        if (spendRecorded && spendTracker.rollback) {
          await spendTracker.rollback(auth.from, requiredMicros);
        }
        const challenge = buildPaymentRequiredChallenge(
          request,
          config,
          route,
          settleJson.errorReason ?? 'facilitator_settlement_rejected',
        );
        return create402Response(request, config, challenge);
      }

      return cloneWithPaymentResponse(
        downstreamResponse,
        {
          success: true,
          transaction: settleJson.txHash,
          network: settleJson.network ?? expectedNetwork,
          payer: auth.from,
          settledAmount: settleJson.settledAmount ?? settleAtomic.toString(),
          rail: 'x402',
          errorReason: null,
        },
        'x402',
      );
    },
  };
}

/**
 * Wrap a Cloudflare Worker `ExportedHandler` or bare Fetch handler `(request, env, ctx) => Response`
 * with dual-rail HTTP 402 protection.
 */
export function withTollbooth<Env = unknown>(
  configOrFactory: TollboothConfig | ((env: Env) => TollboothConfig),
  handlerOrFn: WorkerHandler<Env> | WorkerFetchFn<Env>,
): WorkerHandler<Env> {
  const defaultNonceStore = new MemoryNonceStore();
  const defaultSpendTracker = new MemorySpendTracker();

  const invokeHandler = async (
    request: Request,
    env?: Env,
    ctx?: ExecutionContext,
  ): Promise<Response> => {
    if (typeof handlerOrFn === 'function') {
      return handlerOrFn(request, env, ctx);
    }
    return handlerOrFn.fetch(request, env, ctx);
  };

  return {
    async fetch(request: Request, env?: Env, ctx?: ExecutionContext): Promise<Response> {
      const config =
        typeof configOrFactory === 'function'
          ? configOrFactory(env as Env)
          : configOrFactory;
      const evaluation = await evaluateTollboothRequest(
        request,
        config,
        defaultNonceStore,
        defaultSpendTracker,
      );

      if (evaluation.earlyResponse) {
        return evaluation.earlyResponse;
      }

      const downstream = await invokeHandler(request, env, ctx);
      if (evaluation.isPreflight) {
        if (downstream.status === 404 || downstream.status === 405) {
          const preflight = new Response(null, { status: 204, headers: downstream.headers });
          return attachCorsExposeHeaders(preflight, true);
        }
        return attachCorsExposeHeaders(downstream, true);
      }
      if (evaluation.finalizeResponse) {
        return evaluation.finalizeResponse(downstream);
      }
      return attachCorsExposeHeaders(downstream, false);
    },
  };
}

/**
 * Hono-compatible middleware factory enforcing dual-rail HTTP 402 payment requirements.
 */
export function honoTollbooth(config: TollboothConfig): HonoLikeMiddleware {
  const defaultNonceStore = new MemoryNonceStore();
  const defaultSpendTracker = new MemorySpendTracker();

  return async (c: HonoLikeContext, next: HonoLikeNext): Promise<Response | void> => {
    const evaluation = await evaluateTollboothRequest(
      c.req.raw,
      config,
      defaultNonceStore,
      defaultSpendTracker,
    );

    if (evaluation.earlyResponse) {
      c.res = evaluation.earlyResponse;
      return evaluation.earlyResponse;
    }

    await next();
    if (c.res && evaluation.isPreflight) {
      c.res = attachCorsExposeHeaders(c.res, true);
    } else if (c.res && evaluation.finalizeResponse) {
      c.res = await evaluation.finalizeResponse(c.res);
    } else if (c.res) {
      c.res = attachCorsExposeHeaders(c.res, false);
    }
    return c.res;
  };
}
