/**
 * @redcenterstudio/agent-tollbooth-edge
 * Zero-dependency dual-rail HTTP 402 middleware for Cloudflare Workers, Fetch APIs, and Hono.
 *
 * Rail A: Open x402 V2 standard (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`)
 * Rail B: Red Center Fiat Agent Wallet (`rcs_receipt_...` verified <1ms via Web Crypto + NonceStore)
 */

export type PaymentScheme = 'exact' | 'upto';
export type TollboothRail = 'x402' | 'fiat_wallet';
export type FiatReceiptAlg = 'hs256' | 'ed25519';

export const DEFAULT_FACILITATOR_URL = 'https://tollbooth.redcenterstudio.com';
export const DEFAULT_NETWORK = 'eip155:8453';
export const DEFAULT_USDC_BASE_ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const DEFAULT_EXEMPT_PATHS = ['/health', '/readyz', '/webhook/*'] as const;

const CORS_EXPOSE_HEADERS = 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Tollbooth-Rail';

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
  error: string;
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
  priceMicros: number;
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
  payTo: string;
  facilitatorUrl?: string;
  network?: string;
  asset?: string;
  proPass?: boolean;
  customPaymentPageHtml?:
    | string
    | ((challenge: X402PaymentRequired, request: Request) => string);
  perAgentSpendCapMicros?: number;
  spendTracker?: SpendTracker;
  exemptPaths?: string[];
  nonceStore?: NonceStore;
  fiatWallet?: FiatWalletConfig;
  routes: TollboothRouteConfig[];
  fetchImpl?: typeof fetch;
  nowSeconds?: () => number;
}

export interface WorkerHandler<Env = unknown> {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response>;
}

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
 * Format integer microdollars into a fixed 6-decimal USD string (or trimmed USD string).
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

function matchesAudience(claimAud: string, expectedAudience: string): boolean {
  if (claimAud === '*') {
    return true;
  }
  if (claimAud === expectedAudience) {
    return true;
  }
  if (claimAud.endsWith('/*')) {
    const prefix = claimAud.slice(0, -1);
    return expectedAudience.startsWith(prefix);
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
  const skew = options.clockSkewSeconds ?? 5;

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
  if (custom && custom.trim().startsWith('rcs_receipt_')) {
    return custom.trim();
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

function buildPaymentRequiredChallenge(
  request: Request,
  config: TollboothConfig,
  route: TollboothRouteConfig,
  errorReason: string,
): X402PaymentRequired {
  const scheme: PaymentScheme = route.scheme ?? 'exact';
  const network = route.network ?? config.network ?? DEFAULT_NETWORK;
  const asset = route.asset ?? config.asset ?? DEFAULT_USDC_BASE_ASSET;
  const payTo = route.payTo ?? config.payTo;
  const maxTimeoutSeconds = route.maxTimeoutSeconds ?? 60;
  const amount = usdMicrosToUsdcAtomic(route.priceMicros);

  const extensions: Record<string, unknown> = {};
  if (config.fiatWallet) {
    extensions.fiatAgentWallet = {
      clearinghouseUrl: config.fiatWallet.clearinghouseUrl ?? config.facilitatorUrl ?? DEFAULT_FACILITATOR_URL,
      headers: ['Authorization: Bearer rcs_receipt_...', 'X-Agent-Receipt'],
      priceMicros: route.priceMicros,
      currency: 'USD_MICROS',
    };
  }

  return {
    x402Version: 2,
    error: errorReason,
    resource: {
      url: request.url,
      description: route.description ?? `Paid API resource (${request.method} ${new URL(request.url).pathname})`,
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
  config: TollboothConfig,
  challenge: X402PaymentRequired,
): Response {
  const encodedRequired = encodePaymentHeader(challenge);
  const headers = new Headers({
    'PAYMENT-REQUIRED': encodedRequired,
    'Access-Control-Expose-Headers': CORS_EXPOSE_HEADERS,
  });

  const acceptHeader = request.headers.get('Accept') ?? '';
  const proEnabled = Boolean(config.proPass);
  if (proEnabled && config.customPaymentPageHtml && acceptHeader.includes('text/html')) {
    const html =
      typeof config.customPaymentPageHtml === 'function'
        ? config.customPaymentPageHtml(challenge, request)
        : config.customPaymentPageHtml;
    headers.set('Content-Type', 'text/html; charset=utf-8');
    return new Response(html, { status: 402, headers });
  }

  headers.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(challenge), { status: 402, headers });
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
  earlyResponse?: Response;
  finalizeResponse?: (downstreamResponse: Response) => Promise<Response>;
}

async function evaluateTollboothRequest(
  request: Request,
  config: TollboothConfig,
  defaultNonceStore: NonceStore,
  defaultSpendTracker: SpendTracker,
): Promise<TollboothEvaluatorResult> {
  if (request.method.toUpperCase() === 'OPTIONS') {
    return {};
  }

  const url = new URL(request.url);
  const exemptPaths = config.exemptPaths ?? [...DEFAULT_EXEMPT_PATHS];
  if (exemptPaths.some((pat) => matchPathPattern(pat, url.pathname))) {
    return {};
  }

  const route = config.routes.find(
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

  // Rail B: Red Center Fiat Agent Wallet (<1ms Web Crypto verification)
  const receiptToken = extractFiatReceiptToken(request);
  if (receiptToken) {
    if (!config.fiatWallet) {
      const challenge = buildPaymentRequiredChallenge(request, config, route, 'fiat_wallet_not_enabled');
      return { earlyResponse: create402Response(request, config, challenge) };
    }

    const verifyResult = await verifyFiatReceipt(receiptToken, {
      ...config.fiatWallet,
      expectedAudience: request.url,
      expectedMethod: request.method,
      requiredMicros: route.priceMicros,
      nowSeconds: nowSec,
    });

    if (!verifyResult.valid || !verifyResult.claims) {
      const challenge = buildPaymentRequiredChallenge(
        request,
        config,
        route,
        verifyResult.reason ?? 'invalid_fiat_receipt',
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
        route.priceMicros,
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
            await spendTracker.rollback(claims.sub, route.priceMicros);
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
            settledAmount: String(route.priceMicros),
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
  const requiredAtomicStr = usdMicrosToUsdcAtomic(route.priceMicros);
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
  if (!Number.isSafeInteger(validAfter) || !Number.isSafeInteger(validBefore) || nowSec < validAfter || nowSec > validBefore) {
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

  const verifyResp = await fetchFn(`${facilitatorBase}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      x402Version: 2,
      paymentPayload: parsedSig,
      paymentRequirements,
    }),
  });

  if (!verifyResp.ok) {
    const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_verify_http_error');
    return { earlyResponse: create402Response(request, config, challenge) };
  }

  const verifyJson = (await verifyResp.json()) as X402VerifyResponse;
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
      route.priceMicros,
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
          await spendTracker.rollback(auth.from, route.priceMicros);
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

      const settleResp = await fetchFn(`${facilitatorBase}/settle`, {
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

      if (!settleResp.ok) {
        const challenge = buildPaymentRequiredChallenge(request, config, route, 'facilitator_settlement_failed');
        return create402Response(request, config, challenge);
      }

      const settleJson = (await settleResp.json()) as X402SettleResponse;
      if (!settleJson.success) {
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
 * Wrap a Cloudflare Worker `ExportedHandler` with dual-rail HTTP 402 protection.
 */
export function withTollbooth<Env = unknown>(
  configOrFactory: TollboothConfig | ((env: Env) => TollboothConfig),
  handler: WorkerHandler<Env>,
): WorkerHandler<Env> {
  const defaultNonceStore = new MemoryNonceStore();
  const defaultSpendTracker = new MemorySpendTracker();

  return {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      const config =
        typeof configOrFactory === 'function' ? configOrFactory(env) : configOrFactory;
      const evaluation = await evaluateTollboothRequest(
        request,
        config,
        defaultNonceStore,
        defaultSpendTracker,
      );

      if (evaluation.earlyResponse) {
        return evaluation.earlyResponse;
      }

      const downstream = await handler.fetch(request, env, ctx);
      if (evaluation.finalizeResponse) {
        return evaluation.finalizeResponse(downstream);
      }
      return downstream;
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
    if (c.res && evaluation.finalizeResponse) {
      c.res = await evaluation.finalizeResponse(c.res);
    }
    return c.res;
  };
}
