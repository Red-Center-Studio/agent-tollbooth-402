/**
 * Hands x402 payments to an on-chain facilitator that submits the USDC transfer.
 *
 * - Base Sepolia (eip155:84532): the public x402.org facilitator, no key needed.
 * - Base mainnet (eip155:8453): Coinbase's CDP facilitator when CDP_API_KEY_ID and CDP_API_KEY_SECRET are set,
 *   or any facilitator in X402_MAINNET_FACILITATOR_URL. With neither, mainnet settlement is refused rather than faked.
 */
import { USDC_DOMAINS } from './evm.js';

export const TESTNET_FACILITATOR_URL = 'https://x402.org/facilitator';
export const CDP_FACILITATOR_URL = 'https://api.cdp.coinbase.com/platform/v2/x402';

export interface UpstreamEnv {
  X402_TESTNET_FACILITATOR_URL?: string;
  X402_MAINNET_FACILITATOR_URL?: string;
  CDP_API_KEY_ID?: string;
  CDP_API_KEY_SECRET?: string;
}

export interface UpstreamFacilitator {
  url: string;
  cdp?: { keyId: string; secret: string };
}

export function facilitatorFor(network: string, env: UpstreamEnv): UpstreamFacilitator | null {
  if (network === 'eip155:84532') {
    return { url: (env.X402_TESTNET_FACILITATOR_URL || TESTNET_FACILITATOR_URL).replace(/\/+$/, '') };
  }
  if (network === 'eip155:8453') {
    if (env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET) {
      return { url: CDP_FACILITATOR_URL, cdp: { keyId: env.CDP_API_KEY_ID, secret: env.CDP_API_KEY_SECRET } };
    }
    if (env.X402_MAINNET_FACILITATOR_URL) {
      return { url: env.X402_MAINNET_FACILITATOR_URL.replace(/\/+$/, '') };
    }
  }
  return null;
}

const b64url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlJson = (value: unknown): string => b64url(new TextEncoder().encode(JSON.stringify(value)));

const cdpKeys = new Map<string, Promise<CryptoKey>>();

/** CDP secrets are base64 of the 32-byte Ed25519 seed followed by the 32-byte public key. */
function cdpSigningKey(secret: string): Promise<CryptoKey> {
  let pending = cdpKeys.get(secret);
  if (!pending) {
    const bin = atob(secret.trim());
    if (bin.length !== 64) {
      return Promise.reject(new Error('CDP_API_KEY_SECRET is not a base64 Ed25519 key'));
    }
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const jwk = { kty: 'OKP', crv: 'Ed25519', d: b64url(bytes.slice(0, 32)), x: b64url(bytes.slice(32)) };
    pending = crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
    pending.catch(() => cdpKeys.delete(secret));
    cdpKeys.set(secret, pending);
  }
  return pending;
}

/** A two-minute token for one CDP request, the same shape as generateJwt in @coinbase/cdp-sdk/auth. */
export async function cdpJwt(cdp: { keyId: string; secret: string }, method: string, url: string): Promise<string> {
  const u = new URL(url);
  const key = await cdpSigningKey(cdp.secret);
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  const iat = Math.floor(Date.now() / 1000);
  const head = b64urlJson({ alg: 'EdDSA', kid: cdp.keyId, typ: 'JWT', nonce });
  const body = b64urlJson({ sub: cdp.keyId, iss: 'cdp', uris: [`${method} ${u.host}${u.pathname}`], iat, nbf: iat, exp: iat + 120 });
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(`${head}.${body}`)),
  );
  return `${head}.${body}.${b64url(sig)}`;
}

export interface UpstreamPayment {
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  resource?: string;
  signature: string;
  authorization: Record<string, unknown>;
}

/** The standard x402 V2 verify/settle body. `accepted` is rebuilt in full; the signature covers only the authorization. */
export function upstreamBody(p: UpstreamPayment): Record<string, unknown> {
  const domain = USDC_DOMAINS[p.network];
  const requirements = {
    scheme: 'exact',
    network: p.network,
    asset: p.asset,
    amount: p.amount,
    payTo: p.payTo,
    maxTimeoutSeconds: p.maxTimeoutSeconds ?? 60,
    extra: domain ? { name: domain.name, version: domain.version } : {},
  };
  return {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      ...(p.resource ? { resource: { url: p.resource } } : {}),
      accepted: requirements,
      payload: { signature: p.signature, authorization: p.authorization },
    },
    paymentRequirements: requirements,
  };
}

export interface UpstreamResult {
  ok: boolean;
  status: number;
  json: Record<string, unknown>;
}

export async function callUpstream(
  facilitator: UpstreamFacilitator,
  op: 'verify' | 'settle',
  body: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<UpstreamResult> {
  const url = `${facilitator.url}/${op}`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (facilitator.cdp) {
    headers.Authorization = `Bearer ${await cdpJwt(facilitator.cdp, 'POST', url)}`;
  }
  let res: Response;
  try {
    res = await fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(body) });
  } catch {
    return { ok: false, status: 0, json: { errorReason: 'facilitator_unreachable' } };
  }
  let json: Record<string, unknown> = {};
  try {
    json = (await res.json()) as Record<string, unknown>;
  } catch {
    json = {};
  }
  return { ok: res.ok, status: res.status, json };
}
