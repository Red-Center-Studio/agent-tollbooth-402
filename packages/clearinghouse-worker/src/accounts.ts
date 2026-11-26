/**
 * Self-serve accounts for the Fiat Agent Wallet rail.
 *
 * - An agent owner registers a wallet and gets a wallet key (`rcs_wk_...`): it reads the balance and ledger and
 *   asks for receipts that spend from that wallet only.
 * - A developer registers and gets a developer key (`rcs_dk_...`): it reads their pass status and earnings ledger.
 * Keys are shown once. Only their SHA-256 hash is stored, so a database leak does not leak usable keys.
 * The master CLEARINGHOUSE_API_KEY still works everywhere, for operations.
 */

export type KeyScope = { kind: 'admin' } | { kind: 'wallet'; walletId: string } | { kind: 'developer'; developerId: string };

const enc = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(value: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(value))));
}

export function newId(prefix: 'wallet' | 'dev'): string {
  return `${prefix}_${hex(crypto.getRandomValues(new Uint8Array(10)))}`;
}

export function newKey(kind: 'wallet' | 'developer'): string {
  return `${kind === 'wallet' ? 'rcs_wk_' : 'rcs_dk_'}${b64url(crypto.getRandomValues(new Uint8Array(32)))}`;
}

export function isUniqueConstraintError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /unique constraint failed|constraint_unique/i.test(msg);
}

async function prepareStoreKeyStmt(
  db: D1Database,
  key: string,
  owner: { walletId?: string; developerId?: string },
  now: number,
): Promise<D1PreparedStatement> {
  return db
    .prepare(
      'INSERT INTO api_keys (key_hash, key_prefix, wallet_id, developer_id, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL)',
    )
    .bind(await sha256Hex(key), key.slice(0, 12), owner.walletId ?? null, owner.developerId ?? null, now);
}

export async function storeKey(
  db: D1Database,
  key: string,
  owner: { walletId?: string; developerId?: string },
  now: number,
): Promise<void> {
  await (await prepareStoreKeyStmt(db, key, owner, now)).run();
}

export function bearerToken(request: Request): string | null {
  const m = /^Bearer\s+(.+)$/i.exec((request.headers.get('Authorization') ?? '').trim());
  return m?.[1]?.trim() || null;
}

/** Resolves a scoped key to its wallet or developer, or null when unknown or revoked. */
export async function resolveScopedKey(db: D1Database, token: string): Promise<KeyScope | null> {
  if (!/^rcs_(wk|dk)_[A-Za-z0-9_-]{20,}$/.test(token)) {
    return null;
  }
  const row = await db
    .prepare('SELECT wallet_id, developer_id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL LIMIT 1')
    .bind(await sha256Hex(token))
    .first<{ wallet_id: string | null; developer_id: string | null }>();
  if (!row) {
    return null;
  }
  if (row.wallet_id) {
    return { kind: 'wallet', walletId: row.wallet_id };
  }
  if (row.developer_id) {
    return { kind: 'developer', developerId: row.developer_id };
  }
  return null;
}

export function scopeAllows(scope: KeyScope | null, target: { walletId?: string; developerId?: string }): boolean {
  if (!scope) {
    return false;
  }
  if (scope.kind === 'admin') {
    return true;
  }
  if (scope.kind === 'wallet') {
    return Boolean(target.walletId) && target.walletId === scope.walletId;
  }
  return Boolean(target.developerId) && target.developerId === scope.developerId;
}

const EMAIL_RE = /^[^\s@<>"']{1,64}@[^\s@<>"']{1,190}\.[A-Za-z]{2,}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
// Reject ASCII control chars (except benign space) and Unicode bidi overrides (e.g. U+202E RLO spoofing).
const UNSAFE_TEXT_RE = /[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]/;

export const DEFAULT_DAILY_CAP_MICROS = 25_000_000;
export const MAX_DAILY_CAP_MICROS = 500_000_000;

export type Outcome = { status: number; payload: Record<string, unknown> };

function bad(error: string, fix_hint: string, status = 400): Outcome {
  return { status, payload: { error, code: 'INVALID_REQUEST', fix_hint } };
}

export async function registerWallet(
  db: D1Database,
  body: { label?: unknown; email?: unknown; dailySpendCapUsd?: unknown },
): Promise<Outcome> {
  if (body.label !== undefined && typeof body.label !== 'string') {
    return bad('invalid_label', 'label must be a string up to 80 characters.');
  }
  if (body.email !== undefined && typeof body.email !== 'string') {
    return bad('invalid_email', 'Give a valid email address, or leave it out.');
  }
  const rawLabel = typeof body.label === 'string' ? body.label.trim() : '';
  if (rawLabel.length > 80 || (typeof body.label === 'string' && UNSAFE_TEXT_RE.test(body.label))) {
    return bad('invalid_label', 'label must be printable text up to 80 characters.');
  }
  const label = rawLabel;
  const rawEmail = typeof body.email === 'string' ? body.email.trim() : '';
  const email = rawEmail.toLowerCase();
  if (email && (email.length > 254 || UNSAFE_TEXT_RE.test(rawEmail) || !EMAIL_RE.test(email))) {
    return bad('invalid_email', 'Give a valid email address, or leave it out.');
  }
  let capMicros = DEFAULT_DAILY_CAP_MICROS;
  if (body.dailySpendCapUsd !== undefined) {
    const rawCap = body.dailySpendCapUsd;
    if (
      typeof rawCap !== 'number' &&
      !(typeof rawCap === 'string' && /^\d+(\.\d+)?$/.test(rawCap.trim()))
    ) {
      return bad('invalid_daily_spend_cap', 'dailySpendCapUsd must be a number between 1 and 500.');
    }
    const cap = Number(rawCap);
    if (!Number.isFinite(cap) || cap < 1 || cap * 1_000_000 > MAX_DAILY_CAP_MICROS) {
      return bad('invalid_daily_spend_cap', 'dailySpendCapUsd must be between 1 and 500.');
    }
    capMicros = Math.round(cap * 1_000_000);
  }
  const now = Math.floor(Date.now() / 1000);
  const walletId = newId('wallet');
  const walletKey = newKey('wallet');
  const insertWalletStmt = db
    .prepare(
      'INSERT INTO agent_wallets (id, owner_label, balance_micros, daily_spend_cap_micros, daily_spent_micros, spend_window_day, stripe_customer_id, status, created_at, updated_at, owner_email) VALUES (?, ?, 0, ?, 0, ?, NULL, ?, ?, ?, ?)',
    )
    .bind(walletId, label || 'Agent wallet', capMicros, new Date(now * 1000).toISOString().slice(0, 10), 'active', now, now, email || null);
  const insertKeyStmt = await prepareStoreKeyStmt(db, walletKey, { walletId }, now);
  await db.batch([insertWalletStmt, insertKeyStmt]);
  return {
    status: 201,
    payload: {
      walletId,
      walletKey,
      balanceMicros: 0,
      dailySpendCapMicros: capMicros,
      note: 'Save the wallet key now: it is shown once. Send it as Authorization: Bearer <walletKey>.',
    },
  };
}

export async function registerDeveloper(
  db: D1Database,
  body: { email?: unknown; name?: unknown; payoutAddress?: unknown },
): Promise<Outcome> {
  if (typeof body.email !== 'string' || typeof body.name !== 'string') {
    if (typeof body.email !== 'string') {
      return bad('invalid_email', 'Give a valid email address.');
    }
    return bad('missing_name', 'Give a string name for the developer account (1-80 characters).');
  }
  if (body.payoutAddress !== undefined && typeof body.payoutAddress !== 'string') {
    return bad('invalid_payout_address', 'payoutAddress must be 0x followed by 40 hex characters.');
  }
  const rawEmail = body.email.trim();
  const email = rawEmail.toLowerCase();
  const rawName = body.name.trim();
  const payout = typeof body.payoutAddress === 'string' ? body.payoutAddress.trim() : '';
  if (email.length > 254 || UNSAFE_TEXT_RE.test(rawEmail) || !EMAIL_RE.test(email)) {
    return bad('invalid_email', 'Give a valid email address.');
  }
  if (!rawName) {
    return bad('missing_name', 'Give a name for the developer account (a person or a business).');
  }
  if (rawName.length > 80 || UNSAFE_TEXT_RE.test(body.name)) {
    return bad('invalid_name', 'Developer name must be printable text up to 80 characters.');
  }
  const name = rawName;
  if (payout && !ADDRESS_RE.test(payout)) {
    return bad('invalid_payout_address', 'payoutAddress must be 0x followed by 40 hex characters.');
  }
  if (payout && (await payoutTaken(db, payout))) {
    return payoutInUse();
  }
  const exists = await db.prepare('SELECT id FROM developers WHERE email = ? LIMIT 1').bind(email).first<{ id: string }>();
  if (exists) {
    return bad(
      'email_already_registered',
      'This email already has a developer account. Use its developer key, or email hello@redcenterstudio.com to recover it.',
      409,
    );
  }
  const now = Math.floor(Date.now() / 1000);
  const developerId = newId('dev');
  const developerKey = newKey('developer');
  const insertDevStmt = db
    .prepare(
      "INSERT INTO developers (id, email, name, tier, stripe_account_id, payout_address, created_at) VALUES (?, ?, ?, 'hybrid', NULL, ?, ?)",
    )
    .bind(developerId, email, name, payout || null, now);
  const insertKeyStmt = await prepareStoreKeyStmt(db, developerKey, { developerId }, now);
  try {
    await db.batch([insertDevStmt, insertKeyStmt]);
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
      if (msg.includes('payout_address')) {
        return payoutInUse();
      }
      if (msg.includes('email')) {
        return bad(
          'email_already_registered',
          'This email already has a developer account. Use its developer key, or email hello@redcenterstudio.com to recover it.',
          409,
        );
      }
      if (payout && (await payoutTaken(db, payout))) {
        return payoutInUse();
      }
      return bad(
        'email_already_registered',
        'This email already has a developer account. Use its developer key, or email hello@redcenterstudio.com to recover it.',
        409,
      );
    }
    throw err;
  }
  return {
    status: 201,
    payload: {
      developerId,
      developerKey,
      tier: 'free',
      payoutAddress: payout || null,
      note: 'Save the developer key now: it is shown once. Send it as Authorization: Bearer <developerKey>.',
    },
  };
}

async function payoutTaken(db: D1Database, address: string, exceptDeveloperId = ''): Promise<boolean> {
  const row = await db
    .prepare('SELECT id FROM developers WHERE LOWER(payout_address) = LOWER(?) AND id != ? LIMIT 1')
    .bind(address, exceptDeveloperId)
    .first<{ id: string }>();
  return Boolean(row);
}

function payoutInUse(): Outcome {
  return bad(
    'payout_address_in_use',
    'Another developer account already uses this payout wallet. Each wallet belongs to one account; email hello@redcenterstudio.com if it is yours.',
    409,
  );
}

/** Sets or corrects a developer's payout wallet. Needs that developer's own key. */
export async function setPayoutAddress(db: D1Database, scope: KeyScope, body: { payoutAddress?: unknown }): Promise<Outcome> {
  if (scope.kind !== 'developer') {
    return bad('developer_key_required', 'Use the developer key (rcs_dk_...) of the account to change.', 403);
  }
  const payout = typeof body.payoutAddress === 'string' ? body.payoutAddress.trim() : '';
  if (!ADDRESS_RE.test(payout)) {
    return bad('invalid_payout_address', 'payoutAddress must be 0x followed by 40 hex characters.');
  }
  if (await payoutTaken(db, payout, scope.developerId)) {
    return payoutInUse();
  }
  try {
    await db.prepare('UPDATE developers SET payout_address = ? WHERE id = ?').bind(payout, scope.developerId).run();
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      return payoutInUse();
    }
    throw err;
  }
  return { status: 200, payload: { developerId: scope.developerId, payoutAddress: payout } };
}

/** Revokes the presented scoped key and issues a new one for the same wallet or developer. */
export async function rotateKey(db: D1Database, token: string, scope: KeyScope): Promise<Outcome> {
  if (scope.kind === 'admin') {
    return bad('admin_key_not_rotatable_here', 'Rotate CLEARINGHOUSE_API_KEY with wrangler secret put.');
  }
  const now = Math.floor(Date.now() / 1000);
  const revokeRes = await db
    .prepare('UPDATE api_keys SET revoked_at = ? WHERE key_hash = ? AND revoked_at IS NULL')
    .bind(now, await sha256Hex(token))
    .run();
  if ((revokeRes.meta?.changes ?? 0) !== 1) {
    return bad('key_already_rotated', 'This key has already been rotated or revoked. Use the newer key issued at rotation.', 409);
  }
  if (scope.kind === 'wallet') {
    const walletKey = newKey('wallet');
    await storeKey(db, walletKey, { walletId: scope.walletId }, now);
    return { status: 200, payload: { walletId: scope.walletId, walletKey, revokedPrevious: true } };
  }
  const developerKey = newKey('developer');
  await storeKey(db, developerKey, { developerId: scope.developerId }, now);
  return { status: 200, payload: { developerId: scope.developerId, developerKey, revokedPrevious: true } };
}

export async function ledgerHistory(
  db: D1Database,
  target: { walletId?: string; developerId?: string },
  limitRaw: unknown,
): Promise<Outcome> {
  let limit = 25;
  if (limitRaw !== undefined && limitRaw !== null && limitRaw !== '') {
    if (typeof limitRaw === 'number' && Number.isSafeInteger(limitRaw)) {
      limit = Math.min(100, Math.max(1, limitRaw));
    } else if (typeof limitRaw === 'string' && /^-?\d+$/.test(limitRaw.trim())) {
      const parsed = Number(limitRaw.trim());
      if (Number.isSafeInteger(parsed)) {
        limit = Math.min(100, Math.max(1, parsed));
      }
    }
  }
  const column = target.walletId ? 'wallet_id' : 'developer_id';
  const id = target.walletId ?? target.developerId;
  const rows = await db
    .prepare(
      `SELECT id, rail, entry_type, gross_micros, fee_bps, platform_fee_micros, developer_net_micros, tx_reference, created_at FROM ledger_entries WHERE ${column} = ? ORDER BY created_at DESC LIMIT ?`,
    )
    .bind(id, limit)
    .all<Record<string, unknown>>();
  const entries = (rows.results ?? []).map((r) => ({
    id: r.id,
    rail: r.rail,
    type: r.entry_type,
    grossMicros: r.gross_micros,
    feeBps: r.fee_bps,
    platformFeeMicros: r.platform_fee_micros,
    developerNetMicros: r.developer_net_micros,
    reference: r.tx_reference,
    createdAt: r.created_at,
  }));
  return { status: 200, payload: { ...(target.walletId ? { walletId: id } : { developerId: id }), entries } };
}

// ---------- Ed25519 receipt keys ----------

export interface Ed25519Env {
  RECEIPT_ED25519_PRIVATE_JWK?: string;
}

interface Ed25519Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  d?: string;
}

let cached: { raw: string; key: Promise<CryptoKey>; jwk: Ed25519Jwk; kid: Promise<string> } | null = null;

function loadJwk(env: Ed25519Env): typeof cached {
  const raw = env.RECEIPT_ED25519_PRIVATE_JWK;
  if (!raw) {
    return null;
  }
  if (cached && cached.raw === raw) {
    return cached;
  }
  const jwk = JSON.parse(raw) as Ed25519Jwk;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x || !jwk.d) {
    throw new Error('RECEIPT_ED25519_PRIVATE_JWK must be an Ed25519 private JWK');
  }
  const key = crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
  key.catch(() => {
    if (cached?.raw === raw) {
      cached = null;
    }
  });
  cached = {
    raw,
    jwk,
    key,
    kid: sha256Hex(jwk.x).then((h) => h.slice(0, 16)),
  };
  return cached;
}

/** The private signing key when RECEIPT_ED25519_PRIVATE_JWK is set, otherwise null (HS256 fallback). */
export async function receiptSigningKey(env: Ed25519Env): Promise<CryptoKey | null> {
  const c = loadJwk(env);
  return c ? c.key : null;
}

/** Public keys merchants use to verify Rail B receipts without holding any clearinghouse secret. */
export async function receiptJwks(env: Ed25519Env): Promise<{ keys: Array<Record<string, string>> }> {
  const c = loadJwk(env);
  if (!c) {
    return { keys: [] };
  }
  return { keys: [{ kty: 'OKP', crv: 'Ed25519', x: c.jwk.x, kid: await c.kid, use: 'sig', alg: 'EdDSA' }] };
}
