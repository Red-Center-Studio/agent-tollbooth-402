import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const DEV_VARS_PATH = path.join(ROOT, 'packages', 'clearinghouse-worker', '.dev.vars');

function parseEnvFile(content) {
  const map = new Map();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      continue;
    }
    map.set(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim());
  }
  return map;
}

function isRealValue(val) {
  return Boolean(val && !val.includes('placeholder') && !val.includes('replace_in_prod'));
}

const existing = existsSync(DEV_VARS_PATH)
  ? parseEnvFile(readFileSync(DEV_VARS_PATH, 'utf8'))
  : new Map();

const receiptSecret = isRealValue(existing.get('RECEIPT_SIGNING_SECRET'))
  ? existing.get('RECEIPT_SIGNING_SECRET')
  : `rcs_hmac_${randomBytes(32).toString('hex')}`;

const apiKey = isRealValue(existing.get('CLEARINGHOUSE_API_KEY'))
  ? existing.get('CLEARINGHOUSE_API_KEY')
  : `rcs_key_${randomBytes(32).toString('hex')}`;

const facilitatorSecret = isRealValue(existing.get('FACILITATOR_HMAC_SECRET'))
  ? existing.get('FACILITATOR_HMAC_SECRET')
  : `rcs_fac_${randomBytes(32).toString('hex')}`;

const stripeSecret = existing.get('STRIPE_SECRET_KEY') ?? 'sk_test_placeholder_paste_local_key_here';
const stripeWebhookSecret =
  existing.get('STRIPE_CONNECT_WEBHOOK_SECRET') ?? 'whsec_placeholder_paste_local_secret_here';

const output = [
  '# Local Wrangler .dev.vars (gitignored — NEVER commit this file)',
  `RECEIPT_SIGNING_SECRET=${receiptSecret}`,
  `CLEARINGHOUSE_API_KEY=${apiKey}`,
  `FACILITATOR_HMAC_SECRET=${facilitatorSecret}`,
  `STRIPE_SECRET_KEY=${stripeSecret}`,
  `STRIPE_CONNECT_WEBHOOK_SECRET=${stripeWebhookSecret}`,
  '',
].join('\n');

writeFileSync(DEV_VARS_PATH, output, { encoding: 'utf8', mode: 0o600 });
console.log('Generated/updated gitignored packages/clearinghouse-worker/.dev.vars cleanly.');
