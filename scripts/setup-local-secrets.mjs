import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const SECRETS_LOCAL_PATH = path.join(ROOT, 'SECRETS.local.env');
const DEV_VARS_PATH = path.join(ROOT, 'packages', 'clearinghouse-worker', '.dev.vars');
const DEV_VARS_LIVE_PATH = path.join(ROOT, 'packages', 'clearinghouse-worker', '.dev.vars.live');

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
  return Boolean(
    val &&
      !val.includes('placeholder') &&
      !val.includes('replace_in_prod') &&
      !val.startsWith('PASTE_'),
  );
}

if (process.argv.includes('--purge')) {
  let purged = 0;
  for (const filePath of [SECRETS_LOCAL_PATH, DEV_VARS_PATH, DEV_VARS_LIVE_PATH]) {
    if (existsSync(filePath)) {
      const size = Math.max(64, readFileSync(filePath).length);
      writeFileSync(filePath, '\0'.repeat(size));
      unlinkSync(filePath);
      purged += 1;
      console.log(`Purged local secret file: ${path.relative(ROOT, filePath)}`);
    }
  }
  if (purged === 0) {
    console.log('No local secret files found on disk.');
  }
  process.exit(0);
}

const existingLocal = existsSync(SECRETS_LOCAL_PATH)
  ? parseEnvFile(readFileSync(SECRETS_LOCAL_PATH, 'utf8'))
  : new Map();
const existingDevVars = existsSync(DEV_VARS_PATH)
  ? parseEnvFile(readFileSync(DEV_VARS_PATH, 'utf8'))
  : new Map();

const pick = (key, fallback) => {
  const localVal = existingLocal.get(key);
  if (isRealValue(localVal)) {
    return localVal;
  }
  const devVal = existingDevVars.get(key);
  if (isRealValue(devVal)) {
    return devVal;
  }
  return localVal ?? devVal ?? fallback;
};

const stripeSecretKey = pick('STRIPE_SECRET_KEY', 'PASTE_SK_LIVE_OR_RK_LIVE_HERE_IF_NEEDED');
const stripePubKey = pick('STRIPE_PUBLISHABLE_KEY', 'PASTE_PK_LIVE_HERE_IF_NEEDED');
const stripeWebhookSecret = pick(
  'STRIPE_CONNECT_WEBHOOK_SECRET',
  'whsec_placeholder_paste_local_secret_here',
);
const stripeTestSecretKey = pick(
  'STRIPE_TEST_SECRET_KEY',
  'sk_test_placeholder_paste_local_key_here',
);
const stripeTestWebhookSecret = pick(
  'STRIPE_TEST_WEBHOOK_SECRET',
  'whsec_placeholder_paste_local_secret_here',
);

const receiptSecret = isRealValue(pick('RECEIPT_SIGNING_SECRET', ''))
  ? pick('RECEIPT_SIGNING_SECRET', '')
  : `rcs_hmac_${randomBytes(32).toString('hex')}`;
const apiKey = isRealValue(pick('CLEARINGHOUSE_API_KEY', ''))
  ? pick('CLEARINGHOUSE_API_KEY', '')
  : `rcs_key_${randomBytes(32).toString('hex')}`;
const facilitatorSecret = isRealValue(pick('FACILITATOR_HMAC_SECRET', ''))
  ? pick('FACILITATOR_HMAC_SECRET', '')
  : `rcs_fac_${randomBytes(32).toString('hex')}`;

const secretsLocalOutput = [
  '# ============================================================================',
  '# PASTE YOUR STRIPE KEYS BELOW (THIS FILE IS GITIGNORED & NEVER COMMITTED)',
  '# Note: $10 Top-Up, $39 Pro Pass, and $79 Agency Pass Payment Links work',
  '# WITHOUT sk_live_! Only paste sk_live_ if you want custom-dollar checkouts.',
  '# Run `npm run secrets:purge` after deploying secrets to remove this file.',
  '# ============================================================================',
  `STRIPE_SECRET_KEY=${stripeSecretKey}`,
  `STRIPE_PUBLISHABLE_KEY=${stripePubKey}`,
  '',
  '# Pre-filled / local clearinghouse webhook & test credentials:',
  `STRIPE_CONNECT_WEBHOOK_SECRET=${stripeWebhookSecret}`,
  `STRIPE_TEST_SECRET_KEY=${stripeTestSecretKey}`,
  `STRIPE_TEST_WEBHOOK_SECRET=${stripeTestWebhookSecret}`,
  '',
  '# Auto-generated 256-bit Clearinghouse HMAC & Admin Keys:',
  `RECEIPT_SIGNING_SECRET=${receiptSecret}`,
  `CLEARINGHOUSE_API_KEY=${apiKey}`,
  `FACILITATOR_HMAC_SECRET=${facilitatorSecret}`,
  '',
].join('\n');

writeFileSync(SECRETS_LOCAL_PATH, secretsLocalOutput, { encoding: 'utf8', mode: 0o600 });

const devVarsOutput = [
  '# Local Wrangler .dev.vars synced from SECRETS.local.env (gitignored — NEVER commit)',
  `RECEIPT_SIGNING_SECRET=${receiptSecret}`,
  `CLEARINGHOUSE_API_KEY=${apiKey}`,
  `FACILITATOR_HMAC_SECRET=${facilitatorSecret}`,
  `STRIPE_SECRET_KEY=${isRealValue(stripeSecretKey) ? stripeSecretKey : stripeTestSecretKey}`,
  `STRIPE_CONNECT_WEBHOOK_SECRET=${isRealValue(stripeSecretKey) ? stripeWebhookSecret : stripeTestWebhookSecret}`,
  '',
].join('\n');

writeFileSync(DEV_VARS_PATH, devVarsOutput, { encoding: 'utf8', mode: 0o600 });

console.log('Created/synced gitignored SECRETS.local.env and packages/clearinghouse-worker/.dev.vars.');
