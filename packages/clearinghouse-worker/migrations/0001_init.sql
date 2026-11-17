-- Agent Tollbooth 402 Clearinghouse D1 Schema
-- All monetary quantities are integer USD microdollars ($1.00 = 1,000,000 micros).

CREATE TABLE IF NOT EXISTS developers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  tier TEXT NOT NULL CHECK (tier IN ('free', 'hybrid', 'pro', 'agency')),
  stripe_account_id TEXT,
  payout_address TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS routes (
  id TEXT PRIMARY KEY,
  developer_id TEXT NOT NULL,
  pattern TEXT NOT NULL,
  method TEXT NOT NULL,
  scheme TEXT NOT NULL CHECK (scheme IN ('exact', 'upto')),
  price_micros INTEGER NOT NULL CHECK (price_micros >= 0),
  network TEXT NOT NULL,
  asset TEXT NOT NULL,
  description TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at INTEGER NOT NULL,
  FOREIGN KEY (developer_id) REFERENCES developers(id)
);

CREATE TABLE IF NOT EXISTS agent_wallets (
  id TEXT PRIMARY KEY,
  owner_label TEXT NOT NULL,
  balance_micros INTEGER NOT NULL CHECK (balance_micros >= 0),
  daily_spend_cap_micros INTEGER NOT NULL CHECK (daily_spend_cap_micros >= 0),
  daily_spent_micros INTEGER NOT NULL DEFAULT 0 CHECK (daily_spent_micros >= 0),
  spend_window_day TEXT NOT NULL,
  stripe_customer_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  wallet_id TEXT,
  developer_id TEXT,
  route_id TEXT,
  rail TEXT NOT NULL CHECK (rail IN ('fiat_wallet', 'x402')),
  entry_type TEXT NOT NULL CHECK (entry_type IN ('topup', 'charge', 'settlement', 'refund', 'payout')),
  gross_micros INTEGER NOT NULL CHECK (gross_micros >= 0),
  fee_bps INTEGER NOT NULL CHECK (fee_bps >= 0 AND fee_bps <= 10000),
  platform_fee_micros INTEGER NOT NULL CHECK (platform_fee_micros >= 0),
  developer_net_micros INTEGER NOT NULL CHECK (developer_net_micros >= 0),
  tx_reference TEXT,
  metadata_json TEXT,
  created_at INTEGER NOT NULL,
  CHECK (platform_fee_micros + developer_net_micros = gross_micros),
  FOREIGN KEY (wallet_id) REFERENCES agent_wallets(id),
  FOREIGN KEY (developer_id) REFERENCES developers(id),
  FOREIGN KEY (route_id) REFERENCES routes(id)
);

CREATE TABLE IF NOT EXISTS used_nonces (
  nonce TEXT PRIMARY KEY,
  rail TEXT NOT NULL CHECK (rail IN ('fiat_wallet', 'x402')),
  wallet_or_payer TEXT NOT NULL,
  route_pattern TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_routes_developer ON routes(developer_id);
CREATE INDEX IF NOT EXISTS idx_developers_payout ON developers(payout_address);
CREATE INDEX IF NOT EXISTS idx_ledger_developer_created ON ledger_entries(developer_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ledger_wallet_created ON ledger_entries(wallet_id, created_at);
CREATE INDEX IF NOT EXISTS idx_used_nonces_expires ON used_nonces(expires_at);
