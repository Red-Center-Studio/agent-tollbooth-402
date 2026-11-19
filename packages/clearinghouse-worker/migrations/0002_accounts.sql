-- Self-serve accounts: per-wallet and per-developer API keys (only SHA-256 hashes are stored) and the buyer's email.

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY,
  key_prefix TEXT NOT NULL,
  wallet_id TEXT,
  developer_id TEXT,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK ((wallet_id IS NOT NULL AND developer_id IS NULL) OR (wallet_id IS NULL AND developer_id IS NOT NULL)),
  FOREIGN KEY (wallet_id) REFERENCES agent_wallets(id),
  FOREIGN KEY (developer_id) REFERENCES developers(id)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_wallet ON api_keys(wallet_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_developer ON api_keys(developer_id);

ALTER TABLE agent_wallets ADD COLUMN owner_email TEXT;
