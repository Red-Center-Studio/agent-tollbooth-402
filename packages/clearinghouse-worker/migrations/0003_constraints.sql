-- Enforce database-level uniqueness on non-null developer payout addresses to prevent concurrent squatting races.
CREATE UNIQUE INDEX IF NOT EXISTS idx_developers_payout_unique
  ON developers (LOWER(payout_address))
  WHERE payout_address IS NOT NULL;
