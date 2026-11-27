-- Canonical deterministic Scan queue authority.
-- Safe to run repeatedly while legacy historical rows remain readable.
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS scan_job_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS scan_job_digest TEXT;
