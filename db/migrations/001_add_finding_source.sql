-- Migration: Add source column to findings table
-- This allows tracking whether a finding came from an automated scan,
-- manual testing, or an AI-assisted security session.

-- Add source column with default 'scan' for backward compatibility
ALTER TABLE findings
ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'scan';

-- Add comment
COMMENT ON COLUMN findings.source IS 'Origin of finding: scan, manual, ai_session';

-- Add index for filtering by source
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);

-- Add session_id column for findings from AI sessions
ALTER TABLE findings
ADD COLUMN IF NOT EXISTS session_id TEXT;

-- Add index for session lookups
CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id) WHERE session_id IS NOT NULL;
