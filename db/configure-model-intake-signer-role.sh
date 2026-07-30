#!/bin/sh
set -eu

: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${MODEL_INTAKE_SIGNER_DATABASE_PASSWORD:?MODEL_INTAKE_SIGNER_DATABASE_PASSWORD is required}"

case "$MODEL_INTAKE_SIGNER_DATABASE_PASSWORD" in
  *[!A-Za-z0-9._~-]*|'')
    echo "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD must be URL-safe" >&2
    exit 1
    ;;
esac

export PGPASSWORD="$POSTGRES_PASSWORD"
psql -h postgres -U scanner -d scanner -v ON_ERROR_STOP=1 \
  --set=signer_password="$MODEL_INTAKE_SIGNER_DATABASE_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE model_intake_signer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD %L',
  :'signer_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='model_intake_signer') \gexec
SELECT format('ALTER ROLE model_intake_signer PASSWORD %L', :'signer_password') \gexec
ALTER ROLE model_intake_signer SET statement_timeout='20s';
ALTER ROLE model_intake_signer SET lock_timeout='5s';
ALTER ROLE model_intake_signer SET idle_in_transaction_session_timeout='20s';
ALTER ROLE model_intake_signer SET search_path='public';

GRANT CONNECT ON DATABASE scanner TO model_intake_signer;
GRANT USAGE ON SCHEMA public TO model_intake_signer;
GRANT SELECT ON TABLE
  model_intake_policy_decisions,
  model_intake_evidence_manifests,
  model_intake_approval_receipts,
  scans
TO model_intake_signer;
GRANT SELECT, UPDATE (state, updated_at) ON TABLE model_intake_submissions TO model_intake_signer;
GRANT SELECT, INSERT ON TABLE model_intake_admissions TO model_intake_signer;
GRANT INSERT ON TABLE
  model_intake_admission_events,
  model_intake_submission_events,
  model_intake_deployment_bindings
TO model_intake_signer;

REVOKE CREATE ON SCHEMA public FROM model_intake_signer;
SQL
