BEGIN;

CREATE INDEX IF NOT EXISTS idx_scan_capability_actions_reservation
    ON scan_capability_actions(reservation_id)
    WHERE reservation_id IS NOT NULL;

UPDATE scan_capability_actions a
   SET reservation_id=r.id
  FROM budget_reservations r
 WHERE a.reservation_id IS NULL
   AND r.owner_kind='scan'
   AND r.owner_id=a.scan_id::text
   AND r.action_id=a.action_id
   AND r.action_digest=a.action_digest;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname='scan_capability_actions_reservation_fk'
           AND conrelid='scan_capability_actions'::regclass
    ) THEN
        ALTER TABLE scan_capability_actions
        ADD CONSTRAINT scan_capability_actions_reservation_fk
        FOREIGN KEY (reservation_id) REFERENCES budget_reservations(id)
        ON DELETE RESTRICT;
    END IF;
END $$;

INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_action_budget_link_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
