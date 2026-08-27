-- NEXUS ONE V0.6: Core validation and execution metadata.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_tasks_mission_status ON tasks(mission_id, status, created_at);
