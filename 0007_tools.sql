CREATE TABLE IF NOT EXISTS tool_calls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
  tool TEXT NOT NULL,
  input JSONB,
  output JSONB,
  status TEXT NOT NULL DEFAULT 'COMPLETED',
  duration_ms INTEGER DEFAULT 0,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_mission ON tool_calls (organization_id, mission_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tool_calls_task ON tool_calls (organization_id, task_id, created_at);
