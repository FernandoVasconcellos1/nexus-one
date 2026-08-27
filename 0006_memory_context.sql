-- NEXUS ONE V0.7: Memory and Context Engine
CREATE TABLE IF NOT EXISTS memories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  mission_id UUID REFERENCES missions(id) ON DELETE SET NULL,
  type TEXT NOT NULL CHECK (type IN ('FACT','PREFERENCE','GOAL','DECISION','CONSTRAINT','OUTCOME')),
  content TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'MISSION',
  importance INTEGER NOT NULL DEFAULT 50 CHECK (importance BETWEEN 0 AND 100),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_memories_org_project ON memories(organization_id, project_id, active, importance DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memories_mission ON memories(mission_id);
