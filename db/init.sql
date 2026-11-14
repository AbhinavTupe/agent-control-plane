-- agent-control-plane schema (Step 1). Runs once on first container start.
CREATE EXTENSION IF NOT EXISTS vector;

-- One row per agent session (Claude Code session_id).
CREATE TABLE sessions (
    id           text PRIMARY KEY,
    agent        text NOT NULL DEFAULT 'claude-code',
    cwd          text,
    model        text,
    status       text NOT NULL DEFAULT 'active',   -- active | waiting | idle | ended
    started_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

-- Raw hook events, append-only. JSONB keeps the full payload for later analysis.
CREATE TABLE events (
    id         bigserial PRIMARY KEY,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind       text NOT NULL,                       -- hook_event_name
    tool_name  text,
    payload    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX events_session_time_idx ON events (session_id, created_at DESC);

-- Every permission request and how it was resolved (also the audit log).
CREATE TABLE approvals (
    id         bigserial PRIMARY KEY,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    tool_name  text NOT NULL,
    tool_input jsonb NOT NULL,
    summary    text NOT NULL,                       -- short text shown in UI and embedded (Step 4)
    risk       text NOT NULL,                       -- low | medium | high
    status     text NOT NULL DEFAULT 'pending',     -- pending | allowed | denied | expired
    decided_by text,                                -- policy | human | timeout | client_gone
    reason     text,
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz,
    embedding  vector(384)                          -- filled in Step 4 (precedent memory)
);
CREATE INDEX approvals_pending_idx ON approvals (created_at) WHERE status = 'pending';
CREATE INDEX approvals_session_idx ON approvals (session_id, created_at DESC);
CREATE INDEX approvals_embedding_hnsw ON approvals USING hnsw (embedding vector_cosine_ops);
