-- ASI schema v1 (VISION 4.2). Columns ending in _enc hold values sealed by
-- store.Sealer (AES-256-GCM in internal/crypto, SEC-6); searchable fields
-- (IP, port, state, service name) stay in plain columns.

CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'operator', 'analyst', 'viewer')),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_tokens (
    id           bigserial PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   text NOT NULL UNIQUE,          -- sha256, never the token itself
    name         text NOT NULL DEFAULT '',
    expires_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    user_id     bigint REFERENCES users(id) ON DELETE SET NULL,
    action      text NOT NULL,
    object_type text NOT NULL,
    object_id   text NOT NULL DEFAULT '',
    changes     jsonb,
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at ON audit_log (at DESC);

CREATE TABLE target_sets (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE targets (
    id         bigserial PRIMARY KEY,
    set_id     bigint NOT NULL REFERENCES target_sets(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
    value      text NOT NULL,
    asset      text NOT NULL DEFAULT '',
    owner      text NOT NULL DEFAULT '',
    tags       text[] NOT NULL DEFAULT '{}',
    enabled    boolean NOT NULL DEFAULT true,
    note_enc   bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (set_id, value)
);

CREATE TABLE exclusions (
    id     bigserial PRIMARY KEY,
    set_id bigint REFERENCES target_sets(id) ON DELETE CASCADE,  -- NULL = global
    value  text NOT NULL,
    reason text NOT NULL DEFAULT ''
);

CREATE TABLE runs (
    id          text PRIMARY KEY,                 -- YYYYMMDD-HHMMSS, same as results/<id>
    set_name    text NOT NULL DEFAULT '',
    status      text NOT NULL CHECK (status IN ('planned', 'running', 'paused', 'completed', 'partial', 'failed', 'cancelled')),
    trigger     text NOT NULL DEFAULT 'manual',
    created_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    profile     jsonb NOT NULL DEFAULT '{}',      -- frozen settings of this run
    stats       jsonb NOT NULL DEFAULT '{}',
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX runs_started ON runs (started_at DESC);

CREATE TABLE chunks (
    run_id       text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    stage        text NOT NULL,
    id           int  NOT NULL,
    targets      text[] NOT NULL,
    size         int  NOT NULL,
    status       text NOT NULL CHECK (status IN ('pending', 'queued', 'running', 'done', 'failed', 'killed', 'deferred', 'cancelled')),
    attempts     int  NOT NULL DEFAULT 1,
    started_at   timestamptz,
    finished_at  timestamptz,
    progress_pct real NOT NULL DEFAULT 0,
    duration_ms  bigint,
    error        text NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, stage, id)
);

CREATE TABLE raw_outputs (
    run_id   text NOT NULL,
    stage    text NOT NULL,
    chunk_id int  NOT NULL,
    tool     text NOT NULL,
    format   text NOT NULL,
    data_enc bytea NOT NULL,                       -- evidence (nmap XML, jsonl...)
    PRIMARY KEY (run_id, stage, chunk_id),
    FOREIGN KEY (run_id, stage, chunk_id) REFERENCES chunks(run_id, stage, id) ON DELETE CASCADE
);

CREATE TABLE observations (
    id          bigserial PRIMARY KEY,
    run_id      text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    stage       text NOT NULL,
    chunk_id    int  NOT NULL,
    kind        text NOT NULL,
    asset_key   text NOT NULL,
    ip          inet NOT NULL,
    proto       text NOT NULL DEFAULT '',
    port        int  NOT NULL DEFAULT 0,
    service     text NOT NULL DEFAULT '',          -- plain copy for search/grouping
    data_enc    bytea NOT NULL,
    fp_hash     text NOT NULL,
    confidence  int  NOT NULL,
    tool        text NOT NULL,
    observed_at timestamptz NOT NULL
);
CREATE INDEX observations_run_kind ON observations (run_id, kind);
CREATE INDEX observations_asset ON observations (asset_key);

CREATE TABLE assets (
    id                 bigserial PRIMARY KEY,
    key                text NOT NULL UNIQUE,      -- 192.0.2.10 | 192.0.2.10/tcp/443
    kind               text NOT NULL CHECK (kind IN ('host', 'port')),
    parent_key         text NOT NULL DEFAULT '',
    ip                 inet NOT NULL,
    port               int  NOT NULL DEFAULT 0,
    state              text NOT NULL CHECK (state IN ('new', 'active', 'missing', 'gone')),
    flapping           boolean NOT NULL DEFAULT false,
    first_seen         timestamptz NOT NULL,
    last_seen          timestamptz NOT NULL,
    last_seen_run      text NOT NULL,
    consecutive_misses int NOT NULL DEFAULT 0,
    seen_count         int NOT NULL DEFAULT 1,
    transitions_recent int NOT NULL DEFAULT 0,
    hours_seen         int NOT NULL DEFAULT 0,    -- 24-bit mask of hours (UTC) when seen
    current_fp_hash    text NOT NULL DEFAULT '',
    current_enc        bytea,
    user_tags          text[] NOT NULL DEFAULT '{}',
    user_note_enc      bytea,
    user_overrides     jsonb NOT NULL DEFAULT '{}',
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assets_state ON assets (state);

CREATE TABLE asset_events (
    id         bigserial PRIMARY KEY,
    asset_id   bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    run_id     text NOT NULL,
    type       text NOT NULL CHECK (type IN ('new', 'changed', 'missing', 'gone', 'reappeared', 'flapping')),
    before_enc bytea,
    after_enc  bytea,
    at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX asset_events_run ON asset_events (run_id);

CREATE TABLE exports (
    id          bigserial PRIMARY KEY,
    run_id      text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    target      text NOT NULL DEFAULT 'defectdojo',
    status      text NOT NULL,
    dd_test_ids jsonb NOT NULL DEFAULT '[]',
    error       text NOT NULL DEFAULT '',
    at          timestamptz NOT NULL DEFAULT now()
);
