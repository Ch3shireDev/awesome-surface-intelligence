-- DEV-5: schedules with time windows; runs cut by the window resume in the next one.
CREATE TABLE schedules (
    id             bigserial PRIMARY KEY,
    name           text NOT NULL UNIQUE,
    set_name       text NOT NULL,
    cron           text NOT NULL,              -- 5-field cron, server local time
    window_minutes int  NOT NULL CHECK (window_minutes BETWEEN 1 AND 1440),
    params         jsonb NOT NULL DEFAULT '{}', -- parallel, rate, ports, upload
    enabled        boolean NOT NULL DEFAULT true,
    next_run_at    timestamptz,
    last_run_at    timestamptz,
    last_run_id    text NOT NULL DEFAULT '',
    last_error     text NOT NULL DEFAULT '',
    created_by     bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE runs ADD COLUMN schedule_id bigint REFERENCES schedules(id) ON DELETE SET NULL;
ALTER TABLE runs ADD COLUMN resume_of text NOT NULL DEFAULT '';      -- this run continues that one
ALTER TABLE runs ADD COLUMN pending_targets text[] NOT NULL DEFAULT '{}'; -- not covered when the window closed
ALTER TABLE runs ADD COLUMN resumed_by text NOT NULL DEFAULT '';     -- set when a later run took over pending
