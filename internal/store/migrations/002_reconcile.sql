-- DEV-2: flapping = number of active<->missing transitions within the last
-- flap_window runs; we keep the run ids of recent transitions on the asset.
ALTER TABLE assets ADD COLUMN transition_runs text[] NOT NULL DEFAULT '{}';
ALTER TABLE asset_events ADD COLUMN key text NOT NULL DEFAULT '';
CREATE INDEX asset_events_asset ON asset_events (asset_id, at DESC);
ALTER TABLE runs ADD COLUMN reconciled_at timestamptz;
