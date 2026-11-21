-- new event type "reverted" (inline CHECK from 001_init has the default name asset_events_type_check)
ALTER TABLE asset_events DROP CONSTRAINT asset_events_type_check;
ALTER TABLE asset_events ADD CONSTRAINT asset_events_type_check
    CHECK (type IN ('new', 'changed', 'reverted', 'missing', 'gone', 'reappeared', 'flapping'));
