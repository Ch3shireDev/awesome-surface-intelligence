-- LAB-T11: event "filtered" = known port behind a firewall, result incomplete (not a miss)
ALTER TABLE asset_events DROP CONSTRAINT asset_events_type_check;
ALTER TABLE asset_events ADD CONSTRAINT asset_events_type_check
    CHECK (type IN ('new', 'changed', 'reverted', 'missing', 'gone', 'reappeared', 'flapping', 'filtered'));
