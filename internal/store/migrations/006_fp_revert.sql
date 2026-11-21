-- LAB-T8: fingerprint before the last change (service and HTTP). A later observation equal to it
-- is a REVERT (e.g. a backend behind a proxy was down for a while), reported as "reverted" and
-- counted as instability, not as a second, opposite "changed".
ALTER TABLE assets ADD COLUMN prev_fp_hash text NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN prev_http_fp text NOT NULL DEFAULT '';

