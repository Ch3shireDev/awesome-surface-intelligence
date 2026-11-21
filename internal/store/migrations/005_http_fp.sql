-- DEV-7: HTTP fingerprint (title, status, server, tech, cert, cookies, redirect) tracked on the
-- port asset separately from the service fingerprint, so a changed web page/certificate is a
-- "changed" event without making nmap-only runs look like changes.
ALTER TABLE assets ADD COLUMN http_fp text NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN http_enc bytea;
