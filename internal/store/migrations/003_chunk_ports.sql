-- Coverage rule for ports: a port can only be "missing" if it was in the scanned
-- port set of a done services chunk (nmap <scaninfo services="...">). Empty = unknown/all.
ALTER TABLE chunks ADD COLUMN ports text NOT NULL DEFAULT '';
