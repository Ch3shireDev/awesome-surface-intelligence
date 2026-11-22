-- Decision 25: ports chosen per target. '' = the port profile of the scan.
ALTER TABLE targets ADD COLUMN ports text NOT NULL DEFAULT '';
