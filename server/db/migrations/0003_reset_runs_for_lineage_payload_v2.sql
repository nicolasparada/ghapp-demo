-- PoC reset: discard existing run payloads so UI/API can assume the new lineage tree schema.
TRUNCATE TABLE runs RESTART IDENTITY;
