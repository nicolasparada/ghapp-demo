-- One-time data reset: no production data exists.
-- Lets 0006 and later migrations change the schema without data migration logic.

TRUNCATE
    runs,
    installations,
    repo_links,
    projects,
    sessions,
    users
RESTART IDENTITY CASCADE;
