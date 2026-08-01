-- Schema only. 0005 emptied every table, so NOT NULL columns need no defaults
-- and no backfills are required.



-- ------------------------------------------------------------
-- repos: visibility source of truth (new)
-- ------------------------------------------------------------
CREATE TABLE repos (
    repo_id           BIGINT PRIMARY KEY,       -- immutable GitHub repo id
    full_name         TEXT   NOT NULL,          -- display cache, refreshed by pull
    owner             TEXT   NOT NULL,          -- display cache
    owner_id          BIGINT NOT NULL,          -- immutable
    visibility        TEXT   NOT NULL CHECK (visibility IN ('public','private','internal')),
    visibility_source TEXT   NOT NULL DEFAULT 'oidc' CHECK (visibility_source IN ('oidc','api')),
    synced_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX repos_full_name_idx ON repos(full_name);
CREATE INDEX repos_owner_id_idx  ON repos(owner_id);

-- ------------------------------------------------------------
-- users: provider-agnostic from day one
-- ------------------------------------------------------------
ALTER TABLE users DROP COLUMN github_id;
ALTER TABLE users DROP COLUMN login;
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email TEXT UNIQUE;

CREATE TABLE user_identities (
    provider         TEXT   NOT NULL,          -- 'github', later 'email', 'google', ...
    provider_user_id TEXT   NOT NULL,          -- immutable id, never the login
    provider_login   TEXT   NOT NULL DEFAULT '',
    user_id          BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, provider_user_id)
);
CREATE INDEX user_identities_user_id_idx ON user_identities(user_id);

-- GitHub App user-to-server tokens (Phase 3)
CREATE TABLE user_github_tokens (
    user_id                  BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    access_token_enc         BYTEA NOT NULL,
    access_token_expires_at  TIMESTAMPTZ,
    refresh_token_enc        BYTEA,
    refresh_token_expires_at TIMESTAMPTZ,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------
-- projects: owned by membership, not by a single user
-- ------------------------------------------------------------
DROP INDEX projects_user_id_idx;
ALTER TABLE projects DROP CONSTRAINT projects_user_id_slug_key;
ALTER TABLE projects DROP CONSTRAINT projects_user_id_fkey;
ALTER TABLE projects RENAME COLUMN user_id TO created_by;
ALTER TABLE projects ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE projects ADD CONSTRAINT projects_slug_key UNIQUE (slug);
ALTER TABLE projects ADD CONSTRAINT projects_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

CREATE TABLE project_members (
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    role       TEXT   NOT NULL CHECK (role IN ('owner','admin','member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX project_members_user_id_idx ON project_members(user_id);

-- a repo may belong to several projects
CREATE TABLE project_repos (
    project_id BIGINT NOT NULL REFERENCES projects(id)   ON DELETE CASCADE,
    repo_id    BIGINT NOT NULL REFERENCES repos(repo_id) ON DELETE CASCADE,
    bound_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    bound_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (project_id, repo_id)
);
CREATE INDEX project_repos_repo_id_idx ON project_repos(repo_id) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------
-- installations: keyed by GitHub's id, populated by pull only
-- ------------------------------------------------------------
DROP TABLE repo_links;

DROP INDEX installations_target_login_idx;
ALTER TABLE installations DROP CONSTRAINT installations_pkey;
ALTER TABLE installations DROP COLUMN id;
ALTER TABLE installations DROP CONSTRAINT installations_github_installation_id_key;
ALTER TABLE installations ADD PRIMARY KEY (github_installation_id);
ALTER TABLE installations ADD COLUMN github_account_id    BIGINT NOT NULL;
ALTER TABLE installations ADD COLUMN repository_selection TEXT;
ALTER TABLE installations ADD COLUMN synced_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE installations ADD COLUMN deleted_at TIMESTAMPTZ;   -- soft delete; never orphan references
CREATE INDEX installations_account_id_idx ON installations(github_account_id);

CREATE TABLE installation_repos (
    github_installation_id BIGINT NOT NULL
        REFERENCES installations(github_installation_id) ON DELETE CASCADE,
    repo_id                BIGINT NOT NULL,
    synced_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (github_installation_id, repo_id)
);
CREATE INDEX installation_repos_repo_id_idx ON installation_repos(repo_id);

-- authorizes BINDING a repo into a project; never consulted on reads
CREATE TABLE user_repo_access (
    user_id                BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_id                BIGINT NOT NULL,
    github_installation_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, repo_id)
);

CREATE TABLE user_access_syncs (
    user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    synced_at    TIMESTAMPTZ,
    attempted_at TIMESTAMPTZ,
    last_error   TEXT,
    etag         TEXT
);

-- derived retention signal; deliberately NOT on runs
CREATE TABLE repo_coverage (
    repo_id                BIGINT PRIMARY KEY REFERENCES repos(repo_id) ON DELETE CASCADE,
    github_installation_id BIGINT,
    checked_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    uncovered_since        TIMESTAMPTZ
);

-- ------------------------------------------------------------
-- runs: pure facts (no owner, no visibility, no claim state)
-- ------------------------------------------------------------
ALTER TABLE runs DROP CONSTRAINT runs_repo_full_name_github_run_id_github_job_id_key;
DROP INDEX runs_repo_full_name_idx;
DROP INDEX runs_created_at_idx;

ALTER TABLE runs DROP COLUMN repo_full_name;   -- name-keyed; replaced by repo_id
ALTER TABLE runs DROP COLUMN github_job_id;    -- was a hash of a string; re-added nullable below
ALTER TABLE runs DROP COLUMN job_name;         -- superseded by job_key / job_display_name

-- URL id: non-enumerable and server-generated
ALTER TABLE runs ADD COLUMN public_id UUID NOT NULL DEFAULT uuidv7();
ALTER TABLE runs ADD CONSTRAINT runs_public_id_key UNIQUE (public_id);

ALTER TABLE runs ADD COLUMN repo_id BIGINT NOT NULL REFERENCES repos(repo_id) ON DELETE CASCADE;

-- signed by GitHub via OIDC
ALTER TABLE runs ADD COLUMN run_attempt        INT    NOT NULL;
ALTER TABLE runs ADD COLUMN workflow_ref       TEXT   NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN workflow_sha       TEXT   NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN job_workflow_sha   TEXT   NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN actor_id           BIGINT;
ALTER TABLE runs ADD COLUMN runner_environment TEXT   NOT NULL DEFAULT '';

-- asserted by the action (inside the repo's own trust boundary)
ALTER TABLE runs ADD COLUMN execution_id       UUID   NOT NULL;   -- minted in the main step
ALTER TABLE runs ADD COLUMN job_key            TEXT   NOT NULL;   -- GITHUB_JOB
ALTER TABLE runs ADD COLUMN runner_name        TEXT   NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN runner_os          TEXT   NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN capture_started_at TIMESTAMPTZ;
ALTER TABLE runs ADD COLUMN capture_ended_at   TIMESTAMPTZ;
ALTER TABLE runs ADD COLUMN payload_sha256     TEXT   NOT NULL DEFAULT '';

-- enrichment, all nullable, best-effort
ALTER TABLE runs ADD COLUMN github_job_id    BIGINT;
ALTER TABLE runs ADD COLUMN job_display_name TEXT;
ALTER TABLE runs ADD COLUMN job_conclusion   TEXT;
ALTER TABLE runs ADD COLUMN job_started_at   TIMESTAMPTZ;
ALTER TABLE runs ADD COLUMN job_completed_at TIMESTAMPTZ;
ALTER TABLE runs ADD COLUMN enrichment_state TEXT NOT NULL DEFAULT 'pending'
    CHECK (enrichment_state IN ('pending','matched','ambiguous','unavailable'));

-- repo_id in the key so one repo can never overwrite another's row
ALTER TABLE runs ADD CONSTRAINT runs_execution_key UNIQUE (repo_id, execution_id);
CREATE INDEX runs_repo_created_idx ON runs(repo_id, created_at DESC);
CREATE INDEX runs_attempt_idx      ON runs(repo_id, github_run_id, run_attempt);
CREATE INDEX runs_enrichment_idx   ON runs(enrichment_state) WHERE enrichment_state = 'pending';
