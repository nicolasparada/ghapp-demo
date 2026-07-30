CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    github_id BIGINT NOT NULL UNIQUE,
    login TEXT NOT NULL,
    avatar_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS projects (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, slug)
);
CREATE INDEX IF NOT EXISTS projects_user_id_idx ON projects(user_id);

CREATE TABLE IF NOT EXISTS installations (
    id BIGSERIAL PRIMARY KEY,
    github_installation_id BIGINT NOT NULL UNIQUE,
    target_type TEXT NOT NULL,
    target_login TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS installations_target_login_idx ON installations(target_login);

CREATE TABLE IF NOT EXISTS repo_links (
    id BIGSERIAL PRIMARY KEY,
    installation_id BIGINT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    repo_full_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (installation_id, repo_full_name)
);
CREATE INDEX IF NOT EXISTS repo_links_repo_full_name_idx ON repo_links(repo_full_name);

CREATE TABLE IF NOT EXISTS project_repos (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repo_full_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, repo_full_name)
);
CREATE INDEX IF NOT EXISTS project_repos_repo_full_name_idx ON project_repos(repo_full_name);

CREATE TABLE IF NOT EXISTS runs (
    id BIGSERIAL PRIMARY KEY,
    repo_full_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    workflow_name TEXT NOT NULL DEFAULT '',
    job_workflow_ref TEXT NOT NULL DEFAULT '',
    job_name TEXT NOT NULL DEFAULT '',
    github_run_id BIGINT NOT NULL,
    github_job_id BIGINT NOT NULL,
    branch TEXT NOT NULL DEFAULT '',
    event_name TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    pr_number BIGINT,
    egress_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repo_full_name, github_run_id, github_job_id)
);
CREATE INDEX IF NOT EXISTS runs_repo_full_name_idx ON runs(repo_full_name);
CREATE INDEX IF NOT EXISTS runs_commit_sha_idx ON runs(commit_sha);
CREATE INDEX IF NOT EXISTS runs_created_at_idx ON runs(created_at DESC);
