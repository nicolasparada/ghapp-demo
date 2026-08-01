package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nicolasparada/ghapp-demo/server/internal/types"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) UpsertUserFromGitHub(ctx context.Context, githubID int64, login, avatarURL string) (types.User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return types.User{}, fmt.Errorf("begin user upsert: %w", err)
	}
	defer tx.Rollback(ctx)

	providerUserID := fmt.Sprintf("%d", githubID)

	var userID int64
	err = tx.QueryRow(ctx, `
		SELECT user_id
		FROM user_identities
		WHERE provider = 'github' AND provider_user_id = $1
	`, providerUserID).Scan(&userID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return types.User{}, fmt.Errorf("lookup github identity: %w", err)
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO users (display_name, avatar_url)
			VALUES ($1, $2)
			RETURNING id
		`, login, avatarURL).Scan(&userID)
		if err != nil {
			return types.User{}, fmt.Errorf("insert user: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO user_identities (provider, provider_user_id, provider_login, user_id)
			VALUES ('github', $1, $2, $3)
		`, providerUserID, login, userID); err != nil {
			return types.User{}, fmt.Errorf("insert github identity: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE user_identities
			SET provider_login = $2
			WHERE provider = 'github' AND provider_user_id = $1
		`, providerUserID, login); err != nil {
			return types.User{}, fmt.Errorf("update github identity login: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET display_name = $2, avatar_url = $3
		WHERE id = $1
	`, userID, login, avatarURL); err != nil {
		return types.User{}, fmt.Errorf("update user profile: %w", err)
	}

	u, err := s.getUserByIDTx(ctx, tx, userID)
	if err != nil {
		return types.User{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return types.User{}, fmt.Errorf("commit user upsert: %w", err)
	}
	return u, nil
}

func (s *Store) CreateSession(ctx context.Context, userID int64, token string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (token, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, token, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) GetUserBySessionToken(ctx context.Context, token string) (*types.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			u.id,
			u.display_name,
			COALESCE(ui.provider_login, ''),
			u.email,
			u.avatar_url,
			u.created_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		LEFT JOIN user_identities ui
			ON ui.user_id = u.id
			AND ui.provider = 'github'
		WHERE s.token = $1 AND s.expires_at > NOW()
	`, token)

	var u types.User
	if err := row.Scan(&u.ID, &u.DisplayName, &u.Login, &u.Email, &u.AvatarURL, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by session token: %w", err)
	}
	return &u, nil
}

func (s *Store) CreateProject(ctx context.Context, userID int64, name string) (types.Project, error) {
	base := slugify(name)
	if base == "" {
		base = "project"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return types.Project{}, fmt.Errorf("begin create project: %w", err)
	}
	defer tx.Rollback(ctx)

	for i := range 100 {
		slug := base
		if i > 0 {
			slug = fmt.Sprintf("%s-%d", base, i+1)
		}

		var p types.Project
		err := tx.QueryRow(ctx, `
			INSERT INTO projects (created_by, name, slug)
			VALUES ($1, $2, $3)
			RETURNING id, created_by, name, slug, created_at
		`, userID, name, slug).Scan(&p.ID, &p.CreatedBy, &p.Name, &p.Slug, &p.CreatedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				continue
			}
			return types.Project{}, fmt.Errorf("create project: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO project_members (project_id, user_id, role)
			VALUES ($1, $2, 'owner')
		`, p.ID, userID); err != nil {
			return types.Project{}, fmt.Errorf("create project membership: %w", err)
		}
		p.Role = "owner"

		if err := tx.Commit(ctx); err != nil {
			return types.Project{}, fmt.Errorf("commit create project: %w", err)
		}
		return p, nil
	}

	return types.Project{}, errors.New("could not generate unique project slug")
}

func (s *Store) ListProjectsByUser(ctx context.Context, userID int64) ([]types.Project, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.created_by, pm.role, p.name, p.slug, p.created_at
		FROM project_members pm
		JOIN projects p ON p.id = pm.project_id
		WHERE pm.user_id = $1
		ORDER BY p.created_at DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var projects []types.Project
	for rows.Next() {
		var p types.Project
		if err := rows.Scan(&p.ID, &p.CreatedBy, &p.Role, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate projects: %w", err)
	}
	return projects, nil
}

func (s *Store) GetProjectBySlug(ctx context.Context, userID int64, slug string) (types.Project, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT p.id, p.created_by, pm.role, p.name, p.slug, p.created_at
		FROM projects p
		JOIN project_members pm ON pm.project_id = p.id
		WHERE pm.user_id = $1 AND p.slug = $2
	`, userID, slug)

	var p types.Project
	if err := row.Scan(&p.ID, &p.CreatedBy, &p.Role, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return types.Project{}, ErrNotFound
		}
		return types.Project{}, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

func (s *Store) ListProjectRepos(ctx context.Context, projectID int64) ([]types.Repo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			r.repo_id,
			r.full_name,
			r.owner,
			r.owner_id,
			r.visibility,
			r.synced_at,
			pr.bound_at,
			pr.revoked_at,
			r.visibility_source
		FROM project_repos pr
		JOIN repos r ON r.repo_id = pr.repo_id
		WHERE pr.project_id = $1 AND pr.revoked_at IS NULL
		ORDER BY r.full_name ASC
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list project repos: %w", err)
	}
	defer rows.Close()

	var repos []types.Repo
	for rows.Next() {
		var repo types.Repo
		repo.Bound = true
		if err := rows.Scan(
			&repo.RepoID,
			&repo.FullName,
			&repo.Owner,
			&repo.OwnerID,
			&repo.Visibility,
			&repo.SyncedAt,
			&repo.BoundAt,
			&repo.RevokedAt,
			&repo.UpdatedFrom,
		); err != nil {
			return nil, fmt.Errorf("scan project repo: %w", err)
		}
		repos = append(repos, repo)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate project repos: %w", err)
	}
	return repos, nil
}

func (s *Store) ListReposForProjectBinding(ctx context.Context, projectID int64, userID int64) ([]types.Repo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			r.repo_id,
			r.full_name,
			r.owner,
			r.owner_id,
			r.visibility,
			r.synced_at,
			r.visibility_source,
			pr.bound_at,
			pr.revoked_at,
			(pr.repo_id IS NOT NULL AND pr.revoked_at IS NULL) AS bound,
			(ura.repo_id IS NOT NULL) AS can_bind
		FROM repos r
		LEFT JOIN project_repos pr
			ON pr.project_id = $1
			AND pr.repo_id = r.repo_id
		LEFT JOIN user_repo_access ura
			ON ura.user_id = $2
			AND ura.repo_id = r.repo_id
		ORDER BY r.full_name ASC
	`, projectID, userID)
	if err != nil {
		return nil, fmt.Errorf("list bindable repos: %w", err)
	}
	defer rows.Close()

	var repos []types.Repo
	for rows.Next() {
		var repo types.Repo
		if err := rows.Scan(
			&repo.RepoID,
			&repo.FullName,
			&repo.Owner,
			&repo.OwnerID,
			&repo.Visibility,
			&repo.SyncedAt,
			&repo.UpdatedFrom,
			&repo.BoundAt,
			&repo.RevokedAt,
			&repo.Bound,
			&repo.CanBind,
		); err != nil {
			return nil, fmt.Errorf("scan bindable repo: %w", err)
		}
		repos = append(repos, repo)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate bindable repos: %w", err)
	}
	return repos, nil
}

func (s *Store) UserCanAccessRepoForBinding(ctx context.Context, userID int64, repoID int64) (bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_repo_access
			WHERE user_id = $1 AND repo_id = $2
		)
	`, userID, repoID)
	var ok bool
	if err := row.Scan(&ok); err != nil {
		return false, fmt.Errorf("check user repo access: %w", err)
	}
	return ok, nil
}

func (s *Store) BindRepoToProject(ctx context.Context, projectID int64, repoID int64, userID int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO project_repos (project_id, repo_id, bound_by, bound_at, revoked_at)
		VALUES ($1, $2, $3, NOW(), NULL)
		ON CONFLICT (project_id, repo_id)
		DO UPDATE SET
			bound_by = EXCLUDED.bound_by,
			bound_at = NOW(),
			revoked_at = NULL
	`, projectID, repoID, userID)
	if err != nil {
		return fmt.Errorf("bind repo: %w", err)
	}
	return nil
}

func (s *Store) UnbindRepoFromProject(ctx context.Context, projectID int64, repoID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE project_repos
		SET revoked_at = NOW()
		WHERE project_id = $1 AND repo_id = $2 AND revoked_at IS NULL
	`, projectID, repoID)
	if err != nil {
		return fmt.Errorf("unbind repo: %w", err)
	}
	return nil
}

func (s *Store) UpsertUserGitHubTokens(ctx context.Context, userID int64, accessEnc []byte, accessExp *time.Time, refreshEnc []byte, refreshExp *time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_github_tokens (
			user_id,
			access_token_enc,
			access_token_expires_at,
			refresh_token_enc,
			refresh_token_expires_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (user_id)
		DO UPDATE SET
			access_token_enc = EXCLUDED.access_token_enc,
			access_token_expires_at = EXCLUDED.access_token_expires_at,
			refresh_token_enc = EXCLUDED.refresh_token_enc,
			refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
			updated_at = NOW()
	`, userID, accessEnc, accessExp, refreshEnc, refreshExp)
	if err != nil {
		return fmt.Errorf("upsert user github tokens: %w", err)
	}
	return nil
}

func (s *Store) GetUserGitHubTokens(ctx context.Context, userID int64) (accessEnc []byte, accessExp *time.Time, refreshEnc []byte, refreshExp *time.Time, err error) {
	row := s.pool.QueryRow(ctx, `
		SELECT access_token_enc, access_token_expires_at, refresh_token_enc, refresh_token_expires_at
		FROM user_github_tokens
		WHERE user_id = $1
	`, userID)
	if err := row.Scan(&accessEnc, &accessExp, &refreshEnc, &refreshExp); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil, nil, ErrNotFound
		}
		return nil, nil, nil, nil, fmt.Errorf("get user github tokens: %w", err)
	}
	return accessEnc, accessExp, refreshEnc, refreshExp, nil
}

type UserAccessSync struct {
	SyncedAt    *time.Time
	AttemptedAt *time.Time
	LastError   *string
	ETag        *string
}

func (s *Store) GetUserAccessSync(ctx context.Context, userID int64) (UserAccessSync, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT synced_at, attempted_at, last_error, etag
		FROM user_access_syncs
		WHERE user_id = $1
	`, userID)
	var uas UserAccessSync
	if err := row.Scan(&uas.SyncedAt, &uas.AttemptedAt, &uas.LastError, &uas.ETag); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserAccessSync{}, ErrNotFound
		}
		return UserAccessSync{}, fmt.Errorf("get user access sync: %w", err)
	}
	return uas, nil
}

func (s *Store) UpsertUserAccessSync(ctx context.Context, userID int64, syncedAt *time.Time, attemptedAt time.Time, lastError *string, etag *string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_access_syncs (user_id, synced_at, attempted_at, last_error, etag)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id)
		DO UPDATE SET
			synced_at = EXCLUDED.synced_at,
			attempted_at = EXCLUDED.attempted_at,
			last_error = EXCLUDED.last_error,
			etag = EXCLUDED.etag
	`, userID, syncedAt, attemptedAt, lastError, etag)
	if err != nil {
		return fmt.Errorf("upsert user access sync: %w", err)
	}
	return nil
}

type UserRepoAccessRow struct {
	RepoID         int64
	InstallationID int64
}

func (s *Store) ReplaceUserRepoAccess(ctx context.Context, userID int64, rows []UserRepoAccessRow) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace user repo access: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM user_repo_access WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear user repo access: %w", err)
	}
	for _, row := range rows {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_repo_access (user_id, repo_id, github_installation_id)
			VALUES ($1, $2, $3)
		`, userID, row.RepoID, row.InstallationID); err != nil {
			return fmt.Errorf("insert user repo access: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit replace user repo access: %w", err)
	}
	return nil
}

func (s *Store) ListRunsForProject(ctx context.Context, projectID int64, limit int) ([]types.Run, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			r.id,
			r.public_id::text,
			r.repo_id,
			rp.full_name,
			rp.visibility,
			TRUE,
			r.commit_sha,
			r.workflow_name,
			r.job_workflow_ref,
			COALESCE(r.job_display_name, r.job_key),
			r.job_display_name,
			r.github_run_id,
			r.github_job_id,
			r.run_attempt,
			r.branch,
			r.event_name,
			r.actor,
			r.actor_id,
			r.pr_number,
			r.enrichment_state,
			r.egress_json,
			r.created_at
		FROM runs r
		JOIN repos rp ON rp.repo_id = r.repo_id
		JOIN project_repos pr ON pr.repo_id = r.repo_id
		WHERE pr.project_id = $1
		  AND pr.revoked_at IS NULL
		ORDER BY r.created_at DESC
		LIMIT $2
	`, projectID, limit)
	if err != nil {
		return nil, fmt.Errorf("list runs for project: %w", err)
	}
	defer rows.Close()

	var runs []types.Run
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs: %w", err)
	}
	return runs, nil
}

func (s *Store) GetRunByPublicID(ctx context.Context, publicID string, userID *int64) (types.Run, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			r.id,
			r.public_id::text,
			r.repo_id,
			rp.full_name,
			rp.visibility,
			($2::bigint IS NOT NULL AND EXISTS (
				SELECT 1
				FROM project_repos pr
				JOIN project_members pm ON pm.project_id = pr.project_id
				WHERE pr.repo_id    = r.repo_id
				  AND pr.revoked_at IS NULL
				  AND pm.user_id    = $2
			)),
			r.commit_sha,
			r.workflow_name,
			r.job_workflow_ref,
			COALESCE(r.job_display_name, r.job_key),
			r.job_display_name,
			r.github_run_id,
			r.github_job_id,
			r.run_attempt,
			r.branch,
			r.event_name,
			r.actor,
			r.actor_id,
			r.pr_number,
			r.enrichment_state,
			r.egress_json,
			r.created_at
		FROM runs r
		JOIN repos rp ON rp.repo_id = r.repo_id
		WHERE r.public_id = $1
		  AND (
			rp.visibility = 'public'
			OR ($2::bigint IS NOT NULL AND EXISTS (
				SELECT 1
				FROM project_repos pr
				JOIN project_members pm ON pm.project_id = pr.project_id
				WHERE pr.repo_id    = r.repo_id
				  AND pr.revoked_at IS NULL
				  AND pm.user_id    = $2
			))
		  )
	`, publicID, nullableInt64(userID))

	run, err := scanRun(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return types.Run{}, ErrNotFound
		}
		return types.Run{}, fmt.Errorf("get run by public id: %w", err)
	}
	return run, nil
}

func (s *Store) ListRunsForRepo(ctx context.Context, owner string, repo string, userID *int64, limit int) ([]types.Run, error) {
	if limit <= 0 {
		limit = 100
	}

	fullName := strings.TrimSpace(owner) + "/" + strings.TrimSpace(repo)
	rows, err := s.pool.Query(ctx, `
		SELECT
			r.id,
			r.public_id::text,
			r.repo_id,
			rp.full_name,
			rp.visibility,
			($2::bigint IS NOT NULL AND EXISTS (
				SELECT 1
				FROM project_repos pr
				JOIN project_members pm ON pm.project_id = pr.project_id
				WHERE pr.repo_id    = r.repo_id
				  AND pr.revoked_at IS NULL
				  AND pm.user_id    = $2
			)),
			r.commit_sha,
			r.workflow_name,
			r.job_workflow_ref,
			COALESCE(r.job_display_name, r.job_key),
			r.job_display_name,
			r.github_run_id,
			r.github_job_id,
			r.run_attempt,
			r.branch,
			r.event_name,
			r.actor,
			r.actor_id,
			r.pr_number,
			r.enrichment_state,
			r.egress_json,
			r.created_at
		FROM runs r
		JOIN repos rp ON rp.repo_id = r.repo_id
		WHERE rp.full_name = $1
		  AND (
			rp.visibility = 'public'
			OR ($2::bigint IS NOT NULL AND EXISTS (
				SELECT 1
				FROM project_repos pr
				JOIN project_members pm ON pm.project_id = pr.project_id
				WHERE pr.repo_id    = r.repo_id
				  AND pr.revoked_at IS NULL
				  AND pm.user_id    = $2
			))
		  )
		ORDER BY r.created_at DESC
		LIMIT $3
	`, fullName, nullableInt64(userID), limit)
	if err != nil {
		return nil, fmt.Errorf("list runs for repo: %w", err)
	}
	defer rows.Close()

	var runs []types.Run
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs for repo: %w", err)
	}
	return runs, nil
}

func scanRun(scanner interface {
	Scan(dest ...any) error
}) (types.Run, error) {
	var run types.Run
	if err := scanner.Scan(
		&run.ID,
		&run.PublicID,
		&run.RepoID,
		&run.RepoFullName,
		&run.RepoVisibility,
		&run.ViewerIsMember,
		&run.CommitSHA,
		&run.WorkflowName,
		&run.JobWorkflowRef,
		&run.JobName,
		&run.JobDisplayName,
		&run.GitHubRunID,
		&run.GitHubJobID,
		&run.RunAttempt,
		&run.Branch,
		&run.EventName,
		&run.Actor,
		&run.ActorID,
		&run.PRNumber,
		&run.EnrichmentState,
		&run.EgressJSON,
		&run.CreatedAt,
	); err != nil {
		return types.Run{}, fmt.Errorf("scan run: %w", err)
	}
	return run, nil
}

func (s *Store) UpsertInstallation(ctx context.Context, githubInstallationID, githubAccountID int64, targetType, targetLogin, repositorySelection string) (types.Installation, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO installations (
			github_installation_id,
			github_account_id,
			target_type,
			target_login,
			repository_selection,
			synced_at,
			deleted_at
		)
		VALUES ($1, $2, $3, $4, $5, NOW(), NULL)
		ON CONFLICT (github_installation_id)
		DO UPDATE SET
			github_account_id = EXCLUDED.github_account_id,
			target_type = EXCLUDED.target_type,
			target_login = EXCLUDED.target_login,
			repository_selection = EXCLUDED.repository_selection,
			synced_at = NOW(),
			deleted_at = NULL
		RETURNING github_installation_id, github_account_id, target_type, target_login, repository_selection, created_at, synced_at, deleted_at
	`, githubInstallationID, githubAccountID, targetType, targetLogin, nullableString(repositorySelection))

	var i types.Installation
	if err := row.Scan(
		&i.GitHubInstallationID,
		&i.GitHubAccountID,
		&i.TargetType,
		&i.TargetLogin,
		&i.RepositorySelection,
		&i.CreatedAt,
		&i.SyncedAt,
		&i.DeletedAt,
	); err != nil {
		return types.Installation{}, fmt.Errorf("upsert installation: %w", err)
	}
	return i, nil
}

func (s *Store) DeleteInstallation(ctx context.Context, githubInstallationID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE installations
		SET deleted_at = NOW(), synced_at = NOW()
		WHERE github_installation_id = $1
	`, githubInstallationID)
	if err != nil {
		return fmt.Errorf("soft delete installation: %w", err)
	}
	return nil
}

func (s *Store) UpsertRepo(ctx context.Context, repo types.Repo) error {
	visibility := strings.ToLower(strings.TrimSpace(repo.Visibility))
	if visibility == "" {
		visibility = "private"
	}

	visibilitySource := strings.ToLower(strings.TrimSpace(repo.UpdatedFrom))
	switch visibilitySource {
	case "oidc", "api":
	default:
		visibilitySource = "oidc"
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO repos (repo_id, full_name, owner, owner_id, visibility, visibility_source, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (repo_id)
		DO UPDATE SET
			full_name = EXCLUDED.full_name,
			owner = EXCLUDED.owner,
			owner_id = EXCLUDED.owner_id,
			visibility = EXCLUDED.visibility,
			visibility_source = EXCLUDED.visibility_source,
			synced_at = NOW()
	`, repo.RepoID, repo.FullName, repo.Owner, repo.OwnerID, visibility, visibilitySource)
	if err != nil {
		return fmt.Errorf("upsert repo: %w", err)
	}
	return nil
}

func (s *Store) CountRunsByOwnerSince(ctx context.Context, ownerID int64, since time.Time) (int64, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM runs r
		JOIN repos rp ON rp.repo_id = r.repo_id
		WHERE rp.owner_id = $1
		  AND r.created_at >= $2
	`, ownerID, since)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count runs by owner since: %w", err)
	}
	return count, nil
}

func (s *Store) UpsertRun(ctx context.Context, run types.Run) error {
	if len(run.EgressJSON) == 0 {
		run.EgressJSON = json.RawMessage(`{}`)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO runs (
			repo_id,
			commit_sha,
			workflow_name,
			job_workflow_ref,
			github_run_id,
			branch,
			event_name,
			actor,
			pr_number,
			egress_json,
			run_attempt,
			workflow_ref,
			workflow_sha,
			job_workflow_sha,
			actor_id,
			runner_environment,
			execution_id,
			job_key,
			runner_name,
			runner_os,
			capture_started_at,
			capture_ended_at,
			payload_sha256,
			github_job_id,
			job_display_name
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
		ON CONFLICT (repo_id, execution_id)
		DO UPDATE SET
			commit_sha = EXCLUDED.commit_sha,
			workflow_name = EXCLUDED.workflow_name,
			job_workflow_ref = EXCLUDED.job_workflow_ref,
			github_run_id = EXCLUDED.github_run_id,
			branch = EXCLUDED.branch,
			event_name = EXCLUDED.event_name,
			actor = EXCLUDED.actor,
			pr_number = EXCLUDED.pr_number,
			egress_json = EXCLUDED.egress_json,
			run_attempt = EXCLUDED.run_attempt,
			workflow_ref = EXCLUDED.workflow_ref,
			workflow_sha = EXCLUDED.workflow_sha,
			job_workflow_sha = EXCLUDED.job_workflow_sha,
			actor_id = EXCLUDED.actor_id,
			runner_environment = EXCLUDED.runner_environment,
			job_key = EXCLUDED.job_key,
			runner_name = EXCLUDED.runner_name,
			runner_os = EXCLUDED.runner_os,
			capture_started_at = EXCLUDED.capture_started_at,
			capture_ended_at = EXCLUDED.capture_ended_at,
			payload_sha256 = EXCLUDED.payload_sha256,
			github_job_id = EXCLUDED.github_job_id,
			job_display_name = EXCLUDED.job_display_name
	`,
		run.RepoID,
		run.CommitSHA,
		run.WorkflowName,
		run.JobWorkflowRef,
		run.GitHubRunID,
		run.Branch,
		run.EventName,
		run.Actor,
		run.PRNumber,
		run.EgressJSON,
		run.RunAttempt,
		run.WorkflowRef,
		run.WorkflowSHA,
		run.JobWorkflowSHA,
		run.ActorID,
		run.RunnerEnvironment,
		run.ExecutionID,
		run.JobKey,
		run.RunnerName,
		run.RunnerOS,
		run.CaptureStartedAt,
		run.CaptureEndedAt,
		run.PayloadSHA256,
		run.GitHubJobID,
		run.JobDisplayName,
	)
	if err != nil {
		return fmt.Errorf("upsert run: %w", err)
	}
	return nil
}

type RepoSyncRow struct {
	RepoID     int64
	FullName   string
	Owner      string
	OwnerID    int64
	Visibility string
}

func (s *Store) ListReposForSync(ctx context.Context) ([]RepoSyncRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT repo_id, full_name, owner, owner_id, visibility
		FROM repos
	`)
	if err != nil {
		return nil, fmt.Errorf("list repos for sync: %w", err)
	}
	defer rows.Close()

	out := make([]RepoSyncRow, 0, 64)
	for rows.Next() {
		var row RepoSyncRow
		if err := rows.Scan(&row.RepoID, &row.FullName, &row.Owner, &row.OwnerID, &row.Visibility); err != nil {
			return nil, fmt.Errorf("scan repo for sync: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repos for sync: %w", err)
	}
	return out, nil
}

func (s *Store) GetAnyInstallationIDForRepo(ctx context.Context, repoID int64) (*int64, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT ir.github_installation_id
		FROM installation_repos ir
		JOIN installations i ON i.github_installation_id = ir.github_installation_id
		WHERE ir.repo_id = $1 AND i.deleted_at IS NULL
		ORDER BY ir.github_installation_id
		LIMIT 1
	`, repoID)
	var installationID int64
	if err := row.Scan(&installationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get installation for repo: %w", err)
	}
	return &installationID, nil
}

func (s *Store) ReplaceInstallationRepos(ctx context.Context, installationID int64, repos []types.Repo) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace installation repos: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM installation_repos WHERE github_installation_id = $1`, installationID); err != nil {
		return fmt.Errorf("clear installation repos: %w", err)
	}
	for _, repo := range repos {
		if _, err := tx.Exec(ctx, `
			INSERT INTO installation_repos (github_installation_id, repo_id, synced_at)
			VALUES ($1, $2, NOW())
		`, installationID, repo.RepoID); err != nil {
			return fmt.Errorf("insert installation repo: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit replace installation repos: %w", err)
	}
	return nil
}

func (s *Store) ListRepoCoverageCandidates(ctx context.Context) ([]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT repo_id FROM repos`)
	if err != nil {
		return nil, fmt.Errorf("list coverage candidates: %w", err)
	}
	defer rows.Close()
	out := make([]int64, 0, 64)
	for rows.Next() {
		var repoID int64
		if err := rows.Scan(&repoID); err != nil {
			return nil, err
		}
		out = append(out, repoID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpsertRepoCoverage(ctx context.Context, repoID int64, installationID *int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO repo_coverage (repo_id, github_installation_id, checked_at, uncovered_since)
		VALUES ($1, $2, NOW(), CASE WHEN $2 IS NULL THEN NOW() ELSE NULL END)
		ON CONFLICT (repo_id)
		DO UPDATE SET
			github_installation_id = EXCLUDED.github_installation_id,
			checked_at = NOW(),
			uncovered_since = CASE
				WHEN EXCLUDED.github_installation_id IS NULL
					THEN COALESCE(repo_coverage.uncovered_since, NOW())
				ELSE NULL
			END
	`, repoID, installationID)
	if err != nil {
		return fmt.Errorf("upsert repo coverage: %w", err)
	}
	return nil
}

func (s *Store) RevokeUncoveredProjectBindings(ctx context.Context) (int64, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE project_repos pr
		SET revoked_at = NOW()
		FROM repo_coverage rc
		WHERE pr.repo_id = rc.repo_id
		  AND pr.revoked_at IS NULL
		  AND rc.github_installation_id IS NULL
	`)
	if err != nil {
		return 0, fmt.Errorf("revoke uncovered bindings: %w", err)
	}
	return ct.RowsAffected(), nil
}

func (s *Store) PurgeUnretainedRuns(ctx context.Context, minUncoveredAge time.Duration) (int64, error) {
	seconds := int64(minUncoveredAge.Seconds())
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM runs r
		USING repos rp, repo_coverage rc
		WHERE r.repo_id = rp.repo_id
		  AND r.repo_id = rc.repo_id
		  AND rp.visibility <> 'public'
		  AND rc.uncovered_since IS NOT NULL
		  AND rc.uncovered_since < NOW() - ($1::bigint * INTERVAL '1 second')
		  AND NOT EXISTS (
			SELECT 1
			FROM project_repos pr
			WHERE pr.repo_id = r.repo_id
			  AND pr.revoked_at IS NULL
		  )
	`, seconds)
	if err != nil {
		return 0, fmt.Errorf("purge runs: %w", err)
	}
	return ct.RowsAffected(), nil
}

type EnrichmentGroup struct {
	RepoID     int64
	Owner      string
	RepoName   string
	RunID      int64
	RunAttempt int
}

type EnrichmentRunRow struct {
	ID               int64
	RunnerName       string
	CaptureStartedAt *time.Time
	CaptureEndedAt   *time.Time
}

func (s *Store) ListPendingEnrichmentGroups(ctx context.Context, limit int) ([]EnrichmentGroup, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT r.repo_id, rp.owner, split_part(rp.full_name, '/', 2) AS repo_name, r.github_run_id, r.run_attempt
		FROM runs r
		JOIN repos rp ON rp.repo_id = r.repo_id
		WHERE r.enrichment_state = 'pending'
		ORDER BY r.created_at ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending enrichment groups: %w", err)
	}
	defer rows.Close()
	out := make([]EnrichmentGroup, 0, limit)
	for rows.Next() {
		var g EnrichmentGroup
		if err := rows.Scan(&g.RepoID, &g.Owner, &g.RepoName, &g.RunID, &g.RunAttempt); err != nil {
			return nil, fmt.Errorf("scan enrichment group: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enrichment groups: %w", err)
	}
	return out, nil
}

func (s *Store) ListRunsForEnrichmentGroup(ctx context.Context, repoID int64, runID int64, runAttempt int) ([]EnrichmentRunRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, runner_name, capture_started_at, capture_ended_at
		FROM runs
		WHERE repo_id = $1
		  AND github_run_id = $2
		  AND run_attempt = $3
		  AND enrichment_state = 'pending'
	`, repoID, runID, runAttempt)
	if err != nil {
		return nil, fmt.Errorf("list runs for enrichment group: %w", err)
	}
	defer rows.Close()
	out := make([]EnrichmentRunRow, 0, 8)
	for rows.Next() {
		var row EnrichmentRunRow
		if err := rows.Scan(&row.ID, &row.RunnerName, &row.CaptureStartedAt, &row.CaptureEndedAt); err != nil {
			return nil, fmt.Errorf("scan enrichment run: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enrichment runs: %w", err)
	}
	return out, nil
}

func (s *Store) MarkRunEnrichmentUnavailable(ctx context.Context, runID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE runs SET enrichment_state = 'unavailable' WHERE id = $1`, runID)
	if err != nil {
		return fmt.Errorf("mark run enrichment unavailable: %w", err)
	}
	return nil
}

func (s *Store) MarkRunEnrichmentAmbiguous(ctx context.Context, runID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE runs SET enrichment_state = 'ambiguous' WHERE id = $1`, runID)
	if err != nil {
		return fmt.Errorf("mark run enrichment ambiguous: %w", err)
	}
	return nil
}

func (s *Store) MarkRunEnrichmentMatched(ctx context.Context, runID int64, githubJobID int64, name string, conclusion string, startedAt *time.Time, completedAt *time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE runs
		SET enrichment_state = 'matched',
			github_job_id = $2,
			job_display_name = $3,
			job_conclusion = $4,
			job_started_at = $5,
			job_completed_at = $6
		WHERE id = $1
	`, runID, githubJobID, nullableString(name), nullableString(conclusion), startedAt, completedAt)
	if err != nil {
		return fmt.Errorf("mark run enrichment matched: %w", err)
	}
	return nil
}

func (s *Store) UpsertInstallationFromPull(ctx context.Context, installationID, accountID int64, targetType, targetLogin, repositorySelection string, deleted bool) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO installations (
			github_installation_id,
			github_account_id,
			target_type,
			target_login,
			repository_selection,
			synced_at,
			deleted_at
		)
		VALUES ($1,$2,$3,$4,$5,NOW(),CASE WHEN $6 THEN NOW() ELSE NULL END)
		ON CONFLICT (github_installation_id)
		DO UPDATE SET
			github_account_id = EXCLUDED.github_account_id,
			target_type = EXCLUDED.target_type,
			target_login = EXCLUDED.target_login,
			repository_selection = EXCLUDED.repository_selection,
			synced_at = NOW(),
			deleted_at = CASE WHEN $6 THEN NOW() ELSE NULL END
	`, installationID, accountID, targetType, targetLogin, nullableString(repositorySelection), deleted)
	if err != nil {
		return fmt.Errorf("upsert installation from pull: %w", err)
	}
	return nil
}

func (s *Store) MarkInstallationsMissingFromPullDeleted(ctx context.Context, keepIDs []int64) error {
	if len(keepIDs) == 0 {
		_, err := s.pool.Exec(ctx, `UPDATE installations SET deleted_at = NOW(), synced_at = NOW() WHERE deleted_at IS NULL`)
		if err != nil {
			return fmt.Errorf("mark missing installations deleted: %w", err)
		}
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE installations
		SET deleted_at = NOW(), synced_at = NOW()
		WHERE deleted_at IS NULL
		  AND github_installation_id <> ALL($1)
	`, keepIDs)
	if err != nil {
		return fmt.Errorf("mark missing installations deleted: %w", err)
	}
	return nil
}

func (s *Store) getUserByIDTx(ctx context.Context, tx pgx.Tx, userID int64) (types.User, error) {
	row := tx.QueryRow(ctx, `
		SELECT
			u.id,
			u.display_name,
			COALESCE(ui.provider_login, ''),
			u.email,
			u.avatar_url,
			u.created_at
		FROM users u
		LEFT JOIN user_identities ui
			ON ui.user_id = u.id
			AND ui.provider = 'github'
		WHERE u.id = $1
	`, userID)

	var u types.User
	if err := row.Scan(&u.ID, &u.DisplayName, &u.Login, &u.Email, &u.AvatarURL, &u.CreatedAt); err != nil {
		return types.User{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

func nullableInt64(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullableString(v string) any {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return v
}

var slugSanitizer = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(input string) string {
	slug := strings.ToLower(strings.TrimSpace(input))
	slug = slugSanitizer.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	return slug
}
