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
	row := s.pool.QueryRow(ctx, `
		INSERT INTO users (github_id, login, avatar_url)
		VALUES ($1, $2, $3)
		ON CONFLICT (github_id)
		DO UPDATE SET
			login = EXCLUDED.login,
			avatar_url = EXCLUDED.avatar_url
		RETURNING id, github_id, login, avatar_url, created_at
	`, githubID, login, avatarURL)

	var u types.User
	if err := row.Scan(&u.ID, &u.GitHubID, &u.Login, &u.AvatarURL, &u.CreatedAt); err != nil {
		return types.User{}, fmt.Errorf("upsert user: %w", err)
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
		SELECT u.id, u.github_id, u.login, u.avatar_url, u.created_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token = $1 AND s.expires_at > NOW()
	`, token)

	var u types.User
	if err := row.Scan(&u.ID, &u.GitHubID, &u.Login, &u.AvatarURL, &u.CreatedAt); err != nil {
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

	for i := range 100 {
		slug := base
		if i > 0 {
			slug = fmt.Sprintf("%s-%d", base, i+1)
		}

		row := s.pool.QueryRow(ctx, `
			INSERT INTO projects (user_id, name, slug)
			VALUES ($1, $2, $3)
			RETURNING id, user_id, name, slug, created_at
		`, userID, name, slug)

		var p types.Project
		err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.Slug, &p.CreatedAt)
		if err == nil {
			return p, nil
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}

		return types.Project{}, fmt.Errorf("create project: %w", err)
	}

	return types.Project{}, errors.New("could not generate unique project slug")
}

func (s *Store) ListProjectsByUser(ctx context.Context, userID int64) ([]types.Project, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, slug, created_at
		FROM projects
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var projects []types.Project
	for rows.Next() {
		var p types.Project
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
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
		SELECT id, user_id, name, slug, created_at
		FROM projects
		WHERE user_id = $1 AND slug = $2
	`, userID, slug)

	var p types.Project
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return types.Project{}, ErrNotFound
		}
		return types.Project{}, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

func (s *Store) ListProjectRepos(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT repo_full_name
		FROM repo_links
		ORDER BY repo_full_name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list project repos: %w", err)
	}
	defer rows.Close()

	var repos []string
	for rows.Next() {
		var fullName string
		if err := rows.Scan(&fullName); err != nil {
			return nil, fmt.Errorf("scan project repo: %w", err)
		}
		repos = append(repos, fullName)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate project repos: %w", err)
	}
	return repos, nil
}

func (s *Store) ListAvailableRepoLinks(ctx context.Context) ([]types.RepoLink, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			rl.id,
			rl.installation_id,
			i.github_installation_id,
			i.target_type,
			i.target_login,
			rl.repo_full_name,
			rl.created_at
		FROM repo_links rl
		JOIN installations i ON i.id = rl.installation_id
		ORDER BY rl.repo_full_name ASC, i.target_login ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list available repo links: %w", err)
	}
	defer rows.Close()

	var links []types.RepoLink
	for rows.Next() {
		var l types.RepoLink
		if err := rows.Scan(
			&l.ID,
			&l.InstallationID,
			&l.GitHubInstallationID,
			&l.TargetType,
			&l.TargetLogin,
			&l.RepoFullName,
			&l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan repo link: %w", err)
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repo links: %w", err)
	}
	return links, nil
}

func (s *Store) ListRunsForProject(ctx context.Context, limit int) ([]types.Run, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			r.id,
			r.repo_full_name,
			r.commit_sha,
			r.workflow_name,
			r.job_workflow_ref,
			r.job_name,
			r.github_run_id,
			r.github_job_id,
			r.branch,
			r.event_name,
			r.actor,
			r.pr_number,
			r.egress_json,
			r.created_at
		FROM runs r
		WHERE EXISTS (
			SELECT 1
			FROM repo_links rl
			WHERE rl.repo_full_name = r.repo_full_name
		)
		ORDER BY r.created_at DESC
		LIMIT $1
	`, limit)
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

func (s *Store) GetRunForProject(ctx context.Context, runID int64) (types.Run, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			r.id,
			r.repo_full_name,
			r.commit_sha,
			r.workflow_name,
			r.job_workflow_ref,
			r.job_name,
			r.github_run_id,
			r.github_job_id,
			r.branch,
			r.event_name,
			r.actor,
			r.pr_number,
			r.egress_json,
			r.created_at
		FROM runs r
		WHERE r.id = $1
		AND EXISTS (
			SELECT 1
			FROM repo_links rl
			WHERE rl.repo_full_name = r.repo_full_name
		)
	`, runID)

	run, err := scanRun(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return types.Run{}, ErrNotFound
		}
		return types.Run{}, fmt.Errorf("get run for project: %w", err)
	}
	return run, nil
}

func scanRun(scanner interface {
	Scan(dest ...any) error
}) (types.Run, error) {
	var run types.Run
	var prNumber *int64
	if err := scanner.Scan(
		&run.ID,
		&run.RepoFullName,
		&run.CommitSHA,
		&run.WorkflowName,
		&run.JobWorkflowRef,
		&run.JobName,
		&run.GitHubRunID,
		&run.GitHubJobID,
		&run.Branch,
		&run.EventName,
		&run.Actor,
		&prNumber,
		&run.EgressJSON,
		&run.CreatedAt,
	); err != nil {
		return types.Run{}, fmt.Errorf("scan run: %w", err)
	}
	run.PRNumber = prNumber
	return run, nil
}

func (s *Store) UpsertInstallation(ctx context.Context, githubInstallationID int64, targetType, targetLogin string) (types.Installation, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO installations (github_installation_id, target_type, target_login)
		VALUES ($1, $2, $3)
		ON CONFLICT (github_installation_id)
		DO UPDATE SET
			target_type = EXCLUDED.target_type,
			target_login = EXCLUDED.target_login
		RETURNING id, github_installation_id, target_type, target_login, created_at
	`, githubInstallationID, targetType, targetLogin)

	var i types.Installation
	if err := row.Scan(&i.ID, &i.GitHubInstallationID, &i.TargetType, &i.TargetLogin, &i.CreatedAt); err != nil {
		return types.Installation{}, fmt.Errorf("upsert installation: %w", err)
	}
	return i, nil
}

func (s *Store) DeleteInstallation(ctx context.Context, githubInstallationID int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM installations WHERE github_installation_id = $1`, githubInstallationID)
	if err != nil {
		return fmt.Errorf("delete installation: %w", err)
	}
	return nil
}

func (s *Store) UpsertRepoLink(ctx context.Context, githubInstallationID int64, repoFullName string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO repo_links (installation_id, repo_full_name)
		VALUES (
			(SELECT id FROM installations WHERE github_installation_id = $1),
			$2
		)
		ON CONFLICT (installation_id, repo_full_name) DO NOTHING
	`, githubInstallationID, repoFullName)
	if err != nil {
		return fmt.Errorf("upsert repo link: %w", err)
	}
	return nil
}

func (s *Store) DeleteRepoLink(ctx context.Context, githubInstallationID int64, repoFullName string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM repo_links
		WHERE installation_id = (
			SELECT id FROM installations WHERE github_installation_id = $1
		) AND repo_full_name = $2
	`, githubInstallationID, repoFullName)
	if err != nil {
		return fmt.Errorf("delete repo link: %w", err)
	}
	return nil
}

func (s *Store) IsRepoLinked(ctx context.Context, repoFullName string) (bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM repo_links
			WHERE repo_full_name = $1
		)
	`, repoFullName)

	var exists bool
	if err := row.Scan(&exists); err != nil {
		return false, fmt.Errorf("check repo link: %w", err)
	}
	return exists, nil
}

func (s *Store) UpsertRun(ctx context.Context, run types.Run) error {
	if len(run.EgressJSON) == 0 {
		run.EgressJSON = json.RawMessage(`{}`)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO runs (
			repo_full_name,
			commit_sha,
			workflow_name,
			job_workflow_ref,
			job_name,
			github_run_id,
			github_job_id,
			branch,
			event_name,
			actor,
			pr_number,
			egress_json
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (repo_full_name, github_run_id, github_job_id)
		DO UPDATE SET
			commit_sha = EXCLUDED.commit_sha,
			workflow_name = EXCLUDED.workflow_name,
			job_workflow_ref = EXCLUDED.job_workflow_ref,
			job_name = EXCLUDED.job_name,
			branch = EXCLUDED.branch,
			event_name = EXCLUDED.event_name,
			actor = EXCLUDED.actor,
			pr_number = EXCLUDED.pr_number,
			egress_json = EXCLUDED.egress_json
	`,
		run.RepoFullName,
		run.CommitSHA,
		run.WorkflowName,
		run.JobWorkflowRef,
		run.JobName,
		run.GitHubRunID,
		run.GitHubJobID,
		run.Branch,
		run.EventName,
		run.Actor,
		run.PRNumber,
		run.EgressJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert run: %w", err)
	}
	return nil
}

var slugSanitizer = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(input string) string {
	slug := strings.ToLower(strings.TrimSpace(input))
	slug = slugSanitizer.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	return slug
}
