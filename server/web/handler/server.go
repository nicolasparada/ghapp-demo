package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nicolasparada/ghapp-demo/server/internal/auth"
	"github.com/nicolasparada/ghapp-demo/server/internal/githubapp"
	"github.com/nicolasparada/ghapp-demo/server/internal/oidc"
	"github.com/nicolasparada/ghapp-demo/server/internal/postgres"
	"github.com/nicolasparada/ghapp-demo/server/internal/runsauth"
	"github.com/nicolasparada/ghapp-demo/server/internal/types"
	"github.com/nicolasparada/ghapp-demo/server/web"
)

type Config struct {
	BaseURL              string
	GitHubClientID       string
	GitHubClientSecret   string
	GitHubAppInstallURL  string
	GitHubAppSettingsURL string
}

type Server struct {
	cfg                  Config
	store                *postgres.Store
	renderer             *web.Renderer
	secureCookies        bool
	githubAppClient      *githubapp.Client
	userAccessSyncMu     sync.Map
	oidcVerifier         *oidc.Verifier
	runsTokenManager     *runsauth.TokenManager
	accessCacheTTL       time.Duration
	accessMaxStaleness   time.Duration
	ingestOwnerLimiter   *fixedWindowLimiter
	publicRouteIPLimiter *fixedWindowLimiter
	ownerRunQuotaPerDay  int64
}

type pageData struct {
	Title       string
	CurrentUser *types.User
	Error       string
	Warning     string
}

type dashboardData struct {
	pageData
	Projects []types.Project
}

type connectData struct {
	pageData
	Project              types.Project
	Repos                []types.Repo
	GitHubAppInstallURL  string
	GitHubAppSettingsURL string
	UsingStaleAccess     bool
}

type projectData struct {
	pageData
	Project types.Project
	Repos   []types.Repo
	Runs    []types.Run
}

type repoRunsData struct {
	pageData
	RepoOwner string
	RepoName  string
	Runs      []types.Run
}

type runDetailData struct {
	pageData
	Run             types.Run
	Summary         runSummaryView
	RepoOwner       string
	RepoName        string
	ShowMemberViews bool
}

type runSummaryView struct {
	LineageRootLabel string
	LineageRoots     []lineageTreeNodeView
	ErrorMessages    []string
}

type lineageTreeNodeView struct {
	Label        string
	DirectEgress int
	TotalEgress  int
	Egress       []lineageEgressNodeView
	Children     []lineageTreeNodeView
}

type lineageEgressNodeView struct {
	Target string
	Count  int
}

type runSummaryPayload struct {
	SchemaVersion  string               `json:"schema_version"`
	CaptureBackend string               `json:"capture_backend"`
	TotalEvents    int                  `json:"total_events"`
	DroppedEvents  int                  `json:"dropped_events"`
	DroppedLines   int                  `json:"dropped_lines"`
	Errors         []string             `json:"errors"`
	Events         []runEventPayload    `json:"events"`
	LineageTree    []lineageTreePayload `json:"lineage_tree"`
}

type runEventPayload struct {
	UnixNanos   uint64             `json:"unix_nanos"`
	Family      string             `json:"family"`
	Destination string             `json:"destination"`
	Port        int                `json:"port"`
	Lineage     []lineageEventNode `json:"lineage"`
}

type lineageEventNode struct {
	PID     int64  `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
}

type lineageTreePayload struct {
	NodeType       string                 `json:"node_type"`
	PID            int64                  `json:"pid"`
	PPID           int64                  `json:"ppid"`
	StartTimeTicks *uint64                `json:"start_time_ticks"`
	Name           string                 `json:"name"`
	Cmdline        string                 `json:"cmdline"`
	Exe            string                 `json:"exe"`
	DirectEgress   int                    `json:"direct_egress_events"`
	TotalEgress    int                    `json:"total_egress_events"`
	Egress         []lineageEgressPayload `json:"egress"`
	Children       []lineageTreePayload   `json:"children"`
}

type lineageEgressPayload struct {
	NodeType       string `json:"node_type"`
	Family         string `json:"family"`
	Destination    string `json:"destination"`
	Port           int    `json:"port"`
	Count          int    `json:"count"`
	FirstUnixNanos uint64 `json:"first_unix_nanos"`
	LastUnixNanos  uint64 `json:"last_unix_nanos"`
}

type runTokenRequest struct {
	PayloadSHA256    string `json:"payload_sha256"`
	JobName          string `json:"job_name"`
	JobKey           string `json:"job_key"`
	ExecutionID      string `json:"execution_id"`
	RunnerName       string `json:"runner_name"`
	RunnerOS         string `json:"runner_os"`
	CaptureStartedAt string `json:"capture_started_at"`
	CaptureEndedAt   string `json:"capture_ended_at"`
}

type userContextKey struct{}

var (
	currentUserContextKey = userContextKey{}
	errMissingUserContext = errors.New("missing user in request context")
	pullRefPattern        = regexp.MustCompile(`^refs/pull/(\d+)/(merge|head)$`)
	sha256HexPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

const (
	ownerIngestRatePerMinute       = 120
	publicRouteRatePerMinute       = 240
	ownerRunQuotaPerDay      int64 = 5000
)

type fixedWindowLimiter struct {
	mu   sync.Mutex
	hits map[string]fixedWindowCounter
}

type fixedWindowCounter struct {
	windowStart time.Time
	count       int
}

func newFixedWindowLimiter() *fixedWindowLimiter {
	return &fixedWindowLimiter{hits: make(map[string]fixedWindowCounter)}
}

func (l *fixedWindowLimiter) Allow(key string, limit int, window time.Duration, now time.Time) bool {
	if l == nil {
		return true
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	if limit <= 0 {
		return true
	}
	if window <= 0 {
		window = time.Minute
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	hit, ok := l.hits[key]
	if !ok || now.Sub(hit.windowStart) >= window {
		l.hits[key] = fixedWindowCounter{windowStart: now, count: 1}
		return true
	}
	if hit.count >= limit {
		return false
	}
	hit.count++
	l.hits[key] = hit
	return true
}

func UserFromContext(ctx context.Context) *types.User {
	user, _ := ctx.Value(currentUserContextKey).(*types.User)
	return user
}

func New(
	cfg Config,
	store *postgres.Store,
	renderer *web.Renderer,
	githubAppClient *githubapp.Client,
	oidcVerifier *oidc.Verifier,
	runsTokenManager *runsauth.TokenManager,
) *Server {
	return &Server{
		cfg:                  cfg,
		store:                store,
		renderer:             renderer,
		secureCookies:        strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://"),
		githubAppClient:      githubAppClient,
		oidcVerifier:         oidcVerifier,
		runsTokenManager:     runsTokenManager,
		accessCacheTTL:       5 * time.Minute,
		accessMaxStaleness:   24 * time.Hour,
		ingestOwnerLimiter:   newFixedWindowLimiter(),
		publicRouteIPLimiter: newFixedWindowLimiter(),
		ownerRunQuotaPerDay:  ownerRunQuotaPerDay,
	}
}

func (a *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.StripPrefix("/static/", web.StaticHandler()))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /{$}", a.handleRoot)
	mux.HandleFunc("GET /auth/github", a.handleGitHubLogin)
	mux.HandleFunc("GET /auth/github/callback", a.handleGitHubCallback)
	mux.HandleFunc("POST /auth/logout", a.handleLogout)

	mux.Handle("GET /dashboard", a.requireUser(http.HandlerFunc(a.handleDashboard)))
	mux.Handle("POST /projects", a.requireUser(http.HandlerFunc(a.handleCreateProject)))
	mux.Handle("GET /projects/{slug}", a.requireUser(http.HandlerFunc(a.handleProject)))
	mux.Handle("GET /projects/{slug}/repos", a.requireUser(http.HandlerFunc(a.handleConnectReposPage)))
	mux.Handle("POST /projects/{slug}/repos/bind", a.requireUser(http.HandlerFunc(a.handleBindRepo)))
	mux.Handle("POST /projects/{slug}/repos/unbind", a.requireUser(http.HandlerFunc(a.handleUnbindRepo)))
	mux.Handle("GET /projects/{slug}/members", a.requireUser(http.HandlerFunc(a.handleProjectMembersPage)))
	mux.HandleFunc("GET /runs/{publicID}", a.handleRunDetail)
	mux.HandleFunc("GET /r/{owner}/{repo}", a.handleRepoRuns)

	mux.HandleFunc("POST /runs/token", a.handleRunsToken)
	mux.HandleFunc("POST /runs", a.handleRunsIngest)

	h := http.Handler(mux)
	h = a.loadCurrentUser(h)
	h = RecoveryMiddleware(h)
	h = LoggingMiddleware(h)
	h = http.TimeoutHandler(h, 30*time.Second, "request timed out")
	return h
}

func (a *Server) loadCurrentUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := auth.ReadSessionToken(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		user, err := a.store.GetUserBySessionToken(r.Context(), token)
		if err != nil {
			a.renderError(w, http.StatusInternalServerError, "failed to load user session")
			return
		}

		if user == nil {
			auth.ClearSessionCookie(w, a.secureCookies)
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), currentUserContextKey, user)))
	})
}

func (a *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromContext(r.Context()) == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Server) userFromRequest(r *http.Request) (*types.User, error) {
	user := UserFromContext(r.Context())
	if user == nil {
		return nil, errMissingUserContext
	}
	return user, nil
}

func (a *Server) projectFromPath(r *http.Request, userID int64) (types.Project, error) {
	slug := r.PathValue("slug")
	return a.store.GetProjectBySlug(r.Context(), userID, slug)
}

func (a *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if UserFromContext(r.Context()) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if err := a.renderer.Render(w, "login.html", pageData{Title: "Login"}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	if a.githubAppClient == nil {
		a.renderError(w, http.StatusServiceUnavailable, "GitHub App login is not configured")
		return
	}

	state, err := auth.NewToken()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to generate oauth state")
		return
	}
	auth.SetOAuthStateCookie(w, state, a.secureCookies)

	url := a.githubAppClient.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if a.githubAppClient == nil {
		a.renderError(w, http.StatusServiceUnavailable, "GitHub App login is not configured")
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		a.renderError(w, http.StatusBadRequest, "missing oauth state or code")
		return
	}

	cookieState, ok := auth.ReadOAuthStateCookie(r)
	if !ok || cookieState != state {
		auth.ClearOAuthStateCookie(w, a.secureCookies)
		a.renderError(w, http.StatusUnauthorized, "invalid oauth state")
		return
	}
	auth.ClearOAuthStateCookie(w, a.secureCookies)

	userToken, err := a.githubAppClient.ExchangeUserCode(r.Context(), code)
	if err != nil {
		a.renderError(w, http.StatusBadGateway, "failed to exchange oauth code")
		return
	}

	ghUser, err := a.githubAppClient.GitHubUser(r.Context(), userToken.AccessToken)
	if err != nil {
		a.renderError(w, http.StatusBadGateway, "failed to fetch github profile")
		return
	}

	user, err := a.store.UpsertUserFromGitHub(r.Context(), ghUser.GetID(), ghUser.GetLogin(), ghUser.GetAvatarURL())
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to persist user")
		return
	}

	accessEnc, err := a.githubAppClient.EncryptToken(userToken.AccessToken)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to encrypt access token")
		return
	}
	refreshEnc := []byte(nil)
	if strings.TrimSpace(userToken.RefreshToken) != "" {
		refreshEnc, err = a.githubAppClient.EncryptToken(userToken.RefreshToken)
		if err != nil {
			a.renderError(w, http.StatusInternalServerError, "failed to encrypt refresh token")
			return
		}
	}
	if err := a.store.UpsertUserGitHubTokens(r.Context(), user.ID, accessEnc, userToken.AccessTokenExpiresAt, refreshEnc, userToken.RefreshTokenExpiresAt); err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to persist github tokens")
		return
	}

	sessionToken, err := auth.NewToken()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := a.store.CreateSession(r.Context(), user.ID, sessionToken, expiresAt); err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to store session")
		return
	}
	auth.SetSessionCookie(w, sessionToken, expiresAt, a.secureCookies)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (a *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.ReadSessionToken(r)
	if ok {
		if err := a.store.DeleteSession(r.Context(), token); err != nil {
			log.Printf("delete session: %v", err)
		}
	}
	auth.ClearSessionCookie(w, a.secureCookies)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	projects, err := a.store.ListProjectsByUser(r.Context(), user.ID)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list projects")
		return
	}

	if err := a.renderer.Render(w, "dashboard.html", dashboardData{
		pageData: pageData{Title: "Dashboard", CurrentUser: user},
		Projects: projects,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "invalid form")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		a.renderError(w, http.StatusBadRequest, "project name is required")
		return
	}

	project, err := a.store.CreateProject(r.Context(), user.ID, name)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to create project")
		return
	}

	http.Redirect(w, r, "/projects/"+project.Slug, http.StatusSeeOther)
}

func (a *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	project, err := a.projectFromPath(r, user.ID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "project not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load project")
		return
	}

	repos, err := a.store.ListProjectRepos(r.Context(), project.ID)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list project repositories")
		return
	}

	runs, err := a.store.ListRunsForProject(r.Context(), project.ID, 100)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list runs")
		return
	}

	if err := a.renderer.Render(w, "project.html", projectData{
		pageData: pageData{Title: project.Name, CurrentUser: user},
		Project:  project,
		Repos:    repos,
		Runs:     runs,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	if !a.allowPublicRouteRequest(w, r) {
		return
	}

	var userID *int64
	currentUser := UserFromContext(r.Context())
	if currentUser != nil {
		userID = &currentUser.ID
	}
	a.applyPublicCacheHeaders(w, currentUser == nil)

	publicID := strings.TrimSpace(r.PathValue("publicID"))
	if publicID == "" {
		a.renderError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	run, err := a.store.GetRunByPublicID(r.Context(), publicID, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			// 404 on authz denial to avoid private repo enumeration.
			a.renderError(w, http.StatusNotFound, "run not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load run")
		return
	}

	owner, repo := splitRepoFullName(run.RepoFullName)
	summary := buildRunSummaryView(run, run.ViewerIsMember)

	if err := a.renderer.Render(w, "run.html", runDetailData{
		pageData:        pageData{Title: "Run details", CurrentUser: currentUser},
		Run:             run,
		Summary:         summary,
		RepoOwner:       owner,
		RepoName:        repo,
		ShowMemberViews: run.ViewerIsMember,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleRepoRuns(w http.ResponseWriter, r *http.Request) {
	if !a.allowPublicRouteRequest(w, r) {
		return
	}

	owner := strings.TrimSpace(r.PathValue("owner"))
	repo := strings.TrimSpace(r.PathValue("repo"))
	if owner == "" || repo == "" {
		a.renderError(w, http.StatusNotFound, "repository not found")
		return
	}

	var userID *int64
	currentUser := UserFromContext(r.Context())
	if currentUser != nil {
		userID = &currentUser.ID
	}
	a.applyPublicCacheHeaders(w, currentUser == nil)

	runs, err := a.store.ListRunsForRepo(r.Context(), owner, repo, userID, 100)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list runs")
		return
	}
	if len(runs) == 0 {
		// 404 on authz denial (and empty/non-existent) to avoid private repo enumeration.
		a.renderError(w, http.StatusNotFound, "repository not found")
		return
	}

	if err := a.renderer.Render(w, "repo_runs.html", repoRunsData{
		pageData:  pageData{Title: owner + "/" + repo, CurrentUser: currentUser},
		RepoOwner: owner,
		RepoName:  repo,
		Runs:      runs,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) allowPublicRouteRequest(w http.ResponseWriter, r *http.Request) bool {
	ip := requestIP(r)
	if !a.publicRouteIPLimiter.Allow(ip, publicRouteRatePerMinute, time.Minute, time.Now()) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

func (a *Server) applyPublicCacheHeaders(w http.ResponseWriter, anonymous bool) {
	w.Header().Add("Vary", "Cookie")
	if anonymous {
		w.Header().Set("Cache-Control", "public, max-age=30")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
}

func requestIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			first := strings.TrimSpace(parts[0])
			if first != "" {
				return first
			}
		}
	}
	hostPort := strings.TrimSpace(r.RemoteAddr)
	if hostPort == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err == nil && strings.TrimSpace(host) != "" {
		return host
	}
	return hostPort
}

func (a *Server) handleConnectReposPage(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	project, err := a.projectFromPath(r, user.ID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "project not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load project")
		return
	}

	usingStaleAccess, err := a.ensureUserRepoAccess(r.Context(), user.ID)
	if err != nil {
		a.renderError(w, http.StatusForbidden, "github repository access is unavailable")
		return
	}

	repos, err := a.store.ListReposForProjectBinding(r.Context(), project.ID, user.ID)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}
	if err := a.renderer.Render(w, "connect.html", connectData{
		pageData:             pageData{Title: "Project repositories", CurrentUser: user},
		Project:              project,
		Repos:                repos,
		GitHubAppInstallURL:  a.cfg.GitHubAppInstallURL,
		GitHubAppSettingsURL: configuredGitHubAppSettingsURL(a.cfg.GitHubAppSettingsURL, a.cfg.GitHubAppInstallURL),
		UsingStaleAccess:     usingStaleAccess,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func canManageProject(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	return role == "owner" || role == "admin"
}

func (a *Server) handleBindRepo(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	project, err := a.projectFromPath(r, user.ID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "project not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load project")
		return
	}
	if !canManageProject(project.Role) {
		a.renderError(w, http.StatusForbidden, "insufficient role for repo binding")
		return
	}
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "invalid form")
		return
	}
	repoID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("repo_id")), 10, 64)
	if err != nil || repoID <= 0 {
		a.renderError(w, http.StatusBadRequest, "invalid repo id")
		return
	}

	_, err = a.ensureUserRepoAccess(r.Context(), user.ID)
	if err != nil {
		a.renderError(w, http.StatusForbidden, "github repository access is unavailable")
		return
	}

	canBind, err := a.store.UserCanAccessRepoForBinding(r.Context(), user.ID, repoID)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to verify repo access")
		return
	}
	if !canBind {
		a.renderError(w, http.StatusForbidden, "you do not have github access to this repository")
		return
	}

	if err := a.store.BindRepoToProject(r.Context(), project.ID, repoID, user.ID); err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to bind repository")
		return
	}
	http.Redirect(w, r, "/projects/"+project.Slug+"/repos", http.StatusSeeOther)
}

func (a *Server) handleUnbindRepo(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	project, err := a.projectFromPath(r, user.ID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "project not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load project")
		return
	}
	if !canManageProject(project.Role) {
		a.renderError(w, http.StatusForbidden, "insufficient role for repo binding")
		return
	}
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "invalid form")
		return
	}
	repoID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("repo_id")), 10, 64)
	if err != nil || repoID <= 0 {
		a.renderError(w, http.StatusBadRequest, "invalid repo id")
		return
	}
	if err := a.store.UnbindRepoFromProject(r.Context(), project.ID, repoID); err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to unbind repository")
		return
	}
	http.Redirect(w, r, "/projects/"+project.Slug+"/repos", http.StatusSeeOther)
}

func (a *Server) handleProjectMembersPage(w http.ResponseWriter, r *http.Request) {
	user, err := a.userFromRequest(r)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	project, err := a.projectFromPath(r, user.ID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "project not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load project")
		return
	}

	if err := a.renderer.Render(w, "members.html", struct {
		pageData
		Project types.Project
	}{
		pageData: pageData{Title: "Project members", CurrentUser: user},
		Project:  project,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleRunsToken(w http.ResponseWriter, r *http.Request) {
	if a.oidcVerifier == nil {
		http.Error(w, "oidc verifier not configured", http.StatusServiceUnavailable)
		return
	}
	if a.runsTokenManager == nil {
		http.Error(w, "runs token manager not configured", http.StatusServiceUnavailable)
		return
	}

	bearer, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	principal, err := a.oidcVerifier.Verify(r.Context(), bearer)
	if err != nil {
		http.Error(w, "invalid oidc token", http.StatusUnauthorized)
		return
	}
	if !a.ingestOwnerLimiter.Allow(strconv.FormatInt(principal.RepositoryOwnerID, 10), ownerIngestRatePerMinute, time.Minute, time.Now()) {
		http.Error(w, "repository owner rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	var req runTokenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	payloadSHA, ok := normalizeSHA256Hex(req.PayloadSHA256)
	if !ok {
		http.Error(w, "payload_sha256 must be a 64-char lowercase hex sha256", http.StatusBadRequest)
		return
	}

	executionID := strings.TrimSpace(req.ExecutionID)
	if executionID == "" {
		http.Error(w, "execution_id is required", http.StatusBadRequest)
		return
	}

	jobKey := strings.TrimSpace(req.JobKey)
	if jobKey == "" {
		jobKey = strings.TrimSpace(principal.JobWorkflowRef)
	}
	if jobKey == "" {
		jobKey = strings.TrimSpace(principal.Subject)
	}
	if jobKey == "" {
		jobKey = "default"
	}

	jobName := strings.TrimSpace(req.JobName)
	if jobName == "" {
		jobName = jobKey
	}

	uploadToken, expiresAt, err := a.runsTokenManager.IssueUploadToken(principal, runsauth.UploadRequest{
		PayloadSHA256:    payloadSHA,
		ExecutionID:      executionID,
		JobName:          jobName,
		JobKey:           jobKey,
		RunnerName:       strings.TrimSpace(req.RunnerName),
		RunnerOS:         strings.TrimSpace(req.RunnerOS),
		CaptureStartedAt: strings.TrimSpace(req.CaptureStartedAt),
		CaptureEndedAt:   strings.TrimSpace(req.CaptureEndedAt),
	})
	if err != nil {
		http.Error(w, "failed to issue upload token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"upload_token": uploadToken,
		"expires_at":   expiresAt.Format(time.RFC3339),
	})
}

func (a *Server) handleRunsIngest(w http.ResponseWriter, r *http.Request) {
	if a.runsTokenManager == nil {
		http.Error(w, "runs token manager not configured", http.StatusServiceUnavailable)
		return
	}

	bearer, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	claims, err := a.runsTokenManager.VerifyUploadToken(bearer)
	if err != nil {
		http.Error(w, "invalid upload token", http.StatusUnauthorized)
		return
	}
	if !a.ingestOwnerLimiter.Allow(strconv.FormatInt(claims.RepositoryOwnerID, 10), ownerIngestRatePerMinute, time.Minute, time.Now()) {
		http.Error(w, "repository owner rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 || !json.Valid(body) {
		http.Error(w, "payload must be valid json", http.StatusBadRequest)
		return
	}

	if err := validateRunSummaryPayload(body); err != nil {
		http.Error(w, "invalid run summary payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	actualSHA := sha256Hex(body)
	expectedSHA, ok := normalizeSHA256Hex(claims.PayloadSHA256)
	if !ok {
		http.Error(w, "invalid payload hash in token", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(actualSHA), []byte(expectedSHA)) != 1 {
		http.Error(w, "payload hash mismatch", http.StatusUnauthorized)
		return
	}

	jobKey := strings.TrimSpace(claims.JobKey)
	if jobKey == "" {
		jobKey = strings.TrimSpace(claims.JobWorkflowRef)
	}
	if jobKey == "" {
		jobKey = strings.TrimSpace(claims.Subject)
	}
	if jobKey == "" {
		jobKey = "default"
	}

	jobName := strings.TrimSpace(claims.JobName)
	if jobName == "" {
		jobName = jobKey
	}

	branch := strings.TrimSpace(claims.HeadRef)
	if branch == "" {
		branch = strings.TrimSpace(claims.Ref)
	}

	captureStartedAt, err := parseOptionalRFC3339(claims.CaptureStartedAt)
	if err != nil {
		http.Error(w, "invalid capture_started_at", http.StatusBadRequest)
		return
	}
	captureEndedAt, err := parseOptionalRFC3339(claims.CaptureEndedAt)
	if err != nil {
		http.Error(w, "invalid capture_ended_at", http.StatusBadRequest)
		return
	}

	repo := types.Repo{
		RepoID:      claims.RepositoryID,
		FullName:    claims.Repository,
		Owner:       repoOwnerFromFullName(claims.Repository),
		OwnerID:     claims.RepositoryOwnerID,
		Visibility:  claims.RepositoryVisibility,
		UpdatedFrom: "oidc",
	}
	if err := a.store.UpsertRepo(r.Context(), repo); err != nil {
		http.Error(w, "failed to persist repo", http.StatusInternalServerError)
		return
	}

	if a.ownerRunQuotaPerDay > 0 {
		count, err := a.store.CountRunsByOwnerSince(r.Context(), claims.RepositoryOwnerID, time.Now().Add(-24*time.Hour))
		if err != nil {
			http.Error(w, "failed to evaluate owner quota", http.StatusInternalServerError)
			return
		}
		if count >= a.ownerRunQuotaPerDay {
			http.Error(w, "repository owner daily run quota exceeded", http.StatusTooManyRequests)
			return
		}
	}

	run := types.Run{
		RepoID:            claims.RepositoryID,
		RepoFullName:      claims.Repository,
		CommitSHA:         claims.CommitSHA,
		WorkflowName:      claims.WorkflowName,
		WorkflowRef:       claims.WorkflowRef,
		WorkflowSHA:       claims.WorkflowSHA,
		JobWorkflowRef:    claims.JobWorkflowRef,
		JobWorkflowSHA:    claims.JobWorkflowSHA,
		JobName:           jobName,
		GitHubRunID:       claims.RunID,
		GitHubJobID:       claims.GitHubJobID,
		RunAttempt:        int(claims.RunAttempt),
		Branch:            branch,
		EventName:         claims.EventName,
		Actor:             claims.Actor,
		ActorID:           nullableInt64Pointer(claims.ActorID),
		RunnerEnvironment: claims.RunnerEnvironment,
		ExecutionID:       claims.ExecutionID,
		JobKey:            jobKey,
		RunnerName:        claims.RunnerName,
		RunnerOS:          claims.RunnerOS,
		CaptureStartedAt:  captureStartedAt,
		CaptureEndedAt:    captureEndedAt,
		PayloadSHA256:     expectedSHA,
		PRNumber:          parsePRNumber(claims.Ref),
		EgressJSON:        json.RawMessage(body),
	}

	if err := a.store.UpsertRun(r.Context(), run); err != nil {
		http.Error(w, "failed to persist run", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "accepted",
		"repository":    claims.Repository,
		"github_run_id": claims.RunID,
	})
}

func validateRunSummaryPayload(raw []byte) error {
	var payload runSummaryPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	schemaVersion := strings.ToLower(strings.TrimSpace(payload.SchemaVersion))
	if schemaVersion == "" {
		return errors.New("schema_version is required")
	}
	if schemaVersion != "v2" {
		return fmt.Errorf("unsupported schema_version %q", payload.SchemaVersion)
	}
	if payload.LineageTree == nil {
		return errors.New("lineage_tree field is required for v2 payload")
	}

	return nil
}

func buildRunSummaryView(run types.Run, includeSensitive bool) runSummaryView {
	var payload runSummaryPayload
	if err := json.Unmarshal(run.EgressJSON, &payload); err != nil {
		return runSummaryView{
			ErrorMessages: []string{"failed to parse summary JSON: " + err.Error()},
		}
	}

	return runSummaryView{
		LineageRootLabel: formatRunLineageRootLabel(run),
		LineageRoots:     convertLineageTreeToView(payload.LineageTree, includeSensitive),
		ErrorMessages:    payload.Errors,
	}
}

func formatRunLineageRootLabel(run types.Run) string {
	workflow := strings.TrimSpace(run.WorkflowName)
	job := strings.TrimSpace(run.JobName)

	switch {
	case workflow != "" && job != "":
		return workflow + " · " + job
	case workflow != "":
		return workflow
	case job != "":
		return job
	default:
		return run.RepoFullName
	}
}

func convertLineageTreeToView(nodes []lineageTreePayload, includeSensitive bool) []lineageTreeNodeView {
	if len(nodes) == 0 {
		return nil
	}

	out := make([]lineageTreeNodeView, 0, len(nodes))
	for _, node := range nodes {
		egress := make([]lineageEgressNodeView, 0, len(node.Egress))
		for _, e := range node.Egress {
			egress = append(egress, lineageEgressNodeView{
				Target: formatEgressTargetLabel(e),
				Count:  e.Count,
			})
		}

		out = append(out, lineageTreeNodeView{
			Label:        processNodeDisplayLabel(node, includeSensitive),
			DirectEgress: node.DirectEgress,
			TotalEgress:  node.TotalEgress,
			Egress:       egress,
			Children:     convertLineageTreeToView(node.Children, includeSensitive),
		})
	}

	return out
}

func processNodeDisplayLabel(node lineageTreePayload, includeSensitive bool) string {
	name := strings.TrimSpace(node.Name)
	cmdline := strings.TrimSpace(node.Cmdline)

	if includeSensitive && cmdline != "" {
		parts := strings.Fields(cmdline)
		if len(parts) > 1 {
			first := strings.ToLower(filepath.Base(parts[0]))
			if strings.HasPrefix(first, "python") || strings.HasPrefix(first, "bash") || strings.HasPrefix(first, "sh") || strings.HasPrefix(first, "node") || strings.HasPrefix(first, "ruby") {
				for _, arg := range parts[1:] {
					arg = strings.TrimSpace(arg)
					if arg == "" || strings.HasPrefix(arg, "-") {
						continue
					}
					script := filepath.Base(arg)
					if script != "" && script != "-" {
						return script
					}
				}
			}
		}
		if len(parts) > 0 {
			entry := filepath.Base(parts[0])
			if entry != "" {
				return entry
			}
		}
	}

	if name != "" {
		return name
	}
	if node.PID > 0 {
		return "pid " + strconv.FormatInt(node.PID, 10)
	}
	return "process"
}

func formatEgressTargetLabel(egress lineageEgressPayload) string {
	host := strings.ToLower(strings.TrimSpace(egress.Destination))
	// strip trailing dot and port suffix (e.g. "host:443" → "host")
	host = strings.TrimSuffix(host, ".")
	if idx := strings.LastIndex(host, ":"); idx >= 0 && !strings.HasPrefix(host, "[") {
		host = host[:idx]
	}
	if host == "" {
		host = "unknown"
	}

	if isLocalhostHost(host) && egress.Port == 53 {
		return "localhost (dns resolver)"
	}
	return host
}

func isLocalhostHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	return h == "localhost" || h == "127.0.0.1" || h == "127.0.0.53" || h == "::1"
}

func splitRepoFullName(fullName string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(fullName), "/", 2)
	if len(parts) != 2 {
		return fullName, ""
	}
	return parts[0], parts[1]
}

func (a *Server) userSyncLock(userID int64) *sync.Mutex {
	value, _ := a.userAccessSyncMu.LoadOrStore(userID, &sync.Mutex{})
	lock, _ := value.(*sync.Mutex)
	return lock
}

func (a *Server) ensureUserRepoAccess(ctx context.Context, userID int64) (bool, error) {
	if a.githubAppClient == nil {
		return false, errors.New("github app client unavailable")
	}

	now := time.Now().UTC()
	syncState, err := a.store.GetUserAccessSync(ctx, userID)
	if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		return false, err
	}
	if syncState.SyncedAt != nil && now.Sub(*syncState.SyncedAt) <= a.accessCacheTTL {
		return false, nil
	}

	lock := a.userSyncLock(userID)
	lock.Lock()
	defer lock.Unlock()

	now = time.Now().UTC()
	syncState, err = a.store.GetUserAccessSync(ctx, userID)
	if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		return false, err
	}
	if syncState.SyncedAt != nil && now.Sub(*syncState.SyncedAt) <= a.accessCacheTTL {
		return false, nil
	}

	if err := a.syncUserRepoAccess(ctx, userID); err != nil {
		msg := err.Error()
		_ = a.store.UpsertUserAccessSync(ctx, userID, syncState.SyncedAt, now, &msg, syncState.ETag)
		if syncState.SyncedAt != nil && now.Sub(*syncState.SyncedAt) <= a.accessMaxStaleness {
			return true, nil
		}
		return false, err
	}

	now = time.Now().UTC()
	if err := a.store.UpsertUserAccessSync(ctx, userID, &now, now, nil, nil); err != nil {
		return false, err
	}
	return false, nil
}

func (a *Server) syncUserRepoAccess(ctx context.Context, userID int64) error {
	accessEnc, accessExp, refreshEnc, _, err := a.store.GetUserGitHubTokens(ctx, userID)
	if err != nil {
		return err
	}

	accessToken, err := a.githubAppClient.DecryptToken(accessEnc)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if accessExp != nil && now.After(accessExp.Add(-1*time.Minute)) {
		if len(refreshEnc) == 0 {
			return errors.New("github user token expired and no refresh token is available")
		}
		refreshToken, err := a.githubAppClient.DecryptToken(refreshEnc)
		if err != nil {
			return err
		}
		newTokens, err := a.githubAppClient.RefreshUserToken(ctx, refreshToken)
		if err != nil {
			return err
		}
		accessToken = newTokens.AccessToken
		newAccessEnc, err := a.githubAppClient.EncryptToken(newTokens.AccessToken)
		if err != nil {
			return err
		}
		newRefreshEnc := refreshEnc
		if strings.TrimSpace(newTokens.RefreshToken) != "" {
			newRefreshEnc, err = a.githubAppClient.EncryptToken(newTokens.RefreshToken)
			if err != nil {
				return err
			}
		}
		if err := a.store.UpsertUserGitHubTokens(ctx, userID, newAccessEnc, newTokens.AccessTokenExpiresAt, newRefreshEnc, newTokens.RefreshTokenExpiresAt); err != nil {
			return err
		}
	}

	installations, _, err := a.githubAppClient.ListUserInstallations(ctx, accessToken)
	if err != nil {
		return err
	}

	rows := make([]postgres.UserRepoAccessRow, 0, 64)
	for _, installation := range installations {
		repos, err := a.githubAppClient.ListUserInstallationRepositories(ctx, accessToken, installation.ID)
		if err != nil {
			return err
		}
		for _, repo := range repos {
			repoRecord := types.Repo{
				RepoID:      repo.RepoID,
				FullName:    repo.FullName,
				Owner:       repo.Owner,
				OwnerID:     repo.OwnerID,
				Visibility:  repo.Visibility,
				UpdatedFrom: "api",
			}
			if err := a.store.UpsertRepo(ctx, repoRecord); err != nil {
				return err
			}
			rows = append(rows, postgres.UserRepoAccessRow{RepoID: repo.RepoID, InstallationID: installation.ID})
		}
	}

	if err := a.store.ReplaceUserRepoAccess(ctx, userID, rows); err != nil {
		return err
	}
	return nil
}

func configuredGitHubAppSettingsURL(settingsURL string, installURL string) string {
	if value := strings.TrimSpace(settingsURL); value != "" {
		return value
	}
	if value := strings.TrimSpace(installURL); value != "" {
		return value
	}
	return "https://github.com/apps"
}

func (a *Server) renderError(w http.ResponseWriter, status int, message string) {
	if err := a.renderer.RenderWithStatus(w, status, "login.html", pageData{
		Title: message,
		Error: message,
	}); err != nil {
		http.Error(w, message, status)
	}
}

func bearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func normalizeSHA256Hex(v string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(v))
	if !sha256HexPattern.MatchString(normalized) {
		return "", false
	}
	return normalized, true
}

func parseOptionalRFC3339(v string) (*time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func nullableInt64Pointer(v int64) *int64 {
	if v <= 0 {
		return nil
	}
	value := v
	return &value
}

func repoOwnerFromFullName(fullName string) string {
	owner, _ := splitRepoFullName(fullName)
	return owner
}

func parsePRNumber(ref string) *int64 {
	matches := pullRefPattern.FindStringSubmatch(strings.TrimSpace(ref))
	if len(matches) != 3 {
		return nil
	}
	n, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return &n
}
