package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"
	ghoauth "golang.org/x/oauth2/github"

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
	cfg              Config
	store            *postgres.Store
	renderer         *web.Renderer
	oauthConfig      *oauth2.Config
	secureCookies    bool
	githubAppService *githubapp.Service
	oidcVerifier     *oidc.Verifier
	runsTokenManager *runsauth.TokenManager
}

type pageData struct {
	Title       string
	CurrentUser *types.User
	Error       string
}

type dashboardData struct {
	pageData
	Projects []types.Project
}

type connectData struct {
	pageData
	Project              types.Project
	RepoLinks            []types.RepoLink
	SelectedRepos        map[string]bool
	GitHubAppInstallURL  string
	GitHubAppSettingsURL string
}

type projectRunRow struct {
	Run               types.Run
	DestinationCount  int
	LineageNodeCount  int
	EventCount        int
	HasDetailsSummary bool
}

type projectData struct {
	pageData
	Project types.Project
	Repos   []string
	Runs    []projectRunRow
}

type runDetailData struct {
	pageData
	Project types.Project
	Run     types.Run
	Summary runSummaryView
}

type runSummaryView struct {
	CaptureBackend          string
	TotalEvents             int
	DroppedEvents           int
	DroppedLines            int
	ErrorMessages           []string
	Domains                 []string
	IPs                     []string
	URLs                    []string
	LineageRootLabel        string
	LineageRoots            []lineageTreeNodeView
	LineageProcessNodeCount int
	LineageEgressNodeCount  int
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
	PayloadSHA256 string `json:"payload_sha256"`
	JobName       string `json:"job_name"`
	JobKey        string `json:"job_key"`
}

type userContextKey struct{}

var (
	currentUserContextKey = userContextKey{}
	errMissingUserContext = errors.New("missing user in request context")
	pullRefPattern        = regexp.MustCompile(`^refs/pull/(\d+)/(merge|head)$`)
	sha256HexPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	ipv4Pattern           = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	hostPortSuffixPattern = regexp.MustCompile(`:[0-9]+$`)
	domainPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

func UserFromContext(ctx context.Context) *types.User {
	user, _ := ctx.Value(currentUserContextKey).(*types.User)
	return user
}

func New(
	cfg Config,
	store *postgres.Store,
	renderer *web.Renderer,
	githubAppService *githubapp.Service,
	oidcVerifier *oidc.Verifier,
	runsTokenManager *runsauth.TokenManager,
) *Server {
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		Endpoint:     ghoauth.Endpoint,
		RedirectURL:  strings.TrimRight(cfg.BaseURL, "/") + "/auth/github/callback",
		Scopes:       []string{"read:user", "user:email"},
	}

	return &Server{
		cfg:              cfg,
		store:            store,
		renderer:         renderer,
		oauthConfig:      oauthCfg,
		secureCookies:    strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://"),
		githubAppService: githubAppService,
		oidcVerifier:     oidcVerifier,
		runsTokenManager: runsTokenManager,
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
	mux.Handle("GET /projects/{slug}/runs/{runID}", a.requireUser(http.HandlerFunc(a.handleRunDetail)))
	mux.Handle("GET /projects/{slug}/connect", a.requireUser(http.HandlerFunc(a.handleConnectReposPage)))
	mux.Handle("POST /projects/{slug}/connect", a.requireUser(http.HandlerFunc(a.handleConnectReposSubmit)))

	if a.githubAppService != nil {
		mux.HandleFunc("POST /webhooks/github", a.githubAppService.HandleWebhook)
	} else {
		mux.HandleFunc("POST /webhooks/github", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "github app service not configured", http.StatusServiceUnavailable)
		})
	}

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
	if a.cfg.GitHubClientID == "" || a.cfg.GitHubClientSecret == "" {
		a.renderError(w, http.StatusServiceUnavailable, "GitHub OAuth is not configured")
		return
	}

	state, err := auth.NewToken()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to generate oauth state")
		return
	}
	auth.SetOAuthStateCookie(w, state, a.secureCookies)

	url := a.oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if a.cfg.GitHubClientID == "" || a.cfg.GitHubClientSecret == "" {
		a.renderError(w, http.StatusServiceUnavailable, "GitHub OAuth is not configured")
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

	tok, err := a.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		a.renderError(w, http.StatusBadGateway, "failed to exchange oauth code")
		return
	}

	oauthClient := a.oauthConfig.Client(r.Context(), tok)
	gh := github.NewClient(oauthClient)
	ghUser, _, err := gh.Users.Get(r.Context(), "")
	if err != nil {
		a.renderError(w, http.StatusBadGateway, "failed to fetch github profile")
		return
	}

	user, err := a.store.UpsertUserFromGitHub(r.Context(), ghUser.GetID(), ghUser.GetLogin(), ghUser.GetAvatarURL())
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to persist user")
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

	runRows := make([]projectRunRow, 0, len(runs))
	for _, run := range runs {
		eventCount, destinationCount, lineageNodeCount, hasSummary := summarizeRunForList(run.EgressJSON)
		runRows = append(runRows, projectRunRow{
			Run:               run,
			EventCount:        eventCount,
			DestinationCount:  destinationCount,
			LineageNodeCount:  lineageNodeCount,
			HasDetailsSummary: hasSummary,
		})
	}

	if err := a.renderer.Render(w, "project.html", projectData{
		pageData: pageData{Title: project.Name, CurrentUser: user},
		Project:  project,
		Repos:    repos,
		Runs:     runRows,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
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

	runID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("runID")), 10, 64)
	if err != nil || runID <= 0 {
		a.renderError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	run, err := a.store.GetRunForProject(r.Context(), project.ID, runID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "run not found")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "failed to load run")
		return
	}

	summary := buildRunSummaryView(run)

	if err := a.renderer.Render(w, "run.html", runDetailData{
		pageData: pageData{Title: "Run details", CurrentUser: user},
		Project:  project,
		Run:      run,
		Summary:  summary,
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
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

	repoLinks, err := a.store.ListAvailableRepoLinks(r.Context())
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}
	selectedRepos, err := a.store.ListProjectRepos(r.Context(), project.ID)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to list selected repositories")
		return
	}

	selected := make(map[string]bool, len(selectedRepos))
	for _, repo := range selectedRepos {
		selected[repo] = true
	}

	if err := a.renderer.Render(w, "connect.html", connectData{
		pageData:             pageData{Title: "Connect repositories", CurrentUser: user},
		Project:              project,
		RepoLinks:            repoLinks,
		SelectedRepos:        selected,
		GitHubAppInstallURL:  a.cfg.GitHubAppInstallURL,
		GitHubAppSettingsURL: configuredGitHubAppSettingsURL(a.cfg.GitHubAppSettingsURL, a.cfg.GitHubAppInstallURL),
	}); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (a *Server) handleConnectReposSubmit(w http.ResponseWriter, r *http.Request) {
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

	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "invalid form")
		return
	}

	repos := r.Form["repos"]
	if err := a.store.ReplaceProjectRepos(r.Context(), project.ID, repos); err != nil {
		a.renderError(w, http.StatusInternalServerError, "failed to save repositories")
		return
	}

	http.Redirect(w, r, "/projects/"+project.Slug, http.StatusSeeOther)
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

	repoLinked, err := a.store.IsRepoLinked(r.Context(), principal.Repository)
	if err != nil {
		http.Error(w, "failed to verify repo link", http.StatusInternalServerError)
		return
	}
	if !repoLinked {
		http.Error(w, "repository is not linked to any installation", http.StatusForbidden)
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

	uploadToken, expiresAt, err := a.runsTokenManager.IssueUploadToken(principal, payloadSHA, jobName, jobKey)
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

	repoLinked, err := a.store.IsRepoLinked(r.Context(), claims.Repository)
	if err != nil {
		http.Error(w, "failed to verify repo link", http.StatusInternalServerError)
		return
	}
	if !repoLinked {
		http.Error(w, "repository is not linked to any installation", http.StatusForbidden)
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

	run := types.Run{
		RepoFullName:   claims.Repository,
		CommitSHA:      claims.CommitSHA,
		WorkflowName:   claims.WorkflowName,
		JobWorkflowRef: claims.JobWorkflowRef,
		JobName:        jobName,
		GitHubRunID:    claims.RunID,
		GitHubJobID:    stableInt64(jobKey),
		Branch:         branch,
		EventName:      claims.EventName,
		Actor:          claims.Actor,
		PRNumber:       parsePRNumber(claims.Ref),
		EgressJSON:     json.RawMessage(body),
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

func summarizeRunForList(raw json.RawMessage) (eventCount, destinationCount, lineageNodeCount int, hasSummary bool) {
	var payload runSummaryPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, 0, 0, false
	}

	eventCount = payload.TotalEvents
	if eventCount <= 0 {
		eventCount = len(payload.Events)
	}

	domains, ips, urls := extractEgressTargetsFromTree(payload.LineageTree)
	if len(domains)+len(ips)+len(urls) == 0 {
		domains, ips, urls = extractEgressTargets(payload.Events)
	}
	destinationCount = len(domains) + len(ips) + len(urls)

	lineageNodeCount = countLineageProcessNodes(payload.LineageTree) + countLineageEgressNodes(payload.LineageTree)
	if lineageNodeCount == 0 {
		lineageNodeCount = countLineageEventNodes(payload.Events)
	}

	return eventCount, destinationCount, lineageNodeCount, true
}

func buildRunSummaryView(run types.Run) runSummaryView {
	var payload runSummaryPayload
	if err := json.Unmarshal(run.EgressJSON, &payload); err != nil {
		return runSummaryView{
			ErrorMessages: []string{"failed to parse summary JSON: " + err.Error()},
		}
	}

	domains, ips, urls := extractEgressTargetsFromTree(payload.LineageTree)
	if len(domains)+len(ips)+len(urls) == 0 {
		domains, ips, urls = extractEgressTargets(payload.Events)
	}

	lineageProcessNodeCount := countLineageProcessNodes(payload.LineageTree)
	lineageEgressNodeCount := countLineageEgressNodes(payload.LineageTree)

	view := runSummaryView{
		CaptureBackend:          payload.CaptureBackend,
		TotalEvents:             payload.TotalEvents,
		DroppedEvents:           payload.DroppedEvents,
		DroppedLines:            payload.DroppedLines,
		ErrorMessages:           payload.Errors,
		Domains:                 domains,
		IPs:                     ips,
		URLs:                    urls,
		LineageRootLabel:        formatRunLineageRootLabel(run),
		LineageRoots:            convertLineageTreeToView(payload.LineageTree),
		LineageProcessNodeCount: lineageProcessNodeCount,
		LineageEgressNodeCount:  lineageEgressNodeCount,
	}

	if view.TotalEvents <= 0 {
		view.TotalEvents = len(payload.Events)
	}

	if len(payload.LineageTree) == 0 {
		view.ErrorMessages = append(view.ErrorMessages, "lineage tree not present in this run payload")
	}

	return view
}

func extractEgressTargetsFromTree(roots []lineageTreePayload) (domains, ips, urls []string) {
	domainSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	urlSet := map[string]struct{}{}

	collectLineageEgress(roots, func(egress lineageEgressPayload) {
		classifyEgressValue(egress.Destination, domainSet, ipSet, urlSet, &domains, &ips, &urls)
	})

	return domains, ips, urls
}

func collectLineageEgress(roots []lineageTreePayload, onEgress func(egress lineageEgressPayload)) {
	for _, node := range roots {
		for _, egress := range node.Egress {
			onEgress(egress)
		}
		if len(node.Children) > 0 {
			collectLineageEgress(node.Children, onEgress)
		}
	}
}

func extractEgressTargets(events []runEventPayload) (domains, ips, urls []string) {
	domainSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	urlSet := map[string]struct{}{}

	for _, event := range events {
		classifyEgressValue(event.Destination, domainSet, ipSet, urlSet, &domains, &ips, &urls)
	}

	return domains, ips, urls
}

func classifyEgressValue(raw string, domainSet, ipSet, urlSet map[string]struct{}, domains, ips, urls *[]string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return
	}

	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if _, ok := urlSet[value]; !ok {
			urlSet[value] = struct{}{}
			*urls = append(*urls, value)
		}
		host := extractHostFromURL(value)
		if host != "" {
			classifyHost(host, domainSet, ipSet, domains, ips)
		}
		return
	}

	classifyHost(value, domainSet, ipSet, domains, ips)
}

func extractHostFromURL(raw string) string {
	withoutScheme := raw
	if idx := strings.Index(raw, "://"); idx >= 0 {
		withoutScheme = raw[idx+3:]
	}
	if idx := strings.IndexAny(withoutScheme, "/?#"); idx >= 0 {
		withoutScheme = withoutScheme[:idx]
	}
	if at := strings.LastIndex(withoutScheme, "@"); at >= 0 {
		withoutScheme = withoutScheme[at+1:]
	}
	return normalizeHost(withoutScheme)
}

func classifyHost(raw string, domainSet, ipSet map[string]struct{}, domains, ips *[]string) {
	host := normalizeHost(raw)
	if host == "" {
		return
	}

	if isLikelyIPv4(host) || isLikelyIPv6(host) {
		if _, ok := ipSet[host]; !ok {
			ipSet[host] = struct{}{}
			*ips = append(*ips, host)
		}
		return
	}

	if isLikelyDomain(host) {
		if _, ok := domainSet[host]; !ok {
			domainSet[host] = struct{}{}
			*domains = append(*domains, host)
		}
	}
}

func normalizeHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return ""
	}

	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		end := strings.Index(host, "]")
		if end > 1 {
			return host[1:end]
		}
	}

	if strings.Count(host, ":") == 1 && hostPortSuffixPattern.MatchString(host) {
		host = hostPortSuffixPattern.ReplaceAllString(host, "")
	}

	host = strings.TrimSuffix(host, ".")
	return host
}

func isLikelyIPv4(host string) bool {
	if !ipv4Pattern.MatchString(host) {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func isLikelyIPv6(host string) bool {
	if strings.Count(host, ":") < 2 {
		return false
	}
	for _, r := range host {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || r == ':' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isLikelyDomain(host string) bool {
	return domainPattern.MatchString(host)
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

func convertLineageTreeToView(nodes []lineageTreePayload) []lineageTreeNodeView {
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
			Label:        processNodeDisplayLabel(node),
			DirectEgress: node.DirectEgress,
			TotalEgress:  node.TotalEgress,
			Egress:       egress,
			Children:     convertLineageTreeToView(node.Children),
		})
	}

	return out
}

func processNodeDisplayLabel(node lineageTreePayload) string {
	name := strings.TrimSpace(node.Name)
	cmdline := strings.TrimSpace(node.Cmdline)

	if cmdline != "" {
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
	host := normalizeHost(egress.Destination)
	if host == "" {
		host = strings.TrimSpace(egress.Destination)
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

func countLineageProcessNodes(nodes []lineageTreePayload) int {
	total := 0
	for _, node := range nodes {
		total++
		total += countLineageProcessNodes(node.Children)
	}
	return total
}

func countLineageEgressNodes(nodes []lineageTreePayload) int {
	total := 0
	for _, node := range nodes {
		total += len(node.Egress)
		total += countLineageEgressNodes(node.Children)
	}
	return total
}

func countLineageEventNodes(events []runEventPayload) int {
	seen := map[string]struct{}{}
	for _, event := range events {
		for _, node := range event.Lineage {
			key := strconv.FormatInt(node.PID, 10) + ":" + strings.TrimSpace(node.Name)
			seen[key] = struct{}{}
		}
	}
	return len(seen)
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

func stableInt64(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64() & 0x7fffffffffffffff)
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
