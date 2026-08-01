package githubapp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"
)

const githubTokenURL = "https://github.com/login/oauth/access_token"

type Config struct {
	ClientID           string
	ClientSecret       string
	BaseURL            string
	TokenEncryptionKey string
	AppID              string
	AppPrivateKey      string
	HTTPClient         *http.Client
}

type Client struct {
	clientID     string
	clientSecret string
	baseURL      string
	httpClient   *http.Client
	aead         cipher.AEAD

	appID         string
	appPrivateKey *rsa.PrivateKey

	tokenMu            sync.Mutex
	installationTokens map[int64]cachedInstallationToken
}

type cachedInstallationToken struct {
	Token     string
	ExpiresAt time.Time
}

type UserToken struct {
	AccessToken           string
	AccessTokenExpiresAt  *time.Time
	RefreshToken          string
	RefreshTokenExpiresAt *time.Time
}

type tokenResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

type InstallationLite struct {
	ID                  int64
	AccountID           int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
}

type RepoLite struct {
	RepoID     int64
	FullName   string
	Owner      string
	OwnerID    int64
	Visibility string
}

type RunJob struct {
	ID          int64
	Name        string
	RunnerName  string
	Conclusion  string
	StartedAt   *time.Time
	CompletedAt *time.Time
}

func NewClient(cfg Config) (*Client, error) {
	clientID := strings.TrimSpace(cfg.ClientID)
	clientSecret := strings.TrimSpace(cfg.ClientSecret)
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("missing github app client id/secret")
	}
	keyRaw := strings.TrimSpace(cfg.TokenEncryptionKey)
	if keyRaw == "" {
		return nil, errors.New("missing token encryption key")
	}

	key, err := base64.StdEncoding.DecodeString(keyRaw)
	if err != nil {
		return nil, fmt.Errorf("decode token encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("token encryption key must decode to 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}

	appID := strings.TrimSpace(cfg.AppID)
	if appID == "" {
		return nil, errors.New("missing github app id")
	}
	appPrivateKey, err := parseRSAPrivateKey(cfg.AppPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse app private key: %w", err)
	}

	return &Client{
		clientID:           clientID,
		clientSecret:       clientSecret,
		baseURL:            strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		httpClient:         hc,
		aead:               aead,
		appID:              appID,
		appPrivateKey:      appPrivateKey,
		installationTokens: map[int64]cachedInstallationToken{},
	}, nil
}

func (c *Client) AuthCodeURL(state string) string {
	v := url.Values{}
	v.Set("client_id", c.clientID)
	v.Set("redirect_uri", c.baseURL+"/auth/github/callback")
	v.Set("state", state)
	return "https://github.com/login/oauth/authorize?" + v.Encode()
}

func (c *Client) ExchangeUserCode(ctx context.Context, code string) (UserToken, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", c.baseURL+"/auth/github/callback")

	resp, err := c.tokenRequest(ctx, form)
	if err != nil {
		return UserToken{}, err
	}
	return tokenFromResponse(resp), nil
}

func (c *Client) RefreshUserToken(ctx context.Context, refreshToken string) (UserToken, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	resp, err := c.tokenRequest(ctx, form)
	if err != nil {
		return UserToken{}, err
	}
	return tokenFromResponse(resp), nil
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("exchange token: %w", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return tokenResponse{}, fmt.Errorf("exchange token failed: status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return tokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return tokenResponse{}, errors.New("token response missing access_token")
	}
	return tr, nil
}

func tokenFromResponse(tr tokenResponse) UserToken {
	now := time.Now().UTC()
	var accessExp *time.Time
	if tr.ExpiresIn > 0 {
		t := now.Add(time.Duration(tr.ExpiresIn) * time.Second)
		accessExp = &t
	}
	var refreshExp *time.Time
	if tr.RefreshTokenExpiresIn > 0 {
		t := now.Add(time.Duration(tr.RefreshTokenExpiresIn) * time.Second)
		refreshExp = &t
	}

	return UserToken{
		AccessToken:           tr.AccessToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshToken:          tr.RefreshToken,
		RefreshTokenExpiresAt: refreshExp,
	}
}

func (c *Client) EncryptToken(plaintext string) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	out := bytes.NewBuffer(make([]byte, 0, len(nonce)+len(ciphertext)))
	out.Write(nonce)
	out.Write(ciphertext)
	return out.Bytes(), nil
}

func (c *Client) DecryptToken(ciphertext []byte) (string, error) {
	ns := c.aead.NonceSize()
	if len(ciphertext) < ns {
		return "", errors.New("ciphertext too short")
	}
	nonce, payload := ciphertext[:ns], ciphertext[ns:]
	plain, err := c.aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	return string(plain), nil
}

func (c *Client) GitHubUser(ctx context.Context, accessToken string) (*github.User, error) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	httpClient := oauth2.NewClient(ctx, ts)
	gh := github.NewClient(httpClient)
	u, _, err := gh.Users.Get(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}
	return u, nil
}

func (c *Client) ListUserInstallations(ctx context.Context, accessToken string) ([]InstallationLite, string, error) {
	items := []InstallationLite{}
	etag := ""
	page := 1
	for {
		endpoint := "https://api.github.com/user/installations?per_page=100&page=" + strconv.Itoa(page)
		var payload struct {
			Installations []struct {
				ID                  int64  `json:"id"`
				RepositorySelection string `json:"repository_selection"`
				Account             struct {
					ID    int64  `json:"id"`
					Login string `json:"login"`
					Type  string `json:"type"`
				} `json:"account"`
			} `json:"installations"`
		}
		res, err := c.getJSON(ctx, endpoint, "Bearer "+accessToken, "", &payload)
		if err != nil {
			return nil, "", err
		}
		if etag == "" {
			etag = res.Header.Get("ETag")
		}
		for _, inst := range payload.Installations {
			items = append(items, InstallationLite{
				ID:                  inst.ID,
				AccountID:           inst.Account.ID,
				AccountLogin:        inst.Account.Login,
				AccountType:         strings.ToLower(strings.TrimSpace(inst.Account.Type)),
				RepositorySelection: inst.RepositorySelection,
			})
		}
		if len(payload.Installations) < 100 {
			break
		}
		page++
	}
	return items, etag, nil
}

func (c *Client) ListUserInstallationRepositories(ctx context.Context, accessToken string, installationID int64) ([]RepoLite, error) {
	out := []RepoLite{}
	page := 1
	for {
		endpoint := fmt.Sprintf("https://api.github.com/user/installations/%d/repositories?per_page=100&page=%d", installationID, page)
		var payload struct {
			Repositories []struct {
				ID         int64  `json:"id"`
				FullName   string `json:"full_name"`
				Visibility string `json:"visibility"`
				Owner      struct {
					Login string `json:"login"`
					ID    int64  `json:"id"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		_, err := c.getJSON(ctx, endpoint, "Bearer "+accessToken, "", &payload)
		if err != nil {
			return nil, err
		}
		for _, r := range payload.Repositories {
			out = append(out, RepoLite{
				RepoID:     r.ID,
				FullName:   r.FullName,
				Owner:      r.Owner.Login,
				OwnerID:    r.Owner.ID,
				Visibility: r.Visibility,
			})
		}
		if len(payload.Repositories) < 100 {
			break
		}
		page++
	}
	return out, nil
}

func (c *Client) ListAppInstallations(ctx context.Context, etag string) ([]InstallationLite, string, bool, error) {
	items := []InstallationLite{}
	page := 1
	returnedETag := etag
	for {
		endpoint := fmt.Sprintf("https://api.github.com/app/installations?per_page=100&page=%d", page)
		var payload []struct {
			ID                  int64  `json:"id"`
			RepositorySelection string `json:"repository_selection"`
			Account             struct {
				ID    int64  `json:"id"`
				Login string `json:"login"`
				Type  string `json:"type"`
			} `json:"account"`
		}
		res, notModified, err := c.getJSONWithETag(ctx, endpoint, c.appBearerToken(ctx), etag, &payload)
		if err != nil {
			return nil, "", false, err
		}
		if notModified {
			return nil, etag, true, nil
		}
		if returnedETag == "" {
			returnedETag = res.Header.Get("ETag")
		}
		for _, inst := range payload {
			items = append(items, InstallationLite{
				ID:                  inst.ID,
				AccountID:           inst.Account.ID,
				AccountLogin:        inst.Account.Login,
				AccountType:         strings.ToLower(strings.TrimSpace(inst.Account.Type)),
				RepositorySelection: inst.RepositorySelection,
			})
		}
		if len(payload) < 100 {
			break
		}
		page++
	}
	return items, returnedETag, false, nil
}

func (c *Client) ListInstallationRepositories(ctx context.Context, installationID int64, etag string) ([]RepoLite, string, bool, error) {
	token, err := c.installationToken(ctx, installationID)
	if err != nil {
		return nil, "", false, err
	}

	out := []RepoLite{}
	page := 1
	returnedETag := etag
	for {
		endpoint := fmt.Sprintf("https://api.github.com/installation/repositories?per_page=100&page=%d", page)
		var payload struct {
			Repositories []struct {
				ID         int64  `json:"id"`
				FullName   string `json:"full_name"`
				Visibility string `json:"visibility"`
				Owner      struct {
					Login string `json:"login"`
					ID    int64  `json:"id"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		res, notModified, err := c.getJSONWithETag(ctx, endpoint, "Bearer "+token, etag, &payload)
		if err != nil {
			return nil, "", false, err
		}
		if notModified {
			return nil, etag, true, nil
		}
		if returnedETag == "" {
			returnedETag = res.Header.Get("ETag")
		}
		for _, r := range payload.Repositories {
			out = append(out, RepoLite{
				RepoID:     r.ID,
				FullName:   r.FullName,
				Owner:      r.Owner.Login,
				OwnerID:    r.Owner.ID,
				Visibility: r.Visibility,
			})
		}
		if len(payload.Repositories) < 100 {
			break
		}
		page++
	}
	return out, returnedETag, false, nil
}

func (c *Client) GetRepository(ctx context.Context, owner, repo string, installationID *int64) (RepoLite, error) {
	auth := ""
	if installationID != nil {
		tok, err := c.installationToken(ctx, *installationID)
		if err == nil {
			auth = "Bearer " + tok
		}
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
	var payload struct {
		ID         int64  `json:"id"`
		FullName   string `json:"full_name"`
		Visibility string `json:"visibility"`
		Owner      struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		} `json:"owner"`
	}
	_, err := c.getJSON(ctx, endpoint, auth, "", &payload)
	if err != nil {
		return RepoLite{}, err
	}
	return RepoLite{RepoID: payload.ID, FullName: payload.FullName, Owner: payload.Owner.Login, OwnerID: payload.Owner.ID, Visibility: payload.Visibility}, nil
}

func (c *Client) ListRunAttemptJobs(ctx context.Context, owner, repo string, runID int64, attempt int, installationID int64) ([]RunJob, error) {
	tok, err := c.installationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	out := []RunJob{}
	page := 1
	for {
		endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runs/%d/attempts/%d/jobs?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), runID, attempt, page)
		var payload struct {
			Jobs []struct {
				ID          int64      `json:"id"`
				Name        string     `json:"name"`
				RunnerName  string     `json:"runner_name"`
				Conclusion  string     `json:"conclusion"`
				StartedAt   *time.Time `json:"started_at"`
				CompletedAt *time.Time `json:"completed_at"`
			} `json:"jobs"`
		}
		_, err := c.getJSON(ctx, endpoint, "Bearer "+tok, "", &payload)
		if err != nil {
			return nil, err
		}
		for _, j := range payload.Jobs {
			out = append(out, RunJob{ID: j.ID, Name: j.Name, RunnerName: j.RunnerName, Conclusion: j.Conclusion, StartedAt: j.StartedAt, CompletedAt: j.CompletedAt})
		}
		if len(payload.Jobs) < 100 {
			break
		}
		page++
	}
	return out, nil
}

func (c *Client) appBearerToken(ctx context.Context) string {
	_ = ctx
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Issuer:    c.appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	raw, _ := t.SignedString(c.appPrivateKey)
	return "Bearer " + raw
}

func (c *Client) installationToken(ctx context.Context, installationID int64) (string, error) {
	c.tokenMu.Lock()
	if tok, ok := c.installationTokens[installationID]; ok && time.Now().UTC().Before(tok.ExpiresAt.Add(-1*time.Minute)) {
		c.tokenMu.Unlock()
		return tok.Token, nil
	}
	c.tokenMu.Unlock()

	endpoint := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", c.appBearerToken(ctx))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("create installation token failed: status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", errors.New("missing installation token")
	}

	c.tokenMu.Lock()
	c.installationTokens[installationID] = cachedInstallationToken{Token: payload.Token, ExpiresAt: payload.ExpiresAt}
	c.tokenMu.Unlock()
	return payload.Token, nil
}

func (c *Client) getJSON(ctx context.Context, endpoint string, auth string, etag string, out any) (*http.Response, error) {
	res, _, err := c.getJSONWithETag(ctx, endpoint, auth, etag, out)
	return res, err
}

func (c *Client) getJSONWithETag(ctx context.Context, endpoint string, auth string, etag string, out any) (*http.Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(auth) != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if strings.TrimSpace(etag) != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode == http.StatusNotModified {
		res.Body.Close()
		return res, true, nil
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, false, fmt.Errorf("github request failed: status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return nil, false, err
		}
	}
	return res, false, nil
}

func parseRSAPrivateKey(raw string) (*rsa.PrivateKey, error) {
	key := strings.TrimSpace(strings.ReplaceAll(raw, `\n`, "\n"))
	if key == "" {
		return nil, errors.New("github app private key is required")
	}

	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("github app private key must be PEM encoded")
	}

	if pkcs1, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return pkcs1, nil
	}

	pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := pkcs8.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github app private key must be RSA")
	}
	return rsaKey, nil
}
