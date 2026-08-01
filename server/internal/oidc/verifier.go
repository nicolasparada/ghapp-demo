package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	DefaultIssuer   = "https://token.actions.githubusercontent.com"
	defaultJWKSPath = "/.well-known/jwks"
)

type Config struct {
	Issuer     string
	Audiences  []string
	JWKSURL    string
	CacheTTL   time.Duration
	HTTPClient *http.Client
}

type Verifier struct {
	issuer    string
	audiences []string
	jwksURL   string
	cacheTTL  time.Duration
	client    *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

type Principal struct {
	Repository           string
	RepositoryID         int64
	RepositoryOwnerID    int64
	RepositoryVisibility string
	CommitSHA            string
	RunID                int64
	RunAttempt           int64
	WorkflowName         string
	WorkflowRef          string
	WorkflowSHA          string
	JobWorkflowRef       string
	JobWorkflowSHA       string
	EventName            string
	Actor                string
	ActorID              int64
	Ref                  string
	HeadRef              string
	Subject              string
	RunnerEnvironment    string
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KID string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewVerifier(cfg Config) *Verifier {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = DefaultIssuer
	}

	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	if jwksURL == "" {
		jwksURL = strings.TrimRight(issuer, "/") + defaultJWKSPath
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	audiences := make([]string, 0, len(cfg.Audiences))
	seen := make(map[string]struct{}, len(cfg.Audiences))
	for _, audience := range cfg.Audiences {
		audience = strings.TrimSpace(audience)
		if audience == "" {
			continue
		}
		if _, ok := seen[audience]; ok {
			continue
		}
		seen[audience] = struct{}{}
		audiences = append(audiences, audience)
	}

	return &Verifier{
		issuer:    issuer,
		audiences: audiences,
		jwksURL:   jwksURL,
		cacheTTL:  cacheTTL,
		client:    client,
		keys:      map[string]*rsa.PublicKey{},
	}
}

func (v *Verifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return Principal{}, errors.New("missing token")
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithIssuer(v.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
	}

	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, errors.New("token missing kid header")
		}
		return v.keyForKID(ctx, kid)
	}, parserOptions...)
	if err != nil {
		return Principal{}, fmt.Errorf("verify token: %w", err)
	}
	if !token.Valid {
		return Principal{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Principal{}, errors.New("invalid token claims")
	}
	if !v.isAudienceAllowed(claims) {
		return Principal{}, errors.New("invalid audience")
	}

	principal, err := principalFromClaims(claims)
	if err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func principalFromClaims(claims jwt.MapClaims) (Principal, error) {
	repository := claimString(claims, "repository")
	if repository == "" {
		return Principal{}, errors.New("missing repository claim")
	}

	runID, ok := claimInt64(claims, "run_id")
	if !ok || runID <= 0 {
		return Principal{}, errors.New("missing or invalid run_id claim")
	}

	repositoryID, ok := claimInt64(claims, "repository_id")
	if !ok || repositoryID <= 0 {
		return Principal{}, errors.New("missing or invalid repository_id claim")
	}

	repositoryOwnerID, ok := claimInt64(claims, "repository_owner_id")
	if !ok || repositoryOwnerID <= 0 {
		return Principal{}, errors.New("missing or invalid repository_owner_id claim")
	}

	repositoryVisibility := strings.ToLower(claimString(claims, "repository_visibility"))
	switch repositoryVisibility {
	case "public", "private", "internal":
	default:
		return Principal{}, errors.New("missing or invalid repository_visibility claim")
	}

	runAttempt, ok := claimInt64(claims, "run_attempt")
	if !ok || runAttempt <= 0 {
		return Principal{}, errors.New("missing or invalid run_attempt claim")
	}

	actorID, ok := claimInt64(claims, "actor_id")
	if !ok || actorID <= 0 {
		return Principal{}, errors.New("missing or invalid actor_id claim")
	}

	commitSHA := claimString(claims, "sha")
	if commitSHA == "" {
		return Principal{}, errors.New("missing sha claim")
	}

	return Principal{
		Repository:           repository,
		RepositoryID:         repositoryID,
		RepositoryOwnerID:    repositoryOwnerID,
		RepositoryVisibility: repositoryVisibility,
		CommitSHA:            commitSHA,
		RunID:                runID,
		RunAttempt:           runAttempt,
		WorkflowName:         claimString(claims, "workflow"),
		WorkflowRef:          claimString(claims, "workflow_ref"),
		WorkflowSHA:          claimString(claims, "workflow_sha"),
		JobWorkflowRef:       claimString(claims, "job_workflow_ref"),
		JobWorkflowSHA:       claimString(claims, "job_workflow_sha"),
		EventName:            claimString(claims, "event_name"),
		Actor:                claimString(claims, "actor"),
		ActorID:              actorID,
		Ref:                  claimString(claims, "ref"),
		HeadRef:              claimString(claims, "head_ref"),
		Subject:              claimString(claims, "sub"),
		RunnerEnvironment:    claimString(claims, "runner_environment"),
	}, nil
}

func (v *Verifier) isAudienceAllowed(claims jwt.MapClaims) bool {
	if len(v.audiences) == 0 {
		return true
	}

	audiences := tokenAudiences(claims)
	if len(audiences) == 0 {
		return false
	}

	allowed := make(map[string]struct{}, len(v.audiences))
	for _, audience := range v.audiences {
		allowed[audience] = struct{}{}
	}
	for _, audience := range audiences {
		if _, ok := allowed[audience]; ok {
			return true
		}
	}
	return false
}

func tokenAudiences(claims jwt.MapClaims) []string {
	value, ok := claims["aud"]
	if !ok || value == nil {
		return nil
	}
	out := []string{}
	push := func(raw string) {
		audience := strings.TrimSpace(raw)
		if audience == "" {
			return
		}
		out = append(out, audience)
	}

	switch aud := value.(type) {
	case string:
		push(aud)
	case []any:
		for _, item := range aud {
			s, ok := item.(string)
			if ok {
				push(s)
			}
		}
	case []string:
		for _, item := range aud {
			push(item)
		}
	}

	return out
}

func claimString(claims jwt.MapClaims, key string) string {
	v, ok := claims[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func claimInt64(claims jwt.MapClaims, key string) (int64, bool) {
	v, ok := claims[key]
	if !ok || v == nil {
		return 0, false
	}

	switch value := v.(type) {
	case float64:
		return int64(value), true
	case float32:
		return int64(value), true
	case int64:
		return value, true
	case int:
		return int64(value), true
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return 0, false
		}
		return n, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func (v *Verifier) keyForKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key, ok := v.cachedKey(kid, false); ok {
		return key, nil
	}

	if err := v.refreshJWKS(ctx); err != nil {
		if key, ok := v.cachedKey(kid, true); ok {
			return key, nil
		}
		return nil, err
	}

	if key, ok := v.cachedKey(kid, true); ok {
		return key, nil
	}

	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *Verifier) cachedKey(kid string, allowStale bool) (*rsa.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !allowStale && time.Now().After(v.expiresAt) {
		return nil, false
	}

	key, ok := v.keys[kid]
	if !ok {
		return nil, false
	}
	return key, true
}

func (v *Verifier) refreshJWKS(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if time.Now().Before(v.expiresAt) && len(v.keys) > 0 {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("create jwks request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fetch jwks: unexpected status %s", resp.Status)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if strings.TrimSpace(k.KID) == "" || strings.TrimSpace(k.Kty) != "RSA" {
			continue
		}
		pubKey, err := rsaKeyFromJWK(k)
		if err != nil {
			continue
		}
		keys[k.KID] = pubKey
	}

	if len(keys) == 0 {
		return errors.New("jwks contains no usable rsa keys")
	}

	v.keys = keys
	v.expiresAt = time.Now().Add(v.cacheTTL)
	return nil
}

func rsaKeyFromJWK(key jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode jwk modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode jwk exponent: %w", err)
	}
	if len(eBytes) == 0 {
		return nil, errors.New("empty jwk exponent")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e <= 0 {
		return nil, errors.New("invalid jwk exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
