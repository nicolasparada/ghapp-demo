package runsauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/nicolasparada/ghapp-demo/server/internal/oidc"
)

const tokenAudience = "ghapp-demo:runs-upload"

type TokenManager struct {
	issuer     string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	ttl        time.Duration
}

type UploadClaims struct {
	Repository     string `json:"repository"`
	CommitSHA      string `json:"sha"`
	RunID          int64  `json:"run_id"`
	WorkflowName   string `json:"workflow"`
	JobWorkflowRef string `json:"job_workflow_ref"`
	EventName      string `json:"event_name"`
	Actor          string `json:"actor"`
	Ref            string `json:"ref"`
	HeadRef        string `json:"head_ref"`
	Subject        string `json:"sub"`
	PayloadSHA256  string `json:"payload_sha256"`
	JobName        string `json:"job_name"`
	JobKey         string `json:"job_key"`
	jwt.RegisteredClaims
}

func NewTokenManager(appID, appPrivateKeyPEM string) (*TokenManager, error) {
	return NewTokenManagerWithTTL(appID, appPrivateKeyPEM, 5*time.Minute)
}

func NewTokenManagerWithTTL(appID, appPrivateKeyPEM string, ttl time.Duration) (*TokenManager, error) {
	issuer := strings.TrimSpace(appID)
	if issuer == "" {
		return nil, errors.New("missing app id")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	privateKey, err := parseRSAPrivateKey(appPrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	return &TokenManager{
		issuer:     issuer,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		ttl:        ttl,
	}, nil
}

func (m *TokenManager) IssueUploadToken(principal oidc.Principal, payloadSHA256, jobName, jobKey string) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(m.ttl)

	claims := UploadClaims{
		Repository:     principal.Repository,
		CommitSHA:      principal.CommitSHA,
		RunID:          principal.RunID,
		WorkflowName:   principal.WorkflowName,
		JobWorkflowRef: principal.JobWorkflowRef,
		EventName:      principal.EventName,
		Actor:          principal.Actor,
		Ref:            principal.Ref,
		HeadRef:        principal.HeadRef,
		Subject:        principal.Subject,
		PayloadSHA256:  payloadSHA256,
		JobName:        jobName,
		JobKey:         jobKey,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Audience:  []string{tokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	rawToken, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign upload token: %w", err)
	}

	return rawToken, expiresAt, nil
}

func (m *TokenManager) VerifyUploadToken(rawToken string) (UploadClaims, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return UploadClaims{}, errors.New("missing token")
	}

	claims := UploadClaims{}
	token, err := jwt.ParseWithClaims(rawToken, &claims, func(token *jwt.Token) (any, error) {
		return m.publicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(tokenAudience),
	)
	if err != nil {
		return UploadClaims{}, fmt.Errorf("verify upload token: %w", err)
	}
	if !token.Valid {
		return UploadClaims{}, errors.New("invalid upload token")
	}

	if strings.TrimSpace(claims.Repository) == "" {
		return UploadClaims{}, errors.New("upload token missing repository claim")
	}
	if strings.TrimSpace(claims.CommitSHA) == "" {
		return UploadClaims{}, errors.New("upload token missing sha claim")
	}
	if claims.RunID <= 0 {
		return UploadClaims{}, errors.New("upload token missing run_id claim")
	}
	if strings.TrimSpace(claims.PayloadSHA256) == "" {
		return UploadClaims{}, errors.New("upload token missing payload_sha256 claim")
	}

	return claims, nil
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
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}

	rsaKey, ok := pkcs8.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github app private key must be an RSA private key")
	}

	return rsaKey, nil
}
