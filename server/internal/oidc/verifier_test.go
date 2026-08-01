package oidc

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifierAudienceAllowlist(t *testing.T) {
	t.Parallel()

	v := NewVerifier(Config{Issuer: DefaultIssuer, Audiences: []string{"https://a.example", "https://b.example"}})

	if !v.isAudienceAllowed(jwt.MapClaims{"aud": "https://a.example"}) {
		t.Fatal("expected single audience string to be allowed")
	}
	if !v.isAudienceAllowed(jwt.MapClaims{"aud": []any{"https://x.example", "https://b.example"}}) {
		t.Fatal("expected one audience in array to be allowed")
	}
	if v.isAudienceAllowed(jwt.MapClaims{"aud": "https://x.example"}) {
		t.Fatal("expected non-matching audience to be denied")
	}
}

func TestVerifierAudienceAllowlistDisabled(t *testing.T) {
	t.Parallel()

	v := NewVerifier(Config{Issuer: DefaultIssuer})
	if !v.isAudienceAllowed(jwt.MapClaims{}) {
		t.Fatal("expected no-allowlist verifier to allow token")
	}
}
