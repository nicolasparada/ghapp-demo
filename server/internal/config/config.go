package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL          string
	Port                 string
	BaseURL              string
	OIDCIssuer           string
	OIDCAudiences        []string
	GitHubClientID       string
	GitHubClientSecret   string
	GitHubAppID          string
	GitHubAppPrivateKey  string
	TokenEncryptionKey   string
	GitHubAppSlug        string
	GitHubAppInstallURL  string
	GitHubAppSettingsURL string
	MigrateOnly          bool
}

func FromEnv() Config {
	port := getenv("PORT", "8080")
	baseURL := getenv("BASE_URL", fmt.Sprintf("http://localhost:%s", port))

	oidcAudiences := parseCSVAllowlist(getenv("OIDC_AUDIENCE", strings.TrimRight(baseURL, "/")))

	githubAppSlug := strings.TrimSpace(os.Getenv("GITHUB_APP_SLUG"))
	githubAppSettingsURL := "https://github.com/apps"
	githubAppInstallURL := "https://github.com/apps"
	if githubAppSlug != "" {
		githubAppSettingsURL = "https://github.com/apps/" + githubAppSlug
		githubAppInstallURL = githubAppSettingsURL + "/installations/new"
	}

	return Config{
		DatabaseURL:          getenv("DATABASE_URL", "postgres://ghapp_demo:ghapp_demo@localhost:5432/ghapp_demo?sslmode=disable"),
		Port:                 port,
		BaseURL:              baseURL,
		OIDCIssuer:           getenv("OIDC_ISSUER", "https://token.actions.githubusercontent.com"),
		OIDCAudiences:        oidcAudiences,
		GitHubClientID:       os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:   os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubAppID:          os.Getenv("GITHUB_APP_ID"),
		GitHubAppPrivateKey:  os.Getenv("GITHUB_APP_PRIVATE_KEY"),
		TokenEncryptionKey:   os.Getenv("TOKEN_ENCRYPTION_KEY"),
		GitHubAppSlug:        githubAppSlug,
		GitHubAppInstallURL:  githubAppInstallURL,
		GitHubAppSettingsURL: githubAppSettingsURL,
		MigrateOnly:          os.Getenv("MIGRATE_ONLY") == "1",
	}
}

func (c Config) ListenAddr() string {
	if strings.HasPrefix(c.Port, ":") {
		return c.Port
	}
	return ":" + c.Port
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseCSVAllowlist(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
