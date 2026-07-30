package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL            string
	Port                   string
	BaseURL                string
	OIDCIssuer             string
	OIDCAudience           string
	GitHubClientID         string
	GitHubClientSecret     string
	GitHubAppID            string
	GitHubAppPrivateKey    string
	GitHubAppWebhookSecret string
	GitHubAppSlug          string
	GitHubAppInstallURL    string
	GitHubAppSettingsURL   string
	MigrateOnly            bool
}

func FromEnv() Config {
	port := getenv("PORT", "8080")
	baseURL := getenv("BASE_URL", fmt.Sprintf("http://localhost:%s", port))

	oidcAudience := getenv("OIDC_AUDIENCE", strings.TrimRight(baseURL, "/"))

	githubAppSlug := strings.TrimSpace(os.Getenv("GITHUB_APP_SLUG"))
	githubAppSettingsURL := "https://github.com/apps"
	githubAppInstallURL := "https://github.com/apps"
	if githubAppSlug != "" {
		githubAppSettingsURL = "https://github.com/apps/" + githubAppSlug
		githubAppInstallURL = githubAppSettingsURL + "/installations/new"
	}

	return Config{
		DatabaseURL:            getenv("DATABASE_URL", "postgres://ghapp_demo:ghapp_demo@localhost:5432/ghapp_demo?sslmode=disable"),
		Port:                   port,
		BaseURL:                baseURL,
		OIDCIssuer:             getenv("OIDC_ISSUER", "https://token.actions.githubusercontent.com"),
		OIDCAudience:           oidcAudience,
		GitHubClientID:         os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:     os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubAppID:            os.Getenv("GITHUB_APP_ID"),
		GitHubAppPrivateKey:    os.Getenv("GITHUB_APP_PRIVATE_KEY"),
		GitHubAppWebhookSecret: os.Getenv("GITHUB_APP_WEBHOOK_SECRET"),
		GitHubAppSlug:          githubAppSlug,
		GitHubAppInstallURL:    githubAppInstallURL,
		GitHubAppSettingsURL:   githubAppSettingsURL,
		MigrateOnly:            os.Getenv("MIGRATE_ONLY") == "1",
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
