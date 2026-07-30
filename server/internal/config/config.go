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
	GitHubAppInstallURL    string
	MigrateOnly            bool
}

func FromEnv() Config {
	port := getenv("PORT", "8080")
	baseURL := getenv("BASE_URL", fmt.Sprintf("http://localhost:%s", port))

	oidcAudience := getenv("OIDC_AUDIENCE", strings.TrimRight(baseURL, "/"))

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
		GitHubAppInstallURL:    getenv("GITHUB_APP_INSTALL_URL", "https://github.com/apps"),
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
