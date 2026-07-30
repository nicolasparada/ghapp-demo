package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nicolasparada/ghapp-demo/server/internal/config"
	"github.com/nicolasparada/ghapp-demo/server/internal/githubapp"
	"github.com/nicolasparada/ghapp-demo/server/internal/oidc"
	"github.com/nicolasparada/ghapp-demo/server/internal/postgres"
	"github.com/nicolasparada/ghapp-demo/server/internal/runsauth"
	"github.com/nicolasparada/ghapp-demo/server/web"
	webhandler "github.com/nicolasparada/ghapp-demo/server/web/handler"
)

func main() {
	cfg := config.FromEnv()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("postgres connect: %v", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("migrations applied")

	if cfg.MigrateOnly {
		return
	}

	store := postgres.NewStore(pool)
	renderer := web.NewRenderer()
	githubAppService := githubapp.NewService(store, cfg.GitHubAppWebhookSecret)
	oidcVerifier := oidc.NewVerifier(oidc.Config{
		Issuer:   cfg.OIDCIssuer,
		Audience: cfg.OIDCAudience,
	})

	runsTokenManager, err := runsauth.NewTokenManager(cfg.GitHubAppID, cfg.GitHubAppPrivateKey)
	if err != nil {
		log.Printf("runs token manager disabled: %v", err)
	}

	serverHandler := webhandler.New(webhandler.Config{
		BaseURL:              cfg.BaseURL,
		GitHubClientID:       cfg.GitHubClientID,
		GitHubClientSecret:   cfg.GitHubClientSecret,
		GitHubAppInstallURL:  cfg.GitHubAppInstallURL,
		GitHubAppSettingsURL: cfg.GitHubAppSettingsURL,
	}, store, renderer, githubAppService, oidcVerifier, runsTokenManager)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           serverHandler.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("control-plane listening on %s", cfg.ListenAddr())
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}
