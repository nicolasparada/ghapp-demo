package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nicolasparada/ghapp-demo/server/internal/config"
	"github.com/nicolasparada/ghapp-demo/server/internal/githubapp"
	"github.com/nicolasparada/ghapp-demo/server/internal/oidc"
	"github.com/nicolasparada/ghapp-demo/server/internal/postgres"
	"github.com/nicolasparada/ghapp-demo/server/internal/runsauth"
	"github.com/nicolasparada/ghapp-demo/server/internal/workers"
	"github.com/nicolasparada/ghapp-demo/server/web"
	webhandler "github.com/nicolasparada/ghapp-demo/server/web/handler"
)

func main() {
	cfg := config.FromEnv()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
	oidcVerifier := oidc.NewVerifier(oidc.Config{
		Issuer:    cfg.OIDCIssuer,
		Audiences: cfg.OIDCAudiences,
	})

	runsTokenManager, err := runsauth.NewTokenManager(cfg.GitHubAppID, cfg.GitHubAppPrivateKey)
	if err != nil {
		log.Printf("runs token manager disabled: %v", err)
	}

	githubAppClient, err := githubapp.NewClient(githubapp.Config{
		ClientID:           cfg.GitHubClientID,
		ClientSecret:       cfg.GitHubClientSecret,
		BaseURL:            cfg.BaseURL,
		TokenEncryptionKey: cfg.TokenEncryptionKey,
		AppID:              cfg.GitHubAppID,
		AppPrivateKey:      cfg.GitHubAppPrivateKey,
	})
	if err != nil {
		log.Printf("github app client disabled: %v", err)
	}

	pullRunner := &workers.PullRunner{
		Store:  store,
		GitHub: githubAppClient,
	}
	go pullRunner.Start(ctx, 15*time.Minute)

	serverHandler := webhandler.New(webhandler.Config{
		BaseURL:              cfg.BaseURL,
		GitHubClientID:       cfg.GitHubClientID,
		GitHubClientSecret:   cfg.GitHubClientSecret,
		GitHubAppInstallURL:  cfg.GitHubAppInstallURL,
		GitHubAppSettingsURL: cfg.GitHubAppSettingsURL,
	}, store, renderer, githubAppClient, oidcVerifier, runsTokenManager)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           serverHandler.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("http shutdown: %v", err)
		}
	}()

	log.Printf("control-plane listening on %s", cfg.ListenAddr())
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
	log.Println("server stopped")
}
