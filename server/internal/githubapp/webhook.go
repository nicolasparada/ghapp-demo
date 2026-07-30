package githubapp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v62/github"

	"github.com/nicolasparada/ghapp-demo/server/internal/postgres"
)

type Service struct {
	Store         *postgres.Store
	WebhookSecret string
}

func NewService(store *postgres.Store, webhookSecret string) *Service {
	return &Service{Store: store, WebhookSecret: webhookSecret}
}

func (s *Service) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if s.WebhookSecret == "" {
		http.Error(w, "missing webhook secret", http.StatusServiceUnavailable)
		return
	}

	payload, err := github.ValidatePayload(r, []byte(s.WebhookSecret))
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusUnauthorized)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	switch e := event.(type) {
	case *github.InstallationEvent:
		action := strings.ToLower(e.GetAction())
		installation := e.GetInstallation()
		if installation == nil {
			http.Error(w, "missing installation", http.StatusBadRequest)
			return
		}
		installationID := installation.GetID()

		switch action {
		case "created", "new_permissions_accepted":
			account := installation.GetAccount()
			targetType, targetLogin := "unknown", "unknown"
			if account != nil {
				targetType = normalizeTargetType(account.GetType())
				targetLogin = account.GetLogin()
			}

			if _, err := s.Store.UpsertInstallation(ctx, installationID, targetType, targetLogin); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			for _, repo := range e.Repositories {
				if repo == nil {
					continue
				}
				if err := s.Store.UpsertRepoLink(ctx, installationID, repo.GetFullName()); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		case "deleted":
			if err := s.Store.DeleteInstallation(ctx, installationID); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

	case *github.InstallationRepositoriesEvent:
		installation := e.GetInstallation()
		if installation == nil {
			http.Error(w, "missing installation", http.StatusBadRequest)
			return
		}
		installationID := installation.GetID()

		account := installation.GetAccount()
		targetType, targetLogin := "unknown", "unknown"
		if account != nil {
			targetType = normalizeTargetType(account.GetType())
			targetLogin = account.GetLogin()
		}

		if _, err := s.Store.UpsertInstallation(ctx, installationID, targetType, targetLogin); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for _, repo := range e.RepositoriesAdded {
			if repo == nil {
				continue
			}
			if err := s.Store.UpsertRepoLink(ctx, installationID, repo.GetFullName()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		for _, repo := range e.RepositoriesRemoved {
			if repo == nil {
				continue
			}
			if err := s.Store.DeleteRepoLink(ctx, installationID, repo.GetFullName()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

	default:
		// Ignore other events.
	}

	w.WriteHeader(http.StatusAccepted)
}

func normalizeTargetType(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "organization", "user":
		return s
	default:
		if s == "" {
			return "unknown"
		}
		return s
	}
}
