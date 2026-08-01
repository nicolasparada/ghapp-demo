package web

import (
	"fmt"
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTemplatesParse(t *testing.T) {
	t.Parallel()

	pages := []string{
		"login.html",
		"dashboard.html",
		"project.html",
		"connect.html",
		"members.html",
		"repo_runs.html",
		"run.html",
	}

	funcMap := template.FuncMap{
		"fmtTime": func(any) string {
			return ""
		},
		"shortSHA": func(sha string) string {
			return sha
		},
		"isoTime": func(any) string {
			return ""
		},
		"isSelected": func(selected map[string]bool, key string) bool {
			return selected[key]
		},
		"tailwindCSS": func() template.CSS {
			return ""
		},
	}

	for _, page := range pages {
		page := page
		t.Run(page, func(t *testing.T) {
			t.Parallel()
			_, err := template.New("base").Funcs(funcMap).ParseFS(
				embeddedFiles,
				"templates/base.html",
				fmt.Sprintf("templates/%s", page),
			)
			if err != nil {
				t.Fatalf("parse template %s: %v", page, err)
			}
		})
	}
}

// TestRenderPages executes every page. Contextual auto-escaping is resolved on
// first execution, not at parse time, so this is what catches markup that
// html/template refuses to escape.
func TestRenderPages(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2024, 5, 17, 9, 30, 0, 0, time.UTC)
	user := map[string]any{"Login": "octocat", "AvatarURL": "https://example.test/a.png"}
	project := map[string]any{"Name": "My project", "Slug": "my-project"}

	pages := map[string]any{
		"login.html": map[string]any{
			"Title": "Login",
			"Error": "something went wrong",
		},
		"dashboard.html": map[string]any{
			"Title":       "Dashboard",
			"CurrentUser": user,
			"Projects":    []any{project},
		},
		"project.html": map[string]any{
			"Title":       "My project",
			"CurrentUser": user,
			"Project":     project,
			"Repos": []any{map[string]any{
				"FullName": "octocat/hello-world",
			}},
			"Runs": []any{map[string]any{
				"PublicID":     "018f39f2-45cd-7a7f-9c59-11b83f7937eb",
				"CommitSHA":    "0123456789abcdef",
				"WorkflowName": "CI",
				"JobName":      "build",
				"Branch":       "main",
				"EventName":    "push",
				"CreatedAt":    createdAt,
			}},
		},
		"connect.html": map[string]any{
			"Title":       "Project repositories",
			"CurrentUser": user,
			"Project":     project,
			"Repos": []any{map[string]any{
				"FullName":    "octocat/hello-world",
				"Visibility":  "public",
				"UpdatedFrom": "api",
				"Bound":       true,
			}},
			"GitHubAppInstallURL":  "https://github.com/apps/demo/installations/new",
			"GitHubAppSettingsURL": "https://github.com/settings/installations",
		},
		"members.html": map[string]any{
			"Title":       "Project members",
			"CurrentUser": user,
			"Project":     project,
		},
		"repo_runs.html": map[string]any{
			"Title":       "octocat/hello-world",
			"CurrentUser": user,
			"RepoOwner":   "octocat",
			"RepoName":    "hello-world",
			"Runs": []any{map[string]any{
				"PublicID":     "018f39f2-45cd-7a7f-9c59-11b83f7937eb",
				"CommitSHA":    "0123456789abcdef",
				"WorkflowName": "CI",
				"JobName":      "build",
				"Branch":       "main",
				"CreatedAt":    createdAt,
			}},
		},
		"run.html": map[string]any{
			"Title":           "Run details",
			"CurrentUser":     user,
			"RepoOwner":       "octocat",
			"RepoName":        "hello-world",
			"ShowMemberViews": true,
			"Run": map[string]any{
				"RepoFullName": "octocat/hello-world",
				"CommitSHA":    "0123456789abcdef",
				"Branch":       "main",
				"Actor":        "octocat",
				"EventName":    "push",
				"CreatedAt":    createdAt,
			},
			"Summary": map[string]any{
				"LineageRootLabel": "node",
				"LineageRoots": []any{map[string]any{
					"Label":        "node",
					"DirectEgress": 1,
					"TotalEgress":  2,
					"Egress":       []any{map[string]any{"Target": "api.github.com:443", "Count": 3}},
					"Children": []any{map[string]any{
						"Label":        "curl",
						"DirectEgress": 1,
						"TotalEgress":  1,
						"Egress":       []any{map[string]any{"Target": "example.test:443", "Count": 1}},
					}},
				}},
				"ErrorMessages": []string{"could not resolve pid 42"},
			},
		},
	}

	for page, data := range pages {
		t.Run(page, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			if err := NewRenderer().Render(rec, page, data); err != nil {
				t.Fatalf("render %s: %v", page, err)
			}

			body := rec.Body.String()
			for _, want := range []string{"<!doctype html>", `id="main"`, "@import \"tailwindcss\";"} {
				if !strings.Contains(body, want) {
					t.Errorf("render %s: body missing %q", page, want)
				}
			}
			if strings.Contains(body, "ZgotmplZ") {
				t.Errorf("render %s: body contains an escaping failure (ZgotmplZ)", page)
			}
		})
	}
}
