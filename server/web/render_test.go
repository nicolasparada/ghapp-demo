package web

import (
	"fmt"
	"html/template"
	"testing"
)

func TestTemplatesParse(t *testing.T) {
	t.Parallel()

	pages := []string{
		"login.html",
		"dashboard.html",
		"project.html",
		"connect.html",
		"run.html",
	}

	funcMap := template.FuncMap{
		"fmtTime": func(any) string {
			return ""
		},
		"shortSHA": func(sha string) string {
			return sha
		},
		"isSelected": func(selected map[string]bool, key string) bool {
			return selected[key]
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
