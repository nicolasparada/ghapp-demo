package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"
)

//go:embed templates static
var embeddedFiles embed.FS

// tailwindSource is the Tailwind CSS v4 input, inlined into every page inside a
// <style type="text/tailwindcss"> block. The Tailwind browser CDN script picks
// it up and compiles it client-side, so there is no build step.
var tailwindSource = func() template.CSS {
	b, err := embeddedFiles.ReadFile("static/tailwind.css")
	if err != nil {
		panic(err)
	}
	return template.CSS(b)
}()

type Renderer struct{}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func (r *Renderer) Render(w http.ResponseWriter, page string, data any) error {
	return r.render(w, page, data, 0)
}

func (r *Renderer) RenderWithStatus(w http.ResponseWriter, status int, page string, data any) error {
	return r.render(w, page, data, status)
}

func (r *Renderer) render(w http.ResponseWriter, page string, data any, status int) error {
	tpl, err := template.New("base").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"shortSHA": func(sha string) string {
			if len(sha) <= 7 {
				return sha
			}
			return sha[:7]
		},
		"isoTime": func(t time.Time) string {
			return t.UTC().Format(time.RFC3339)
		},
		"isSelected": func(selected map[string]bool, key string) bool {
			return selected[key]
		},
		"tailwindCSS": func() template.CSS {
			return tailwindSource
		},
	}).ParseFS(embeddedFiles, "templates/base.html", fmt.Sprintf("templates/%s", page))
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status > 0 {
		w.WriteHeader(status)
	}
	if err := tpl.ExecuteTemplate(w, "base", data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	return nil
}

func StaticHandler() http.Handler {
	sub, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
