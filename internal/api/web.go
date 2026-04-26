package api

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed web
var webFS embed.FS

// tmplManager parses and caches named page templates composed with a base layout.
type tmplManager struct {
	base *template.Template
}

func newTmplManager(baseFile string) (*tmplManager, error) {
	base, err := template.New("").ParseFS(webFS, "web/tmpl/"+baseFile)
	if err != nil {
		return nil, fmt.Errorf("parse base %s: %w", baseFile, err)
	}
	return &tmplManager{base: base}, nil
}

// render executes the named page template composed with this manager's base layout.
func (m *tmplManager) render(w http.ResponseWriter, pageFile string, data any) {
	t, err := m.base.Clone()
	if err != nil {
		http.Error(w, "template clone error", http.StatusInternalServerError)
		return
	}
	t, err = t.ParseFS(webFS, "web/tmpl/"+pageFile)
	if err != nil {
		http.Error(w, "template parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		// Headers already sent; log only.
		_ = err
	}
}

// staticHandler serves embedded files under web/static/ at /static/.
func staticHandler() http.Handler {
	sub, err := fs.Sub(webFS, "web/static")
	if err != nil {
		panic("web/static not found in embed: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
