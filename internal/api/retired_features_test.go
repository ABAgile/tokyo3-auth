package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetiredOAuthRoutesRemoved(t *testing.T) {
	r := newTestRig(t)
	handler := r.server.Routes()
	for _, path := range []string{
		"/login/oauth/authorize",
		"/api/v3/user", "/api/v3/user/emails", "/api/v3/user/orgs", "/api/v3/user/teams",
		"/user", "/user/emails", "/user/orgs", "/user/teams",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusNotFound {
				t.Errorf("GET %s: status = %d, want 404", path, w.Code)
			}
		})
	}

	// The GET / fallback makes unknown POST paths return 405, not 404.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login/oauth/access_token", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("retired token exchange: status = %d, want 405", w.Code)
	}
}

func TestExtractBearerTokenRejectsLegacyScheme(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   string
	}{
		{"Bearer opaque-token", "opaque-token"},
		{"token opaque-token", ""},
		{"Basic opaque-token", ""},
		{"Bearer ", ""},
		{"", ""},
	} {
		t.Run(tc.header, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			r.Header.Set("Authorization", tc.header)
			if got := extractBearerToken(r); got != tc.want {
				t.Errorf("extractBearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
