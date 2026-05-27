package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	creds "github.com/abagile/tokyo3-base/auth/creds"
)

type contextKey int

const (
	ctxSession contextKey = iota
	ctxAdminToken
)

func sessionFromCtx(r *http.Request) *model.Session {
	s, _ := r.Context().Value(ctxSession).(*model.Session)
	return s
}

// extractBearerToken returns the access token from the Authorization header,
// accepting both `Bearer <token>` (RFC 6750) and `token <token>` (GitHub's
// legacy v3 scheme). Teleport's github connector uses the `token` form when
// calling our github-compat /user endpoints; OIDC clients use `Bearer`.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if raw, ok := strings.CutPrefix(h, "Bearer "); ok {
		return raw
	}
	if raw, ok := strings.CutPrefix(h, "token "); ok {
		return raw
	}
	return ""
}

// bearerAuth validates the bearer token and injects the session into context.
// Accepts both RFC 6750 `Bearer <token>` and GitHub's legacy `token <token>`
// scheme; see extractBearerToken.
func (s *Server) bearerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := extractBearerToken(r)
		if raw == "" {
			s.writeError(w, http.StatusUnauthorized, "unauthorized", "missing token")
			return
		}
		sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), creds.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusUnauthorized, "invalid_token", "token not found")
			return
		}
		if err != nil {
			s.log.Error("bearer auth", "err", err)
			s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}
		if !sessionTokenLive(sess) {
			s.writeError(w, http.StatusUnauthorized, "invalid_token", "access token expired")
			return
		}
		ctx := context.WithValue(r.Context(), ctxSession, sess)
		next(w, r.WithContext(ctx))
	}
}

// adminAuth validates an admin bearer token (same mechanism, but checks the user is an admin).
// For simplicity, admin tokens are stored as sessions with scope "admin".
func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			s.writeError(w, http.StatusUnauthorized, "unauthorized", "missing token")
			return
		}
		sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), creds.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusUnauthorized, "invalid_token", "token not found")
			return
		}
		if err != nil {
			s.log.Error("admin auth", "err", err)
			s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}
		if !containsStr(sess.Scopes, "admin") {
			s.writeError(w, http.StatusForbidden, "insufficient_scope", "admin scope required")
			return
		}
		if !sessionTokenLive(sess) {
			s.writeError(w, http.StatusUnauthorized, "invalid_token", "access token expired")
			return
		}
		ctx := context.WithValue(r.Context(), ctxSession, sess)
		next(w, r.WithContext(ctx))
	}
}

// sessionTokenLive enforces both gates for a bearer access token: the
// per-token expiry advertised in `expires_in`, and the absolute session
// lifetime. Past either, the token is dead — re-auth or refresh required.
func sessionTokenLive(sess *model.Session) bool {
	now := time.Now()
	if now.After(sess.AccessExpiresAt) {
		return false
	}
	if now.After(sess.CreatedAt.Add(absoluteSessionTTL)) {
		return false
	}
	return true
}

func containsStr(ss []string, target string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}
