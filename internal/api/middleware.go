package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/auth"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
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

// bearerAuth validates the Bearer token and injects the session into context.
func (s *Server) bearerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			s.writeError(w, http.StatusUnauthorized, "unauthorized", "missing token")
			return
		}
		sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), auth.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusUnauthorized, "invalid_token", "token not found")
			return
		}
		if err != nil {
			s.log.Error("bearer auth", "err", err)
			s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
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
		sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), auth.HashToken(raw))
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
		ctx := context.WithValue(r.Context(), ctxSession, sess)
		next(w, r.WithContext(ctx))
	}
}

// scimAuth validates the SCIM bearer token.
func (s *Server) scimAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			writeSCIMError(w, http.StatusUnauthorized, "missing token")
			return
		}
		_, err := s.store.GetSCIMTokenByHash(r.Context(), auth.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			writeSCIMError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if err != nil {
			s.log.Error("scim auth", "err", err)
			writeSCIMError(w, http.StatusInternalServerError, "internal error")
			return
		}
		next(w, r)
	}
}

func containsStr(ss []string, target string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}
