package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	creds "github.com/abagile/tokyo3-base/auth/creds"
)

// recoverMiddleware catches any panic from a handler, logs the panic with
// the originating method/path + a full stack trace, and writes a 500 to
// the client if the response headers haven't been flushed yet. Mounted
// once around the whole mux from Routes() — every endpoint goes through
// it. http.Server's built-in recovery also catches panics but just drops
// the connection and writes the stack to stderr; that's invisible in
// structured log shipping and leaves clients hanging.
//
// http.ErrAbortHandler is re-panicked: it's the documented sentinel for
// "abort this request without logging" used by net/http internals.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			s.log.Error("handler panic recovered",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"panic", fmt.Sprintf("%v", rec),
				"stack", string(debug.Stack()))
			// Best-effort 500. If the handler has already written
			// headers (e.g. mid-stream SSE) the WriteHeader call is
			// a no-op net/http logs but doesn't crash on; the
			// connection still terminates cleanly when the deferred
			// recover unwinds.
			defer func() { _ = recover() }()
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"internal error"}`))
		}()
		next.ServeHTTP(w, r)
	})
}

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
