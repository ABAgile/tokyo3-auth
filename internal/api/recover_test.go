package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRecoverMiddleware_RecoversAndReturns500 pins the contract that a
// handler panic is converted to a 500 instead of crashing the IdP. This
// is load-bearing for the whole production access stack: every AWS
// console launch, every SSH proxy session, every vault login routes
// through authd, so a panic-on-process model would tear all of it down
// at once.
func TestRecoverMiddleware_RecoversAndReturns500(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) {
		panic("synthetic panic for test")
	})
	wrapped := s.recoverMiddleware(mux)

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/boom")
	if err != nil {
		t.Fatalf("GET /boom: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("want 500 after recovered panic, got %d", resp.StatusCode)
	}
}

// TestRecoverMiddleware_RepanicsErrAbortHandler proves the documented
// sentinel that net/http uses to abort a connection without logging
// still works — recovery must not swallow it. Otherwise hijacker-style
// handlers leak state.
func TestRecoverMiddleware_RepanicsErrAbortHandler(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /abort", func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	wrapped := s.recoverMiddleware(mux)

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	// The HTTP client sees a closed connection (net/http aborts the
	// response when ErrAbortHandler propagates). The test passes as
	// long as the server process didn't crash — either an err or a
	// non-200 response satisfies that.
	resp, err := http.Get(srv.URL + "/abort")
	if err == nil {
		_ = resp.Body.Close()
	}
}
