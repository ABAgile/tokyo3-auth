package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/audit"
	"github.com/abagile/tokyo3-base/journal"
)

func TestClientIP_TrustsForwardedForOnlyFromTrustedProxy(t *testing.T) {
	r := newTestRig(t)
	cases := []struct {
		name, remote, xff, want string
	}{
		{"direct client, no header", "203.0.113.50:4000", "", "203.0.113.50"},
		{"untrusted peer cannot spoof", "203.0.113.50:4000", "1.2.3.4", "203.0.113.50"},
		{"trusted proxy forwards client", "10.0.0.5:4000", "198.51.100.7", "198.51.100.7"},
		{"client-supplied hop is skipped", "10.0.0.5:4000", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"trusted hops are skipped", "10.0.0.5:4000", "198.51.100.7, 10.0.0.9", "198.51.100.7"},
		{"trusted proxy, no header", "10.0.0.5:4000", "", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := r.server.clientIP(req); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

type captureSink struct {
	mu   sync.Mutex
	rows [][]byte
}

func (c *captureSink) Append(_ context.Context, p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, append([]byte(nil), p...))
	return nil
}
func (*captureSink) Close() error { return nil }

// The audit record carries the resolved client address (not the proxy's, and
// not a forged header from an untrusted peer).
func TestAuditEntryUsesResolvedClientIP(t *testing.T) {
	r := newTestRig(t)
	sink := &captureSink{}
	r.server.audit = journal.NewJSONSink[audit.Entry](sink)
	req := httptest.NewRequest(http.MethodPost, "/portal/login", nil)
	req.RemoteAddr = "10.0.0.5:4000" // trusted proxy
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	if err := r.server.logAudit(req, ActionLoginFailed, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.50:4000" // untrusted peer forging a header
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if err := r.server.logAudit(req, ActionLoginFailed, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range sink.rows {
		var e audit.Entry
		if err := json.Unmarshal(p, &e); err != nil {
			t.Fatal(err)
		}
		got = append(got, e.IP)
	}
	if len(got) != 2 || got[0] != "198.51.100.7" || got[1] != "203.0.113.50" {
		t.Errorf("audit IPs = %v, want [198.51.100.7 203.0.113.50]", got)
	}
}
