package api

import (
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
)

// TestValidRedirectURI_LoopbackAnyPort: the contract that lets
// auth-aws-creds / auth-ssh-creds register one bare loopback URI
// once and have it accept whatever ephemeral port the CLI picks. The
// table is the load-bearing documentation here — every accept/reject
// case is captured so a future refactor can't loosen or tighten the
// match silently.
func TestValidRedirectURI_LoopbackAnyPort(t *testing.T) {
	tests := []struct {
		name       string
		registered []string
		uri        string
		want       bool
	}{
		{
			name:       "exact match still wins",
			registered: []string{"https://app.example/cb"},
			uri:        "https://app.example/cb",
			want:       true,
		},
		{
			name:       "non-loopback rejects on any mismatch",
			registered: []string{"https://app.example/cb"},
			uri:        "https://attacker.example/cb",
			want:       false,
		},
		{
			name:       "loopback bare registered, ephemeral port used",
			registered: []string{"http://127.0.0.1/callback"},
			uri:        "http://127.0.0.1:51823/callback",
			want:       true,
		},
		{
			name:       "loopback registered with placeholder port, different port used",
			registered: []string{"http://127.0.0.1:8080/callback"},
			uri:        "http://127.0.0.1:51823/callback",
			want:       true,
		},
		{
			name:       "localhost name accepted as loopback",
			registered: []string{"http://localhost/callback"},
			uri:        "http://localhost:51823/callback",
			want:       true,
		},
		{
			name:       "registered 127.0.0.1 matches localhost name (both loopback)",
			registered: []string{"http://127.0.0.1/callback"},
			uri:        "http://localhost:9999/callback",
			want:       true,
		},
		{
			name:       "ipv6 loopback ::1 accepted",
			registered: []string{"http://[::1]/callback"},
			uri:        "http://[::1]:9999/callback",
			want:       true,
		},
		{
			name:       "path mismatch on loopback still rejected",
			registered: []string{"http://127.0.0.1/callback"},
			uri:        "http://127.0.0.1:9999/other",
			want:       false,
		},
		{
			name:       "https scheme on loopback NOT auto-accepted",
			registered: []string{"http://127.0.0.1/callback"},
			uri:        "https://127.0.0.1:9999/callback",
			want:       false,
		},
		{
			name:       "non-loopback host rejected even if structurally similar",
			registered: []string{"http://127.0.0.1/callback"},
			uri:        "http://192.168.1.1:9999/callback",
			want:       false,
		},
		{
			name:       "empty registered list rejects everything",
			registered: []string{},
			uri:        "http://127.0.0.1:9999/callback",
			want:       false,
		},
		{
			name:       "malformed uri rejected",
			registered: []string{"http://127.0.0.1/callback"},
			uri:        ":::not-a-url",
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &model.Client{RedirectURIs: tc.registered}
			got := validRedirectURI(client, tc.uri)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
