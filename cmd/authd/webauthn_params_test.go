package main

import (
	"slices"
	"testing"
)

// TestWebAuthnParams covers RPID derivation from the issuer plus the
// AUTH_WEBAUTHN_RPID override. The override is what lets credentials be
// scoped to a parent domain (e.g. example.com) so they survive moves
// between sibling subdomains; the regression we're guarding against is
// the override being dropped or applied to origins instead of the RPID.
func TestWebAuthnParams(t *testing.T) {
	cases := []struct {
		name        string
		issuer      string
		rpidEnv     string
		originsEnv  string
		wantRPID    string
		wantOrigins []string
	}{
		{
			name:        "derived from issuer",
			issuer:      "https://auth.example.com",
			wantRPID:    "auth.example.com",
			wantOrigins: []string{"https://auth.example.com"},
		},
		{
			name:        "port stripped from rpid but kept in origin",
			issuer:      "https://auth.example.com:8443",
			wantRPID:    "auth.example.com",
			wantOrigins: []string{"https://auth.example.com:8443"},
		},
		{
			name:        "rpid override",
			issuer:      "https://auth.example.com",
			rpidEnv:     "example.com",
			originsEnv:  "https://auth2.example.com",
			wantRPID:    "example.com",
			wantOrigins: []string{"https://auth.example.com", "https://auth2.example.com"},
		},
		{
			name:        "unparseable issuer falls back to localhost",
			issuer:      "not a url",
			rpidEnv:     "example.com",
			wantRPID:    "localhost",
			wantOrigins: []string{"not a url"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTH_WEBAUTHN_RPID", tc.rpidEnv)
			t.Setenv("AUTH_WEBAUTHN_ORIGINS", tc.originsEnv)
			rpID, origins := webAuthnParams(tc.issuer)
			if rpID != tc.wantRPID {
				t.Errorf("rpID = %q, want %q", rpID, tc.wantRPID)
			}
			if !slices.Equal(origins, tc.wantOrigins) {
				t.Errorf("origins = %v, want %v", origins, tc.wantOrigins)
			}
		})
	}
}
