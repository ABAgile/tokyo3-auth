package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestAdminCreateUser_RejectsWeakPassword asserts that POST /admin/users
// runs the same policy engine as the portal admin form. Without this
// gate, calling SDKs and provisioning scripts could create accounts
// with weak passwords that the UI would have refused — a meaningful
// hole in the password-policy story.
//
// Three cases:
//   - Weak password ("password") → 400 weak_password
//   - Empty password → 400 invalid_request (existing behavior, unchanged)
//   - Policy-compliant password → 201 Created
func TestAdminCreateUser_RejectsWeakPassword(t *testing.T) {
	r := newTestRig(t)
	tok := seedAdminSession(t, r)

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantErr    string // empty = no specific error code expected
	}{
		{
			name:       "weak password rejected",
			body:       `{"email":"weak@example.com","password":"password","name":"Weak"}`,
			wantStatus: http.StatusBadRequest,
			wantErr:    "weak_password",
		},
		{
			name:       "missing password still 400 invalid_request",
			body:       `{"email":"empty@example.com","password":"","name":"Empty"}`,
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid_request",
		},
		{
			name:       "strong password succeeds",
			body:       `{"email":"strong@example.com","password":"FullyC0mpliant!Pass","name":"Strong"}`,
			wantStatus: http.StatusCreated,
			wantErr:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := adminReq(t, r, "POST", "/admin/users", tc.body, tok)
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantErr == "" {
				return
			}
			body := decodeJSON[map[string]any](t, resp)
			if got, _ := body["error"].(string); got != tc.wantErr {
				t.Errorf("error code = %q, want %q (body: %v)", got, tc.wantErr, body)
			}
			if got, _ := body["error_description"].(string); got == "" {
				t.Error("error_description empty; clients need a human-readable reason to surface")
			}
		})
	}
}

// TestAdminCreateUser_PolicyMessageDescribesRule guards against the
// regression where a policy violation 400 omits the specific rule's
// message — clients calling this API need actionable feedback, not just
// "weak_password" without context.
func TestAdminCreateUser_PolicyMessageDescribesRule(t *testing.T) {
	r := newTestRig(t)
	tok := seedAdminSession(t, r)
	// "Aaaa1!" is short — should trip the length rule specifically.
	resp := adminReq(t, r, "POST", "/admin/users",
		`{"email":"short@example.com","password":"Aa1!","name":"Short"}`, tok)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp)
	desc, _ := body["error_description"].(string)
	// The PCI rule's message mentions "12 characters" for the length
	// gate; brittle on the exact wording, but if the description is
	// totally missing or generic ("invalid password") that's worse than
	// matching the substring.
	if !strings.Contains(strings.ToLower(desc), "character") &&
		!strings.Contains(strings.ToLower(desc), "length") {
		t.Errorf("error_description %q doesn't seem to describe the length rule", desc)
	}
}
