package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// seedAdminPortalCookie seeds an admin user, drives the portal login,
// and returns the resulting auth_portal cookie so a test can authenticate
// portalAdminAuth-gated routes. The user's email is the email param;
// password is fixed (PCI-compliant) to keep test data terse.
func seedAdminPortalCookie(t *testing.T, r *testRig, email string) *http.Cookie {
	t.Helper()
	const pw = "AdminP@ssw0rd-test"
	u := seedTestUser(t, r.store, email, pw)
	if err := r.store.SetUserAdmin(t.Context(), u.ID, true); err != nil {
		t.Fatalf("SetUserAdmin: %v", err)
	}
	form := url.Values{"email": {email}, "password": {pw}}
	resp := r.postForm(t, "/portal/login", form.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("portal login status = %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" {
			return c
		}
	}
	t.Fatal("no auth_portal cookie after admin login")
	return nil
}

// TestRevokeAWSSessions_NoIntegrationEnabled verifies the safety branch:
// clicking the button when no aws_federation provisioner is registered
// returns a clear "nothing to revoke" message rather than silently
// succeeding with zero effect. This is the most common deployment
// state (federation set up, revocation provisioner not yet enabled)
// and the operator needs to know the click did nothing.
func TestRevokeAWSSessions_NoIntegrationEnabled(t *testing.T) {
	r := newTestRig(t)
	cookie := seedAdminPortalCookie(t, r, "admin@example.com")

	// Seed a target user — the revoke endpoint only cares about the ID.
	target := seedTestUser(t, r.store, "victim@example.com", "V1ctimP@ssword!")

	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/admin/users/"+target.ID.String()+"/revoke-aws",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	wantPath := "/portal/admin/users/" + target.ID.String() + "/edit"
	if !strings.HasPrefix(loc, wantPath) {
		t.Errorf("redirect target = %q, want prefix %q", loc, wantPath)
	}
	// The error query param should carry the "nothing to revoke"
	// message — not literal string match (URL-encoded), just verify
	// "error=" present and "nothing to revoke" appears decoded.
	parsed, _ := url.Parse(loc)
	if got := parsed.Query().Get("error"); !strings.Contains(got, "nothing to revoke") {
		t.Errorf("error query = %q, want substring %q", got, "nothing to revoke")
	}
}

// TestRevokeAWSSessions_RequiresAdmin asserts the portalAdminAuth gate.
// A regular (non-admin) user hitting the endpoint must be refused; the
// awsfed revocation push is too privileged to expose without admin role.
func TestRevokeAWSSessions_RequiresAdmin(t *testing.T) {
	r := newTestRig(t)
	const pw = "RegularP@ssw0rd"
	u := seedTestUser(t, r.store, "regular@example.com", pw)

	form := url.Values{"email": {u.Email}, "password": {pw}}
	resp := r.postForm(t, "/portal/login", form.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no auth_portal cookie after login")
	}

	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/admin/users/"+u.ID.String()+"/revoke-aws",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp2, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", resp2.StatusCode)
	}
}

// TestRevokeAWSSessions_RequiresPortalSession asserts that the route is
// gated by portalAuth — anonymous POSTs must redirect to login, not
// silently process the request as some default-user.
func TestRevokeAWSSessions_RequiresPortalSession(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "anon-target@example.com", "Targ3tP@ssw0rd")

	resp := r.postForm(t, "/portal/admin/users/"+u.ID.String()+"/revoke-aws", "")
	if resp.StatusCode != http.StatusFound {
		t.Errorf("anonymous status = %d, want 302 (redirect to login)", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/portal/login") {
		t.Errorf("Location = %q, want /portal/login prefix", loc)
	}
}
