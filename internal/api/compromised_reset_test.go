package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/google/uuid"
)

// TestResetPassword_GeneratesTempAndSetsFlag verifies the
// auto-generated temp password pattern: the handler must not require
// an admin-supplied password (the input was removed), must surface a
// non-empty temp credential in the redirect's `temp_pw` query, and
// must flip must_change_password on the user row.
func TestResetPassword_GeneratesTempAndSetsFlag(t *testing.T) {
	r := newTestRig(t)
	cookie := seedAdminPortalCookie(t, r, "admin@example.com")
	target := seedTestUser(t, r.store, "victim@example.com", "OldP@ssw0rd!")

	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/admin/users/"+target.ID.String()+"/reset-password",
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
	loc, _ := url.Parse(resp.Header.Get("Location"))
	temp := loc.Query().Get("temp_pw")
	if temp == "" {
		t.Fatal("redirect missing temp_pw query — handler should surface the generated token once")
	}
	if len(temp) < 16 {
		t.Errorf("temp_pw length = %d, want ≥16 (security)", len(temp))
	}

	// Flag must be set on the target user.
	updated, err := r.store.GetUserByID(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !updated.MustChangePassword {
		t.Error("must_change_password should be TRUE after reset; user can use temp pw forever otherwise")
	}
	// The new password hash must verify against the temp credential —
	// proves the server-generated token is what got stored.
	if !creds.CheckPassword(updated.PasswordHash, temp) {
		t.Error("stored password hash doesn't verify against the surfaced temp_pw")
	}
}

// TestLogin_MustChangePasswordRoutesToRotation asserts the interceptor:
// after CheckPassword succeeds, a user with must_change_password=true
// is routed to /portal/login/change-password instead of being issued a
// session or proceeding to MFA. This is the load-bearing guarantee for
// "forced rotation works."
func TestLogin_MustChangePasswordRoutesToRotation(t *testing.T) {
	r := newTestRig(t)
	const pw = "RotateM3-Pl3@se"
	u := seedTestUser(t, r.store, "rotator@example.com", pw)
	if err := r.store.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	form := url.Values{"email": {u.Email}, "password": {pw}}
	resp := r.postForm(t, "/portal/login", form.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/portal/login/change-password") {
		t.Errorf("Location = %q, want /portal/login/change-password prefix", loc)
	}
	// portal_login cookie should be set (carries userID for the
	// change-password handler).
	var loginCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "portal_login" {
			loginCookie = c
		}
	}
	if loginCookie == nil {
		t.Error("portal_login cookie not set; change-password handler won't know which user to rotate")
	}
	// auth_portal session cookie should NOT be set — the user is not
	// authenticated for portal yet.
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" {
			t.Error("auth_portal session cookie issued before forced rotation; rotation gate is bypassable")
		}
	}
}

// TestChangePassword_ClearsFlagAndIssuesSession exercises the full
// happy path: user with must_change_password=true logs in, gets the
// portal_login cookie, posts a new password to /portal/login/change-password,
// the handler validates against PCI policy, persists the new hash,
// clears the flag, and issues a session (since MFA is not enabled
// on this test user).
func TestChangePassword_ClearsFlagAndIssuesSession(t *testing.T) {
	r := newTestRig(t)
	const oldPw = "ExpiredP@ssw0rd-1"
	const newPw = "FreshP@ssw0rd-2"
	u := seedTestUser(t, r.store, "alice@example.com", oldPw)
	if err := r.store.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	// Step 1: login with the temp/old credential, capture portal_login cookie.
	loginResp := r.postForm(t, "/portal/login",
		url.Values{"email": {u.Email}, "password": {oldPw}}.Encode())
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", loginResp.StatusCode)
	}
	var portalLogin *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "portal_login" {
			portalLogin = c
		}
	}
	if portalLogin == nil {
		t.Fatal("no portal_login cookie after login")
	}

	// Step 2: post the new password to the rotation endpoint.
	form := url.Values{"new_password": {newPw}, "confirm": {newPw}}
	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/login/change-password",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(portalLogin)
	resp, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("rotation status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/portal" {
		t.Errorf("post-rotation Location = %q, want /portal", loc)
	}
	// auth_portal session cookie should NOW be set.
	var portal *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" {
			portal = c
		}
	}
	if portal == nil {
		t.Error("auth_portal session cookie not issued after successful rotation")
	}

	// Flag must be cleared; new password must validate.
	updated, _ := r.store.GetUserByID(context.Background(), u.ID)
	if updated.MustChangePassword {
		t.Error("must_change_password still TRUE after successful rotation")
	}
	if !creds.CheckPassword(updated.PasswordHash, newPw) {
		t.Error("stored hash doesn't verify against the new password")
	}
	if creds.CheckPassword(updated.PasswordHash, oldPw) {
		t.Error("old (temp) password still verifies — rotation didn't actually replace it")
	}
}

// TestChangePassword_WeakPasswordRejected verifies the PCI policy
// engine still runs on the rotation form. The user can't get past
// rotation with a weak password just because they're holding a temp
// credential.
func TestChangePassword_WeakPasswordRejected(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "OldP@ssw0rd1!")
	if err := r.store.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}
	loginResp := r.postForm(t, "/portal/login",
		url.Values{"email": {u.Email}, "password": {"OldP@ssw0rd1!"}}.Encode())
	var portalLogin *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "portal_login" {
			portalLogin = c
		}
	}

	form := url.Values{"new_password": {"weak"}, "confirm": {"weak"}}
	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/login/change-password",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(portalLogin)
	resp, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	// Re-renders the form with an error (200 OK), not a redirect.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("weak password status = %d, want 200 (form re-render with error)", resp.StatusCode)
	}
	// Flag should still be set — rotation didn't succeed.
	updated, _ := r.store.GetUserByID(context.Background(), u.ID)
	if !updated.MustChangePassword {
		t.Error("must_change_password cleared despite weak password being rejected")
	}
}

// TestCompromisedReset_BundlesAllPrimitives verifies the headline
// behavior: one click clears MFA + sets the rotation flag + kills
// sessions + surfaces a temp password. AWS revocation is exercised
// in the awsfed package tests (the test rig has no aws_federation
// integration, so awsTargets=0 here — but the audit row records that).
func TestCompromisedReset_BundlesAllPrimitives(t *testing.T) {
	r := newTestRig(t)
	cookie := seedAdminPortalCookie(t, r, "admin@example.com")
	target := seedTestUser(t, r.store, "victim@example.com", "OldP@ssw0rd!")

	// Enable MFA on the target so the wipe has something to remove.
	if err := r.store.UpdateUserMFAEnabled(context.Background(), target.ID, true); err != nil {
		t.Fatalf("UpdateUserMFAEnabled: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/admin/users/"+target.ID.String()+"/compromised-reset",
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

	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("temp_pw") == "" {
		t.Error("compromised reset must surface a temp_pw, same as Reset Password")
	}

	updated, _ := r.store.GetUserByID(context.Background(), target.ID)
	if !updated.MustChangePassword {
		t.Error("must_change_password should be TRUE after compromised reset")
	}
	if updated.MFAEnabled {
		t.Error("MFAEnabled should be FALSE after compromised reset (forces re-enrollment)")
	}
	if !updated.Active {
		t.Error("user should remain Active — compromised reset is not deactivation")
	}
}

// TestCompromisedReset_RequiresAdmin asserts the portalAdminAuth gate.
// A regular user must not be able to trigger a compromised reset
// against any account, including their own.
func TestCompromisedReset_RequiresAdmin(t *testing.T) {
	r := newTestRig(t)
	const pw = "RegularP@ssword!"
	u := seedTestUser(t, r.store, "regular@example.com", pw)

	loginResp := r.postForm(t, "/portal/login",
		url.Values{"email": {u.Email}, "password": {pw}}.Encode())
	var cookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "auth_portal" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no auth_portal cookie after login")
	}

	req, _ := http.NewRequest(http.MethodPost,
		r.srv.URL+"/portal/admin/users/"+u.ID.String()+"/compromised-reset",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin compromised-reset status = %d, want 403", resp.StatusCode)
	}
}

// confirm the model field rounds-trips through CreateUser→GetUser.
// Mostly a sanity check that the migration + scan-extension landed
// correctly across both backends.
func TestUserStore_MustChangePasswordRoundTrip(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "rtr@example.com", "Roundtr1pP@ss!")
	if u.MustChangePassword {
		t.Error("freshly-created user should have MustChangePassword=false by default")
	}
	if err := r.store.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}
	got, _ := r.store.GetUserByID(context.Background(), u.ID)
	if !got.MustChangePassword {
		t.Error("flag didn't persist; expected TRUE after SetUserMustChangePassword")
	}
	// UpdateUserPassword should clear the flag in the same statement.
	hash, _ := creds.HashPassword("NewP@ssw0rd-12!")
	if err := r.store.UpdateUserPassword(context.Background(), u.ID, hash); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	got, _ = r.store.GetUserByID(context.Background(), u.ID)
	if got.MustChangePassword {
		t.Error("UpdateUserPassword should clear MustChangePassword; flag still TRUE")
	}
}

// unused, but suppresses the "imported and not used" check if the helper
// imports drift. Keeping it tied to a referenced symbol.
var _ = uuid.Nil
