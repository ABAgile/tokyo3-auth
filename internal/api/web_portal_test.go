package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPortalLoginGET_RendersForm(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/portal/login")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestPortalRegisterGET_RendersForm(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/portal/register")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPortalRegisterPOST_Success(t *testing.T) {
	r := newTestRig(t)
	form := url.Values{
		"email":    {"reg@example.com"},
		"name":     {"Reg User"},
		"password": {"V3ryStr0ngP@ss"},
		"confirm":  {"V3ryStr0ngP@ss"},
	}
	resp := r.postForm(t, "/portal/register", form.Encode())
	// Successful register → 302 to /portal.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/portal" {
		t.Errorf("Location = %q, want /portal", loc)
	}

	// User row was created.
	if _, err := r.store.GetUserByEmail(t.Context(), "reg@example.com"); err != nil {
		t.Errorf("user not persisted: %v", err)
	}

	// A portal cookie should have been set.
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("auth_portal cookie not set on successful register")
	}
}

func TestPortalRegisterPOST_PasswordMismatch(t *testing.T) {
	r := newTestRig(t)
	form := url.Values{
		"email":    {"mismatch@example.com"},
		"password": {"V3ryStr0ngP@ss"},
		"confirm":  {"D1fferentP@ss!"},
	}
	resp := r.postForm(t, "/portal/register", form.Encode())
	// Form re-render (200), no redirect.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (re-render)", resp.StatusCode)
	}
	if _, err := r.store.GetUserByEmail(t.Context(), "mismatch@example.com"); err == nil {
		t.Error("user should not have been created on password mismatch")
	}
}

func TestPortalRegisterPOST_WeakPassword(t *testing.T) {
	r := newTestRig(t)
	form := url.Values{
		"email":    {"weak@example.com"},
		"password": {"short"},
		"confirm":  {"short"},
	}
	resp := r.postForm(t, "/portal/register", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (policy rejection re-renders)", resp.StatusCode)
	}
}

func TestPortalRegisterPOST_DuplicateEmail(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "dup@example.com", "OriginalP@ss12")
	form := url.Values{
		"email":    {"dup@example.com"},
		"password": {"V3ryStr0ngP@ss"},
		"confirm":  {"V3ryStr0ngP@ss"},
	}
	resp := r.postForm(t, "/portal/register", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (conflict re-renders form)", resp.StatusCode)
	}
}

func TestPortalLoginPOST_BadCredentials(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "loginuser@example.com", "G00dP@ss123!")
	form := url.Values{
		"email":    {"loginuser@example.com"},
		"password": {"WrongP@ss123!"},
	}
	resp := r.postForm(t, "/portal/login", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Errorf("bad creds: status = %d, want 200", resp.StatusCode)
	}
}

func TestPortalLoginPOST_UnknownUser(t *testing.T) {
	r := newTestRig(t)
	form := url.Values{
		"email":    {"ghost@example.com"},
		"password": {"AnyP@ss123!"},
	}
	resp := r.postForm(t, "/portal/login", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unknown user: status = %d, want 200", resp.StatusCode)
	}
}

func TestPortalLoginPOST_SuccessRedirects(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "good@example.com", "G00dP@ssword!")
	form := url.Values{
		"email":    {"good@example.com"},
		"password": {"G00dP@ssword!"},
	}
	resp := r.postForm(t, "/portal/login", form.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/portal" {
		t.Errorf("Location = %q, want /portal", loc)
	}
	var hasCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" && c.Value != "" {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Error("portal cookie not set on successful login")
	}
}

func TestPortalHome_NoSessionRedirects(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/portal")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/portal/login") {
		t.Errorf("Location = %q, want /portal/login prefix", loc)
	}
}

func TestPortalAccount_NoSessionRedirects(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/portal/account")
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
}

func TestPortalAdmin_NoSessionRedirects(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/portal/admin/users")
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
}

func TestPortalHome_WithSessionRenders(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "home@example.com", "H0meP@ssword!")

	// Drive a real login to obtain the cookie.
	form := url.Values{
		"email":    {"home@example.com"},
		"password": {"H0meP@ssword!"},
	}
	loginResp := r.postForm(t, "/portal/login", form.Encode())
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", loginResp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "auth_portal" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no auth_portal cookie after login")
	}

	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/portal", nil)
	req.AddCookie(cookie)
	client := &http.Client{CheckRedirect: noFollow}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("portal home status = %d, want 200", resp.StatusCode)
	}
}

func TestPortalLogout_ClearsCookie(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "out@example.com", "L0g0utP@ss12!")

	form := url.Values{
		"email":    {"out@example.com"},
		"password": {"L0g0utP@ss12!"},
	}
	loginResp := r.postForm(t, "/portal/login", form.Encode())
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", loginResp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "auth_portal" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no auth_portal cookie after login")
	}

	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/logout", nil)
	req.AddCookie(cookie)
	client := &http.Client{CheckRedirect: noFollow}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("logout status = %d, want 302", resp.StatusCode)
	}
	// Cleared cookie has MaxAge < 0.
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == "auth_portal" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("auth_portal cookie was not cleared on logout")
	}
}
