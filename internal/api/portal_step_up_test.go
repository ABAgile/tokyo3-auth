package api

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/auth"
	iMFA "github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// loginPortal performs a real /portal/login POST for a user without
// MFA and returns the auth_portal cookie + the session row created by
// the login. Tests use the cookie to drive subsequent portal hits and
// the session row to mutate mfa_verified_at to exercise the step-up
// freshness gate.
func loginPortal(t *testing.T, r *testRig, email, password string) (*http.Cookie, *model.Session) {
	t.Helper()
	form := url.Values{"email": {email}, "password": {password}}
	resp := r.postForm(t, "/portal/login", form.Encode())
	defer resp.Body.Close()
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
	sess := sessionFromCookie(t, r, cookie)
	return cookie, sess
}

// sessionFromCookie unseals the auth_portal cookie value with the rig's
// master key, hashes the embedded raw token, and looks up the matching
// session row. Mirrors readAuthPortalSession without exporting it.
func sessionFromCookie(t *testing.T, r *testRig, cookie *http.Cookie) *model.Session {
	t.Helper()
	enc, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("decode cookie value: %v", err)
	}
	raw, err := bcrypto.Open(r.mk, enc)
	if err != nil {
		t.Fatalf("open cookie: %v", err)
	}
	sess, err := r.store.GetSessionByAccessTokenHash(context.Background(), auth.HashToken(string(raw)))
	if err != nil {
		t.Fatalf("session lookup: %v", err)
	}
	return sess
}

// enrollTOTPForUser walks EnrollTOTP + ConfirmTOTP so tests can produce
// valid 6-digit codes via totp.GenerateCodeCustom. Returns the base32
// secret extracted from the otpauth:// URI.
func enrollTOTPForUser(t *testing.T, r *testRig, userID uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	user, err := r.store.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	enrollResp, err := iMFA.EnrollTOTP(ctx, r.store, r.kp, user)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	u, err := url.Parse(enrollResp.OTPURI)
	if err != nil {
		t.Fatalf("parse otp uri: %v", err)
	}
	secret := u.Query().Get("secret")
	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	if err := iMFA.ConfirmTOTP(ctx, r.store, r.kp, userID, code); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	return secret
}

// doRequest is a small wrapper that attaches the auth_portal cookie
// and uses the no-redirect-follow client so 302s can be inspected.
func doRequest(t *testing.T, req *http.Request, cookie *http.Cookie) *http.Response {
	t.Helper()
	if cookie != nil {
		req.AddCookie(cookie)
	}
	c := &http.Client{CheckRedirect: noFollow}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestAWSConsole_NoMFA_RedirectsToStepUp covers the cold case: the
// session has never seen MFA (MFAVerifiedAt nil) and the role requires
// step-up. The handler must 302 to /portal/step-up carrying both the
// next and role_id so the dispatcher can resume after the challenge.
func TestAWSConsole_NoMFA_RedirectsToStepUp(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "nomfa@example.com", "N0n3MFAP@ss1!")
	cookie, _ := loginPortal(t, r, "nomfa@example.com", "N0n3MFAP@ss1!")
	role := seedAWSCatalog(t, r, u, "step-up-role", true /* RequireStepUpMFA */)

	form := url.Values{"role_id": {role.ID.String()}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/aws/console", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/portal/step-up?") {
		t.Fatalf("Location = %q, want prefix /portal/step-up?", loc)
	}
	parsed, _ := url.Parse(loc)
	if parsed.Query().Get("next") != "aws_console" {
		t.Errorf("next = %q, want aws_console", parsed.Query().Get("next"))
	}
	if parsed.Query().Get("role_id") != role.ID.String() {
		t.Errorf("role_id = %q, want %s", parsed.Query().Get("role_id"), role.ID)
	}
}

// TestAWSConsole_StaleMFA_RedirectsToStepUp: a session that MFA'd long
// ago must re-challenge. Uses MarkSessionMFA to age the timestamp past
// the default 5-minute TTL.
func TestAWSConsole_StaleMFA_RedirectsToStepUp(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "stale@example.com", "St@l3MfaPass1!")
	cookie, sess := loginPortal(t, r, "stale@example.com", "St@l3MfaPass1!")
	role := seedAWSCatalog(t, r, u, "step-up-stale", true)
	if err := r.store.MarkSessionMFA(context.Background(), sess.ID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("MarkSessionMFA: %v", err)
	}

	form := url.Values{"role_id": {role.ID.String()}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/aws/console", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "/portal/step-up?") {
		t.Errorf("stale MFA did not redirect to step-up: Location=%q", resp.Header.Get("Location"))
	}
}

// TestAWSConsole_FreshMFA_PassesStepUpGate verifies the inverse: a
// session whose MFA is within the TTL window flows past the step-up
// gate and reaches the AWS-side STS call. We can't complete STS
// against real AWS in tests, so we settle for "Location does NOT
// point at /portal/step-up" — proving the gate ran.
func TestAWSConsole_FreshMFA_PassesStepUpGate(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "fresh@example.com", "Fr3shMfaP@ss1!")
	cookie, sess := loginPortal(t, r, "fresh@example.com", "Fr3shMfaP@ss1!")
	role := seedAWSCatalog(t, r, u, "step-up-fresh", true)
	if err := r.store.MarkSessionMFA(context.Background(), sess.ID, time.Now()); err != nil {
		t.Fatalf("MarkSessionMFA: %v", err)
	}

	form := url.Values{"role_id": {role.ID.String()}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/aws/console", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if strings.HasPrefix(resp.Header.Get("Location"), "/portal/step-up") {
		t.Errorf("fresh MFA was wrongly bounced to step-up: Location=%q", resp.Header.Get("Location"))
	}
}

// TestAWSConsole_NonStepUpRole_NoRedirect: a regular role (RequireStepUpMFA
// false) bypasses the gate even with no MFA. Guards against future
// refactors accidentally making step-up apply to every role.
func TestAWSConsole_NonStepUpRole_NoRedirect(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "regular@example.com", "Regul@rPass1!")
	cookie, _ := loginPortal(t, r, "regular@example.com", "Regul@rPass1!")
	role := seedAWSCatalog(t, r, u, "regular-role", false /* RequireStepUpMFA */)

	form := url.Values{"role_id": {role.ID.String()}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/aws/console", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if strings.HasPrefix(resp.Header.Get("Location"), "/portal/step-up") {
		t.Errorf("non-step-up role bounced to step-up: Location=%q", resp.Header.Get("Location"))
	}
}

// TestStepUp_GET_NoFactors_RedirectsToApps: a user who has no MFA
// enrolled cannot satisfy step-up. The handler refuses at GET time
// rather than rendering a dead-end challenge page.
func TestStepUp_GET_NoFactors_RedirectsToApps(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "nofactor@example.com", "N0F@ctorPass1!")
	cookie, _ := loginPortal(t, r, "nofactor@example.com", "N0F@ctorPass1!")

	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/portal/step-up?next=aws_console&role_id="+uuid.NewString(), nil)
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "/portal/apps") {
		t.Errorf("Location = %q, want prefix /portal/apps", resp.Header.Get("Location"))
	}
}

// TestStepUp_GET_RendersChallenge: TOTP-enrolled user gets the
// challenge page when navigating to /portal/step-up.
func TestStepUp_GET_RendersChallenge(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "challenge@example.com", "Ch@llengeP@ss1!")
	cookie, _ := loginPortal(t, r, "challenge@example.com", "Ch@llengeP@ss1!")
	enrollTOTPForUser(t, r, u.ID)

	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/portal/step-up?next=aws_console&role_id="+uuid.NewString(), nil)
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Verify code") {
		t.Errorf("body missing expected challenge copy")
	}
}

// TestStepUp_TOTP_InvalidCode_DoesNotMarkSession verifies a wrong
// code leaves the session's mfa_verified_at unchanged — the gate
// must NOT accept the bad attempt as a refresh.
func TestStepUp_TOTP_InvalidCode_DoesNotMarkSession(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "wrong@example.com", "Wr0ngC0deP@ss1!")
	cookie, sess := loginPortal(t, r, "wrong@example.com", "Wr0ngC0deP@ss1!")
	enrollTOTPForUser(t, r, u.ID)
	before := sess.MFAVerifiedAt

	form := url.Values{
		"code":    {"000000"},
		"next":    {"aws_console"},
		"role_id": {uuid.NewString()},
	}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (re-render with error)", resp.StatusCode)
	}

	fresh, err := r.store.GetSessionByAccessTokenHash(context.Background(), sess.AccessTokenHash)
	if err != nil {
		t.Fatalf("re-read session: %v", err)
	}
	if (before == nil) != (fresh.MFAVerifiedAt == nil) {
		t.Errorf("MFAVerifiedAt nil-ness changed after bad TOTP: before=%v after=%v", before, fresh.MFAVerifiedAt)
	}
}

// TestStepUp_TOTP_ValidCode_MarksSession verifies a correct code
// stamps mfa_verified_at = now, the critical postcondition the AWS
// console handler reads on the dispatch round trip.
func TestStepUp_TOTP_ValidCode_MarksSession(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "good@example.com", "G00dCodeP@ss1!")
	cookie, sess := loginPortal(t, r, "good@example.com", "G00dCodeP@ss1!")
	secret := enrollTOTPForUser(t, r, u.ID)

	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	// next= and role_id= are deliberately omitted: the dispatch
	// branch is exercised separately in TestAWSConsole_FreshMFA_*. This
	// test only pins the timestamp-update behaviour.
	form := url.Values{"code": {code}}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, cookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 after dispatch", resp.StatusCode)
	}

	fresh, err := r.store.GetSessionByAccessTokenHash(context.Background(), sess.AccessTokenHash)
	if err != nil {
		t.Fatalf("re-read session: %v", err)
	}
	if fresh.MFAVerifiedAt == nil {
		t.Fatal("MFAVerifiedAt still nil after successful TOTP")
	}
	if d := time.Since(*fresh.MFAVerifiedAt); d > 30*time.Second {
		t.Errorf("MFAVerifiedAt set %v ago, expected ~now", d)
	}
	if !fresh.MFAVerified {
		t.Error("MFAVerified flag still false after successful step-up")
	}
}
