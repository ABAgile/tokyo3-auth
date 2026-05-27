package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	creds "github.com/abagile/tokyo3-base/auth/creds"
)

// deviceAuthzResp is the subset of the /device_authorization JSON we
// care about in tests.
type deviceAuthzResp struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

// enableDeviceGrant flips allow_device_grant on a freshly-created
// public client. The store helper exists for the admin form so we
// reuse it here rather than touching the DB directly.
func enableDeviceGrant(t *testing.T, r *testRig, clientID string) {
	t.Helper()
	c, err := r.store.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClientByClientID: %v", err)
	}
	if err := r.store.UpdateClientDeviceGrant(context.Background(), c.ID, true); err != nil {
		t.Fatalf("UpdateClientDeviceGrant: %v", err)
	}
}

// startDeviceAuthorization is the round-trip helper every test starts
// with. Returns the decoded JSON so the test can use device_code +
// user_code in subsequent steps.
func startDeviceAuthorization(t *testing.T, r *testRig, clientID string) deviceAuthzResp {
	t.Helper()
	form := url.Values{"client_id": {clientID}}
	resp := r.postForm(t, "/device_authorization", form.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("device_authorization status = %d: %s", resp.StatusCode, body)
	}
	var out deviceAuthzResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode device_authorization: %v", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		t.Fatalf("missing codes in device_authorization response: %+v", out)
	}
	return out
}

// pollToken sends one /token request for a device_code grant and
// returns the status + decoded body for the test to assert on.
func pollToken(t *testing.T, r *testRig, deviceCode, clientID string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}
	resp := r.postForm(t, "/token", form.Encode())
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

// approveGrant simulates the browser-side approval: looks up the
// pending grant by user_code (via the hash, same as the server) and
// calls the store helper directly. Bypassing the portal HTML form
// keeps the test focused on the protocol mechanics rather than the
// template.
func approveGrant(t *testing.T, r *testRig, userCode string, userID model.User) {
	t.Helper()
	ctx := context.Background()
	hash := hashUserCodeForTest(userCode)
	grant, err := r.store.GetDeviceGrantByUserCodeHash(ctx, hash)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if err := r.store.MarkDeviceGrantApproved(ctx, grant.ID, userID.ID, true, nil, "127.0.0.1"); err != nil {
		t.Fatalf("MarkDeviceGrantApproved: %v", err)
	}
}

// hashUserCodeForTest runs the same normalize+hash the server uses
// at /device. Tests live in this package so the production helpers
// are directly accessible.
func hashUserCodeForTest(in string) string {
	return creds.HashToken(normalizeUserCode(in))
}

// TestDeviceGrant_HappyPath: full round-trip — authorize, approve as
// a real user, poll /token, receive bearer tokens.
func TestDeviceGrant_HappyPath(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "deviceok@example.com", "D3viceOkP@ss1!")
	c := seedPublicClient(t, r.store, "device-cli", "http://localhost/cb",
		[]string{"openid", "email", "profile"})
	enableDeviceGrant(t, r, c.ClientID)

	authz := startDeviceAuthorization(t, r, c.ClientID)
	approveGrant(t, r, authz.UserCode, *u)

	status, body := pollToken(t, r, authz.DeviceCode, c.ClientID)
	if status != http.StatusOK {
		t.Fatalf("poll after approve: status = %d body = %v", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("missing access_token in token response: %v", body)
	}
}

// TestDeviceGrant_PendingThenApproved: the canonical state machine —
// pending poll returns authorization_pending, then once approved the
// next poll returns tokens.
func TestDeviceGrant_PendingThenApproved(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "devicepending@example.com", "P3ndingP@ss1!")
	c := seedPublicClient(t, r.store, "device-cli2", "http://localhost/cb",
		[]string{"openid"})
	enableDeviceGrant(t, r, c.ClientID)

	authz := startDeviceAuthorization(t, r, c.ClientID)

	status, body := pollToken(t, r, authz.DeviceCode, c.ClientID)
	if status != http.StatusBadRequest {
		t.Errorf("first poll status = %d, want 400", status)
	}
	if body["error"] != "authorization_pending" {
		t.Errorf("first poll error = %v, want authorization_pending", body["error"])
	}

	approveGrant(t, r, authz.UserCode, *u)

	status, body = pollToken(t, r, authz.DeviceCode, c.ClientID)
	if status != http.StatusOK {
		t.Fatalf("second poll status = %d body = %v", status, body)
	}
}

// TestDeviceGrant_DoubleRedeemRejected: single-use enforcement. The
// first poll after approval mints tokens; the second must be rejected
// with invalid_grant even though device_code itself is still well-
// formed and not yet expired.
func TestDeviceGrant_DoubleRedeemRejected(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "deviceredeem@example.com", "Red33mP@ss12!")
	c := seedPublicClient(t, r.store, "device-cli3", "http://localhost/cb",
		[]string{"openid"})
	enableDeviceGrant(t, r, c.ClientID)

	authz := startDeviceAuthorization(t, r, c.ClientID)
	approveGrant(t, r, authz.UserCode, *u)

	status, _ := pollToken(t, r, authz.DeviceCode, c.ClientID)
	if status != http.StatusOK {
		t.Fatalf("first redeem status = %d, want 200", status)
	}

	status, body := pollToken(t, r, authz.DeviceCode, c.ClientID)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("replay: status=%d error=%v, want 400 invalid_grant", status, body["error"])
	}
}

// TestDeviceGrant_ClientNotAllowed: a client without
// allow_device_grant=true must be refused at /device_authorization
// regardless of whether it's otherwise registered.
func TestDeviceGrant_ClientNotAllowed(t *testing.T) {
	r := newTestRig(t)
	c := seedPublicClient(t, r.store, "device-noflag", "http://localhost/cb",
		[]string{"openid"})
	// Intentionally do NOT enableDeviceGrant.

	form := url.Values{"client_id": {c.ClientID}}
	resp := r.postForm(t, "/device_authorization", form.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "unauthorized_client") {
		t.Errorf("body does not signal unauthorized_client: %s", body)
	}
}

// TestDeviceGrant_DeniedAccessDenied: a user-denied grant surfaces as
// access_denied at /token, distinct from authorization_pending so the
// CLI can stop polling immediately.
func TestDeviceGrant_DeniedAccessDenied(t *testing.T) {
	r := newTestRig(t)
	c := seedPublicClient(t, r.store, "device-deny", "http://localhost/cb",
		[]string{"openid"})
	enableDeviceGrant(t, r, c.ClientID)

	authz := startDeviceAuthorization(t, r, c.ClientID)

	hash := hashUserCodeForTest(authz.UserCode)
	grant, err := r.store.GetDeviceGrantByUserCodeHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if err := r.store.MarkDeviceGrantDenied(context.Background(), grant.ID, "127.0.0.1"); err != nil {
		t.Fatalf("MarkDeviceGrantDenied: %v", err)
	}

	status, body := pollToken(t, r, authz.DeviceCode, c.ClientID)
	if status != http.StatusBadRequest || body["error"] != "access_denied" {
		t.Errorf("denied poll: status=%d error=%v, want 400 access_denied", status, body["error"])
	}
}

// TestDeviceGrant_ClientMismatch: a different client_id at /token
// cannot redeem a device_code minted for the original client.
// Protects against confusion attacks where an attacker who somehow
// intercepts a device_code (e.g. from a log file) can't redeem it
// under their own client identity.
func TestDeviceGrant_ClientMismatch(t *testing.T) {
	r := newTestRig(t)
	c := seedPublicClient(t, r.store, "device-orig", "http://localhost/cb",
		[]string{"openid"})
	other := seedPublicClient(t, r.store, "device-other", "http://localhost/cb",
		[]string{"openid"})
	enableDeviceGrant(t, r, c.ClientID)
	enableDeviceGrant(t, r, other.ClientID)

	authz := startDeviceAuthorization(t, r, c.ClientID)
	status, body := pollToken(t, r, authz.DeviceCode, other.ClientID)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("mismatched client poll: status=%d error=%v, want 400 invalid_grant",
			status, body["error"])
	}
}
