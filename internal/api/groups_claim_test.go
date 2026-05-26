package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// runAuthCodeFlow drives /authorize + /token end-to-end and returns
// the decoded token response. Mirrors TestAuthorizePOST_Success so we
// don't depend on its internals; lets the groups-claim tests vary
// just the scope string they exercise.
func runAuthCodeFlow(t *testing.T, r *testRig, clientID, scope, email, password string) map[string]any {
	t.Helper()
	verifier, challenge := pkcePair("verifier-1234567890123456789012345678901234567890")
	form := url.Values{
		"client_id":      {clientID},
		"redirect_uri":   {"https://app.example/cb"},
		"scope":          {scope},
		"state":          {"state-xyz"},
		"nonce":          {"nonce-xyz"},
		"code_challenge": {challenge},
		"email":          {email},
		"password":       {password},
	}
	resp := r.postForm(t, "/authorize", form.Encode())
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from /authorize: %s", resp.Header.Get("Location"))
	}
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example/cb"},
		"client_id":     {clientID},
	}
	tokResp := r.postForm(t, "/token", tokenForm.Encode())
	defer tokResp.Body.Close()
	return decodeJSON[map[string]any](t, tokResp)
}

// decodeJWTPayload pulls the middle segment of a JWS and base64url-
// decodes it into a claims map. Unverified — fine for tests that
// only need to inspect what was put in, not verify signature.
func decodeJWTPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

// TestIDToken_GroupsScope_IncludesMemberGroups: requesting the
// `groups` scope causes the user's SCIM group display names to land
// in the id_token. Wazuh / OpenSearch Security `backend_roles`
// mappings depend on this contract.
func TestIDToken_GroupsScope_IncludesMemberGroups(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "grouped@example.com", "Group3dP@ss12!")
	c := seedPublicClient(t, r.store, "groups-cli", "https://app.example/cb",
		[]string{"openid", "groups"})

	g1, err := r.store.CreateGroup(ctx, "platform-admins")
	if err != nil {
		t.Fatalf("CreateGroup g1: %v", err)
	}
	g2, err := r.store.CreateGroup(ctx, "data-analysts")
	if err != nil {
		t.Fatalf("CreateGroup g2: %v", err)
	}
	if err := r.store.AddGroupMember(ctx, g1.ID, u.ID); err != nil {
		t.Fatalf("AddGroupMember g1: %v", err)
	}
	if err := r.store.AddGroupMember(ctx, g2.ID, u.ID); err != nil {
		t.Fatalf("AddGroupMember g2: %v", err)
	}

	tok := runAuthCodeFlow(t, r, c.ClientID, "openid groups", "grouped@example.com", "Group3dP@ss12!")
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatal("missing id_token")
	}
	claims := decodeJWTPayload(t, idToken)

	groups, ok := claims["groups"].([]any)
	if !ok {
		t.Fatalf("groups claim missing or wrong type: %v", claims["groups"])
	}
	got := map[string]bool{}
	for _, v := range groups {
		got[v.(string)] = true
	}
	if !got["platform-admins"] || !got["data-analysts"] {
		t.Errorf("groups = %v, expected both platform-admins and data-analysts", groups)
	}
}

// TestIDToken_NoGroupsScope_OmitsClaim: without the `groups` scope
// the claim must not appear, even if the user is in groups. Keeps
// tokens lean for RPs that don't care.
func TestIDToken_NoGroupsScope_OmitsClaim(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "noscope@example.com", "N0Sc0peP@ss12!")
	c := seedPublicClient(t, r.store, "openid-cli", "https://app.example/cb",
		[]string{"openid"})

	g, err := r.store.CreateGroup(ctx, "engineers")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := r.store.AddGroupMember(ctx, g.ID, u.ID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}

	tok := runAuthCodeFlow(t, r, c.ClientID, "openid", "noscope@example.com", "N0Sc0peP@ss12!")
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatal("missing id_token")
	}
	claims := decodeJWTPayload(t, idToken)

	if _, present := claims["groups"]; present {
		t.Errorf("groups claim present without scope: %v", claims["groups"])
	}
}
