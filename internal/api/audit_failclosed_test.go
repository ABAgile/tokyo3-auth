package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/audit"
	"github.com/abagile/tokyo3-auth/internal/model"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/google/uuid"
)

// journalDown makes every later audit write fail.
func journalDown(r *testRig) {
	r.server.audit = journal.NewJSONSink[audit.Entry](failingSink{})
}

// portalAdmin logs a fresh admin user into the portal and returns a request
// helper. Call journalDown AFTER this: login itself is audited.
func portalAdmin(t *testing.T, r *testRig) func(method, path string, form url.Values) *http.Response {
	t.Helper()
	u := seedTestUser(t, r.store, "root@example.com", "R00tP@ssword-1")
	if err := r.store.SetUserAdmin(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	login := r.postForm(t, "/portal/login", url.Values{"email": {u.Email}, "password": {"R00tP@ssword-1"}}.Encode())
	var cookie *http.Cookie
	for _, c := range login.Cookies() {
		if c.Name == "auth_portal" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("no auth_portal cookie (login status %d)", login.StatusCode)
	}
	return func(method, path string, form url.Values) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, r.srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		resp, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
}

func want503(t *testing.T, resp *http.Response, what string) {
	t.Helper()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("%s: status = %d, want 503 (journal down)", what, resp.StatusCode)
	}
}

// Destructive and credential-weakening admin actions are audited BEFORE they
// happen: with the journal down they are refused and nothing changes.
func TestPortalAdmin_DestructiveActionsRefusedWhenJournalDown(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	do := portalAdmin(t, r)

	victim := seedTestUser(t, r.store, "victim@example.com", "V1ctimP@ssword-1")
	if err := r.store.CreateTOTPCredential(ctx, &model.TOTPCredential{
		ID: uuid.New(), UserID: victim.ID, EncryptedSecret: []byte("s"), EncryptedDEK: []byte("d"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.store.UpdateUserMFAEnabled(ctx, victim.ID, true); err != nil {
		t.Fatal(err)
	}
	client, err := r.store.CreateClient(ctx, "doomed-cid", "oldhash", "Doomed", nil, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	group, err := r.store.CreateGroup(ctx, "doomed-group")
	if err != nil {
		t.Fatal(err)
	}
	acct := &model.AWSAccount{AccountID: "111111111111", OIDCProviderARN: "arn:aws:iam::111:oidc-provider/x"}
	if err := r.store.CreateAWSAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	role := &model.AWSRole{AccountID: acct.ID, RoleARN: "arn:aws:iam::111:role/R", Slug: "r", DisplayName: "R"}
	if err := r.store.CreateAWSRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	asg := &model.AWSRoleAssignment{GroupID: group.ID, RoleID: role.ID}
	if err := r.store.CreateAWSRoleAssignment(ctx, asg); err != nil {
		t.Fatal(err)
	}
	integ := &model.AppIntegration{ID: uuid.New(), Name: "scim-x", Provider: model.AppIntegrationProviderSCIM, Enabled: true}
	if err := r.store.CreateIntegration(ctx, integ); err != nil {
		t.Fatal(err)
	}

	journalDown(r)
	vid := victim.ID.String()
	want503(t, do("POST", "/portal/admin/users/"+vid+"/edit", url.Values{"name": {"X"}, "active": {""}}), "deactivate user")
	want503(t, do("POST", "/portal/admin/users/"+vid+"/reset-password", nil), "reset password")
	want503(t, do("POST", "/portal/admin/users/"+vid+"/compromised-reset", nil), "compromised reset")
	want503(t, do("POST", "/portal/admin/users/"+vid+"/clear-mfa", nil), "clear mfa")
	want503(t, do("POST", "/portal/admin/users/"+vid+"/delete", nil), "delete user")
	want503(t, do("POST", "/portal/admin/clients/"+client.ID.String()+"/rotate-secret", nil), "rotate secret")
	want503(t, do("POST", "/portal/admin/clients/"+client.ID.String()+"/delete", nil), "delete client")
	want503(t, do("POST", "/portal/admin/groups/"+group.ID.String()+"/delete", nil), "delete group")
	want503(t, do("POST", "/portal/admin/aws/assignments/"+asg.ID.String()+"/delete", nil), "delete assignment")
	want503(t, do("POST", "/portal/admin/aws/roles/"+role.ID.String()+"/delete", nil), "delete role")
	want503(t, do("POST", "/portal/admin/aws/accounts/"+acct.ID.String()+"/delete", nil), "delete account")
	want503(t, do("POST", "/portal/admin/integrations/"+integ.ID.String()+"/delete", nil), "delete integration")

	// Nothing may have changed.
	if u, err := r.store.GetUserByID(ctx, victim.ID); err != nil || !u.Active || !u.MFAEnabled || u.MustChangePassword {
		t.Errorf("victim modified: %+v, %v", u, err)
	}
	if u, _ := r.store.GetUserByID(ctx, victim.ID); u == nil || !creds.CheckPassword(u.PasswordHash, "V1ctimP@ssword-1") {
		t.Error("victim's password changed despite refused action")
	}
	if _, err := r.store.GetTOTPByUserID(ctx, victim.ID); err != nil {
		t.Errorf("TOTP removed despite refused action: %v", err)
	}
	if c, err := r.store.GetClientByID(ctx, client.ID); err != nil || c.ClientSecretHash != "oldhash" {
		t.Errorf("client changed: %+v, %v", c, err)
	}
	if _, err := r.store.GetGroupByID(ctx, group.ID); err != nil {
		t.Errorf("group deleted: %v", err)
	}
	if _, err := r.store.GetAWSAccount(ctx, acct.ID); err != nil {
		t.Errorf("aws account deleted: %v", err)
	}
	if _, err := r.store.GetAWSRole(ctx, role.ID); err != nil {
		t.Errorf("aws role deleted: %v", err)
	}
	if _, err := r.store.GetIntegration(ctx, integ.ID); err != nil {
		t.Errorf("integration deleted: %v", err)
	}
}

// Creates cannot be audited first (the id doesn't exist yet), so a failed
// audit write rolls the new row back: 503 and no unaudited state.
func TestCreates_RolledBackWhenJournalDown(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	do := portalAdmin(t, r)
	adminTok := seedAdminSession(t, r)
	acct := &model.AWSAccount{AccountID: "222222222222", OIDCProviderARN: "arn:aws:iam::222:oidc-provider/x"}
	if err := r.store.CreateAWSAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	grp, _ := r.store.CreateGroup(ctx, "existing")
	role := &model.AWSRole{AccountID: acct.ID, RoleARN: "arn:aws:iam::222:role/R", Slug: "r2", DisplayName: "R"}
	if err := r.store.CreateAWSRole(ctx, role); err != nil {
		t.Fatal(err)
	}

	journalDown(r)

	want503(t, do("POST", "/portal/admin/users/new", url.Values{
		"email": {"new1@example.com"}, "name": {"N"}, "password": {"SuperLongP@ss12"}, "active": {"1"},
	}), "portal create user")
	if _, err := r.store.GetUserByEmail(ctx, "new1@example.com"); err == nil {
		t.Error("portal-created user survived a refused create")
	}

	want503(t, do("POST", "/portal/admin/groups/new", url.Values{"display_name": {"ghost-group"}}), "portal create group")
	groups, _ := r.store.ListGroups(ctx)
	for _, g := range groups {
		if g.DisplayName == "ghost-group" {
			t.Error("group survived a refused create")
		}
	}

	want503(t, do("POST", "/portal/admin/aws/accounts/new", url.Values{
		"account_id": {"333333333333"}, "oidc_provider_arn": {"arn:aws:iam::333:oidc-provider/x"},
	}), "create aws account")
	if accts, _ := r.store.ListAWSAccounts(ctx); len(accts) != 1 {
		t.Errorf("aws accounts = %d after refused create, want 1", len(accts))
	}

	want503(t, do("POST", "/portal/admin/aws/assignments/new", url.Values{
		"group_id": {grp.ID.String()}, "role_id": {role.ID.String()},
	}), "create assignment")
	if asg, _ := r.store.ListAWSRoleAssignments(ctx); len(asg) != 0 {
		t.Errorf("assignments = %d after refused create, want 0", len(asg))
	}

	// Admin API client create.
	resp := adminReq(t, r, "POST", "/admin/clients", `{"name":"ghost-client","public":true}`, adminTok)
	want503(t, resp, "API create client")
	clients, _ := r.store.ListClients(ctx)
	for _, c := range clients {
		if c.Name == "ghost-client" {
			t.Error("client survived a refused create")
		}
	}
	// Admin API user create.
	resp = adminReq(t, r, "POST", "/admin/users", `{"email":"api-new@example.com","password":"SuperLongP@ss12","name":"A"}`, adminTok)
	want503(t, resp, "API create user")
	if _, err := r.store.GetUserByEmail(ctx, "api-new@example.com"); err == nil {
		t.Error("API-created user survived a refused create")
	}
}

// Self-service MFA removal is refused (and nothing removed) with the journal down.
func TestSelfServiceMFARemoval_RefusedWhenJournalDown(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "mfa-self@example.com", "SelfP@ssword-123")
	if err := r.store.CreateTOTPCredential(ctx, &model.TOTPCredential{
		ID: uuid.New(), UserID: u.ID, EncryptedSecret: []byte("s"), EncryptedDEK: []byte("d"),
	}); err != nil {
		t.Fatal(err)
	}
	tok := seedSessionWithToken(t, r, u.ID, false)
	journalDown(r)

	req, _ := http.NewRequest(http.MethodDelete, r.srv.URL+"/mfa/totp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	want503(t, resp, "API TOTP delete")
	if _, err := r.store.GetTOTPByUserID(ctx, u.ID); err != nil {
		t.Errorf("TOTP removed despite refused action: %v", err)
	}
}

// Self-registration is rolled back too: a refused signup leaves no account
// (and, crucially, does not burn the "first user becomes admin" slot).
func TestSelfRegistration_RolledBackWhenJournalDown(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	journalDown(r)

	resp := r.postForm(t, "/portal/register", url.Values{
		"email": {"reg@example.com"}, "name": {"Reg"}, "password": {"V3ryStr0ngP@ss"}, "confirm": {"V3ryStr0ngP@ss"},
	}.Encode())
	want503(t, resp, "portal register")

	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})
	resp = r.postForm(t, "/register", url.Values{
		"email": {"sso@example.com"}, "name": {"Sso"}, "password": {"V3ryStr0ngP@ss"}, "confirm": {"V3ryStr0ngP@ss"},
		"client_id": {c.ClientID}, "redirect_uri": {"https://app.example/cb"},
	}.Encode())
	want503(t, resp, "sso register")

	if n, _ := r.store.CountUsers(ctx); n != 0 {
		t.Errorf("users = %d after refused registrations, want 0", n)
	}
}
