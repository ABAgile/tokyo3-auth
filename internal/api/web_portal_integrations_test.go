package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
)

func integrationAdminCookie(t *testing.T, r *testRig) *http.Cookie {
	t.Helper()
	u := seedTestUser(t, r.store, "integration-admin@example.com", "CorrectHorseB1!")
	if err := r.store.SetUserAdmin(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	token := seedSessionWithToken(t, r, u.ID, false)
	w := httptest.NewRecorder()
	if err := r.server.setPortalCookie(w, token, portalCookieTTL, portalCookie); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0]
}

func integrationRequest(r *testRig, cookie *http.Cookie, method, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	r.server.Routes().ServeHTTP(w, req)
	return w
}

func TestIntegrationFormExcludesIAMUsers(t *testing.T) {
	r := newTestRig(t)
	cookie := integrationAdminCookie(t, r)
	w := integrationRequest(r, cookie, http.MethodGet, "/portal/admin/integrations/new", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, provider := range []string{"scim", "aws_federation"} {
		if !strings.Contains(body, `<option value="`+provider+`"`) {
			t.Errorf("missing supported provider %q", provider)
		}
	}
	if strings.Contains(body, "aws_iam") || strings.Contains(body, "group_map") {
		t.Error("retired IAM provider or group mapping is still exposed")
	}

	w = integrationRequest(r, cookie, http.MethodPost, "/portal/admin/integrations/new", url.Values{
		"name": {"retired"}, "provider": {"aws_iam"}, "enabled": {"1"},
		"group_map": {"Engineering=legacy-group"},
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Unsupported provider.") {
		t.Fatalf("tampered provider form was not rejected: status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Create integration") {
		t.Error("new integration form must remain usable after a validation error")
	}
	if _, err := r.store.GetIntegrationByName(context.Background(), "retired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retired provider was persisted: %v", err)
	}
}

func TestIntegrationFormPreservesSupportedProviders(t *testing.T) {
	r := newTestRig(t)
	cookie := integrationAdminCookie(t, r)
	for _, provider := range []string{model.AppIntegrationProviderSCIM, model.AppIntegrationProviderAWSFederation} {
		t.Run(provider, func(t *testing.T) {
			form := url.Values{"name": {provider}, "provider": {provider}, "enabled": {"1"}}
			if provider == model.AppIntegrationProviderSCIM {
				form.Set("base_url", "https://scim.example/scim/v2")
				form.Set("auth_mode", model.AppIntegrationAuthBearer)
				form.Set("token", "scim-secret")
			}
			w := integrationRequest(r, cookie, http.MethodPost, "/portal/admin/integrations/new", form)
			if w.Code != http.StatusFound {
				t.Fatalf("create status = %d, body = %s", w.Code, w.Body.String())
			}
			row, err := r.store.GetIntegrationByName(context.Background(), provider)
			if err != nil {
				t.Fatal(err)
			}
			if row.Provider != provider || !row.Enabled {
				t.Errorf("wrong persisted provider or status: %+v", row)
			}
			if provider == model.AppIntegrationProviderSCIM {
				token, err := bcrypto.DecryptEnvelope(context.Background(), r.kp, row.EncryptedDEK, row.EncryptedToken)
				if err != nil || string(token) != "scim-secret" {
					t.Errorf("SCIM token was not preserved: token = %q, error = %v", token, err)
				}
			}
		})
	}
}

func TestRetiredIntegrationCannotBeEnabledButCanBeDeleted(t *testing.T) {
	r := newTestRig(t)
	cookie := integrationAdminCookie(t, r)
	row := &model.AppIntegration{ID: uuid.New(), Name: "retired", Provider: "aws_iam", Enabled: false}
	if err := r.store.CreateIntegration(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	path := "/portal/admin/integrations/" + row.ID.String()
	w := integrationRequest(r, cookie, http.MethodGet, path+"/edit", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "no longer supported") ||
		strings.Contains(w.Body.String(), "Save changes") || !strings.Contains(w.Body.String(), "Delete integration") {
		t.Fatalf("retired integration has no cleanup-only view: status = %d, body = %s", w.Code, w.Body.String())
	}
	w = integrationRequest(r, cookie, http.MethodPost, path+"/edit", url.Values{
		"name": {row.Name}, "provider": {"aws_federation"}, "enabled": {"1"},
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Unsupported provider.") {
		t.Fatalf("retired integration re-enable was not rejected: status = %d", w.Code)
	}
	got, err := r.store.GetIntegration(context.Background(), row.ID)
	if err != nil || got.Enabled || got.Provider != "aws_iam" {
		t.Fatalf("retired integration changed: row = %+v, error = %v", got, err)
	}
	w = integrationRequest(r, cookie, http.MethodGet, "/portal/admin/integrations", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Unsupported") || strings.Contains(w.Body.String(), "Sync now") {
		t.Fatalf("retired integration list exposes provisioning actions: status = %d", w.Code)
	}
	w = integrationRequest(r, cookie, http.MethodPost, path+"/delete", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("delete status = %d", w.Code)
	}
	if _, err := r.store.GetIntegration(context.Background(), row.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retired integration was not deleted: %v", err)
	}
}
