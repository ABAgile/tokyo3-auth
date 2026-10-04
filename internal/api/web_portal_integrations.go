package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
)

// integrationFormView is the data passed to the create/edit template. Token is
// never echoed back — the form treats it as write-only and persists the
// previous value when "update_token" is unchecked.
type integrationFormView struct {
	portalBase
	Integration *model.AppIntegration
	IsNew       bool
	Error       string
}

func (s *Server) handlePortalAdminIntegrations(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	integrations, err := s.store.ListIntegrations(r.Context())
	if err != nil {
		http.Error(w, "error listing integrations", http.StatusInternalServerError)
		return
	}
	s.portalTmpl.render(w, "portal_admin_integrations.html", struct {
		portalBase
		Integrations  []*model.AppIntegration
		Success       string
		Error, Notice string
	}{
		portalBase:   newPortalBase(pc, "admin-integrations"),
		Integrations: integrations,
		Success:      r.URL.Query().Get("success"),
		Error:        r.URL.Query().Get("error"),
		Notice:       r.URL.Query().Get("notice"),
	})
}

func (s *Server) handlePortalAdminIntegrationNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if r.Method == http.MethodGet {
		s.portalTmpl.render(w, "portal_admin_integration_edit.html", integrationFormView{
			portalBase: newPortalBase(pc, "admin-integrations"),
			Integration: &model.AppIntegration{
				Enabled:  true,
				Provider: model.AppIntegrationProviderSCIM,
				Config:   model.AppIntegrationConfig{AuthMode: model.AppIntegrationAuthBearer},
			},
			IsNew: true,
		})
		return
	}
	_ = r.ParseForm()

	form := readIntegrationForm(r, true)
	showErr := func(msg string) {
		s.portalTmpl.render(w, "portal_admin_integration_edit.html", integrationFormView{
			portalBase:  newPortalBase(pc, "admin-integrations"),
			Integration: form.row,
			IsNew:       true,
			Error:       msg,
		})
	}

	if msg := form.validate(true); msg != "" {
		showErr(msg)
		return
	}

	row := form.row
	if row.Provider == model.AppIntegrationProviderSCIM && row.Config.AuthMode == model.AppIntegrationAuthBearer {
		encToken, encDEK, err := bcrypto.EncryptEnvelope(r.Context(), s.kp, []byte(form.tokenPlain))
		if err != nil {
			showErr("Encryption failed.")
			return
		}
		row.EncryptedToken = encToken
		row.EncryptedDEK = encDEK
	}

	if err := s.store.CreateIntegration(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			showErr("An integration with that name already exists.")
			return
		}
		s.log.Error("create integration", "err", err)
		showErr("Create failed.")
		return
	}
	if err := s.logAudit(r, ActionIntegrationCreated, &pc.User.ID, nil,
		logMeta("name", row.Name, "provider", row.Provider)); err != nil {
		s.auditFail(w, err)
		return
	}
	s.reloadProvisioners(r.Context())
	http.Redirect(w, r, "/portal/admin/integrations?success=Integration+created.", http.StatusFound)
}

func (s *Server) handlePortalAdminIntegrationEdit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	existing, err := s.store.GetIntegration(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "integration not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		var message string
		if existing.Provider != model.AppIntegrationProviderSCIM && existing.Provider != model.AppIntegrationProviderAWSFederation {
			message = "This provider is no longer supported. Clean up downstream resources before deleting this integration."
		}
		s.portalTmpl.render(w, "portal_admin_integration_edit.html", integrationFormView{
			portalBase:  newPortalBase(pc, "admin-integrations"),
			Integration: existing,
			IsNew:       false,
			Error:       message,
		})
		return
	}
	_ = r.ParseForm()
	form := readIntegrationForm(r, false)
	form.row.ID = existing.ID
	form.row.Provider = existing.Provider // type is immutable on edit

	showErr := func(msg string) {
		s.portalTmpl.render(w, "portal_admin_integration_edit.html", integrationFormView{
			portalBase:  newPortalBase(pc, "admin-integrations"),
			Integration: form.row,
			IsNew:       false,
			Error:       msg,
		})
	}

	updateToken := r.FormValue("update_token") == "1"
	if msg := form.validate(updateToken); msg != "" {
		showErr(msg)
		return
	}

	switch {
	case form.row.Config.AuthMode == model.AppIntegrationAuthMTLS:
		// Switching to mTLS clears any previously stored bearer token.
		form.row.EncryptedToken = nil
		form.row.EncryptedDEK = nil
	case form.row.Provider == model.AppIntegrationProviderSCIM && updateToken:
		encToken, encDEK, err := bcrypto.EncryptEnvelope(r.Context(), s.kp, []byte(form.tokenPlain))
		if err != nil {
			showErr("Encryption failed.")
			return
		}
		form.row.EncryptedToken = encToken
		form.row.EncryptedDEK = encDEK
	default:
		form.row.EncryptedToken = existing.EncryptedToken
		form.row.EncryptedDEK = existing.EncryptedDEK
	}

	if err := s.store.UpdateIntegration(r.Context(), form.row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			showErr("An integration with that name already exists.")
			return
		}
		s.log.Error("update integration", "err", err)
		showErr("Update failed.")
		return
	}
	if err := s.logAudit(r, ActionIntegrationUpdated, &pc.User.ID, nil,
		logMeta("name", form.row.Name, "provider", form.row.Provider, "rotated_token", updateToken)); err != nil {
		s.auditFail(w, err)
		return
	}
	s.reloadProvisioners(r.Context())
	http.Redirect(w, r, "/portal/admin/integrations?success=Integration+updated.", http.StatusFound)
}

func (s *Server) handlePortalAdminIntegrationDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	existing, err := s.store.GetIntegration(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/portal/admin/integrations?error=integration+not+found", http.StatusFound)
		return
	}
	if err := s.store.DeleteIntegration(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/integrations?error=delete+failed", http.StatusFound)
		return
	}
	if err := s.logAudit(r, ActionIntegrationDeleted, &pc.User.ID, nil,
		logMeta("name", existing.Name, "provider", existing.Provider)); err != nil {
		s.auditFail(w, err)
		return
	}
	s.reloadProvisioners(r.Context())
	http.Redirect(w, r, "/portal/admin/integrations?success=Integration+deleted.", http.StatusFound)
}

// handlePortalAdminIntegrationTest pings the integration to verify connectivity.
// For SCIM it issues GET {BaseURL}/ServiceProviderConfig; federation testing
// is left out because credentials are validated lazily by the AWS SDK.
func (s *Server) handlePortalAdminIntegrationTest(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/integrations?error=invalid+id", http.StatusFound)
		return
	}
	row, err := s.store.GetIntegration(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/portal/admin/integrations?error=integration+not+found", http.StatusFound)
		return
	}
	if row.Provider != model.AppIntegrationProviderSCIM {
		http.Redirect(w, r, "/portal/admin/integrations?notice=Test+only+supported+for+SCIM+integrations.", http.StatusFound)
		return
	}
	status, body, err := s.scimServiceProviderConfig(r.Context(), row)
	if err != nil {
		if aerr := s.logAudit(r, ActionIntegrationTested, &pc.User.ID, nil,
			logMeta("name", row.Name, "ok", false, "err", err.Error())); aerr != nil {
			s.auditFail(w, aerr)
			return
		}
		http.Redirect(w, r, "/portal/admin/integrations?error="+url.QueryEscape("Test failed: "+err.Error()), http.StatusFound)
		return
	}
	if err := s.logAudit(r, ActionIntegrationTested, &pc.User.ID, nil,
		logMeta("name", row.Name, "ok", true, "status", status)); err != nil {
		s.auditFail(w, err)
		return
	}
	msg := "Connection OK (HTTP " + strconv.Itoa(status) + ")"
	if body != "" {
		msg += " " + body
	}
	http.Redirect(w, r, "/portal/admin/integrations?success="+url.QueryEscape(msg), http.StatusFound)
}

func (s *Server) scimServiceProviderConfig(ctx context.Context, row *model.AppIntegration) (int, string, error) {
	if row.Config.BaseURL == "" {
		return 0, "", errors.New("missing base URL")
	}
	authMode := row.Config.AuthMode
	if authMode == "" {
		authMode = model.AppIntegrationAuthBearer
	}
	timeout := time.Duration(row.Config.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	endpoint := strings.TrimRight(row.Config.BaseURL, "/") + "/ServiceProviderConfig"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/scim+json")

	client := &http.Client{Timeout: timeout}
	switch authMode {
	case model.AppIntegrationAuthBearer:
		tokenBytes, err := bcrypto.DecryptEnvelope(ctx, s.kp, row.EncryptedDEK, row.EncryptedToken)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	case model.AppIntegrationAuthMTLS:
		if s.scimTLS == nil {
			return 0, "", errors.New("mtls auth_mode but AUTHD_SCIM_MTLS_CERT/KEY are unset")
		}
		client.Transport = &http.Transport{TLSClientConfig: s.scimTLS}
	default:
		return 0, "", errors.New("unsupported auth_mode: " + authMode)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode >= 400 {
		return resp.StatusCode, "", errors.New(strings.TrimSpace(string(excerpt)))
	}
	var doc struct {
		DocumentationURI string `json:"documentationUri"`
	}
	_ = json.Unmarshal(excerpt, &doc)
	return resp.StatusCode, doc.DocumentationURI, nil
}

// handlePortalAdminIntegrationSync runs a full sync against a single
// integration on demand: re-pushes every user and group to that target as
// OpCreate (idempotent — PATCH-or-POST per user, full-list PUT per group).
// Reuses the live provisioner from the registry rather than rebuilding,
// matching what the periodic-sync goroutine does.
func (s *Server) handlePortalAdminIntegrationSync(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/integrations?error=invalid+id", http.StatusFound)
		return
	}
	row, err := s.store.GetIntegration(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/portal/admin/integrations?error=integration+not+found", http.StatusFound)
		return
	}
	if !row.Enabled {
		http.Redirect(w, r, "/portal/admin/integrations?error="+url.QueryEscape("Integration "+row.Name+" is disabled — enable it before syncing."), http.StatusFound)
		return
	}
	prov := s.lookupProvisioner(row.Name)
	if prov == nil {
		http.Redirect(w, r, "/portal/admin/integrations?error="+url.QueryEscape("Provisioner for "+row.Name+" not loaded — try saving the integration to reload."), http.StatusFound)
		return
	}
	userOK, userFail, groupOK, groupFail := provision.SyncAll(r.Context(), s.store, prov, s.log)
	if err := s.logAudit(r, ActionIntegrationSynced, &pc.User.ID, nil, logMeta(
		"name", row.Name,
		"users_ok", userOK, "users_failed", userFail,
		"groups_ok", groupOK, "groups_failed", groupFail,
		"trigger", "manual",
	)); err != nil {
		s.auditFail(w, err)
		return
	}
	msg := fmt.Sprintf("Sync %s done: users %d ok / %d failed; groups %d ok / %d failed", row.Name, userOK, userFail, groupOK, groupFail)
	flashKey := "success"
	if userFail+groupFail > 0 {
		flashKey = "error"
	}
	http.Redirect(w, r, "/portal/admin/integrations?"+flashKey+"="+url.QueryEscape(msg), http.StatusFound)
}

// lookupProvisioner returns the loaded provisioner whose Name matches `name`,
// or nil if none. Used by the manual-sync handler to dispatch against the
// already-built provisioner without re-decrypting the integration's token.
func (s *Server) lookupProvisioner(name string) provision.Provisioner {
	if s.provReg == nil {
		return nil
	}
	for _, p := range s.provReg.Snapshot() {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func (s *Server) reloadProvisioners(ctx context.Context) {
	if s.provReg == nil {
		return
	}
	if err := s.provReg.Reload(ctx); err != nil {
		s.log.Error("reload provisioners", "err", err)
	}
}

// ── form parsing ──────────────────────────────────────────────────────────────

type integrationFormInput struct {
	row        *model.AppIntegration
	tokenPlain string
}

func readIntegrationForm(r *http.Request, isNew bool) integrationFormInput {
	provider := r.FormValue("provider")
	if !isNew {
		// On edit we ignore the form-supplied provider; caller restores from existing row.
		provider = ""
	}
	timeoutMS, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_ms")))
	authMode := strings.TrimSpace(r.FormValue("auth_mode"))
	if authMode == "" {
		authMode = model.AppIntegrationAuthBearer
	}
	row := &model.AppIntegration{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Provider: provider,
		Enabled:  r.FormValue("enabled") == "1",
		Config: model.AppIntegrationConfig{
			BaseURL:   strings.TrimSpace(r.FormValue("base_url")),
			TimeoutMS: timeoutMS,
			AuthMode:  authMode,
		},
	}
	return integrationFormInput{
		row:        row,
		tokenPlain: r.FormValue("token"),
	}
}

func (f integrationFormInput) validate(needToken bool) string {
	if f.row.Name == "" {
		return "Name is required."
	}
	switch f.row.Provider {
	case model.AppIntegrationProviderSCIM:
		if f.row.Config.BaseURL == "" {
			return "Base URL is required for SCIM integrations."
		}
		switch f.row.Config.AuthMode {
		case model.AppIntegrationAuthBearer, "":
			if needToken && strings.TrimSpace(f.tokenPlain) == "" {
				return "Token is required for bearer auth."
			}
		case model.AppIntegrationAuthMTLS:
			if strings.TrimSpace(f.tokenPlain) != "" {
				return "Token must be empty when auth mode is mTLS — auth presents its client cert from AUTHD_SCIM_* env vars."
			}
		default:
			return "Unsupported auth mode."
		}
	case model.AppIntegrationProviderAWSFederation:
		// Credential-less provisioner: name + enabled is the whole row.
		// IAM permissions come from the SDK default chain on the host.
	case "":
		return "Provider is required."
	default:
		return "Unsupported provider."
	}
	return ""
}
