package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
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
	GroupMapStr string
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
			GroupMapStr: form.groupMapStr,
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
	s.logAudit(r, ActionIntegrationCreated, &pc.User.ID, nil,
		logMeta("name", row.Name, "provider", row.Provider))
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
		s.portalTmpl.render(w, "portal_admin_integration_edit.html", integrationFormView{
			portalBase:  newPortalBase(pc, "admin-integrations"),
			Integration: existing,
			IsNew:       false,
			GroupMapStr: groupMapToString(existing.Config.GroupMap),
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
			GroupMapStr: form.groupMapStr,
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
	s.logAudit(r, ActionIntegrationUpdated, &pc.User.ID, nil,
		logMeta("name", form.row.Name, "provider", form.row.Provider, "rotated_token", updateToken))
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
	s.logAudit(r, ActionIntegrationDeleted, &pc.User.ID, nil,
		logMeta("name", existing.Name, "provider", existing.Provider))
	s.reloadProvisioners(r.Context())
	http.Redirect(w, r, "/portal/admin/integrations?success=Integration+deleted.", http.StatusFound)
}

// handlePortalAdminIntegrationTest pings the integration to verify connectivity.
// For SCIM it issues GET {BaseURL}/ServiceProviderConfig; IAM testing is left
// out because credentials are validated lazily by the AWS SDK on first use.
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
		s.logAudit(r, ActionIntegrationTested, &pc.User.ID, nil,
			logMeta("name", row.Name, "ok", false, "err", err.Error()))
		http.Redirect(w, r, "/portal/admin/integrations?error="+url.QueryEscape("Test failed: "+err.Error()), http.StatusFound)
		return
	}
	s.logAudit(r, ActionIntegrationTested, &pc.User.ID, nil,
		logMeta("name", row.Name, "ok", true, "status", status))
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
		if s.outboundTLS == nil {
			return 0, "", errors.New("mtls auth_mode but AUTH_OUTBOUND_TLS_CERT/KEY are unset")
		}
		client.Transport = &http.Transport{TLSClientConfig: s.outboundTLS}
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
	row         *model.AppIntegration
	tokenPlain  string
	groupMapStr string
}

func readIntegrationForm(r *http.Request, isNew bool) integrationFormInput {
	provider := r.FormValue("provider")
	if !isNew {
		// On edit we ignore the form-supplied provider; caller restores from existing row.
		provider = ""
	}
	timeoutMS, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_ms")))
	groupMapStr := r.FormValue("group_map")
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
			GroupMap:  parseGroupMap(groupMapStr),
			AuthMode:  authMode,
		},
	}
	return integrationFormInput{
		row:         row,
		tokenPlain:  r.FormValue("token"),
		groupMapStr: groupMapStr,
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
				return "Token must be empty when auth mode is mTLS — auth presents its client cert from AUTH_OUTBOUND_TLS_* env vars."
			}
		default:
			return "Unsupported auth mode."
		}
	case model.AppIntegrationProviderIAM:
		// no required fields beyond name
	case "":
		return "Provider is required."
	default:
		return "Unsupported provider."
	}
	return ""
}

func parseGroupMap(s string) map[string]string {
	out := map[string]string{}
	for _, line := range parseLines(s) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// groupMapToString renders the SCIM-group → IAM-group mapping for the edit
// form. Keys are sorted so re-rendering an unchanged map produces stable text;
// otherwise Go's randomized map iteration would shuffle the lines on every save.
func groupMapToString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
	return b.String()
}
