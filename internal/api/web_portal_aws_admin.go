package api

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// awsAdminPageData aggregates the AWS federation catalog into one view —
// accounts, roles, and the SCIM-group → role assignment matrix. Keeping all
// three on one page mirrors how operators reason about federation setup:
// "I have this account, I want this role in it, mapped to this group."
type awsAdminPageData struct {
	portalBase
	Accounts       []*model.AWSAccount
	Roles          []*roleRow
	Groups         []*model.SCIMGroup
	Assignments    []*model.AWSRoleAssignment
	Audience       string // server-global, from AUTHD_AWS_AUDIENCE
	Success, Error string
}

type roleRow struct {
	*model.AWSRole
	AccountAlias     string
	AccountAccountID string
}

func (s *Server) handlePortalAdminAWS(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	accounts, err := s.store.ListAWSAccounts(r.Context())
	if err != nil {
		http.Error(w, "list aws accounts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rolesRaw, err := s.store.ListAWSRoles(r.Context())
	if err != nil {
		http.Error(w, "list aws roles: "+err.Error(), http.StatusInternalServerError)
		return
	}
	groups, _ := s.store.ListGroups(r.Context())
	assigns, _ := s.store.ListAWSRoleAssignments(r.Context())
	acctByID := make(map[uuid.UUID]*model.AWSAccount, len(accounts))
	for _, a := range accounts {
		acctByID[a.ID] = a
	}
	rows := make([]*roleRow, len(rolesRaw))
	for i, r := range rolesRaw {
		rr := &roleRow{AWSRole: r}
		if a := acctByID[r.AccountID]; a != nil {
			rr.AccountAlias = a.Alias
			rr.AccountAccountID = a.AccountID
		}
		rows[i] = rr
	}
	s.portalTmpl.render(w, "portal_admin_aws.html", awsAdminPageData{
		portalBase:  newPortalBase(pc, "admin-aws"),
		Accounts:    accounts,
		Roles:       rows,
		Groups:      groups,
		Assignments: assigns,
		Audience:    s.awsAudience,
		Success:     r.URL.Query().Get("success"),
		Error:       r.URL.Query().Get("error"),
	})
}

// ── account handlers ─────────────────────────────────────────────────────────

func (s *Server) handlePortalAdminAWSAccountNew(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	row := &model.AWSAccount{
		AccountID:       strings.TrimSpace(r.FormValue("account_id")),
		Alias:           strings.TrimSpace(r.FormValue("alias")),
		OIDCProviderARN: strings.TrimSpace(r.FormValue("oidc_provider_arn")),
	}
	if row.AccountID == "" || row.OIDCProviderARN == "" {
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("account_id and oidc_provider_arn are required"), http.StatusFound)
		return
	}
	if err := s.store.CreateAWSAccount(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			http.Redirect(w, r, "/portal/admin/aws?error="+escape("account_id already registered"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("create account failed"), http.StatusFound)
		return
	}
	pc := portalFromCtx(r)
	if err := s.logAudit(r, ActionAWSAccountCreated, &pc.User.ID, nil,
		logMeta("account_id", row.AccountID, "alias", row.Alias)); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/admin/aws?success="+escape("Account added."), http.StatusFound)
}

func (s *Server) handlePortalAdminAWSAccountDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error=invalid+id", http.StatusFound)
		return
	}
	existing, _ := s.store.GetAWSAccount(r.Context(), id)
	if err := s.store.DeleteAWSAccount(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("delete failed"), http.StatusFound)
		return
	}
	pc := portalFromCtx(r)
	if existing != nil {
		_ = s.logAudit(r, ActionAWSAccountDeleted, &pc.User.ID, nil,
			logMeta("account_id", existing.AccountID))
	}
	http.Redirect(w, r, "/portal/admin/aws?success="+escape("Account deleted."), http.StatusFound)
}

// ── role handlers ────────────────────────────────────────────────────────────

// slugPattern restricts role slug to URL/CLI-safe characters. Slugs flow
// through the user's ~/.aws/config (credential_process flag), the API
// `role` form field, and the helper's cache filename — keeping the
// allowed set narrow eliminates a class of shell-escaping pitfalls.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func (s *Server) handlePortalAdminAWSRoleNew(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	acctID, err := uuid.Parse(strings.TrimSpace(r.FormValue("account_id")))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error=invalid+account_id", http.StatusFound)
		return
	}
	maxDur := 3600
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("max_session_duration_sec"))); err == nil && v > 0 {
		maxDur = v
	}
	row := &model.AWSRole{
		AccountID:             acctID,
		RoleARN:               strings.TrimSpace(r.FormValue("role_arn")),
		Slug:                  strings.TrimSpace(r.FormValue("slug")),
		DisplayName:           strings.TrimSpace(r.FormValue("display_name")),
		RequireStepUpMFA:      r.FormValue("require_step_up_mfa") == "1",
		MaxSessionDurationSec: maxDur,
	}
	if row.RoleARN == "" || row.Slug == "" || row.DisplayName == "" {
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("role_arn, slug, and display_name are required"), http.StatusFound)
		return
	}
	if !slugPattern.MatchString(row.Slug) {
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("slug must match [a-z0-9][a-z0-9_-]{0,62} (lowercase alphanumeric, dash, underscore)"), http.StatusFound)
		return
	}
	if err := s.store.CreateAWSRole(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			http.Redirect(w, r, "/portal/admin/aws?error="+escape("role_arn or slug already registered"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("create role failed"), http.StatusFound)
		return
	}
	pc := portalFromCtx(r)
	if err := s.logAudit(r, ActionAWSRoleCreated, &pc.User.ID, nil,
		logMeta("role_arn", row.RoleARN, "role_slug", row.Slug)); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/admin/aws?success="+escape("Role added."), http.StatusFound)
}

func (s *Server) handlePortalAdminAWSRoleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error=invalid+id", http.StatusFound)
		return
	}
	existing, _ := s.store.GetAWSRole(r.Context(), id)
	if err := s.store.DeleteAWSRole(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("delete failed"), http.StatusFound)
		return
	}
	pc := portalFromCtx(r)
	if existing != nil {
		_ = s.logAudit(r, ActionAWSRoleDeleted, &pc.User.ID, nil,
			logMeta("role_arn", existing.RoleARN))
	}
	http.Redirect(w, r, "/portal/admin/aws?success="+escape("Role deleted."), http.StatusFound)
}

// ── assignment handlers ──────────────────────────────────────────────────────

func (s *Server) handlePortalAdminAWSAssignmentNew(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	groupID, err := uuid.Parse(strings.TrimSpace(r.FormValue("group_id")))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error=invalid+group_id", http.StatusFound)
		return
	}
	roleID, err := uuid.Parse(strings.TrimSpace(r.FormValue("role_id")))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error=invalid+role_id", http.StatusFound)
		return
	}
	row := &model.AWSRoleAssignment{GroupID: groupID, RoleID: roleID}
	if err := s.store.CreateAWSRoleAssignment(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			http.Redirect(w, r, "/portal/admin/aws?error="+escape("assignment already exists"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("create assignment failed"), http.StatusFound)
		return
	}
	pc := portalFromCtx(r)
	if err := s.logAudit(r, ActionAWSAssignmentCreated, &pc.User.ID, nil,
		logMeta("group_id", groupID.String(), "role_id", roleID.String())); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/admin/aws?success="+escape("Assignment added."), http.StatusFound)
}

func (s *Server) handlePortalAdminAWSAssignmentDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error=invalid+id", http.StatusFound)
		return
	}
	if err := s.store.DeleteAWSRoleAssignment(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/aws?error="+escape("delete failed"), http.StatusFound)
		return
	}
	pc := portalFromCtx(r)
	_ = s.logAudit(r, ActionAWSAssignmentDeleted, &pc.User.ID, nil, logMeta("assignment_id", id.String()))
	http.Redirect(w, r, "/portal/admin/aws?success="+escape("Assignment deleted."), http.StatusFound)
}

func escape(s string) string { return url.QueryEscape(s) }
