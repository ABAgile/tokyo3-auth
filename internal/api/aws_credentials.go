package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"

	"github.com/abagile/tokyo3-auth/internal/model"
)

// awsCredentialsResponse mirrors the AWS CLI v2 credential_process JSON
// shape (https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html).
// Emitting this shape directly lets the auth-aws-creds CLI helper pass the
// response straight through to stdout without re-marshalling.
type awsCredentialsResponse struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

// handleAWSCredentials issues STS session credentials for the requested
// role to a programmatic caller (typically the auth-aws-creds CLI helper
// running as boto3's credential_process). Bearer-auth via the normal
// OAuth2 access token; the caller specifies which role to assume by its
// slug (matching how it appears in the user's ~/.aws/config under
// `credential_process = auth-aws-creds get --role <slug>`).
//
// Authorization mirrors the portal handler: the user must be in a SCIM
// group assigned to a role with that slug. Step-up MFA is also enforced
// — sessions without MFAVerified=true cannot assume MFA-gated roles via
// this endpoint.
//
// The `aud` claim of every minted JWT comes from AUTH_AWS_AUDIENCE
// (server-global), not from the role row — per-role authorisation moves
// to aws:RequestTag/<key> conditions in trust policies. Returns 503 when
// the audience is unconfigured so operators see a clear server-side
// misconfiguration rather than an opaque AWS rejection.
//
// Returns the AWS CLI v2 credential_process JSON shape so the helper
// can stream the response straight to stdout. No CloudTrail-visible
// behavioural difference from the portal-driven path; both end up at
// the same sts:AssumeRoleWithWebIdentity call.
func (s *Server) handleAWSCredentials(w http.ResponseWriter, r *http.Request) {
	if s.awsAudience == "" {
		s.writeError(w, http.StatusServiceUnavailable, "federation_disabled",
			"AWS federation is not configured (AUTH_AWS_AUDIENCE is unset)")
		return
	}
	sess := sessionFromCtx(r)
	if sess == nil || sess.UserID == (model.User{}).ID {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "no session")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user not found")
		return
	}
	if !user.Active {
		s.writeError(w, http.StatusForbidden, "user_inactive", "user is deactivated")
		return
	}

	_ = r.ParseForm()
	// Accept `role` (canonical) and `audience` (deprecated alias) so the
	// 0.x → 1.x upgrade doesn't break in-flight ~/.aws/config entries.
	// The aliased value still selects roles by slug regardless of the
	// flag name a client uses.
	slug := strings.TrimSpace(r.FormValue("role"))
	if slug == "" {
		slug = strings.TrimSpace(r.FormValue("audience"))
	}
	if slug == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "role is required")
		return
	}

	role, err := s.resolveAWSRoleBySlugForUser(r.Context(), user.ID, slug)
	if err != nil {
		s.log.Error("resolve aws role", "slug", slug, "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "role lookup failed")
		return
	}
	if role == nil {
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &user.ID, nil,
			logMeta("role_slug", slug, "reason", "not_assigned", "via", "api"))
		s.writeError(w, http.StatusForbidden, "forbidden", "no role with that slug is assigned to you")
		return
	}
	if role.RequireStepUpMFA && !sess.MFAVerified {
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &user.ID, nil,
			logMeta("role_id", role.ID.String(), "role_slug", slug, "reason", "step_up_required",
				"mfa_authenticated", false, "via", "api"))
		s.writeError(w, http.StatusForbidden, "step_up_required",
			"this role requires MFA; enroll TOTP or a security key and re-authenticate")
		return
	}

	out, sessionName, err := s.assumeRoleForUser(r.Context(), user, sess, role)
	if err != nil {
		if errors.Is(err, errFederationUnconfigured) {
			s.writeError(w, http.StatusServiceUnavailable, "federation_disabled", err.Error())
			return
		}
		s.log.Error("AssumeRoleWithWebIdentity", "role", role.RoleARN, "err", err)
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &user.ID, nil,
			logMeta("role_id", role.ID.String(), "role_slug", slug, "role_arn", role.RoleARN,
				"reason", "sts_error", "err", err.Error(), "via", "api"))
		s.writeError(w, http.StatusBadGateway, "sts_error", "AWS rejected the federation request: "+err.Error())
		return
	}
	if out == nil || out.Credentials == nil {
		s.writeError(w, http.StatusBadGateway, "sts_error", "AWS returned no credentials")
		return
	}
	if err := s.logAudit(r, ActionAWSConsoleAssumed, &user.ID, nil,
		logMeta(
			"role_id", role.ID.String(),
			"role_arn", role.RoleARN,
			"role_slug", role.Slug,
			"audience", s.awsAudience,
			"role_session_name", sessionName,
			"step_up", role.RequireStepUpMFA,
			"mfa_authenticated", sess.MFAVerified,
			"via", "api",
		)); err != nil {
		s.auditFail(w, err)
		return
	}
	resp := awsCredentialsResponse{
		Version:         1,
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
	if out.Credentials.Expiration != nil {
		resp.Expiration = *out.Credentials.Expiration
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// resolveAWSRoleBySlugForUser returns the role with the given slug IF
// the user is authorized to assume it via SCIM group membership,
// otherwise nil. Slug is the URL/CLI-safe identifier operators set at
// /portal/admin/aws/roles; users supply it in their AWS profile config
// (see README quickstart).
func (s *Server) resolveAWSRoleBySlugForUser(ctx context.Context, userID uuid.UUID, slug string) (*model.AWSRole, error) {
	roles, err := s.store.ListAWSRolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if r.Slug == slug {
			return r, nil
		}
	}
	return nil, nil
}
