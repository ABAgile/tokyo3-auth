package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

// errFederationUnconfigured is returned by assumeRoleForUser when
// AUTHD_AWS_AUDIENCE is empty. Surfaces as a 503 in the API handler and as
// a portal error banner in the browser handler — both more useful than
// letting AWS reject the JWT with an opaque "InvalidIdentityToken: Token
// has no audience" message.
var errFederationUnconfigured = errors.New("AUTHD_AWS_AUDIENCE is not set; aws federation is disabled")

// AWS console federation endpoints. Both are well-known and stable. We
// post unauthenticated requests against them — the user's id_token is the
// authentication for STS, and the resulting STS session is the
// authentication for getSigninToken.
const (
	awsSTSEndpoint     = "https://sts.amazonaws.com"
	awsSigninFedURL    = "https://signin.aws.amazon.com/federation"
	awsConsoleHomeURL  = "https://console.aws.amazon.com/"
	federationTokenTTL = 15 * time.Minute
)

// stsAPI is the subset of *sts.Client this handler uses. Defined as an
// interface so tests can supply a mock and verify the federation flow
// without touching real AWS.
type stsAPI interface {
	AssumeRoleWithWebIdentity(ctx context.Context, in *sts.AssumeRoleWithWebIdentityInput, opts ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// handlePortalAWSConsole assumes the requested role on the user's behalf,
// exchanges the resulting STS credentials for an AWS console SigninToken,
// and 302-redirects the browser into the console with that token.
//
// Auth never holds AWS credentials for this path — the federation flow
// is one-way: AWS verifies the id_token's RS256 signature via auth's
// public JWKS, the SDK call to STS is sent with aws.AnonymousCredentials
// (the JWT is the auth), and the federation endpoint authenticates via
// the STS session credentials returned by step 1.
func (s *Server) handlePortalAWSConsole(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	roleIDStr := r.FormValue("role_id")
	if roleIDStr == "" {
		roleIDStr = r.URL.Query().Get("role_id")
	}
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		http.Redirect(w, r, "/portal/aws?error="+url.QueryEscape("invalid role_id"), http.StatusFound)
		return
	}

	role, allowed, err := s.resolveAuthorizedAWSRole(r.Context(), pc.User.ID, roleID)
	if err != nil {
		http.Redirect(w, r, "/portal/aws?error="+url.QueryEscape("lookup failed"), http.StatusFound)
		return
	}
	if !allowed {
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &pc.User.ID, nil,
			logMeta("role_id", roleID.String(), "reason", "not_assigned"))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Step-up gate: a role flagged sensitive requires a freshly proven
	// MFA challenge — not just "did MFA happen at login." Sessions whose
	// mfa_verified_at is nil or older than s.stepUpMFATTL get bounced to
	// /portal/step-up, which prompts and then dispatches back here.
	if role.RequireStepUpMFA && !s.stepUpMFAFresh(pc.Session) {
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &pc.User.ID, nil,
			logMeta(
				"role_id", roleID.String(),
				"reason", "step_up_required",
				"mfa_authenticated", pc.Session.MFAVerified,
			))
		q := url.Values{"next": {"aws_console"}, "role_id": {roleID.String()}}
		http.Redirect(w, r, "/portal/step-up?"+q.Encode(), http.StatusFound)
		return
	}

	consoleURL, err := s.buildAWSConsoleURL(r, pc, role)
	if err != nil {
		http.Redirect(w, r, "/portal/aws?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, consoleURL, http.StatusFound)
}

// stepUpMFAFresh returns true when sess completed an MFA challenge
// recently enough to satisfy a step-up gate. Older or never-verified
// sessions must re-prompt.
func (s *Server) stepUpMFAFresh(sess *model.Session) bool {
	if sess == nil || sess.MFAVerifiedAt == nil {
		return false
	}
	return time.Since(*sess.MFAVerifiedAt) <= s.stepUpMFATTL
}

// buildAWSConsoleURL runs the role-assume + getSigninToken steps and
// returns the AWS Console SigninToken URL for the resulting session.
// Audit-logs success and the two failure modes; callers translate the
// returned error to a redirect or JSON response.
//
// Extracted from handlePortalAWSConsole because the step-up MFA path
// needs to reach the same finish line from a different entrypoint
// (the step-up handler), and the two callers need different response
// shapes (302 vs JSON for WebAuthn).
func (s *Server) buildAWSConsoleURL(r *http.Request, pc *portalCtx, role *model.AWSRole) (string, error) {
	out, sessionName, err := s.assumeRoleForUser(r.Context(), pc.User, pc.Session, role)
	if err != nil {
		s.log.Error("AssumeRoleWithWebIdentity", "role", role.RoleARN, "err", err)
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &pc.User.ID, nil,
			logMeta("role_id", role.ID.String(), "role_arn", role.RoleARN, "reason", "sts_error", "err", err.Error()))
		return "", fmt.Errorf("AWS rejected the federation request: %s", err.Error())
	}

	signinToken, err := s.exchangeSigninToken(r.Context(), out)
	if err != nil {
		s.log.Error("getSigninToken", "err", err)
		_ = s.logAudit(r, ActionAWSConsoleAssumeFailed, &pc.User.ID, nil,
			logMeta("role_id", role.ID.String(), "reason", "signin_token_error", "err", err.Error()))
		return "", fmt.Errorf("AWS console federation failed: %s", err.Error())
	}

	consoleURL := buildConsoleLoginURL(signinToken, s.issuer+"/portal/aws/refresh?role_id="+role.ID.String(), awsConsoleHomeURL)
	// mfa_authenticated and step_up together let auditors distinguish
	// "MFA required and present" from "MFA optional but present" from
	// "MFA not required, not present" without joining against sessions.
	if err := s.logAudit(r, ActionAWSConsoleAssumed, &pc.User.ID, nil,
		logMeta(
			"role_id", role.ID.String(),
			"role_arn", role.RoleARN,
			"role_slug", role.Slug,
			"audience", s.awsAudience,
			"role_session_name", sessionName,
			"step_up", role.RequireStepUpMFA,
			"mfa_authenticated", pc.Session.MFAVerified,
		)); err != nil {
		return "", err
	}
	return consoleURL, nil
}

// handlePortalAWSRefresh is the URL AWS bounces back to when the console
// session expires (~hourly) so the same role can be re-federated silently.
// AWS calls it via 302; we treat it as a GET equivalent of /console: if
// the user's portal session is still alive, re-run the AssumeRole + signin
// dance with a fresh id_token; if not, portalAuth has already redirected
// to /portal/login.
func (s *Server) handlePortalAWSRefresh(w http.ResponseWriter, r *http.Request) {
	// Delegate to the same handler — accepting role_id from the query.
	s.handlePortalAWSConsole(w, r)
}

// assumeRoleForUser performs the user-identity → STS-credentials exchange
// that's shared by the console-redirect handler and the programmatic
// /aws/credentials endpoint. Both paths need exactly the same auth-side
// work (token mint with session tags, anonymous STS POST), differing only
// in what they do with the result — the console handler trades it for a
// SigninToken and 302s the browser; the API handler emits it as
// credential_process JSON. Returning the raw STS output keeps the helper
// free of presentation concerns.
//
// The audience claim comes from s.awsAudience (the AUTHD_AWS_AUDIENCE env
// var), not from the role row — per-role authorisation is delegated to
// aws:RequestTag/<key> conditions in the role's trust policy. Returns
// errFederationUnconfigured when the audience is empty so callers can
// surface a clear "server misconfigured" error instead of letting AWS
// reject a JWT with no aud.
//
// Returns the raw AssumeRoleWithWebIdentity output plus the
// CloudTrail-friendly RoleSessionName for audit metadata.
func (s *Server) assumeRoleForUser(ctx context.Context, user *model.User, sess *model.Session, role *model.AWSRole) (*sts.AssumeRoleWithWebIdentityOutput, string, error) {
	if s.awsAudience == "" {
		return nil, "", errFederationUnconfigured
	}
	groups, _ := s.groupNamesForUser(ctx, user.ID)
	amr := []string{"pwd"}
	if sess.MFAVerified {
		amr = append(amr, "mfa")
	}
	// principalTags becomes the `https://aws.amazon.com/tags` claim that
	// STS reads when minting the role session. Each key surfaces as
	// `aws:RequestTag/<key>` at trust-policy evaluation time and as
	// `aws:PrincipalTag/<key>` for the lifetime of the session. Trust
	// policies for individual roles gate on aws:RequestTag/team so the
	// shared audience is safe (the per-role discriminator moves from
	// `aud` to `team`). The role trust policy MUST allow sts:TagSession
	// for this to be accepted (see README); without it, AWS rejects the
	// call with AccessDenied at AssumeRole time.
	//
	// `team` is set to the group that actually authorized this assumption
	// (intersection of the user's SCIM groups and aws_role_assignments
	// for role.ID), not the user's first group overall — otherwise a user
	// with multiple group memberships would always present the same
	// `team` value regardless of which role they're assuming, breaking
	// per-role trust-policy gating.
	principalTags := map[string]string{
		"sub": user.ID.String(),
	}
	if user.Email != "" {
		principalTags["email"] = user.Email
	}
	authzGroups, err := s.authorizingGroupsForRole(ctx, user.ID, role.ID)
	if err != nil {
		return nil, "", fmt.Errorf("resolve authorizing groups: %w", err)
	}
	if len(authzGroups) > 0 {
		principalTags["team"] = authzGroups[0]
	}
	idToken, err := s.signer.MintFederationToken(
		user.ID.String(),
		s.awsAudience,
		user.Email,
		user.Name,
		groups,
		amr,
		sess.CreatedAt,
		federationTokenTTL,
		principalTags,
	)
	if err != nil {
		return nil, "", fmt.Errorf("mint federation token: %w", err)
	}
	sessionName := buildRoleSessionName(user.Email, user.ID)
	out, err := s.stsClient().AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(role.RoleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(idToken),
		DurationSeconds:  aws.Int32(int32(role.MaxSessionDurationSec)),
	})
	if err != nil {
		return nil, sessionName, err
	}
	return out, sessionName, nil
}

// resolveAuthorizedAWSRole returns the role and whether userID is allowed
// to assume it (i.e. role belongs to a group the user is a member of).
func (s *Server) resolveAuthorizedAWSRole(ctx context.Context, userID, roleID uuid.UUID) (*model.AWSRole, bool, error) {
	role, err := s.store.GetAWSRole(ctx, roleID)
	if err != nil {
		return nil, false, err
	}
	authorized, err := s.store.ListAWSRolesForUser(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	for _, ar := range authorized {
		if ar.ID == roleID {
			return role, true, nil
		}
	}
	return role, false, nil
}

// groupNamesForUser returns the display names of every SCIM group the
// user belongs to. Sent as the `groups` claim on the federation id_token
// for CloudTrail visibility — AWS does not use it for trust-policy
// evaluation (custom claims aren't condition-key expanded).
func (s *Server) groupNamesForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range groups {
		if slices.Contains(g.Members, userID) {
			out = append(out, g.DisplayName)
		}
	}
	return out, nil
}

// stsClient builds an STS client with anonymous credentials.
// AssumeRoleWithWebIdentity is one of the few AWS API calls that
// authenticates via the JWT body rather than SigV4 — the SDK still
// requires *some* credentials provider, so we pass aws.AnonymousCredentials
// to suppress signing and avoid attempting to read ambient creds (which
// authd may not even have if it's deployed without an IAM role).
func (s *Server) stsClient() stsAPI {
	cfg := aws.Config{
		Region:      "us-east-1", // STS global endpoint is region-bound for SDK purposes; us-east-1 is canonical
		Credentials: aws.AnonymousCredentials{},
	}
	return sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.BaseEndpoint = aws.String(awsSTSEndpoint)
	})
}

// exchangeSigninToken trades STS session credentials for a single-use
// SigninToken at https://signin.aws.amazon.com/federation. The request is
// authenticated by the session JSON it carries — no SigV4 needed.
func (s *Server) exchangeSigninToken(ctx context.Context, creds *sts.AssumeRoleWithWebIdentityOutput) (string, error) {
	if creds == nil || creds.Credentials == nil {
		return "", errors.New("nil STS credentials")
	}
	session := struct {
		SessionID    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		SessionID:    aws.ToString(creds.Credentials.AccessKeyId),
		SessionKey:   aws.ToString(creds.Credentials.SecretAccessKey),
		SessionToken: aws.ToString(creds.Credentials.SessionToken),
	}
	b, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}
	q := url.Values{}
	q.Set("Action", "getSigninToken")
	q.Set("Session", string(b))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, awsSigninFedURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getSigninToken: %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		SigninToken string `json:"SigninToken"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode SigninToken: %w", err)
	}
	if out.SigninToken == "" {
		return "", errors.New("empty SigninToken in response")
	}
	return out.SigninToken, nil
}

// buildConsoleLoginURL constructs the redirect URL that signs the user
// into the AWS Console. Issuer is the URL AWS bounces back to when the
// console session expires — we point it at /portal/aws/refresh so the
// re-federation is transparent.
func buildConsoleLoginURL(signinToken, issuerURL, destination string) string {
	q := url.Values{}
	q.Set("Action", "login")
	q.Set("Issuer", issuerURL)
	q.Set("Destination", destination)
	q.Set("SigninToken", signinToken)
	return awsSigninFedURL + "?" + q.Encode()
}

// authorizingGroupsForRole returns the display names of SCIM groups
// that both contain userID and map to roleID in aws_role_assignments —
// i.e. the groups that gave this user the right to assume this role.
// Sorted lexicographically so the caller can deterministically pick a
// single value (e.g. for the `team` session tag) without re-sorting.
//
// The two-table walk is intentional: ListAWSRolesForUser collapses
// assignments to roles and loses the originating group, but the team
// tag has to name a group, not a role.
func (s *Server) authorizingGroupsForRole(ctx context.Context, userID, roleID uuid.UUID) ([]string, error) {
	assigns, err := s.store.ListAWSRoleAssignments(ctx)
	if err != nil {
		return nil, err
	}
	authorizing := make(map[uuid.UUID]struct{})
	for _, a := range assigns {
		if a.RoleID == roleID {
			authorizing[a.GroupID] = struct{}{}
		}
	}
	if len(authorizing) == 0 {
		return nil, nil
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, g := range groups {
		if _, ok := authorizing[g.ID]; !ok {
			continue
		}
		if !slices.Contains(g.Members, userID) {
			continue
		}
		names = append(names, g.DisplayName)
	}
	sort.Strings(names)
	return names, nil
}

// buildRoleSessionName produces a CloudTrail-friendly identifier for the
// STS session. Format: <emailLocal>-<uuidPrefix>-<unixSeconds>. AWS limits
// session names to characters in [A-Za-z0-9=,.@-]; we sanitise by
// replacing anything else with '-'.
func buildRoleSessionName(email string, userID uuid.UUID) string {
	local := strings.SplitN(email, "@", 2)[0]
	uid := userID.String()
	if len(uid) > 8 {
		uid = uid[:8]
	}
	raw := fmt.Sprintf("%s-%s-%d", local, uid, time.Now().Unix())
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case 'a' <= c && c <= 'z',
			'A' <= c && c <= 'Z',
			'0' <= c && c <= '9',
			c == '=' || c == ',' || c == '.' || c == '@' || c == '-':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	// AWS caps RoleSessionName at 64 characters.
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}
