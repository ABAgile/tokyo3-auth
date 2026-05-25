// Package api implements the HTTP server for the IdP.
package api

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/journal"
)

// Server holds all dependencies for the HTTP API.
type Server struct {
	store       store.Store
	signer      *internaljwt.Signer
	policy      *policy.Engine
	wa          *mfa.WAHandler
	kp          bcrypto.KeyProvider
	provReg     *provision.Registry // outbound user/group provisioning fan-out; may be nil
	outboundTLS *tls.Config         // shared client cert + CA for mtls-mode integrations; may be nil
	audit       audit.Sink          // JetStream publisher; NoopSink when AUTH_NATS_URL is unset
	auditSrc    journal.Source      // JetStream reader for the audit-log stream page; NoopSource when AUTH_NATS_URL is unset
	issuer      string
	// awsAudience is the single value emitted as the `aud` claim on every
	// federation JWT minted for AWS console / CLI assumption. Sourced from
	// the AUTH_AWS_AUDIENCE env var at startup; empty disables federation
	// (handlers fail with a clear server-misconfigured message). One audience
	// per IdP (typically also per AWS account for cross-account replay
	// safety); per-role authorisation moves to aws:RequestTag/<key>
	// conditions in the role trust policies.
	awsAudience string
	// stepUpMFATTL is the freshness window for the step-up MFA gate that
	// protects AWS roles flagged require_step_up_mfa. A click on such a
	// role's tile re-prompts MFA when the session's mfa_verified_at is
	// older than this duration (or missing). Configured by
	// AUTH_STEP_UP_MFA_TTL; defaults to 5m when unset.
	stepUpMFATTL time.Duration
	masterKey    []byte
	log          *slog.Logger
	ssoTmpl      *tmplManager
	portalTmpl   *tmplManager
	allowReg     bool
}

// Config holds server constructor options.
type Config struct {
	Store        store.Store
	Signer       *internaljwt.Signer
	Policy       *policy.Engine
	WAHandler    *mfa.WAHandler
	KP           bcrypto.KeyProvider
	Provisioners *provision.Registry
	OutboundTLS  *tls.Config
	Audit        audit.Sink
	AuditSource  journal.Source
	Issuer       string
	AWSAudience  string
	// StepUpMFATTL bounds how recently the user must have completed an
	// MFA challenge for sensitive role assumption to proceed without
	// re-prompting. Zero or negative falls back to the package default.
	StepUpMFATTL      time.Duration
	MasterKey         []byte
	Log               *slog.Logger
	AllowRegistration bool
}

// defaultStepUpMFATTL is the fallback freshness window applied when
// Config.StepUpMFATTL is zero/negative. Chosen to match the typical
// IdP-suite default (Okta, Identity Center) so operators have one less
// knob to think about for the average case.
const defaultStepUpMFATTL = 5 * time.Minute

// New creates a Server.
func New(cfg Config) (*Server, error) {
	ssoTmpl, err := newTmplManager("base_sso.html")
	if err != nil {
		return nil, fmt.Errorf("sso template: %w", err)
	}
	portalTmpl, err := newTmplManager("base_portal.html")
	if err != nil {
		return nil, fmt.Errorf("portal template: %w", err)
	}
	auditSink := cfg.Audit
	if auditSink == nil {
		auditSink = audit.NoopSink
	}
	auditSrc := cfg.AuditSource
	if auditSrc == nil {
		auditSrc = journal.NoopSource{}
	}
	stepUpTTL := cfg.StepUpMFATTL
	if stepUpTTL <= 0 {
		stepUpTTL = defaultStepUpMFATTL
	}
	return &Server{
		store:        cfg.Store,
		signer:       cfg.Signer,
		policy:       cfg.Policy,
		wa:           cfg.WAHandler,
		kp:           cfg.KP,
		provReg:      cfg.Provisioners,
		outboundTLS:  cfg.OutboundTLS,
		audit:        auditSink,
		auditSrc:     auditSrc,
		issuer:       cfg.Issuer,
		awsAudience:  cfg.AWSAudience,
		stepUpMFATTL: stepUpTTL,
		masterKey:    cfg.MasterKey,
		log:          cfg.Log,
		ssoTmpl:      ssoTmpl,
		portalTmpl:   portalTmpl,
		allowReg:     cfg.AllowRegistration,
	}, nil
}

// Routes returns the root HTTP handler with all routes registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Root redirect
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/portal", http.StatusFound)
	})

	// Static assets
	mux.Handle("GET /static/", staticHandler())

	// OIDC discovery
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)

	// OAuth2 / OIDC
	mux.HandleFunc("GET /authorize", s.handleAuthorizeGET)
	mux.HandleFunc("POST /authorize", s.handleAuthorizePost)
	mux.HandleFunc("POST /authorize/mfa/totp", s.handleMFATOTPPost)
	mux.HandleFunc("GET /authorize/mfa/webauthn", s.handleSSOWebAuthnPage)
	mux.HandleFunc("POST /authorize/mfa/webauthn/begin", s.handleSSOWebAuthnBegin)
	mux.HandleFunc("POST /authorize/mfa/webauthn/finish", s.handleSSOWebAuthnFinish)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /userinfo", s.bearerAuth(s.handleUserInfo))
	mux.HandleFunc("POST /revoke", s.handleRevoke)

	// RFC 8628 — device authorization grant. /device_authorization is
	// public (the device has no user yet); /device and /device/confirm
	// wrap in portalAuth so the approver's identity drives the issued
	// session. The /token endpoint above gates the new grant_type
	// internally.
	mux.HandleFunc("POST /device_authorization", s.handleDeviceAuthorization)
	mux.HandleFunc("GET /device", s.portalAuth(s.handleDevice))
	mux.HandleFunc("POST /device", s.portalAuth(s.handleDevice))
	mux.HandleFunc("POST /device/confirm", s.portalAuth(s.handleDeviceConfirm))

	// AWS OIDC federation — programmatic credentials issuance for the
	// auth-aws-creds CLI helper (boto3 credential_process).
	mux.HandleFunc("POST /aws/credentials", s.bearerAuth(s.handleAWSCredentials))

	// Self-registration (optional)
	mux.HandleFunc("GET /register", s.handleRegisterGET)
	mux.HandleFunc("POST /register", s.handleRegisterPOST)

	// GitHub OAuth2 compatibility.
	// User-info endpoints are mounted at BOTH /api/v3/user* (the GitHub
	// Enterprise convention) AND /user* (the github.com / api.github.com
	// convention). Teleport CE hard-codes api_endpoint_url=https://api.github.com
	// and appends /user etc., so when the docker-compose.teleport.yml
	// extra_hosts entry hijacks api.github.com to auth, the bare /user paths
	// are the ones it actually hits.
	mux.HandleFunc("GET /login/oauth/authorize", s.handleGitHubAuthorize)
	mux.HandleFunc("POST /login/oauth/access_token", s.handleGitHubAccessToken)
	mux.HandleFunc("GET /api/v3/user", s.bearerAuth(s.handleGitHubUser))
	mux.HandleFunc("GET /api/v3/user/emails", s.bearerAuth(s.handleGitHubUserEmails))
	mux.HandleFunc("GET /api/v3/user/orgs", s.bearerAuth(s.handleGitHubUserOrgs))
	mux.HandleFunc("GET /api/v3/user/teams", s.bearerAuth(s.handleGitHubUserTeams))
	mux.HandleFunc("GET /user", s.bearerAuth(s.handleGitHubUser))
	mux.HandleFunc("GET /user/emails", s.bearerAuth(s.handleGitHubUserEmails))
	mux.HandleFunc("GET /user/orgs", s.bearerAuth(s.handleGitHubUserOrgs))
	mux.HandleFunc("GET /user/teams", s.bearerAuth(s.handleGitHubUserTeams))

	// MFA — TOTP
	mux.HandleFunc("POST /mfa/totp/enroll", s.bearerAuth(s.handleTOTPEnroll))
	mux.HandleFunc("POST /mfa/totp/confirm", s.bearerAuth(s.handleTOTPConfirm))
	mux.HandleFunc("POST /mfa/totp/verify", s.bearerAuth(s.handleTOTPVerify))
	mux.HandleFunc("DELETE /mfa/totp", s.bearerAuth(s.handleTOTPDelete))

	// MFA — WebAuthn (API, bearer auth)
	mux.HandleFunc("POST /mfa/webauthn/register/begin", s.bearerAuth(s.handleWebAuthnRegisterBegin))
	mux.HandleFunc("POST /mfa/webauthn/register/finish", s.bearerAuth(s.handleWebAuthnRegisterFinish))
	mux.HandleFunc("POST /mfa/webauthn/login/begin", s.handleWebAuthnLoginBegin)
	mux.HandleFunc("POST /mfa/webauthn/login/finish", s.handleWebAuthnLoginFinish)
	mux.HandleFunc("DELETE /mfa/webauthn/{id}", s.bearerAuth(s.handleWebAuthnDelete))

	// Admin API (bearer token, admin scope)
	mux.HandleFunc("GET /admin/users", s.adminAuth(s.handleAdminListUsers))
	mux.HandleFunc("POST /admin/users", s.adminAuth(s.handleAdminCreateUser))
	mux.HandleFunc("GET /admin/users/{id}", s.adminAuth(s.handleAdminGetUser))
	mux.HandleFunc("PUT /admin/users/{id}", s.adminAuth(s.handleAdminUpdateUser))
	mux.HandleFunc("DELETE /admin/users/{id}", s.adminAuth(s.handleAdminDeleteUser))
	mux.HandleFunc("GET /admin/clients", s.adminAuth(s.handleAdminListClients))
	mux.HandleFunc("POST /admin/clients", s.adminAuth(s.handleAdminCreateClient))
	mux.HandleFunc("GET /admin/clients/{id}", s.adminAuth(s.handleAdminGetClient))
	mux.HandleFunc("DELETE /admin/clients/{id}", s.adminAuth(s.handleAdminDeleteClient))
	mux.HandleFunc("POST /admin/clients/{id}/rotate-secret", s.adminAuth(s.handleAdminRotateClientSecret))

	// Portal — login / logout / register
	mux.HandleFunc("GET /portal/login", s.handlePortalLoginGET)
	mux.HandleFunc("POST /portal/login", s.handlePortalLoginPOST)
	mux.HandleFunc("GET /portal/login/mfa", s.handlePortalLoginMFA)
	mux.HandleFunc("POST /portal/login/mfa", s.handlePortalLoginMFA)
	mux.HandleFunc("GET /portal/login/change-password", s.handlePortalChangePassword)
	mux.HandleFunc("POST /portal/login/change-password", s.handlePortalChangePassword)
	mux.HandleFunc("POST /portal/login/mfa/webauthn/begin", s.handlePortalLoginMFAWebAuthnBegin)
	mux.HandleFunc("POST /portal/login/mfa/webauthn/finish", s.handlePortalLoginMFAWebAuthnFinish)
	mux.HandleFunc("POST /portal/logout", s.portalAuth(s.handlePortalLogout))
	mux.HandleFunc("GET /portal/register", s.handlePortalRegisterGET)
	mux.HandleFunc("POST /portal/register", s.handlePortalRegisterPOST)

	// Portal — application portal (unified tile page for OIDC + AWS apps).
	// /portal/aws redirects here for one transition cycle; bookmarks and
	// legacy nav entries continue to work.
	mux.HandleFunc("GET /portal/apps", s.portalAuth(s.handlePortalApps))
	mux.HandleFunc("GET /portal/aws", s.portalAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/portal/apps", http.StatusFound)
	}))
	mux.HandleFunc("POST /portal/aws/console", s.portalAuth(s.handlePortalAWSConsole))
	mux.HandleFunc("GET /portal/aws/refresh", s.portalAuth(s.handlePortalAWSRefresh))

	// Portal — step-up MFA challenge interposed between clicking a
	// sensitive launcher tile and reaching the underlying action. Today
	// only AWS console assumption uses it (handlePortalAWSConsole 302s
	// here when the role requires step-up and the session's MFA is
	// stale); the `next` dispatch table extends to additional targets
	// as they come online.
	mux.HandleFunc("GET /portal/step-up", s.portalAuth(s.handlePortalStepUp))
	mux.HandleFunc("POST /portal/step-up", s.portalAuth(s.handlePortalStepUp))
	mux.HandleFunc("POST /portal/step-up/webauthn/begin", s.portalAuth(s.handlePortalStepUpWebAuthnBegin))
	mux.HandleFunc("POST /portal/step-up/webauthn/finish", s.portalAuth(s.handlePortalStepUpWebAuthnFinish))

	// Portal — account (requires portal session)
	mux.HandleFunc("GET /portal", s.portalAuth(s.handlePortalHome))
	mux.HandleFunc("GET /portal/account", s.portalAuth(s.handlePortalAccount))
	mux.HandleFunc("POST /portal/account/profile", s.portalAuth(s.handlePortalAccountProfile))
	mux.HandleFunc("POST /portal/account/password", s.portalAuth(s.handlePortalAccountPassword))
	mux.HandleFunc("POST /portal/mfa/totp/enroll", s.portalAuth(s.handlePortalMFATOTPEnroll))
	mux.HandleFunc("POST /portal/mfa/totp/confirm", s.portalAuth(s.handlePortalMFATOTPConfirm))
	mux.HandleFunc("POST /portal/mfa/totp/delete", s.portalAuth(s.handlePortalMFATOTPDelete))
	mux.HandleFunc("POST /portal/mfa/webauthn/register/begin", s.portalAuth(s.handlePortalMFAWebAuthnBegin))
	mux.HandleFunc("POST /portal/mfa/webauthn/register/finish", s.portalAuth(s.handlePortalMFAWebAuthnFinish))
	mux.HandleFunc("POST /portal/mfa/webauthn/{id}/delete", s.portalAuth(s.handlePortalMFAWebAuthnDelete))

	// Portal — admin (requires portal session + IsAdmin)
	mux.HandleFunc("GET /portal/admin/users", s.portalAdminAuth(s.handlePortalAdminUsers))
	mux.HandleFunc("GET /portal/admin/users/new", s.portalAdminAuth(s.handlePortalAdminUserNew))
	mux.HandleFunc("POST /portal/admin/users/new", s.portalAdminAuth(s.handlePortalAdminUserNew))
	mux.HandleFunc("GET /portal/admin/users/{id}/edit", s.portalAdminAuth(s.handlePortalAdminUserEdit))
	mux.HandleFunc("POST /portal/admin/users/{id}/edit", s.portalAdminAuth(s.handlePortalAdminUserEdit))
	mux.HandleFunc("POST /portal/admin/users/{id}/delete", s.portalAdminAuth(s.handlePortalAdminUserDelete))
	mux.HandleFunc("POST /portal/admin/users/{id}/reset-password", s.portalAdminAuth(s.handlePortalAdminUserResetPassword))
	mux.HandleFunc("POST /portal/admin/users/{id}/compromised-reset", s.portalAdminAuth(s.handlePortalAdminUserCompromisedReset))
	mux.HandleFunc("POST /portal/admin/users/{id}/clear-mfa", s.portalAdminAuth(s.handlePortalAdminUserClearMFA))
	mux.HandleFunc("POST /portal/admin/users/{id}/revoke-aws", s.portalAdminAuth(s.handlePortalAdminUserRevokeAWS))
	mux.HandleFunc("GET /portal/admin/clients", s.portalAdminAuth(s.handlePortalAdminClients))
	mux.HandleFunc("GET /portal/admin/clients/new", s.portalAdminAuth(s.handlePortalAdminClientNew))
	mux.HandleFunc("POST /portal/admin/clients/new", s.portalAdminAuth(s.handlePortalAdminClientNew))
	mux.HandleFunc("GET /portal/admin/clients/{id}/edit", s.portalAdminAuth(s.handlePortalAdminClientEdit))
	mux.HandleFunc("POST /portal/admin/clients/{id}/edit", s.portalAdminAuth(s.handlePortalAdminClientEdit))
	mux.HandleFunc("POST /portal/admin/clients/{id}/delete", s.portalAdminAuth(s.handlePortalAdminClientDelete))
	mux.HandleFunc("POST /portal/admin/clients/{id}/rotate-secret", s.portalAdminAuth(s.handlePortalAdminClientRotate))
	mux.HandleFunc("GET /portal/admin/integrations", s.portalAdminAuth(s.handlePortalAdminIntegrations))
	mux.HandleFunc("GET /portal/admin/integrations/new", s.portalAdminAuth(s.handlePortalAdminIntegrationNew))
	mux.HandleFunc("POST /portal/admin/integrations/new", s.portalAdminAuth(s.handlePortalAdminIntegrationNew))
	mux.HandleFunc("GET /portal/admin/integrations/{id}/edit", s.portalAdminAuth(s.handlePortalAdminIntegrationEdit))
	mux.HandleFunc("POST /portal/admin/integrations/{id}/edit", s.portalAdminAuth(s.handlePortalAdminIntegrationEdit))
	mux.HandleFunc("POST /portal/admin/integrations/{id}/delete", s.portalAdminAuth(s.handlePortalAdminIntegrationDelete))
	mux.HandleFunc("POST /portal/admin/integrations/{id}/test", s.portalAdminAuth(s.handlePortalAdminIntegrationTest))
	mux.HandleFunc("POST /portal/admin/integrations/{id}/sync", s.portalAdminAuth(s.handlePortalAdminIntegrationSync))
	mux.HandleFunc("GET /portal/admin/aws", s.portalAdminAuth(s.handlePortalAdminAWS))
	mux.HandleFunc("POST /portal/admin/aws/accounts/new", s.portalAdminAuth(s.handlePortalAdminAWSAccountNew))
	mux.HandleFunc("POST /portal/admin/aws/accounts/{id}/delete", s.portalAdminAuth(s.handlePortalAdminAWSAccountDelete))
	mux.HandleFunc("POST /portal/admin/aws/roles/new", s.portalAdminAuth(s.handlePortalAdminAWSRoleNew))
	mux.HandleFunc("POST /portal/admin/aws/roles/{id}/delete", s.portalAdminAuth(s.handlePortalAdminAWSRoleDelete))
	mux.HandleFunc("POST /portal/admin/aws/assignments/new", s.portalAdminAuth(s.handlePortalAdminAWSAssignmentNew))
	mux.HandleFunc("POST /portal/admin/aws/assignments/{id}/delete", s.portalAdminAuth(s.handlePortalAdminAWSAssignmentDelete))
	mux.HandleFunc("GET /portal/admin/groups", s.portalAdminAuth(s.handlePortalAdminGroups))
	mux.HandleFunc("GET /portal/admin/groups/new", s.portalAdminAuth(s.handlePortalAdminGroupNew))
	mux.HandleFunc("POST /portal/admin/groups/new", s.portalAdminAuth(s.handlePortalAdminGroupNew))
	mux.HandleFunc("GET /portal/admin/groups/{id}/edit", s.portalAdminAuth(s.handlePortalAdminGroupEdit))
	mux.HandleFunc("POST /portal/admin/groups/{id}/edit", s.portalAdminAuth(s.handlePortalAdminGroupEdit))
	mux.HandleFunc("POST /portal/admin/groups/{id}/delete", s.portalAdminAuth(s.handlePortalAdminGroupDelete))
	mux.HandleFunc("GET /portal/admin/audit", s.portalAdminAuth(s.handlePortalAdminAuditPage))
	mux.HandleFunc("GET /portal/admin/audit/sse", s.portalAdminAuth(s.handlePortalAdminAuditSSE))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}
