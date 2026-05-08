// Package api implements the HTTP server for the IdP.
package api

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/abagile/tokyo3-auth/internal/audit"
	"github.com/abagile/tokyo3-auth/internal/crypto"
	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
)

// Server holds all dependencies for the HTTP API.
type Server struct {
	store       store.Store
	signer      *internaljwt.Signer
	policy      *policy.Engine
	wa          *mfa.WAHandler
	kp          crypto.KeyProvider
	provReg     *provision.Registry // outbound user/group provisioning fan-out; may be nil
	outboundTLS *tls.Config         // shared client cert + CA for mtls-mode integrations; may be nil
	audit       audit.Sink          // JetStream publisher; NoopSink when AUTH_NATS_URL is unset
	issuer      string
	masterKey   []byte
	log         *slog.Logger
	ssoTmpl     *tmplManager
	portalTmpl  *tmplManager
	allowReg    bool
}

// Config holds server constructor options.
type Config struct {
	Store             store.Store
	Signer            *internaljwt.Signer
	Policy            *policy.Engine
	WAHandler         *mfa.WAHandler
	KP                crypto.KeyProvider
	Provisioners      *provision.Registry
	OutboundTLS       *tls.Config
	Audit             audit.Sink
	Issuer            string
	MasterKey         []byte
	Log               *slog.Logger
	AllowRegistration bool
}

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
		auditSink = audit.NoopSink{}
	}
	return &Server{
		store:       cfg.Store,
		signer:      cfg.Signer,
		policy:      cfg.Policy,
		wa:          cfg.WAHandler,
		kp:          cfg.KP,
		provReg:     cfg.Provisioners,
		outboundTLS: cfg.OutboundTLS,
		audit:       auditSink,
		issuer:      cfg.Issuer,
		masterKey:   cfg.MasterKey,
		log:         cfg.Log,
		ssoTmpl:     ssoTmpl,
		portalTmpl:  portalTmpl,
		allowReg:    cfg.AllowRegistration,
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

	// Self-registration (optional)
	mux.HandleFunc("GET /register", s.handleRegisterGET)
	mux.HandleFunc("POST /register", s.handleRegisterPOST)

	// GitHub OAuth2 compatibility
	mux.HandleFunc("GET /login/oauth/authorize", s.handleGitHubAuthorize)
	mux.HandleFunc("POST /login/oauth/access_token", s.handleGitHubAccessToken)
	mux.HandleFunc("GET /api/v3/user", s.bearerAuth(s.handleGitHubUser))
	mux.HandleFunc("GET /api/v3/user/emails", s.bearerAuth(s.handleGitHubUserEmails))

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
	mux.HandleFunc("GET /admin/audit", s.adminAuth(s.handleAdminAuditLogs))

	// Portal — login / logout / register
	mux.HandleFunc("GET /portal/login", s.handlePortalLoginGET)
	mux.HandleFunc("POST /portal/login", s.handlePortalLoginPOST)
	mux.HandleFunc("GET /portal/login/mfa", s.handlePortalLoginMFA)
	mux.HandleFunc("POST /portal/login/mfa", s.handlePortalLoginMFA)
	mux.HandleFunc("POST /portal/login/mfa/webauthn/begin", s.handlePortalLoginMFAWebAuthnBegin)
	mux.HandleFunc("POST /portal/login/mfa/webauthn/finish", s.handlePortalLoginMFAWebAuthnFinish)
	mux.HandleFunc("POST /portal/logout", s.portalAuth(s.handlePortalLogout))
	mux.HandleFunc("GET /portal/register", s.handlePortalRegisterGET)
	mux.HandleFunc("POST /portal/register", s.handlePortalRegisterPOST)

	// Portal — account (requires portal session)
	mux.HandleFunc("GET /portal", s.portalAuth(s.handlePortalHome))
	mux.HandleFunc("GET /portal/account", s.portalAuth(s.handlePortalAccount))
	mux.HandleFunc("POST /portal/account/profile", s.portalAuth(s.handlePortalAccountProfile))
	mux.HandleFunc("POST /portal/account/password", s.portalAuth(s.handlePortalAccountPassword))
	mux.HandleFunc("GET /portal/mfa", s.portalAuth(s.handlePortalMFA))
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
	mux.HandleFunc("GET /portal/admin/groups", s.portalAdminAuth(s.handlePortalAdminGroups))
	mux.HandleFunc("GET /portal/admin/groups/new", s.portalAdminAuth(s.handlePortalAdminGroupNew))
	mux.HandleFunc("POST /portal/admin/groups/new", s.portalAdminAuth(s.handlePortalAdminGroupNew))
	mux.HandleFunc("GET /portal/admin/groups/{id}/edit", s.portalAdminAuth(s.handlePortalAdminGroupEdit))
	mux.HandleFunc("POST /portal/admin/groups/{id}/edit", s.portalAdminAuth(s.handlePortalAdminGroupEdit))
	mux.HandleFunc("POST /portal/admin/groups/{id}/delete", s.portalAdminAuth(s.handlePortalAdminGroupDelete))
	mux.HandleFunc("GET /portal/admin/audit", s.portalAdminAuth(s.handlePortalAdminAudit))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}
