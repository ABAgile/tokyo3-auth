package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                uuid.UUID
	Email             string
	PasswordHash      string
	Name              string
	Active            bool
	SCIMExternalID    string
	MFAEnabled        bool
	IsAdmin           bool
	PasswordChangedAt time.Time
	FailedAttempts    int
	LockedUntil       *time.Time
	// MustChangePassword routes the user to /portal/login/change-password
	// after successful CheckPassword, instead of issuing a session. Set by
	// admin reset actions; cleared automatically when the user rotates.
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Client is an OAuth2/OIDC client registration.
//
// BackchannelLogoutURI, when non-nil, opts the client into OIDC Back-Channel
// Logout 1.0: on every event that ends a user's session at the OP (portal
// logout, admin deactivation, SCIM deprovision, password reset) auth POSTs
// a signed logout_token JWT to this URI so the RP can invalidate its local
// session state without waiting for the credential to expire.
//
// The Portal* fields drive /portal/apps. ShowInPortal gates the tile;
// LaunchURL is where the tile's click navigates (typically the RP's
// initiate-login endpoint, e.g. https://vault.example.com/ui/vault/auth/oidc
// — NOT auth's /authorize, since the RP needs to set its own state/nonce
// for the code flow). BrandColor and IconURL are cosmetic. VisibleToAll
// makes the tile show to every authenticated user; when false, visibility
// is scoped via the client_visibility table (SCIM-group join, parallel
// to aws_role_assignments).
type Client struct {
	ID                   uuid.UUID
	ClientID             string
	ClientSecretHash     string
	Name                 string
	RedirectURIs         []string
	Scopes               []string
	Public               bool
	BackchannelLogoutURI *string
	ShowInPortal         bool
	LaunchURL            string
	BrandColor           string
	IconURL              string
	VisibleToAll         bool
	SecretRotatedAt      time.Time
	CreatedAt            time.Time
}

type Grant struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	ClientID      uuid.UUID
	CodeHash      string
	CodeChallenge string // S256 code challenge stored from /authorize; verified at /token
	Nonce         string
	Scopes        []string
	RedirectURI   string
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

// Session backs both portal cookies and OIDC bearer credentials. The two
// expiry columns split what used to be a single field:
//
//   - AccessExpiresAt   — when the bearer access token stops being honoured
//     by bearerAuth. Slid forward on portal hits and on each refresh-token
//     exchange. Matches the `expires_in` value advertised to RPs.
//   - RefreshExpiresAt  — when the refresh token grant stops working. Slid
//     forward on each successful refresh exchange.
//
// An absolute session lifetime is enforced in code as `now - CreatedAt >
// absoluteSessionTTL` rather than via a third column — re-auth at /authorize
// resets it by minting a new row.
type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	ClientID         uuid.UUID
	AccessTokenHash  string
	RefreshTokenHash string
	Scopes           []string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	LastActivityAt   time.Time
	MFAVerified      bool
	// MFAVerifiedAt is when the session last completed an MFA challenge.
	// MFAVerified is "ever?" — kept for the audit/policy code paths that
	// just need a yes/no — and MFAVerifiedAt is "when?", used by step-up
	// gates that demand a freshly proven MFA. Nil for sessions that
	// never saw an MFA prompt (e.g. user has MFA disabled).
	MFAVerifiedAt *time.Time
	CreatedAt     time.Time
}

type TOTPCredential struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	EncryptedSecret []byte
	EncryptedDEK    []byte
	Enabled         bool
	CreatedAt       time.Time
}

type WebAuthnCredential struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	CredentialID []byte
	PublicKey    []byte
	AAGUID       []byte
	SignCount    uint32
	DeviceName   string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

type SCIMGroup struct {
	ID          uuid.UUID
	DisplayName string
	Members     []uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type SigningKey struct {
	ID                  uuid.UUID
	EncryptedPrivateKey []byte
	EncryptedDEK        []byte
	Algorithm           string
	KID                 string
	Active              bool
	CreatedAt           time.Time
}

// AppIntegrationProvider enumerates the supported provider types stored in
// AppIntegration.Provider. Keep in sync with the provisioner builders in
// cmd/authd/main.go.
const (
	AppIntegrationProviderSCIM          = "scim"
	AppIntegrationProviderIAM           = "aws_iam"
	AppIntegrationProviderAWSFederation = "aws_federation"
)

// AppIntegrationAuthMode enumerates the mutually-exclusive ways auth proves
// itself to a downstream SCIM endpoint. AWS IAM ignores this field — credentials
// always come from the AWS SDK's default chain.
const (
	AppIntegrationAuthBearer = "bearer" // RP-issued bearer token; stored encrypted on the row
	AppIntegrationAuthMTLS   = "mtls"   // client cert from AUTH_SCIM_* env vars
)

// AppIntegrationConfig is the non-secret JSON payload persisted alongside an
// AppIntegration. SCIM providers populate BaseURL + TimeoutMS + AuthMode;
// AWS IAM uses GroupMap (SCIM display name → IAM group name). Unknown fields
// for the chosen provider are ignored at runtime.
type AppIntegrationConfig struct {
	BaseURL   string            `json:"base_url,omitempty"`
	TimeoutMS int               `json:"timeout_ms,omitempty"`
	GroupMap  map[string]string `json:"group_map,omitempty"`
	// AuthMode applies to SCIM integrations only: "bearer" or "mtls".
	// Empty defaults to "bearer" for backward compatibility with rows
	// created before this field was added.
	AuthMode string `json:"auth_mode,omitempty"`
}

// AppIntegration is a single outbound provisioning target. Tokens are
// envelope-encrypted via bcrypto.EncryptEnvelope (matching mfa/totp.go); the
// EncryptedToken/EncryptedDEK pair is nil for IAM-style providers that source
// credentials from elsewhere.
type AppIntegration struct {
	ID             uuid.UUID
	Name           string
	Provider       string
	Enabled        bool
	Config         AppIntegrationConfig
	EncryptedToken []byte
	EncryptedDEK   []byte
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AWSAccount is one AWS account that auth federates into. account_id is the
// numeric account ID, alias is the human label, and oidc_provider_arn is what
// auth needs to identify which OIDC provider object to reference in role trust
// policies (matches the principal: arn:aws:iam::<account>:oidc-provider/...
// shape — auth doesn't call AWS to read this, the operator records it once at
// setup time so the federation handler can emit the right session-tag
// confirmation in the audit row).
type AWSAccount struct {
	ID              uuid.UUID
	AccountID       string
	Alias           string
	OIDCProviderARN string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AWSRole is one assumable IAM role. Slug is a URL/CLI-safe stable
// identifier the user supplies in `auth-aws-creds get --role <slug>` and
// `/aws/credentials?role=<slug>`. Audience is server-global (configured
// via AUTH_AWS_AUDIENCE), not per-role — every minted JWT carries the
// same `aud` claim, and per-role authorization happens via
// aws:RequestTag/<key> conditions in trust policies.
//
// RequireStepUpMFA forces a fresh MFA prompt before token mint regardless
// of session age. MaxSessionDurationSec is passed as DurationSeconds on
// AssumeRoleWithWebIdentity and capped by the role's AWS-side
// MaxSessionDuration.
type AWSRole struct {
	ID                    uuid.UUID
	AccountID             uuid.UUID
	RoleARN               string
	Slug                  string
	DisplayName           string
	RequireStepUpMFA      bool
	MaxSessionDurationSec int
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// AWSRoleAssignment links a SCIM group to an AWS role. Membership in the
// group grants the user the right to assume the role via the portal. The
// pair (group_id, role_id) is unique.
type AWSRoleAssignment struct {
	ID        uuid.UUID
	GroupID   uuid.UUID
	RoleID    uuid.UUID
	CreatedAt time.Time
}

// AWSRevokedUser is one (role, user-uuid) entry that the revocation
// provisioner has added to the role's AuthRevokedUsers inline policy.
// RevokedAt is when the entry was added; the reaper trims rows older than
// the role's MaxSessionDurationSec — by then every session denied by the
// statement has expired naturally.
type AWSRevokedUser struct {
	RoleID    uuid.UUID
	SubUUID   string
	RevokedAt time.Time
}
