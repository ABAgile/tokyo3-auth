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
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type Client struct {
	ID               uuid.UUID
	ClientID         string
	ClientSecretHash string
	Name             string
	RedirectURIs     []string
	Scopes           []string
	Public           bool
	SecretRotatedAt  time.Time
	CreatedAt        time.Time
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
	CreatedAt        time.Time
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
	AppIntegrationProviderSCIM = "scim"
	AppIntegrationProviderIAM  = "aws_iam"
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
