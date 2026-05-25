package store

import (
	"context"
	"errors"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store interface {
	UserStore
	ClientStore
	GrantStore
	SessionStore
	MFAStore
	GroupStore
	SigningKeyStore
	ExternalIDStore
	IntegrationStore
	AWSFederationStore
}

type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash, name string) (*model.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	ListUsers(ctx context.Context) ([]*model.User, error)
	CountUsers(ctx context.Context) (int, error)
	UpdateUser(ctx context.Context, id uuid.UUID, name string, active bool) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	UpdateUserMFAEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	UpdateUserFailedAttempts(ctx context.Context, id uuid.UUID, count int, lockedUntil *time.Time) error
	SetUserActive(ctx context.Context, id uuid.UUID, active bool) error
	SetUserSCIMExternalID(ctx context.Context, id uuid.UUID, externalID string) error
	SetUserAdmin(ctx context.Context, id uuid.UUID, isAdmin bool) error
	// SetUserMustChangePassword is set TRUE by admin reset actions to
	// force the user through /portal/login/change-password on next
	// login. UpdateUserPassword clears it automatically on success;
	// callers who want to be explicit can also call it with FALSE.
	SetUserMustChangePassword(ctx context.Context, id uuid.UUID, flag bool) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

type ClientStore interface {
	CreateClient(ctx context.Context, clientID, clientSecretHash, name string, redirectURIs, scopes []string, public bool, backchannelLogoutURI *string) (*model.Client, error)
	GetClientByID(ctx context.Context, id uuid.UUID) (*model.Client, error)
	GetClientByClientID(ctx context.Context, clientID string) (*model.Client, error)
	ListClients(ctx context.Context) ([]*model.Client, error)
	UpdateClient(ctx context.Context, id uuid.UUID, name string, redirectURIs, scopes []string, public bool, backchannelLogoutURI *string) error
	UpdateClientSecret(ctx context.Context, id uuid.UUID, secretHash string) error
	DeleteClient(ctx context.Context, id uuid.UUID) error

	// UpdateClientPortalConfig persists the /portal/apps fields
	// independently of the core client metadata so admin handlers can
	// edit visibility without touching redirect URIs / scopes / etc.
	UpdateClientPortalConfig(ctx context.Context, id uuid.UUID, showInPortal bool, launchURL, brandColor, iconURL string, visibleToAll bool) error
	// ReplaceClientVisibility sets the per-group visibility list for
	// a client to exactly groupIDs (a la ReplaceGroupMembers).
	ReplaceClientVisibility(ctx context.Context, clientID uuid.UUID, groupIDs []uuid.UUID) error
	// ListClientVisibility returns the group IDs that can see this
	// client's portal tile. Empty when visible_to_all is set OR when
	// no groups are linked.
	ListClientVisibility(ctx context.Context, clientID uuid.UUID) ([]uuid.UUID, error)
	// ListPortalClientsForUser returns clients with show_in_portal=true
	// and (visible_to_all=true OR userID is a member of any linked
	// group). Sentinel clients (portal sentinel, etc.) are filtered out
	// at the application layer if needed by setting show_in_portal=false.
	ListPortalClientsForUser(ctx context.Context, userID uuid.UUID) ([]*model.Client, error)
}

type GrantStore interface {
	CreateGrant(ctx context.Context, g *model.Grant) error
	GetGrantByCodeHash(ctx context.Context, codeHash string) (*model.Grant, error)
	MarkGrantUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpiredGrants(ctx context.Context) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, s *model.Session) error
	GetSessionByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error)
	GetSessionByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error)
	UpdateSessionActivity(ctx context.Context, id uuid.UUID, lastActivity time.Time) error
	// ExtendSessionExpiry slides expires_at to newExpiry. Used by the portal
	// session middleware to enforce a sliding idle timeout — every
	// authenticated portal hit pushes the deadline forward.
	ExtendSessionExpiry(ctx context.Context, id uuid.UUID, newExpiry time.Time) error
	// RotateRefreshToken issues a new refresh token hash and resets both
	// expiry windows in one atomic UPDATE. Called by the refresh_token grant
	// at the OIDC /token endpoint — clients hand us an old refresh, we mint a
	// new access + refresh pair and slide the row. The caller is responsible
	// for capping both expiries at the absolute session lifetime.
	RotateRefreshToken(ctx context.Context, id uuid.UUID, newRefreshHash string, newAccessExpiry, newRefreshExpiry time.Time) error
	// MarkSessionMFA bumps mfa_verified_at (and mfa_verified) on an
	// existing session row. Used by the step-up MFA flow so that a
	// freshly proven challenge resets the freshness window without
	// minting a new session.
	MarkSessionMFA(ctx context.Context, id uuid.UUID, when time.Time) error
	DeleteSession(ctx context.Context, id uuid.UUID) error
	DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID) error
	// ListSessionClientIDsByUser returns the distinct client_ids that
	// currently hold at least one live session for userID. Used by the
	// back-channel logout broadcaster to determine which RPs to notify
	// when a user's sessions are being killed. The portal sentinel client
	// is included — callers filter it out.
	ListSessionClientIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	DeleteExpiredSessions(ctx context.Context) error
}

type MFAStore interface {
	CreateTOTPCredential(ctx context.Context, c *model.TOTPCredential) error
	GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*model.TOTPCredential, error)
	EnableTOTP(ctx context.Context, id uuid.UUID) error
	DeleteTOTP(ctx context.Context, userID uuid.UUID) error

	CreateWebAuthnCredential(ctx context.Context, c *model.WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*model.WebAuthnCredential, error)
	GetWebAuthnCredentialByCredentialID(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error)
	UpdateWebAuthnSignCount(ctx context.Context, id uuid.UUID, signCount uint32, lastUsed time.Time) error
	DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID, userID uuid.UUID) error

	CreateWebAuthnSession(ctx context.Context, userID uuid.UUID, data []byte, purpose string) (uuid.UUID, error)
	GetWebAuthnSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, purpose string) ([]byte, error)
	DeleteWebAuthnSession(ctx context.Context, id uuid.UUID) error
}

type GroupStore interface {
	CreateGroup(ctx context.Context, displayName string) (*model.SCIMGroup, error)
	GetGroupByID(ctx context.Context, id uuid.UUID) (*model.SCIMGroup, error)
	ListGroups(ctx context.Context) ([]*model.SCIMGroup, error)
	UpdateGroup(ctx context.Context, id uuid.UUID, displayName string) error
	ReplaceGroupMembers(ctx context.Context, groupID uuid.UUID, memberIDs []uuid.UUID) error
	AddGroupMember(ctx context.Context, groupID, userID uuid.UUID) error
	RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error
	DeleteGroup(ctx context.Context, id uuid.UUID) error
}

type SigningKeyStore interface {
	CreateSigningKey(ctx context.Context, k *model.SigningKey) error
	GetActiveSigningKey(ctx context.Context) (*model.SigningKey, error)
	ListActiveSigningKeys(ctx context.Context) ([]*model.SigningKey, error)
	DeactivateSigningKey(ctx context.Context, id uuid.UUID) error
}

// ExternalIDStore caches each user's identity in downstream provisioning targets
// (vault, AWS IAM, etc.). It is a best-effort cache: outbound provisioners write
// the downstream UUID on first create and read it back to avoid a filter lookup
// per update. Callers MUST be prepared for ErrNotFound on Get and treat it as a
// cache miss (re-resolve via the downstream's filter, then SetExternalID).
type ExternalIDStore interface {
	GetExternalID(ctx context.Context, provider string, userID uuid.UUID) (string, error)
	SetExternalID(ctx context.Context, provider string, userID uuid.UUID, externalID string) error
	DeleteExternalID(ctx context.Context, provider string, userID uuid.UUID) error
}

// IntegrationStore manages outbound provisioner configurations (Vault SCIM,
// AWS IAM, etc.). Tokens are encrypted/decrypted in the handler layer via
// bcrypto.EncryptEnvelope; the store is intentionally oblivious to the KEK.
type IntegrationStore interface {
	CreateIntegration(ctx context.Context, i *model.AppIntegration) error
	GetIntegration(ctx context.Context, id uuid.UUID) (*model.AppIntegration, error)
	GetIntegrationByName(ctx context.Context, name string) (*model.AppIntegration, error)
	ListIntegrations(ctx context.Context) ([]*model.AppIntegration, error)
	ListEnabledIntegrations(ctx context.Context) ([]*model.AppIntegration, error)
	UpdateIntegration(ctx context.Context, i *model.AppIntegration) error
	DeleteIntegration(ctx context.Context, id uuid.UUID) error
}

// AWSFederationStore manages the AWS OIDC federation catalog: accounts, roles,
// SCIM-group→role assignments, and the revocation bookkeeping table that
// pairs with the awsfed provisioner. None of these rows carry secrets — the
// federation flow itself is credential-less at auth's side.
type AWSFederationStore interface {
	CreateAWSAccount(ctx context.Context, a *model.AWSAccount) error
	GetAWSAccount(ctx context.Context, id uuid.UUID) (*model.AWSAccount, error)
	ListAWSAccounts(ctx context.Context) ([]*model.AWSAccount, error)
	UpdateAWSAccount(ctx context.Context, a *model.AWSAccount) error
	DeleteAWSAccount(ctx context.Context, id uuid.UUID) error

	CreateAWSRole(ctx context.Context, r *model.AWSRole) error
	GetAWSRole(ctx context.Context, id uuid.UUID) (*model.AWSRole, error)
	ListAWSRoles(ctx context.Context) ([]*model.AWSRole, error)
	UpdateAWSRole(ctx context.Context, r *model.AWSRole) error
	DeleteAWSRole(ctx context.Context, id uuid.UUID) error

	CreateAWSRoleAssignment(ctx context.Context, a *model.AWSRoleAssignment) error
	ListAWSRoleAssignments(ctx context.Context) ([]*model.AWSRoleAssignment, error)
	// ListAWSRolesForUser returns the distinct AWSRoles assignable to userID,
	// derived from their SCIM group memberships. Used by the portal tile page.
	ListAWSRolesForUser(ctx context.Context, userID uuid.UUID) ([]*model.AWSRole, error)
	DeleteAWSRoleAssignment(ctx context.Context, id uuid.UUID) error

	AddAWSRevokedUser(ctx context.Context, roleID uuid.UUID, subUUID string) error
	ListAWSRevokedUsers(ctx context.Context, roleID uuid.UUID) ([]*model.AWSRevokedUser, error)
	// ListAWSRevokedUsersOlderThan returns rows whose revoked_at is before
	// cutoff. The reaper passes (now - role.MaxSessionDurationSec) — by then
	// every session protected by the Deny statement has expired naturally.
	ListAWSRevokedUsersOlderThan(ctx context.Context, cutoff time.Time) ([]*model.AWSRevokedUser, error)
	DeleteAWSRevokedUser(ctx context.Context, roleID uuid.UUID, subUUID string) error
}
