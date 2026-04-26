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

type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	ClientID         uuid.UUID
	AccessTokenHash  string
	RefreshTokenHash string
	Scopes           []string
	ExpiresAt        time.Time
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

type SCIMToken struct {
	ID          uuid.UUID
	TokenHash   string
	Description string
	CreatedAt   time.Time
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

type AuditLog struct {
	ID        uuid.UUID
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	Action    string
	IP        string
	UserAgent string
	Metadata  map[string]any
	CreatedAt time.Time
}
