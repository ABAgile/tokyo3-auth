// Package jwt handles RS256 key management and ID token signing.
package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const rsaKeyBits = 2048

// IDClaims holds standard OIDC ID token claims.
type IDClaims struct {
	gojwt.RegisteredClaims
	Nonce             string   `json:"nonce,omitempty"`
	AuthTime          int64    `json:"auth_time"`
	ACR               string   `json:"acr,omitempty"`
	AMR               []string `json:"amr,omitempty"`
	Email             string   `json:"email,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
}

// Signer holds an active RS256 private key and mints ID tokens.
type Signer struct {
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string
}

// LoadOrCreate loads the active signing key from the store, decrypts it,
// and returns a Signer. If no active key exists, it generates a new one.
func LoadOrCreate(ctx context.Context, st store.SigningKeyStore, kp bcrypto.KeyProvider, issuer string) (*Signer, error) {
	k, err := st.GetActiveSigningKey(ctx)
	if err == nil {
		return decryptKey(ctx, k, kp, issuer)
	}
	if err != store.ErrNotFound {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	return generateAndStore(ctx, st, kp, issuer)
}

func decryptKey(ctx context.Context, k *model.SigningKey, kp bcrypto.KeyProvider, issuer string) (*Signer, error) {
	der, err := bcrypto.DecryptEnvelope(ctx, kp, k.EncryptedDEK, k.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt signing key: %w", err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not RSA")
	}
	return &Signer{privateKey: rsaKey, kid: k.KID, issuer: issuer}, nil
}

func generateAndStore(ctx context.Context, st store.SigningKeyStore, kp bcrypto.KeyProvider, issuer string) (*Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	encVal, encDEK, err := bcrypto.EncryptEnvelope(ctx, kp, der)
	if err != nil {
		return nil, fmt.Errorf("encrypt signing key: %w", err)
	}

	// kid = first 16 hex chars of SHA-256 over the public key DER
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(sum[:8])

	k := &model.SigningKey{
		ID:                  uuid.New(),
		EncryptedPrivateKey: encVal,
		EncryptedDEK:        encDEK,
		Algorithm:           "RS256",
		KID:                 kid,
		Active:              true,
	}
	if err := st.CreateSigningKey(ctx, k); err != nil {
		return nil, fmt.Errorf("store signing key: %w", err)
	}
	return &Signer{privateKey: priv, kid: kid, issuer: issuer}, nil
}

// MintIDToken creates a signed RS256 JWT ID token.
func (s *Signer) MintIDToken(userID, clientID, email, name, nonce string, scopes []string, mfaVerified bool, amr []string, authTime time.Time) (string, error) {
	now := time.Now().UTC()
	acr := ""
	if mfaVerified {
		acr = "urn:mace:incommon:iap:silver"
	}
	claims := IDClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  gojwt.ClaimStrings{clientID},
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  gojwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Nonce:             nonce,
		AuthTime:          authTime.Unix(),
		ACR:               acr,
		AMR:               amr,
		Email:             email,
		Name:              name,
		PreferredUsername: email,
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}

// KID returns the active key identifier.
func (s *Signer) KID() string { return s.kid }

// PublicKey returns the active RSA public key.
func (s *Signer) PublicKey() *rsa.PublicKey { return &s.privateKey.PublicKey }
