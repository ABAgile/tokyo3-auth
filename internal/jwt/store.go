// Package jwt is the server-side wrapper around
// github.com/abagile/tokyo3-base/auth/jwt: it adds the store-backed
// key-management bits the IdP needs but a generic JWT signer
// shouldn't know about.
//
// Specifically, LoadOrCreate reads (or generates + persists) an
// envelope-encrypted RSA private key from store.SigningKeyStore, and
// BuildJWKS walks every active key in the store to publish the
// /.well-known/jwks.json document.
//
// All the signing primitives — Signer, MintIDToken, MintFederation
// Token, MintLogoutToken, IDClaims, JWK, JWKS, etc. — are re-exported
// from base/auth/jwt via type aliases so existing call sites keep
// importing "internal/jwt" without churn.
package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	bjwt "github.com/abagile/tokyo3-base/auth/jwt"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
)

// Re-exports — call sites that imported the old internal/jwt keep
// working without changes. Adding a new symbol to base/auth/jwt
// requires one new line here if downstream callers want to reach it.
type (
	Signer           = bjwt.Signer
	Config           = bjwt.Config
	IDClaims         = bjwt.IDClaims
	FederationClaims = bjwt.FederationClaims
	LogoutClaims     = bjwt.LogoutClaims
	JWK              = bjwt.JWK
	JWKS             = bjwt.JWKS
)

const rsaKeyBits = 2048

// LoadOrCreate loads the active signing key from the store, decrypts
// it, and returns a Signer. If no active key exists, it generates a
// new RSA-2048 key, persists it under envelope encryption, and
// returns the Signer for it.
//
// cfg controls the lifted policy parameters (ID-token TTL,
// federation-token default TTL, MFA ACR string); pass bjwt.Config{}
// to accept the package defaults.
func LoadOrCreate(ctx context.Context, st store.SigningKeyStore, kp bcrypto.KeyProvider, issuer string, cfg Config) (*Signer, error) {
	k, err := st.GetActiveSigningKey(ctx)
	if err == nil {
		return decryptKey(ctx, k, kp, issuer, cfg)
	}
	if err != store.ErrNotFound {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	return generateAndStore(ctx, st, kp, issuer, cfg)
}

func decryptKey(ctx context.Context, k *model.SigningKey, kp bcrypto.KeyProvider, issuer string, cfg Config) (*Signer, error) {
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
	return bjwt.New(rsaKey, k.KID, issuer, cfg), nil
}

func generateAndStore(ctx context.Context, st store.SigningKeyStore, kp bcrypto.KeyProvider, issuer string, cfg Config) (*Signer, error) {
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
	return bjwt.New(priv, kid, issuer, cfg), nil
}

// BuildJWKS loads all active signing keys from the store, decrypts
// each, and returns the JWKS document for /.well-known/jwks.json.
func BuildJWKS(ctx context.Context, st store.SigningKeyStore, kp bcrypto.KeyProvider) (*JWKS, error) {
	keys, err := st.ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	set := &JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		der, err := bcrypto.DecryptEnvelope(ctx, kp, k.EncryptedDEK, k.EncryptedPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt key %s: %w", k.KID, err)
		}
		priv, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", k.KID, err)
		}
		rsaKey, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key %s is not RSA", k.KID)
		}
		set.Keys = append(set.Keys, bjwt.PublicKeyToJWK(&rsaKey.PublicKey, k.KID))
	}
	return set, nil
}
