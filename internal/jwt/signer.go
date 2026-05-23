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
	"sort"
	"time"

	"github.com/abagile/tokyo3-auth/internal/awsclaims"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const rsaKeyBits = 2048

// IDClaims holds standard OIDC ID token claims.
//
// SID is the OIDC Back-Channel Logout 1.0 `sid` claim — a stable identifier
// for the user's session at the OP that's emitted on every ID token minted
// under that session (initial code grant + every refresh). RPs persist `sid`
// on their own session row at first issuance so a later logout_token POST
// can tell them which local session to invalidate. Omitted when the caller
// passes the empty string (e.g. session-less client-credentials flows).
type IDClaims struct {
	gojwt.RegisteredClaims
	Nonce             string   `json:"nonce,omitempty"`
	AuthTime          int64    `json:"auth_time"`
	ACR               string   `json:"acr,omitempty"`
	AMR               []string `json:"amr,omitempty"`
	SID               string   `json:"sid,omitempty"`
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

// FederationClaims is the JWT payload shape minted by MintFederationToken
// and exchanged for STS credentials via sts:AssumeRoleWithWebIdentity. The
// ordinary OIDC claims (email, name, groups, …) are informational only —
// AWS only expands a fixed set (iss, sub, aud, amr) as `<iss>:<claim>`
// trust-policy condition keys. The mechanism that actually makes user
// attributes available throughout the session is the AWSTags claim, which
// STS reads out and exposes as `aws:PrincipalTag/<key>` in every policy
// evaluated for the session. The claim name and inner type are defined in
// internal/awsclaims so the CLI helper can validate token shape without
// pulling in this package's full dependency graph.
type FederationClaims struct {
	gojwt.RegisteredClaims
	Email             string                        `json:"email,omitempty"`
	Name              string                        `json:"name,omitempty"`
	PreferredUsername string                        `json:"preferred_username,omitempty"`
	Groups            []string                      `json:"groups,omitempty"`
	AMR               []string                      `json:"amr,omitempty"`
	AuthTime          int64                         `json:"auth_time,omitempty"`
	AWSTags           *awsclaims.PrincipalTagsValue `json:"https://aws.amazon.com/tags,omitempty"`
}

// MintFederationToken creates a signed RS256 JWT shaped for AWS STS
// `sts:AssumeRoleWithWebIdentity`. The `aud` value is set per role from the
// caller-supplied audience (matching the role trust policy's audience
// condition). Subject is the user UUID — AWS surfaces this as the `sub`
// claim that ends up in CloudTrail webIdFederationData.attributes.sub.
//
// principalTags is the **only** path by which user attributes (sub, email,
// team, etc.) reach AWS's policy-evaluation context as
// `aws:PrincipalTag/<key>`. Resource policies, permission policies, the
// awsfed revocation Deny, ABAC patterns — all consume these tags. The
// claim format is fixed by AWS; we shape it correctly here. Required
// prerequisite: the target role's trust policy must include
// `sts:TagSession` in Action, otherwise AWS rejects the AssumeRole when
// tags are present.
//
// The token lifetime is bounded by `lifetime`, but should be short (≤15min
// is standard) since it's exchanged for STS credentials almost immediately.
// AWS only needs to verify the signature once, at exchange time.
func (s *Signer) MintFederationToken(userID, audience, email, name string, groups []string, amr []string, authTime time.Time, lifetime time.Duration, principalTags map[string]string) (string, error) {
	now := time.Now().UTC()
	if lifetime <= 0 {
		lifetime = 15 * time.Minute
	}
	claims := FederationClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  gojwt.ClaimStrings{audience},
			ExpiresAt: gojwt.NewNumericDate(now.Add(lifetime)),
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Email:             email,
		Name:              name,
		PreferredUsername: email,
		Groups:            groups,
		AMR:               amr,
		AuthTime:          authTime.Unix(),
	}
	if len(principalTags) > 0 {
		// Deterministic key order keeps the JWT byte-stable for any given
		// input — important for cache hashing and test diff readability.
		keys := make([]string, 0, len(principalTags))
		for k := range principalTags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pt := make(map[string][]string, len(principalTags))
		for _, k := range keys {
			pt[k] = []string{principalTags[k]}
		}
		claims.AWSTags = &awsclaims.PrincipalTagsValue{
			PrincipalTags:     pt,
			TransitiveTagKeys: keys,
		}
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}

// MintIDToken creates a signed RS256 JWT ID token. sid (empty string accepted)
// is emitted as the OIDC Back-Channel Logout 1.0 `sid` claim and lets RPs
// correlate a logout_token back to a specific local session row.
func (s *Signer) MintIDToken(userID, clientID, email, name, nonce string, scopes []string, mfaVerified bool, amr []string, authTime time.Time, sid string) (string, error) {
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
		SID:               sid,
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
