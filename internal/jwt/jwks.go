package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
)

// JWK is a JSON Web Key (RFC 7517) for an RSA public key.
type JWK struct {
	KTY string `json:"kty"`
	USE string `json:"use"`
	ALG string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the JSON Web Key Set returned at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS loads all active signing keys and returns the key set.
func BuildJWKS(ctx context.Context, st store.SigningKeyStore, kp bcrypto.KeyProvider) (*JWKS, error) {
	keys, err := st.ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	set := &JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		jwk, err := keyToJWK(ctx, k, kp)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

func keyToJWK(ctx context.Context, k *model.SigningKey, kp bcrypto.KeyProvider) (JWK, error) {
	der, err := bcrypto.DecryptEnvelope(ctx, kp, k.EncryptedDEK, k.EncryptedPrivateKey)
	if err != nil {
		return JWK{}, fmt.Errorf("decrypt key %s: %w", k.KID, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return JWK{}, fmt.Errorf("parse key %s: %w", k.KID, err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return JWK{}, fmt.Errorf("key %s is not RSA", k.KID)
	}
	return rsaPublicToJWK(&rsaKey.PublicKey, k.KID), nil
}

func rsaPublicToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		KTY: "RSA",
		USE: "sig",
		ALG: "RS256",
		KID: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
