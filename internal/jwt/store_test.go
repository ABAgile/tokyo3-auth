package jwt_test

import (
	"context"
	"encoding/base64"
	"math/big"
	"testing"

	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/store/sqlite"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
)

// Backs the store-driven Load/Build paths with an in-memory sqlite store
// and a LocalKeyProvider so we exercise the full encrypt-decrypt envelope.
func newStoreAndKP(t *testing.T) (*sqlite.DB, bcrypto.KeyProvider) {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk, err := bcrypto.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return db, bcrypto.NewLocalKeyProvider(mk)
}

func TestLoadOrCreate_Generates(t *testing.T) {
	db, kp := newStoreAndKP(t)
	ctx := context.Background()

	signer, err := internaljwt.LoadOrCreate(ctx, db, kp, "https://issuer.test")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if signer.KID() == "" {
		t.Error("KID should be non-empty after generate")
	}
	if signer.PublicKey() == nil {
		t.Error("PublicKey should be non-nil")
	}

	// A row landed in signing_keys.
	k, err := db.GetActiveSigningKey(ctx)
	if err != nil {
		t.Fatalf("GetActiveSigningKey: %v", err)
	}
	if k.KID != signer.KID() {
		t.Errorf("stored KID = %q, want %q", k.KID, signer.KID())
	}
	if k.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want RS256", k.Algorithm)
	}
	if !k.Active {
		t.Error("stored key should be Active")
	}
}

func TestLoadOrCreate_ReusesExisting(t *testing.T) {
	db, kp := newStoreAndKP(t)
	ctx := context.Background()

	first, err := internaljwt.LoadOrCreate(ctx, db, kp, "https://issuer.test")
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	second, err := internaljwt.LoadOrCreate(ctx, db, kp, "https://issuer.test")
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if first.KID() != second.KID() {
		t.Errorf("kid changed across LoadOrCreate calls: %q vs %q", first.KID(), second.KID())
	}
	// Modulus must match — same private key.
	if first.PublicKey().N.Cmp(second.PublicKey().N) != 0 {
		t.Error("reload returned a different key")
	}
}

func TestBuildJWKS_ReflectsStore(t *testing.T) {
	db, kp := newStoreAndKP(t)
	ctx := context.Background()

	// Empty store → empty key set.
	jwks, err := internaljwt.BuildJWKS(ctx, db, kp)
	if err != nil {
		t.Fatalf("BuildJWKS empty: %v", err)
	}
	if len(jwks.Keys) != 0 {
		t.Errorf("empty store should yield 0 keys, got %d", len(jwks.Keys))
	}

	signer, err := internaljwt.LoadOrCreate(ctx, db, kp, "https://issuer.test")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	jwks, err = internaljwt.BuildJWKS(ctx, db, kp)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("after generate: want 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.KID != signer.KID() {
		t.Errorf("jwk.kid = %q, want %q", k.KID, signer.KID())
	}
	if k.KTY != "RSA" || k.USE != "sig" || k.ALG != "RS256" {
		t.Errorf("jwk metadata: %+v", k)
	}

	// Reconstruct the modulus from the published JWK and confirm it matches
	// the signer's private key. This exercises the full encrypt → store →
	// load → decrypt → unmarshal → publish pipeline.
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	if new(big.Int).SetBytes(nb).Cmp(signer.PublicKey().N) != 0 {
		t.Error("published modulus does not match signer's modulus")
	}
}
