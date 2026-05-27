package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
)

// errStore is a SigningKeyStore mock where each method's error is
// programmable per-test. Lets the error branches in LoadOrCreate /
// BuildJWKS get exercised without having to coerce the sqlite driver
// into failing.
type errStore struct {
	getErr    error // returned from GetActiveSigningKey (nil → ErrNotFound)
	createErr error // returned from CreateSigningKey
	listErr   error // returned from ListActiveSigningKeys
	listKeys  []*model.SigningKey
	getKey    *model.SigningKey // if non-nil and getErr nil, returned from Get
}

func (s *errStore) GetActiveSigningKey(_ context.Context) (*model.SigningKey, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.getKey != nil {
		return s.getKey, nil
	}
	return nil, store.ErrNotFound
}
func (s *errStore) ListActiveSigningKeys(_ context.Context) ([]*model.SigningKey, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.listKeys, nil
}
func (s *errStore) CreateSigningKey(_ context.Context, _ *model.SigningKey) error {
	return s.createErr
}
func (s *errStore) DeactivateSigningKey(_ context.Context, _ uuid.UUID) error { return nil }

// TestLoadOrCreate_StoreReadErrorWraps: a non-NotFound failure from
// GetActiveSigningKey must surface with a "load signing key" wrap so
// the operator can distinguish "no key yet" from "DB is down."
func TestLoadOrCreate_StoreReadErrorWraps(t *testing.T) {
	st := &errStore{getErr: errors.New("boom: connection refused")}
	_, kp := newStoreAndKP(t)
	_, err := internaljwt.LoadOrCreate(context.Background(), st, kp, "https://issuer.test", internaljwt.Config{})
	if err == nil {
		t.Fatal("LoadOrCreate: expected store error, got nil")
	}
	if !strings.Contains(err.Error(), "load signing key") {
		t.Errorf("error %q missing 'load signing key' wrap", err.Error())
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %q missing underlying message", err.Error())
	}
}

// TestLoadOrCreate_StoreWriteErrorWraps: GetActiveSigningKey returns
// ErrNotFound (genuinely empty store), so LoadOrCreate falls through
// to generateAndStore — which then fails on CreateSigningKey. Verify
// the wrap surfaces the originating call site.
func TestLoadOrCreate_StoreWriteErrorWraps(t *testing.T) {
	st := &errStore{createErr: errors.New("constraint violation")}
	_, kp := newStoreAndKP(t)
	_, err := internaljwt.LoadOrCreate(context.Background(), st, kp, "https://issuer.test", internaljwt.Config{})
	if err == nil {
		t.Fatal("LoadOrCreate: expected create error, got nil")
	}
	if !strings.Contains(err.Error(), "store signing key") {
		t.Errorf("error %q missing 'store signing key' wrap", err.Error())
	}
}

// TestLoadOrCreate_CorruptEnvelopeWraps: stored row has a bogus
// EncryptedPrivateKey, so DecryptEnvelope fails — that surfaces as
// "decrypt signing key" through the wrap.
func TestLoadOrCreate_CorruptEnvelopeWraps(t *testing.T) {
	_, kp := newStoreAndKP(t)
	st := &errStore{getKey: &model.SigningKey{
		ID:                  uuid.New(),
		EncryptedPrivateKey: []byte("not a valid envelope"),
		EncryptedDEK:        []byte("also bogus"),
		KID:                 "broken-kid",
		Algorithm:           "RS256",
		Active:              true,
	}}
	_, err := internaljwt.LoadOrCreate(context.Background(), st, kp, "https://issuer.test", internaljwt.Config{})
	if err == nil {
		t.Fatal("LoadOrCreate: expected decrypt error, got nil")
	}
	if !strings.Contains(err.Error(), "decrypt signing key") {
		t.Errorf("error %q missing 'decrypt signing key' wrap", err.Error())
	}
}

// TestLoadOrCreate_NonRSAKeyRejected: a valid envelope wrapping an
// ECDSA key (not RSA) must surface as the "is not RSA" error rather
// than silently mint an unsignable Signer.
func TestLoadOrCreate_NonRSAKeyRejected(t *testing.T) {
	_, kp := newStoreAndKP(t)
	// Generate an ECDSA P-256 key, marshal as PKCS#8, envelope-encrypt.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	encVal, encDEK, err := bcrypto.EncryptEnvelope(context.Background(), kp, der)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	st := &errStore{getKey: &model.SigningKey{
		ID:                  uuid.New(),
		EncryptedPrivateKey: encVal,
		EncryptedDEK:        encDEK,
		KID:                 "ec-kid",
		Algorithm:           "RS256",
		Active:              true,
	}}
	_, err = internaljwt.LoadOrCreate(context.Background(), st, kp, "https://issuer.test", internaljwt.Config{})
	if err == nil {
		t.Fatal("LoadOrCreate: expected non-RSA rejection, got nil")
	}
	if !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error %q does not name 'not RSA'", err.Error())
	}
}

// TestBuildJWKS_StoreListErrorPropagates: ListActiveSigningKeys
// failure must surface verbatim — BuildJWKS is the JWKS-endpoint
// helper, and a 500 with a clear cause is better than an empty key
// set (which would silently break every RP's signature verification).
func TestBuildJWKS_StoreListErrorPropagates(t *testing.T) {
	_, kp := newStoreAndKP(t)
	st := &errStore{listErr: errors.New("list query failed")}
	_, err := internaljwt.BuildJWKS(context.Background(), st, kp)
	if err == nil {
		t.Fatal("BuildJWKS: expected list error, got nil")
	}
	if !strings.Contains(err.Error(), "list query failed") {
		t.Errorf("error %q does not include underlying", err.Error())
	}
}

// TestBuildJWKS_PerKeyDecryptErrorWraps: one of the keys has a
// corrupt envelope. BuildJWKS aborts on the first bad key (so the
// JWKS doc never goes out with missing keys) and wraps the kid for
// debuggability.
func TestBuildJWKS_PerKeyDecryptErrorWraps(t *testing.T) {
	_, kp := newStoreAndKP(t)
	st := &errStore{listKeys: []*model.SigningKey{
		{
			ID:                  uuid.New(),
			EncryptedPrivateKey: []byte("garbage"),
			EncryptedDEK:        []byte("garbage"),
			KID:                 "kid-corrupt",
			Algorithm:           "RS256",
			Active:              true,
		},
	}}
	_, err := internaljwt.BuildJWKS(context.Background(), st, kp)
	if err == nil {
		t.Fatal("BuildJWKS: expected decrypt error, got nil")
	}
	if !strings.Contains(err.Error(), "kid-corrupt") {
		t.Errorf("error %q missing kid for debugging", err.Error())
	}
	if !strings.Contains(err.Error(), "decrypt key") {
		t.Errorf("error %q missing 'decrypt key' wrap", err.Error())
	}
}

// TestBuildJWKS_NonRSAKeyRejected: a stored key that decrypts to an
// ECDSA private aborts JWKS construction — RS256 is the only signing
// algorithm supported, and silently dropping the bad key would let
// the JWKS doc go out incomplete.
func TestBuildJWKS_NonRSAKeyRejected(t *testing.T) {
	_, kp := newStoreAndKP(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	encVal, encDEK, _ := bcrypto.EncryptEnvelope(context.Background(), kp, der)
	st := &errStore{listKeys: []*model.SigningKey{
		{
			ID:                  uuid.New(),
			EncryptedPrivateKey: encVal,
			EncryptedDEK:        encDEK,
			KID:                 "kid-ec",
			Algorithm:           "RS256",
			Active:              true,
		},
	}}
	_, err := internaljwt.BuildJWKS(context.Background(), st, kp)
	if err == nil {
		t.Fatal("BuildJWKS: expected non-RSA rejection, got nil")
	}
	if !strings.Contains(err.Error(), "kid-ec") || !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error %q missing kid or 'not RSA'", err.Error())
	}
}
