package mfa_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store/sqlite"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
)

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost"

	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagBE = 0x08 // backup eligible (synced passkey)
	flagBS = 0x10 // backup state
	flagAT = 0x40 // attested credential data included
)

var b64 = base64.RawURLEncoding

// fakeAuthenticator is a minimal software authenticator: one ES256 key
// pair, "none" attestation, and caller-chosen authenticator flags so the
// tests can impersonate both synced passkeys (BE=1) and hardware keys
// (BE=0).
type fakeAuthenticator struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
}

func newFakeAuthenticator(t *testing.T) *fakeAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	credID := make([]byte, 16)
	_, _ = rand.Read(credID)
	return &fakeAuthenticator{t: t, key: key, credID: credID}
}

func (a *fakeAuthenticator) coseKey() []byte {
	a.t.Helper()
	// Uncompressed SEC 1 point: 0x04 || X (32 bytes) || Y (32 bytes).
	pt, err := a.key.PublicKey.Bytes()
	if err != nil {
		a.t.Fatalf("public key bytes: %v", err)
	}
	x, y := pt[1:33], pt[33:]
	k, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		KeyType:   int64(webauthncose.EllipticKey),
		Algorithm: int64(webauthncose.AlgES256),
		Curve:     int64(webauthncose.P256),
		XCoord:    x,
		YCoord:    y,
	})
	if err != nil {
		a.t.Fatalf("marshal COSE key: %v", err)
	}
	return k
}

func (a *fakeAuthenticator) authData(flags byte, attested bool) []byte {
	rpHash := sha256.Sum256([]byte(testRPID))
	var buf bytes.Buffer
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, a.count)
	if attested {
		buf.Write(make([]byte, 16)) // AAGUID
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(a.credID)))
		buf.Write(a.credID)
		buf.Write(a.coseKey())
	}
	return buf.Bytes()
}

func clientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": testOrigin})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	return b
}

func challengeOf(t *testing.T, optionsJSON []byte) string {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		t.Fatalf("unmarshal options: %v", err)
	}
	return opts.PublicKey.Challenge
}

// attestation builds the JSON body navigator.credentials.create() would
// produce (after the portal's encodeCredential helper).
func (a *fakeAuthenticator) attestation(challenge string, flags byte) []byte {
	a.t.Helper()
	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(flags|flagAT, true),
	})
	if err != nil {
		a.t.Fatalf("marshal attestationObject: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.credID),
		"rawId": b64.EncodeToString(a.credID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(clientData(a.t, "webauthn.create", challenge)),
			"attestationObject": b64.EncodeToString(attObj),
		},
	})
	return body
}

// assertion builds the JSON body navigator.credentials.get() would produce.
func (a *fakeAuthenticator) assertion(challenge string, flags byte, userHandle []byte) []byte {
	a.t.Helper()
	a.count++
	ad := a.authData(flags, false)
	cd := clientData(a.t, "webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatalf("sign: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.credID),
		"rawId": b64.EncodeToString(a.credID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(userHandle),
		},
	})
	return body
}

func newWAEnv(t *testing.T) (*sqlite.DB, *mfa.WAHandler, *model.User) {
	t.Helper()
	db, _, u := newMFAEnv(t)
	h, err := mfa.NewWAHandler(testRPID, "tokyo3-auth test", []string{testOrigin}, db)
	if err != nil {
		t.Fatalf("NewWAHandler: %v", err)
	}
	return db, h, u
}

func register(t *testing.T, h *mfa.WAHandler, u *model.User, a *fakeAuthenticator, flags byte) *model.WebAuthnCredential {
	t.Helper()
	ctx := context.Background()
	opts, sid, err := h.BeginRegistration(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader(a.attestation(challengeOf(t, opts), flags)))
	cred, err := h.FinishRegistration(ctx, u, sid, req, "test key")
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return cred
}

func login(t *testing.T, h *mfa.WAHandler, u *model.User, a *fakeAuthenticator, flags byte) error {
	t.Helper()
	ctx := context.Background()
	opts, sid, err := h.BeginLogin(ctx, u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader(a.assertion(challengeOf(t, opts), flags, u.ID[:])))
	_, err = h.FinishLogin(ctx, u, sid, req)
	return err
}

func storedCred(t *testing.T, db *sqlite.DB, credID []byte) *model.WebAuthnCredential {
	t.Helper()
	c, err := db.GetWebAuthnCredentialByCredentialID(context.Background(), credID)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByCredentialID: %v", err)
	}
	return c
}

// A synced passkey (iCloud Keychain, Google Password Manager, …) reports
// BE=1 on every ceremony. Registration must persist that so later
// assertions pass go-webauthn's BE consistency check.
// BS may change between assertions and is written back each time; BE
// stays fixed. BE and BS start out different so a mixed-up mapping fails.
func TestWebAuthn_SyncedPasskeyRoundTrip(t *testing.T) {
	db, h, u := newWAEnv(t)
	a := newFakeAuthenticator(t)

	assertFlags := func(step string, wantBS bool) {
		t.Helper()
		c := storedCred(t, db, a.credID)
		if c.BackupEligible == nil || !*c.BackupEligible || c.BackupState != wantBS {
			t.Fatalf("%s: BE=%v BS=%v, want BE=true BS=%v", step, c.BackupEligible, c.BackupState, wantBS)
		}
	}

	register(t, h, u, a, flagUP|flagUV|flagBE)
	assertFlags("after register", false)

	if err := login(t, h, u, a, flagUP|flagUV|flagBE|flagBS); err != nil {
		t.Fatalf("FinishLogin with synced passkey: %v", err)
	}
	assertFlags("after BS=1 login", true)

	if err := login(t, h, u, a, flagUP|flagUV|flagBE); err != nil {
		t.Fatalf("FinishLogin with BS cleared: %v", err)
	}
	assertFlags("after BS=0 login", false)
}

// A hardware key (BE=0) keeps working, and a later assertion claiming
// BE=1 for the same credential is rejected.
func TestWebAuthn_HardwareKeyRejectsBEFlip(t *testing.T) {
	db, h, u := newWAEnv(t)
	a := newFakeAuthenticator(t)

	register(t, h, u, a, flagUP)
	c := storedCred(t, db, a.credID)
	if c.BackupEligible == nil || *c.BackupEligible {
		t.Fatalf("stored BE=%v, want false", c.BackupEligible)
	}

	if err := login(t, h, u, a, flagUP); err != nil {
		t.Fatalf("FinishLogin with hardware key: %v", err)
	}
	if err := login(t, h, u, a, flagUP|flagBE); err == nil {
		t.Fatal("FinishLogin accepted a BE flip from false to true")
	}
}

// Credentials enrolled before BE was persisted have BackupEligible=nil.
// The first successful assertion adopts the authenticator's BE value and
// records it; from then on the consistency check is enforced.
func TestWebAuthn_LegacyCredentialBackfillsBE(t *testing.T) {
	db, h, u := newWAEnv(t)
	a := newFakeAuthenticator(t)

	legacy := &model.WebAuthnCredential{
		ID:           uuid.New(),
		UserID:       u.ID,
		CredentialID: a.credID,
		PublicKey:    a.coseKey(),
		AAGUID:       make([]byte, 16),
		DeviceName:   "legacy passkey",
	}
	if err := db.CreateWebAuthnCredential(context.Background(), legacy); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}
	if c := storedCred(t, db, a.credID); c.BackupEligible != nil {
		t.Fatalf("legacy credential BE=%v, want nil", *c.BackupEligible)
	}

	if err := login(t, h, u, a, flagUP|flagBE|flagBS); err != nil {
		t.Fatalf("FinishLogin with legacy synced passkey: %v", err)
	}
	c := storedCred(t, db, a.credID)
	if c.BackupEligible == nil || !*c.BackupEligible || !c.BackupState {
		t.Fatalf("after backfill: BE=%v BS=%v, want BE=true BS=true", c.BackupEligible, c.BackupState)
	}

	if err := login(t, h, u, a, flagUP); err == nil {
		t.Fatal("FinishLogin accepted a BE flip after backfill")
	}
}

var errWriteFailed = errors.New("write failed")

type failingUseStore struct{ *sqlite.DB }

func (failingUseStore) UpdateWebAuthnCredentialUse(context.Context, uuid.UUID, uint32, bool, bool, time.Time) error {
	return errWriteFailed
}

// If BE can't be recorded for a legacy credential, the login must fail;
// otherwise BE stays NULL and the next assertion skips the check again.
func TestWebAuthn_LegacyBackfillWriteFailureFailsLogin(t *testing.T) {
	db, _, u := newWAEnv(t)
	h, err := mfa.NewWAHandler(testRPID, "tokyo3-auth test", []string{testOrigin}, failingUseStore{db})
	if err != nil {
		t.Fatalf("NewWAHandler: %v", err)
	}
	a := newFakeAuthenticator(t)
	if err := db.CreateWebAuthnCredential(context.Background(), &model.WebAuthnCredential{
		ID: uuid.New(), UserID: u.ID, CredentialID: a.credID, PublicKey: a.coseKey(), AAGUID: make([]byte, 16),
	}); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}

	if err := login(t, h, u, a, flagUP|flagBE); !errors.Is(err, errWriteFailed) {
		t.Fatalf("FinishLogin: want errWriteFailed, got %v", err)
	}
	if c := storedCred(t, db, a.credID); c.BackupEligible != nil {
		t.Fatalf("BE=%v after failed write, want nil", *c.BackupEligible)
	}
}
