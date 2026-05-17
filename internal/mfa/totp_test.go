package mfa_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store/sqlite"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func newMFAEnv(t *testing.T) (*sqlite.DB, bcrypto.KeyProvider, *model.User) {
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
	kp := bcrypto.NewLocalKeyProvider(mk)

	u, err := db.CreateUser(context.Background(), "mfa-user@example.com", "h", "MFA User")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return db, kp, u
}

// extractSecret pulls the base32 secret out of the otpauth:// URI returned by
// EnrollTOTP so the test can generate a valid code with the same library.
func extractSecret(t *testing.T, rawURI string) string {
	t.Helper()
	u, err := url.Parse(rawURI)
	if err != nil {
		t.Fatalf("parse otp uri: %v", err)
	}
	return u.Query().Get("secret")
}

func TestEnrollTOTP_ShapesResponse(t *testing.T) {
	db, kp, u := newMFAEnv(t)
	ctx := context.Background()

	resp, err := mfa.EnrollTOTP(ctx, db, kp, u)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	if resp.CredentialID == uuid.Nil {
		t.Error("CredentialID is nil UUID")
	}
	if resp.Secret == "" {
		t.Error("Secret is empty")
	}
	if !strings.HasPrefix(resp.OTPURI, "otpauth://") {
		t.Errorf("OTPURI prefix: %q", resp.OTPURI)
	}
	if !strings.Contains(resp.OTPURI, "mfa-user@example.com") {
		t.Errorf("OTPURI should embed account name: %q", resp.OTPURI)
	}

	// Credential row exists and is disabled until ConfirmTOTP succeeds.
	cred, err := db.GetTOTPByUserID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
	}
	if cred.Enabled {
		t.Error("freshly enrolled credential must start disabled")
	}
	if len(cred.EncryptedSecret) == 0 || len(cred.EncryptedDEK) == 0 {
		t.Error("encrypted blobs not populated")
	}
}

func TestEnrollTOTP_OverwritesPriorUnenrolled(t *testing.T) {
	db, kp, u := newMFAEnv(t)
	ctx := context.Background()

	r1, err := mfa.EnrollTOTP(ctx, db, kp, u)
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	r2, err := mfa.EnrollTOTP(ctx, db, kp, u)
	if err != nil {
		t.Fatalf("second enroll: %v", err)
	}
	if r1.CredentialID == r2.CredentialID {
		t.Error("second enroll should mint a new credential row")
	}
	if r1.Secret == r2.Secret {
		t.Error("second enroll should mint a fresh secret")
	}

	// Only the second credential survives.
	cred, _ := db.GetTOTPByUserID(ctx, u.ID)
	if cred.ID != r2.CredentialID {
		t.Errorf("stored credential ID: want %s, got %s", r2.CredentialID, cred.ID)
	}
}

func TestConfirmTOTP_Success(t *testing.T) {
	db, kp, u := newMFAEnv(t)
	ctx := context.Background()

	resp, err := mfa.EnrollTOTP(ctx, db, kp, u)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	secret := extractSecret(t, resp.OTPURI)

	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	if err := mfa.ConfirmTOTP(ctx, db, kp, u.ID, code); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}

	cred, _ := db.GetTOTPByUserID(ctx, u.ID)
	if !cred.Enabled {
		t.Error("after confirm: expected Enabled=true")
	}
}

func TestConfirmTOTP_RejectsBadCode(t *testing.T) {
	db, kp, u := newMFAEnv(t)
	ctx := context.Background()

	if _, err := mfa.EnrollTOTP(ctx, db, kp, u); err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	err := mfa.ConfirmTOTP(ctx, db, kp, u.ID, "000000")
	if err == nil {
		t.Error("ConfirmTOTP must reject a wrong code")
	}
	cred, _ := db.GetTOTPByUserID(ctx, u.ID)
	if cred.Enabled {
		t.Error("rejection must not flip Enabled")
	}
}

func TestVerifyTOTP_RequiresEnabled(t *testing.T) {
	db, kp, u := newMFAEnv(t)
	ctx := context.Background()

	resp, _ := mfa.EnrollTOTP(ctx, db, kp, u)
	secret := extractSecret(t, resp.OTPURI)
	code, _ := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})

	// Not yet confirmed — VerifyTOTP must refuse even a correct code.
	if err := mfa.VerifyTOTP(ctx, db, kp, u.ID, code); err == nil {
		t.Error("VerifyTOTP must reject when credential is disabled")
	}

	// Enable directly via the store, then a valid code should pass.
	cred, _ := db.GetTOTPByUserID(ctx, u.ID)
	if err := db.EnableTOTP(ctx, cred.ID); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	// Regenerate the code in case we crossed a 30s boundary.
	code, _ = totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err := mfa.VerifyTOTP(ctx, db, kp, u.ID, code); err != nil {
		t.Errorf("VerifyTOTP after enable: %v", err)
	}

	if err := mfa.VerifyTOTP(ctx, db, kp, u.ID, "000000"); err == nil {
		t.Error("VerifyTOTP must reject wrong code")
	}
}

func TestConfirmTOTP_NoCredential(t *testing.T) {
	db, kp, _ := newMFAEnv(t)
	if err := mfa.ConfirmTOTP(context.Background(), db, kp, uuid.New(), "123456"); err == nil {
		t.Error("ConfirmTOTP for unknown user must error")
	}
}

func TestVerifyTOTP_NoCredential(t *testing.T) {
	db, kp, _ := newMFAEnv(t)
	if err := mfa.VerifyTOTP(context.Background(), db, kp, uuid.New(), "123456"); err == nil {
		t.Error("VerifyTOTP for unknown user must error")
	}
}
