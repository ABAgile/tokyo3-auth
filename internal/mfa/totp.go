// Package mfa implements TOTP and WebAuthn multi-factor authentication.
package mfa

import (
	"context"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-auth/internal/crypto"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpIssuer = "tokyo3-auth"

// TOTPEnrollResponse is returned when a user begins TOTP enrollment.
type TOTPEnrollResponse struct {
	CredentialID uuid.UUID `json:"credential_id"`
	Secret       string    `json:"secret"`  // base32, shown once for manual entry
	OTPURI       string    `json:"otp_uri"` // otpauth:// URI for QR codes
}

// EnrollTOTP generates a new TOTP secret for the user and stores it (disabled until confirmed).
func EnrollTOTP(ctx context.Context, st store.MFAStore, kp crypto.KeyProvider, user *model.User) (*TOTPEnrollResponse, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: user.Email,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	encSecret, encDEK, err := crypto.EncryptSecret(ctx, kp, []byte(key.Secret()))
	if err != nil {
		return nil, fmt.Errorf("encrypt totp secret: %w", err)
	}

	// Delete any existing (unenrolled) TOTP before creating a new one.
	_ = st.DeleteTOTP(ctx, user.ID)

	cred := &model.TOTPCredential{
		ID:              uuid.New(),
		UserID:          user.ID,
		EncryptedSecret: encSecret,
		EncryptedDEK:    encDEK,
		Enabled:         false,
	}
	if err := st.CreateTOTPCredential(ctx, cred); err != nil {
		return nil, fmt.Errorf("store totp credential: %w", err)
	}
	return &TOTPEnrollResponse{
		CredentialID: cred.ID,
		Secret:       key.Secret(),
		OTPURI:       key.URL(),
	}, nil
}

// ConfirmTOTP verifies the first code after enrollment and enables the credential.
func ConfirmTOTP(ctx context.Context, st store.MFAStore, kp crypto.KeyProvider, userID uuid.UUID, code string) error {
	cred, err := st.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return err
	}
	secret, err := decryptTOTPSecret(ctx, kp, cred)
	if err != nil {
		return err
	}
	if !validateTOTP(secret, code) {
		return fmt.Errorf("invalid TOTP code")
	}
	return st.EnableTOTP(ctx, cred.ID)
}

// VerifyTOTP checks a TOTP code for an already-enrolled user.
func VerifyTOTP(ctx context.Context, st store.MFAStore, kp crypto.KeyProvider, userID uuid.UUID, code string) error {
	cred, err := st.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if !cred.Enabled {
		return fmt.Errorf("TOTP not enabled")
	}
	secret, err := decryptTOTPSecret(ctx, kp, cred)
	if err != nil {
		return err
	}
	if !validateTOTP(secret, code) {
		return fmt.Errorf("invalid TOTP code")
	}
	return nil
}

func decryptTOTPSecret(ctx context.Context, kp crypto.KeyProvider, cred *model.TOTPCredential) (string, error) {
	plain, err := crypto.DecryptSecret(ctx, kp, cred.EncryptedDEK, cred.EncryptedSecret)
	if err != nil {
		return "", fmt.Errorf("decrypt totp secret: %w", err)
	}
	return string(plain), nil
}

func validateTOTP(secret, code string) bool {
	ok, _ := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // allow ±1 window for clock skew
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return ok
}
