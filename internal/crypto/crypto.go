// Package crypto provides AES-256-GCM encryption using a DEK+KEK model.
//
// Each protected value gets its own random Data Encryption Key (DEK).
// The DEK is wrapped by the master Key Encryption Key (KEK).
// Rotating the KEK only requires re-wrapping DEKs, not re-encrypting values.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// ParseKEK decodes a 64-hex-character string into a 32-byte key.
func ParseKEK(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid master key encoding: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	return b, nil
}

// GenerateKEK returns a random 32-byte key encoded as a 64-char hex string.
func GenerateKEK() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// seal encrypts plaintext with key using AES-256-GCM. Output: nonce || ciphertext+tag.
func seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// open decrypts ciphertext (nonce || ciphertext+tag) with key.
func open(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// EncryptSecret encrypts plaintext under a fresh random DEK, then wraps the DEK via kp.
// Returns (encryptedValue, encryptedDEK, error).
func EncryptSecret(ctx context.Context, kp KeyProvider, plaintext []byte) (encryptedValue, encryptedDEK []byte, err error) {
	dek := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("generate dek: %w", err)
	}
	encryptedValue, err = seal(dek, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("seal value: %w", err)
	}
	encryptedDEK, err = kp.WrapDEK(ctx, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	return encryptedValue, encryptedDEK, nil
}

// DecryptSecret unwraps the DEK via kp, then decrypts the value.
func DecryptSecret(ctx context.Context, kp KeyProvider, encryptedDEK, encryptedValue []byte) ([]byte, error) {
	dek, err := kp.UnwrapDEK(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	plaintext, err := open(dek, encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}
	return plaintext, nil
}

// SealBytes encrypts plaintext directly with key using AES-256-GCM.
// Use for short-lived values (cookies, session tokens) where DEK wrapping is unnecessary.
func SealBytes(key, plaintext []byte) ([]byte, error) { return seal(key, plaintext) }

// OpenBytes decrypts ciphertext produced by SealBytes.
func OpenBytes(key, ciphertext []byte) ([]byte, error) { return open(key, ciphertext) }
