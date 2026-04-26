package crypto

import "context"

// KeyProvider wraps and unwraps Data Encryption Keys (DEKs).
type KeyProvider interface {
	WrapDEK(ctx context.Context, dek []byte) ([]byte, error)
	UnwrapDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error)
}

// LocalKeyProvider implements KeyProvider with an in-memory AES-256 KEK.
type LocalKeyProvider struct {
	kek []byte
}

func NewLocalKeyProvider(kek []byte) *LocalKeyProvider {
	return &LocalKeyProvider{kek: kek}
}

func (p *LocalKeyProvider) WrapDEK(_ context.Context, dek []byte) ([]byte, error) {
	return seal(p.kek, dek)
}

func (p *LocalKeyProvider) UnwrapDEK(_ context.Context, encryptedDEK []byte) ([]byte, error) {
	return open(p.kek, encryptedDEK)
}
