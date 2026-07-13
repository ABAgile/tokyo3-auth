package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyFromEnvFile(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	t.Setenv("AUTHD_MASTER_KEY", "file:"+path)

	got, err := masterKeyFromEnv()
	if err != nil {
		t.Fatalf("masterKeyFromEnv: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("len(master key) = %d, want 32", len(got))
	}
}
