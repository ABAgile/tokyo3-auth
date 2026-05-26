package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{",,", nil},
		{"alice", []string{"alice"}},
		{"alice,bob", []string{"alice", "bob"}},
		{"  alice ,  bob  ,deployer", []string{"alice", "bob", "deployer"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, c := range cases {
		got := splitCSV(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestDeriveKeyID_PrefersEmailOverSubject(t *testing.T) {
	mkToken := func(claims map[string]any) string {
		b, _ := json.Marshal(claims)
		return "header." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	}
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"email-wins", map[string]any{"sub": "uuid-1", "email": "alice@example.com"}, "alice@example.com"},
		{"sub-fallback", map[string]any{"sub": "uuid-1"}, "uuid-1"},
		{"empty-claims", map[string]any{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := deriveKeyID(mkToken(c.claims))
			if got != c.want {
				t.Errorf("deriveKeyID = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDeriveKeyID_MalformedTokenReturnsEmpty(t *testing.T) {
	for _, in := range []string{"", "not-a-jwt", "only.two"} {
		if got := deriveKeyID(in); got != "" {
			t.Errorf("deriveKeyID(%q) = %q, want empty", in, got)
		}
	}
}

// TestEnsureKeypair_GeneratesAndReuses verifies the on-disk shape and
// that a second call with the same path re-uses the existing key (no
// regeneration, deterministic public key).
func TestEnsureKeypair_GeneratesAndReuses(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "id_ed25519")

	pub1, err := ensureKeypair(keyPath)
	if err != nil {
		t.Fatalf("first ensureKeypair: %v", err)
	}
	if !strings.HasPrefix(pub1, "ssh-ed25519 ") {
		t.Errorf("pubkey should start with 'ssh-ed25519 ', got %q", pub1)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("private key mode = %v, want 0o600", mode)
	}
	pubInfo, err := os.Stat(keyPath + ".pub")
	if err != nil {
		t.Fatalf("stat pubkey: %v", err)
	}
	if mode := pubInfo.Mode().Perm(); mode != 0o644 {
		t.Errorf("pubkey mode = %v, want 0o644", mode)
	}

	// Verify the saved private key is a valid OpenSSH key the same
	// runtime can parse — guards against accidental format drift.
	raw, _ := os.ReadFile(keyPath)
	if _, err := ssh.ParsePrivateKey(raw); err != nil {
		t.Errorf("re-parse private key: %v", err)
	}

	// Second call should not regenerate — same public key bytes.
	pub2, err := ensureKeypair(keyPath)
	if err != nil {
		t.Fatalf("second ensureKeypair: %v", err)
	}
	if pub1 != pub2 {
		t.Errorf("ensureKeypair regenerated; pub mismatch:\n  first: %s\n  second: %s", pub1, pub2)
	}
}

// TestSignUserCert_HappyPath spins up a fake certd and checks the
// request shape (bearer header, JSON body) and the response decoding.
func TestSignUserCert_HappyPath(t *testing.T) {
	var (
		gotAuth string
		gotReq  signUserRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssh/sign-user" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		when := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(signResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA",
			Serial:      42,
			KeyID:       gotReq.KeyID,
			Principals:  gotReq.Principals,
			ValidAfter:  when,
			ValidBefore: when.Add(time.Hour),
		})
	}))
	defer srv.Close()

	req := signUserRequest{
		PublicKey:  "ssh-ed25519 AAAA",
		KeyID:      "alice@example.com",
		Principals: []string{"alice"},
		Groups:     []string{"eng"},
		TTLSeconds: 3600,
	}
	got, err := signUserCert(srv.URL, "id-tok", req)
	if err != nil {
		t.Fatalf("signUserCert: %v", err)
	}
	if gotAuth != "Bearer id-tok" {
		t.Errorf("Authorization = %q, want 'Bearer id-tok'", gotAuth)
	}
	if gotReq.KeyID != "alice@example.com" || len(gotReq.Principals) != 1 || gotReq.TTLSeconds != 3600 {
		t.Errorf("request shape mismatch: %+v", gotReq)
	}
	if got.Serial != 42 || got.Certificate == "" {
		t.Errorf("response decoding: %+v", got)
	}
}

// TestSignUserCert_PropagatesServerError surfaces non-2xx with the
// status code and body so users see why certd refused.
func TestSignUserCert_PropagatesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"policy denied for groups [eng]"}`))
	}))
	defer srv.Close()

	_, err := signUserCert(srv.URL, "tok", signUserRequest{KeyID: "k", PublicKey: "p", Principals: []string{"x"}})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "policy denied") {
		t.Errorf("err = %v, want 403 + body", err)
	}
}

// TestResolveOutPaths_DerivesCertFromKey checks the default
// "<key>-cert.pub" convention so users get the OpenSSH-standard
// layout out of the box.
func TestResolveOutPaths_DerivesCertFromKey(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "my-key")
	k, c, err := resolveOutPaths(keyPath, "")
	if err != nil {
		t.Fatalf("resolveOutPaths: %v", err)
	}
	if k != keyPath {
		t.Errorf("key path = %q, want %q", k, keyPath)
	}
	if c != keyPath+"-cert.pub" {
		t.Errorf("cert path = %q, want %q", c, keyPath+"-cert.pub")
	}
}

// TestResolveOutPaths_ExplicitOverride lets operators put the cert
// somewhere other than next to the key.
func TestResolveOutPaths_ExplicitOverride(t *testing.T) {
	k, c, err := resolveOutPaths("/tmp/k", "/elsewhere/c.pub")
	if err != nil {
		t.Fatalf("resolveOutPaths: %v", err)
	}
	if k != "/tmp/k" || c != "/elsewhere/c.pub" {
		t.Errorf("paths = (%q, %q)", k, c)
	}
}

func TestBuildSSHConfigSnippet_EmitsExpectedDirectives(t *testing.T) {
	snippet := buildSSHConfigSnippet("/path/key", "/path/cert.pub", "ssh-proxyd.internal:22", []string{"alice", "bob"})
	for _, want := range []string{
		"Host *.internal",
		"User alice",
		"IdentityFile /path/key",
		"CertificateFile /path/cert.pub",
		"ProxyJump ssh-proxyd.internal:22",
		"IdentitiesOnly yes",
	} {
		if !strings.Contains(snippet, want) {
			t.Errorf("snippet missing %q\n%s", want, snippet)
		}
	}
}

func TestWriteCert_AppendsNewlineAndSetsMode(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "id-cert.pub")
	if err := writeCert(path, "ssh-ed25519-cert-v01@openssh.com AAAA"); err != nil {
		t.Fatalf("writeCert: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(b), "\n") {
		t.Errorf("cert file should end with newline; got %q", b)
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("cert mode = %v, want 0o644", mode)
	}
}
