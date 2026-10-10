package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	btls "github.com/abagile/tokyo3-base/tls"
)

// An IP-literal SCIM URL sends no SNI, so the shared hot-reloading config
// fails closed. scimTLSForURL must hand such an integration a config that
// verifies the server's IP SAN, and leave hostname URLs on the shared config.
func TestSCIMTLSForURLIPLiteral(t *testing.T) {
	cert, err := btls.SelfSignedCert() // SANs include 127.0.0.1
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The self-signed server cert doubles as the trusted CA and client cert.
	t.Setenv("AUTHD_SCIM_MTLS_CERT", certPath)
	t.Setenv("AUTHD_SCIM_MTLS_KEY", keyPath)
	t.Setenv("AUTHD_SCIM_MTLS_CA", certPath)

	shared, err := scimTLSFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	get := func(url string, cfg *tls.Config) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 2 * time.Second}
		resp, err := c.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	if err := get(srv.URL, shared); err == nil {
		t.Fatal("shared config verified an IP-literal dial; premise of the test no longer holds")
	}
	cfg, err := scimTLSForURL(shared, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == shared {
		t.Fatal("IP-literal URL reused the shared config")
	}
	if err := get(srv.URL, cfg); err != nil {
		t.Errorf("IP-literal dial with per-integration config: %v", err)
	}

	hostURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if got, err := scimTLSForURL(shared, hostURL); err != nil || got != shared {
		t.Errorf("hostname URL: got (%p, %v), want shared config", got, err)
	}
	if err := get(hostURL, shared); err != nil {
		t.Errorf("hostname dial with shared config: %v", err)
	}
}
