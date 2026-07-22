package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCA(t *testing.T, commonName string) (string, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), commonName+".pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cert
}

func poolTrusts(pool *x509.CertPool, cert *x509.Certificate) bool {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

func TestBackchannelTLSFromEnvUsesWorkloadCAFallback(t *testing.T) {
	workloadCA, workloadCert := writeTestCA(t, "workload")
	t.Setenv("AUTHD_BACKCHANNEL_CA", "")
	t.Setenv("AUTHD_WORKLOAD_CA", workloadCA)

	cfg, err := backchannelTLSFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected backchannel root CA pool")
	}
	if !poolTrusts(cfg.RootCAs, workloadCert) {
		t.Error("backchannel root pool does not contain workload CA")
	}
	if len(cfg.Certificates) != 0 || cfg.GetClientCertificate != nil {
		t.Error("backchannel TLS must not carry a client certificate")
	}
}

func TestBackchannelTLSFromEnvPrefersExplicitCA(t *testing.T) {
	backchannelCA, backchannelCert := writeTestCA(t, "backchannel")
	workloadCA, workloadCert := writeTestCA(t, "workload")
	t.Setenv("AUTHD_BACKCHANNEL_CA", backchannelCA)
	t.Setenv("AUTHD_WORKLOAD_CA", workloadCA)

	cfg, err := backchannelTLSFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected backchannel root CA pool")
	}
	if !poolTrusts(cfg.RootCAs, backchannelCert) {
		t.Error("backchannel root pool does not contain explicit CA")
	}
	if poolTrusts(cfg.RootCAs, workloadCert) {
		t.Error("backchannel root pool unexpectedly contains fallback workload CA")
	}
}

func TestBackchannelTLSFromEnvUsesSystemRootsWhenUnset(t *testing.T) {
	t.Setenv("AUTHD_BACKCHANNEL_CA", "")
	t.Setenv("AUTHD_WORKLOAD_CA", "")

	cfg, err := backchannelTLSFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for net/http system roots, got %+v", cfg)
	}
}
