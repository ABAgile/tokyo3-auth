package api

import (
	"net/http"
	"testing"
)

func TestHandleDiscovery(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	doc := decodeJSON[map[string]any](t, resp)

	if doc["issuer"] != "https://issuer.test" {
		t.Errorf("issuer = %v, want https://issuer.test", doc["issuer"])
	}
	wantEndpoints := map[string]string{
		"authorization_endpoint": "https://issuer.test/authorize",
		"token_endpoint":         "https://issuer.test/token",
		"userinfo_endpoint":      "https://issuer.test/userinfo",
		"jwks_uri":               "https://issuer.test/.well-known/jwks.json",
		"revocation_endpoint":    "https://issuer.test/revoke",
	}
	for k, want := range wantEndpoints {
		if doc[k] != want {
			t.Errorf("%s = %v, want %s", k, doc[k], want)
		}
	}

	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Errorf("alg list = %v, want [RS256]", algs)
	}
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods = %v, want [S256]", methods)
	}
}

func TestHandleJWKS(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/.well-known/jwks.json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	jwks := decodeJSON[map[string]any](t, resp)

	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("keys length = %d, want 1", len(keys))
	}
	k, _ := keys[0].(map[string]any)
	if k["kty"] != "RSA" || k["use"] != "sig" || k["alg"] != "RS256" {
		t.Errorf("key metadata: kty=%v use=%v alg=%v", k["kty"], k["use"], k["alg"])
	}
	if k["kid"] != r.signer.KID() {
		t.Errorf("kid = %v, want %s", k["kid"], r.signer.KID())
	}
	if _, ok := k["n"].(string); !ok || k["n"] == "" {
		t.Error("missing or empty n")
	}
	if _, ok := k["e"].(string); !ok || k["e"] == "" {
		t.Error("missing or empty e")
	}
}

func TestHandleHealth(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/health")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health status = %d, want 200", resp.StatusCode)
	}
}

func TestRootRedirect(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/")
	if resp.StatusCode != http.StatusFound {
		t.Errorf("/ status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/portal" {
		t.Errorf("Location = %q, want /portal", loc)
	}

	// Non-root path → 404 (handler explicitly NotFound's non-root paths).
	resp = r.get(t, "/no-such-route-anywhere")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing route status = %d, want 404", resp.StatusCode)
	}
}
