package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &Signer{privateKey: priv, kid: "test-kid", issuer: "https://issuer.example"}
}

// parseUnverified decodes the JWT header and claims without checking the
// signature — useful for asserting on the shape of what we minted.
func parseUnverified(t *testing.T, tok string) (header map[string]any, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 segments: %d", len(parts))
	}
	decode := func(s string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		return m
	}
	return decode(parts[0]), decode(parts[1])
}

func TestSigner_KIDAndPublicKey(t *testing.T) {
	s := newTestSigner(t)
	if s.KID() != "test-kid" {
		t.Errorf("KID() = %q, want test-kid", s.KID())
	}
	pub := s.PublicKey()
	if pub == nil || pub.N == nil {
		t.Fatal("PublicKey returned nil or empty modulus")
	}
	if pub.N.BitLen() < 2040 {
		t.Errorf("public key bit length %d looks wrong for RSA-2048", pub.N.BitLen())
	}
}

func TestMintIDToken_ClaimsAndHeader(t *testing.T) {
	s := newTestSigner(t)
	authTime := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)

	tok, err := s.MintIDToken(
		"user-123", "client-abc", "alice@example.com", "Alice",
		"nonce-xyz", []string{"openid", "email"},
		true, []string{"pwd", "mfa"}, authTime, "sid-456",
	)
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}

	header, claims := parseUnverified(t, tok)

	if header["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", header["alg"])
	}
	if header["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", header["kid"])
	}

	wantStrings := map[string]string{
		"iss":                "https://issuer.example",
		"sub":                "user-123",
		"nonce":              "nonce-xyz",
		"sid":                "sid-456",
		"email":              "alice@example.com",
		"name":               "Alice",
		"preferred_username": "alice@example.com",
		"acr":                "urn:mace:incommon:iap:silver",
	}
	for k, want := range wantStrings {
		if got, _ := claims[k].(string); got != want {
			t.Errorf("claim %q = %q, want %q", k, got, want)
		}
	}

	if at, ok := claims["auth_time"].(float64); !ok || int64(at) != authTime.Unix() {
		t.Errorf("auth_time = %v, want %d", claims["auth_time"], authTime.Unix())
	}

	amr, _ := claims["amr"].([]any)
	if len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Errorf("amr = %v, want [pwd mfa]", amr)
	}

	aud, _ := claims["aud"].([]any)
	if len(aud) != 1 || aud[0] != "client-abc" {
		t.Errorf("aud = %v, want [client-abc]", claims["aud"])
	}
}

func TestMintIDToken_NoMFAOmitsACR(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintIDToken("u", "c", "e@x", "", "", nil, false, nil, time.Now(), "")
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	if _, ok := claims["acr"]; ok {
		t.Errorf("acr should be omitted when mfaVerified=false, got %v", claims["acr"])
	}
	if _, ok := claims["sid"]; ok {
		t.Errorf("sid should be omitted when empty, got %v", claims["sid"])
	}
	if _, ok := claims["nonce"]; ok {
		t.Errorf("nonce should be omitted when empty, got %v", claims["nonce"])
	}
}

func TestMintIDToken_SignatureVerifies(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintIDToken("u", "c", "e@x", "n", "", nil, true, nil, time.Now(), "")
	if err != nil {
		t.Fatalf("MintIDToken: %v", err)
	}
	parsed, err := gojwt.Parse(tok, func(_ *gojwt.Token) (any, error) { return s.PublicKey(), nil })
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Valid {
		t.Error("parsed token reports invalid")
	}
}

func TestMintLogoutToken_Shape(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now().UTC().Truncate(time.Second)
	tok, err := s.MintLogoutToken("rp-aud", "user-7", "sid-7", "jti-7", now)
	if err != nil {
		t.Fatalf("MintLogoutToken: %v", err)
	}

	header, claims := parseUnverified(t, tok)
	if header["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", header["kid"])
	}
	if claims["iss"] != "https://issuer.example" {
		t.Errorf("iss = %v, want https://issuer.example", claims["iss"])
	}
	if claims["sub"] != "user-7" {
		t.Errorf("sub = %v, want user-7", claims["sub"])
	}
	if claims["sid"] != "sid-7" {
		t.Errorf("sid = %v, want sid-7", claims["sid"])
	}
	if claims["jti"] != "jti-7" {
		t.Errorf("jti = %v, want jti-7", claims["jti"])
	}
	if _, ok := claims["nonce"]; ok {
		t.Error("logout_token MUST NOT contain a nonce claim (spec §2.6)")
	}

	events, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim is not an object: %T", claims["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Errorf("missing backchannel-logout event member: %v", events)
	}

	if iat, ok := claims["iat"].(float64); !ok || int64(iat) != now.Unix() {
		t.Errorf("iat = %v, want %d", claims["iat"], now.Unix())
	}
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) != now.Add(2*time.Minute).Unix() {
		t.Errorf("exp = %v, want iat + 2m", claims["exp"])
	}
}

func TestMintLogoutToken_AutoJTI(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.MintLogoutToken("rp", "u", "", "", time.Now())
	if err != nil {
		t.Fatalf("MintLogoutToken: %v", err)
	}
	_, claims := parseUnverified(t, tok)
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Error("empty jti was not auto-populated")
	}
	if _, ok := claims["sid"]; ok {
		t.Error("empty sid should be omitted")
	}
}

func TestRSAPublicToJWK(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := rsaPublicToJWK(&priv.PublicKey, "kid-1")

	if jwk.KTY != "RSA" || jwk.USE != "sig" || jwk.ALG != "RS256" || jwk.KID != "kid-1" {
		t.Errorf("metadata mismatch: %+v", jwk)
	}

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode N: %v", err)
	}
	if new(big.Int).SetBytes(n).Cmp(priv.PublicKey.N) != 0 {
		t.Error("decoded N does not match original modulus")
	}

	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode E: %v", err)
	}
	if int(new(big.Int).SetBytes(e).Int64()) != priv.PublicKey.E {
		t.Errorf("decoded E = %d, want %d", new(big.Int).SetBytes(e).Int64(), priv.PublicKey.E)
	}
}
