package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// limitedServer re-mounts the rig's routes with tiny budgets so tests can
// exhaust them quickly. Limiters are bound at Routes() time, so they must be
// swapped before the new test server is created.
func limitedServer(t *testing.T, r *testRig, authPerMin, tokenPerMin int) *httptest.Server {
	t.Helper()
	proxies := mergeProxies(nil)
	r.server.authLimiter = newLimiter(authPerMin, defaultAuthRatePerMin, proxies, r.server.log)
	r.server.tokenLimiter = newLimiter(tokenPerMin, defaultTokenRatePerMin, proxies, r.server.log)
	srv := httptest.NewServer(r.server.Routes())
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRateLimit_LoginBruteForceThrottled(t *testing.T) {
	r := newTestRig(t)
	srv := limitedServer(t, r, 3, 100)
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})
	body := "client_id=" + c.ClientID + "&redirect_uri=https://app.example/cb&scope=openid&email=x@example.com&password=wrong"

	for i := range 3 {
		if got := post(t, srv.URL+"/authorize", body, nil).StatusCode; got == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled within burst", i+1)
		}
	}
	resp := post(t, srv.URL+"/authorize", body, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After")
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Browsers get plain text.
	resp = post(t, srv.URL+"/authorize", body, map[string]string{"Accept": "text/html"})
	if resp.StatusCode != http.StatusTooManyRequests || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("html client: status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// Other routes and the separate token budget are unaffected.
	if got := post(t, srv.URL+"/token", "grant_type=bogus", nil).StatusCode; got == http.StatusTooManyRequests {
		t.Error("/token shares the interactive budget")
	}
	if resp, err := http.Get(srv.URL + "/health"); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("/health affected by limiter: %v", err)
	}
}

func TestRateLimit_TokenEndpointThrottled(t *testing.T) {
	r := newTestRig(t)
	srv := limitedServer(t, r, 100, 2)
	for range 2 {
		post(t, srv.URL+"/token", "grant_type=bogus", nil)
	}
	if got := post(t, srv.URL+"/token", "grant_type=bogus", nil).StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got)
	}
}

// Behind a trusted proxy the key is the forwarded client, not the proxy, so
// one abusive client cannot lock out everyone sharing the edge.
func TestRateLimit_KeysOnForwardedClientBehindTrustedProxy(t *testing.T) {
	r := newTestRig(t)
	srv := limitedServer(t, r, 1, 100)
	a := map[string]string{"X-Forwarded-For": "203.0.113.1"}
	b := map[string]string{"X-Forwarded-For": "203.0.113.2"}

	post(t, srv.URL+"/register", "", a)
	if got := post(t, srv.URL+"/register", "", a).StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("client A second request = %d, want 429", got)
	}
	if got := post(t, srv.URL+"/register", "", b).StatusCode; got == http.StatusTooManyRequests {
		t.Fatal("client B throttled by client A's usage")
	}
}

// The remaining bearer endpoints that guess secrets or call AWS are limited.
func TestRateLimit_BearerEndpoints(t *testing.T) {
	cases := []struct {
		name, path string
		auth       bool // true: interactive budget, false: machine budget
	}{
		{"totp confirm", "/mfa/totp/confirm", true},
		{"totp enroll", "/mfa/totp/enroll", true},
		{"aws credentials", "/aws/credentials", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRig(t)
			a, tk := 100, 100
			if tc.auth {
				a = 2
			} else {
				tk = 2
			}
			srv := limitedServer(t, r, a, tk)
			for range 2 {
				post(t, srv.URL+tc.path, "{}", map[string]string{"Authorization": "Bearer nope"})
			}
			if got := post(t, srv.URL+tc.path, "{}", map[string]string{"Authorization": "Bearer nope"}).StatusCode; got != http.StatusTooManyRequests {
				t.Errorf("status = %d, want 429 after the budget", got)
			}
		})
	}
}
