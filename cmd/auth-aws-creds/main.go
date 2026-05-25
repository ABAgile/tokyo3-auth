// Command auth-aws-creds is a credential helper that bridges auth's OIDC
// federation to the AWS CLI / SDKs via the credential_process protocol.
//
//	$ go install github.com/abagile/tokyo3-auth/cmd/auth-aws-creds@latest
//
// One-time interactive login (opens browser, completes OIDC code flow on
// a loopback redirect, caches the refresh token):
//
//	$ auth-aws-creds login --issuer https://id.example.com --client-id tokyo3-cli
//
// Configure each AWS profile to invoke this helper as its credential
// source (slug matches what an admin configured under
// /portal/admin/aws/roles):
//
//	[profile platform-prod]
//	credential_process = auth-aws-creds get --role platform-prod
//	region = us-east-1
//
// When boto3 / AWS CLI invokes the helper, it silently refreshes the
// access token if needed, calls auth's /aws/credentials endpoint, caches
// the resulting STS session credentials, and emits them as
// credential_process JSON on stdout. No browser, no interaction —
// designed to be fast enough for the AWS SDK's invocation timeout.
//
// Dependencies are intentionally minimal: only the Go standard library
// and internal/awsclaims (constants for token validation). No AWS SDK,
// no database, no OAuth library — the helper makes plain HTTP calls
// against auth's standard OIDC endpoints.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// stsExpirySkew is the safety margin we apply when deciding whether
	// cached STS credentials are still good to use. Returning creds within
	// 60s of their actual expiry would race the SDK's own request timing.
	stsExpirySkew = 60 * time.Second
	// accessTokenSkew similarly buffers the OAuth access token check.
	accessTokenSkew = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "login":
		os.Exit(cmdLogin(args))
	case "logout":
		os.Exit(cmdLogout(args))
	case "get":
		os.Exit(cmdGet(args))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "auth-aws-creds: unknown command %q\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `auth-aws-creds — credential helper for auth's OIDC federation

Usage:
  auth-aws-creds login   --issuer URL --client-id ID [--port N]
  auth-aws-creds login   --issuer URL --client-id ID --device
  auth-aws-creds get     --role SLUG
  auth-aws-creds logout

login modes:
  default  Opens a browser on this host, loopback redirect captures the
           authorization code (OAuth 2.0 + PKCE). Good for desktops.
  --device RFC 8628 device authorization grant: prints a verification
           URL + short code, you complete the browser part on any device
           (phone, another laptop), the CLI polls in the background.
           Required when this host has no browser. The OAuth client must
           have allow_device_grant=true at /portal/admin/clients.

The --role flag identifies which AWS role to assume by its admin-set slug
(see /portal/admin/aws/roles). For backward compatibility with 0.x
configurations the deprecated alias --audience is also accepted.

Files:
  ~/.config/auth-aws-creds/config.json     issuer + client_id (non-secret)
  ~/.config/auth-aws-creds/tokens.json     OAuth refresh + access tokens (0600)
  ~/.config/auth-aws-creds/sts/<slug>.json cached STS credentials per role (0600)`)
}

// ── login ────────────────────────────────────────────────────────────────────

func cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	issuer := fs.String("issuer", "", "auth issuer URL (e.g. https://id.example.com)")
	clientID := fs.String("client-id", "", "OAuth2 public client id (PKCE)")
	port := fs.Int("port", 0, "loopback redirect port (0 = pick a free one)")
	device := fs.Bool("device", false, "use RFC 8628 device authorization grant instead of opening a browser locally")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *issuer == "" || *clientID == "" {
		fmt.Fprintln(os.Stderr, "--issuer and --client-id are required for login")
		return 2
	}
	if err := saveConfig(config{Issuer: *issuer, ClientID: *clientID}); err != nil {
		fmt.Fprintf(os.Stderr, "save config: %v\n", err)
		return 1
	}
	var (
		tokens *tokenSet
		err    error
	)
	if *device {
		tokens, err = runDeviceFlow(*issuer, *clientID)
	} else {
		tokens, err = runCodeFlow(*issuer, *clientID, *port)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "login: %v\n", err)
		return 1
	}
	if err := saveTokens(tokens); err != nil {
		fmt.Fprintf(os.Stderr, "save tokens: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "auth-aws-creds: login successful")
	return 0
}

// runCodeFlow performs an OAuth2 authorization-code flow with PKCE,
// using a loopback http.Server to capture the redirect. The /token
// endpoint returns access + refresh; we hand both back to the caller.
//
// Standard public-client pattern: no client secret, S256 PKCE binds
// the code to this specific browser session so the redirect URL alone
// can't be replayed to mint someone else's tokens.
func runCodeFlow(issuer, clientID string, port int) (*tokenSet, error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randomURLSafe(24)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("loopback listen: %w", err)
	}
	defer listener.Close()
	redirectURI := fmt.Sprintf("http://%s/callback", listener.Addr().String())

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			errCh <- fmt.Errorf("auth server returned error: %s (%s)", e, q.Get("error_description"))
			http.Error(w, "Auth error: "+e, http.StatusBadRequest)
			return
		}
		if q.Get("state") != state {
			errCh <- errors.New("state mismatch (possible CSRF)")
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			errCh <- errors.New("authorization server returned no code")
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "<html><body><h2>Login successful</h2><p>You may close this tab.</p></body></html>")
		codeCh <- code
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	authURL := buildAuthorizeURL(issuer, clientID, redirectURI, state, challenge)
	fmt.Fprintln(os.Stderr, "Opening browser for OIDC login. If it doesn't open, paste this URL:")
	fmt.Fprintln(os.Stderr, "  ", authURL)
	_ = openBrowser(authURL)

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, errors.New("login timed out after 5 minutes")
	}
	return exchangeCode(issuer, clientID, redirectURI, code, verifier)
}

func buildAuthorizeURL(issuer, clientID, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email profile offline_access")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return strings.TrimRight(issuer, "/") + "/authorize?" + q.Encode()
}

func exchangeCode(issuer, clientID, redirectURI, code, verifier string) (*tokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return postToken(issuer, form)
}

// refreshTokens swaps a refresh_token for a fresh access (+ refresh)
// pair. Auth rotates refresh tokens on each use, so the response
// includes a NEW refresh_token; the caller must persist it.
func refreshTokens(issuer, clientID, refreshToken string) (*tokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	return postToken(issuer, form)
}

// postToken POSTs to /token and decodes the standard OAuth2 response.
// expires_in is normalised into an absolute Expiration timestamp here
// so callers don't have to track relative-vs-absolute time semantics.
func postToken(issuer string, form url.Values) (*tokenSet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(issuer, "/")+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, errors.New("token endpoint returned no access_token")
	}
	ts := &tokenSet{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		Expiration:   time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second),
	}
	return ts, nil
}

// runDeviceFlow performs the RFC 8628 device authorization grant.
// Prints the verification URL + user code to stderr, polls /token at
// the server-supplied interval (with slow_down backoff) until the
// approver completes the browser side.
//
// Capped at the server-supplied expires_in (typically 15 min); if the
// user takes longer, the grant expires server-side and we exit with
// the expired_token error so the user knows to restart.
func runDeviceFlow(issuer, clientID string) (*tokenSet, error) {
	authzURL := strings.TrimRight(issuer, "/") + "/device_authorization"
	tokenURL := strings.TrimRight(issuer, "/") + "/token"

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "openid email profile offline_access")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authzURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device_authorization: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device_authorization %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var authz struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, fmt.Errorf("decode device_authorization: %w", err)
	}
	if authz.Interval <= 0 {
		authz.Interval = 5
	}
	if authz.ExpiresIn <= 0 {
		authz.ExpiresIn = 900
	}

	fmt.Fprintln(os.Stderr, "Visit this URL to approve sign-in:")
	if authz.VerificationURIComplete != "" {
		fmt.Fprintln(os.Stderr, "  ", authz.VerificationURIComplete)
	} else {
		fmt.Fprintln(os.Stderr, "  ", authz.VerificationURI)
	}
	fmt.Fprintln(os.Stderr, "Or open this URL and enter the code below:")
	fmt.Fprintln(os.Stderr, "  ", authz.VerificationURI)
	fmt.Fprintln(os.Stderr, "  code:", authz.UserCode)
	fmt.Fprintln(os.Stderr, "Waiting for approval…")

	deadline := time.Now().Add(time.Duration(authz.ExpiresIn) * time.Second)
	interval := time.Duration(authz.Interval) * time.Second
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("device code expired before approval")
		}
		time.Sleep(interval)
		pollForm := url.Values{}
		pollForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		pollForm.Set("device_code", authz.DeviceCode)
		pollForm.Set("client_id", clientID)

		pollCtx, pollCancel := context.WithTimeout(context.Background(), 15*time.Second)
		pollReq, err := http.NewRequestWithContext(pollCtx, http.MethodPost, tokenURL,
			strings.NewReader(pollForm.Encode()))
		if err != nil {
			pollCancel()
			return nil, err
		}
		pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pollReq.Header.Set("Accept", "application/json")
		pollResp, err := http.DefaultClient.Do(pollReq)
		pollCancel()
		if err != nil {
			return nil, fmt.Errorf("token poll: %w", err)
		}
		pollBody, _ := io.ReadAll(io.LimitReader(pollResp.Body, 64*1024))
		pollResp.Body.Close()

		if pollResp.StatusCode == http.StatusOK {
			var raw struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				ExpiresIn    int64  `json:"expires_in"`
			}
			if err := json.Unmarshal(pollBody, &raw); err != nil {
				return nil, fmt.Errorf("decode token response: %w", err)
			}
			if raw.AccessToken == "" {
				return nil, errors.New("token endpoint returned no access_token")
			}
			return &tokenSet{
				AccessToken:  raw.AccessToken,
				RefreshToken: raw.RefreshToken,
				Expiration:   time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second),
			}, nil
		}
		// Non-200: decode the RFC error code from the JSON body so we
		// can distinguish "keep polling" from "abort." Anything we
		// don't recognise is treated as terminal.
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(pollBody, &errResp)
		switch errResp.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += time.Duration(authz.Interval) * time.Second
			continue
		case "access_denied":
			return nil, errors.New("authorization denied by user")
		case "expired_token":
			return nil, errors.New("device code expired before approval")
		default:
			return nil, fmt.Errorf("token poll: %s %s",
				errResp.Error, strings.TrimSpace(errResp.ErrorDescription))
		}
	}
}

func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "linux":
		return exec.Command("xdg-open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	}
	return errors.New("unsupported platform; copy the URL above manually")
}

// ── get (credential_process) ─────────────────────────────────────────────────

func cmdGet(args []string) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	role := fs.String("role", "", "AWS role slug (matches what an admin set at /portal/admin/aws/roles)")
	// --audience is a deprecated alias for --role to ease the 0.x → 1.x
	// migration; existing ~/.aws/config entries keep working until the
	// alias is dropped in a future release. Documented in usage().
	audienceAlias := fs.String("audience", "", "deprecated alias for --role; will be removed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	slug := *role
	if slug == "" {
		slug = *audienceAlias
	}
	if slug == "" {
		fmt.Fprintln(os.Stderr, "--role is required")
		return 2
	}

	// Cache hit short-circuit — the credential_process path is invoked
	// SYNCHRONOUSLY by every boto3 call against the profile, so cache
	// lookups must be cheap and predictable. We re-emit the cached
	// JSON verbatim if it has at least stsExpirySkew remaining.
	if cached, ok := loadSTSCache(slug); ok {
		_ = json.NewEncoder(os.Stdout).Encode(cached)
		return 0
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v (run `auth-aws-creds login` first)\n", err)
		return 1
	}
	tokens, err := loadTokens()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load tokens: %v (run `auth-aws-creds login` first)\n", err)
		return 1
	}

	// Refresh the OAuth access token if it's stale. Refresh-token rotation:
	// the response carries a NEW refresh_token; persist it before issuing
	// any other call so a crash doesn't leave us with a burnt token.
	if time.Until(tokens.Expiration) < accessTokenSkew {
		fresh, err := refreshTokens(cfg.Issuer, cfg.ClientID, tokens.RefreshToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "refresh token failed: %v (run `auth-aws-creds login` again)\n", err)
			return 1
		}
		// Auth's /token may not echo refresh_token if rotation is disabled;
		// retain the previous value in that case.
		if fresh.RefreshToken == "" {
			fresh.RefreshToken = tokens.RefreshToken
		}
		if err := saveTokens(fresh); err != nil {
			fmt.Fprintf(os.Stderr, "save tokens: %v\n", err)
			return 1
		}
		tokens = fresh
	}

	creds, err := fetchAWSCredentials(cfg.Issuer, tokens.AccessToken, slug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch credentials: %v\n", err)
		return 1
	}
	if err := saveSTSCache(slug, creds); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cache save failed: %v\n", err)
		// Non-fatal — still emit the creds so this boto3 call works.
	}
	_ = json.NewEncoder(os.Stdout).Encode(creds)
	return 0
}

// awsCredentialsResponse matches the JSON shape auth's /aws/credentials
// endpoint returns, which is also the AWS CLI v2 credential_process
// format. We pass the response straight through to stdout — no
// re-marshalling, identical types between server and client.
type awsCredentialsResponse struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

func fetchAWSCredentials(issuer, accessToken, slug string) (*awsCredentialsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	form := url.Values{}
	form.Set("role", slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(issuer, "/")+"/aws/credentials",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/aws/credentials %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out awsCredentialsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &out, nil
}

// ── logout ───────────────────────────────────────────────────────────────────

func cmdLogout(_ []string) int {
	dir, err := cacheDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cacheDir: %v\n", err)
		return 1
	}
	// Best-effort removal: missing files aren't errors. We intentionally
	// keep config.json (issuer + client_id) so a subsequent `login` can
	// re-use the same setup without re-typing flags.
	for _, p := range []string{
		filepath.Join(dir, "tokens.json"),
	} {
		_ = os.Remove(p)
	}
	_ = os.RemoveAll(filepath.Join(dir, "sts"))
	fmt.Fprintln(os.Stderr, "auth-aws-creds: logged out (tokens + STS cache cleared)")
	return 0
}

// ── config + cache (filesystem-backed) ───────────────────────────────────────

type config struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

type tokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiration   time.Time `json:"expiration"`
}

func cacheDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "auth-aws-creds")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func saveConfig(c config) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "config.json"), b, 0o600)
}

func loadConfig() (*config, error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Issuer == "" || c.ClientID == "" {
		return nil, errors.New("config.json incomplete (missing issuer or client_id)")
	}
	return &c, nil
}

func saveTokens(t *tokenSet) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "tokens.json"), b, 0o600)
}

func loadTokens() (*tokenSet, error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		return nil, err
	}
	var t tokenSet
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// loadSTSCache returns the cached credentials for the role slug if they
// have at least stsExpirySkew remaining; otherwise (file missing,
// expired, malformed) returns false so the caller falls through to a
// fresh exchange.
func loadSTSCache(slug string) (*awsCredentialsResponse, bool) {
	dir, err := cacheDir()
	if err != nil {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(dir, "sts", safeFilename(slug)+".json"))
	if err != nil {
		return nil, false
	}
	var c awsCredentialsResponse
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, false
	}
	if time.Until(c.Expiration) < stsExpirySkew {
		return nil, false
	}
	return &c, true
}

func saveSTSCache(slug string, c *awsCredentialsResponse) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	stsDir := filepath.Join(dir, "sts")
	if err := os.MkdirAll(stsDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(stsDir, safeFilename(slug)+".json"), b, 0o600)
}

// safeFilename strips path separators and other shell-meaningful chars
// from the role slug. Slugs are operator-chosen strings (validated
// against a regex at admin form time, but the server-side validation
// can't be assumed when the helper is talking to an arbitrary issuer);
// this guards against a slug like "../../../etc/passwd" being turned
// into a path-traversal write target.
func safeFilename(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z',
			'A' <= c && c <= 'Z',
			'0' <= c && c <= '9',
			c == '-' || c == '_' || c == '.':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "default"
	}
	return string(b)
}

// writeFileAtomic writes to a sibling tmpfile and renames over the target
// so a crash mid-write doesn't corrupt the existing file. The tmpfile
// inherits the mode of the target so secrets stay 0600 across rotations.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		// If rename succeeded, tmpName no longer exists; this remove is a no-op.
		// If we returned early after a write error, remove the partial file.
		_ = os.Remove(tmpName)
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// randomURLSafe returns n random bytes encoded as base64url (RFC 4648
// §5, no padding). Used for PKCE verifiers and CSRF state values.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
