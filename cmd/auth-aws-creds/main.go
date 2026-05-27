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
// The OIDC code (browser/device flow, token cache, refresh-token
// rotation) lives in github.com/abagile/tokyo3-base/oidcclient and is
// shared with auth-ssh-creds and any future SSO helper. The shared
// SSO cache means a single `login` serves every helper — this binary
// only owns the AWS-specific bits: STS-cache handling at
// ~/.config/auth-sso/aws-creds/sts/<slug>.json and the
// /aws/credentials call.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
)

const (
	// appCacheSubdir names this helper's subdir under the shared SSO
	// cache root (~/.config/auth-sso/aws-creds/). Conventionally
	// matches the binary name minus the "auth-" prefix.
	appCacheSubdir = "aws-creds"

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

Files (shared SSO cache; same root for all auth-* helpers):
  ~/.config/auth-sso/config.json                issuer + client_id (non-secret)
  ~/.config/auth-sso/tokens.json                OAuth refresh + access tokens (0600)
  ~/.config/auth-sso/aws-creds/sts/<slug>.json  cached STS credentials per role (0600)`)
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
	if _, err := oidcclient.Login(context.Background(),
		oidcclient.Config{Issuer: *issuer, ClientID: *clientID},
		oidcclient.LoginOptions{Port: *port, Device: *device, Stderr: os.Stderr}); err != nil {
		fmt.Fprintf(os.Stderr, "login: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "auth-aws-creds: login successful")
	return 0
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

	cfg, err := oidcclient.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v (run `auth-aws-creds login` first)\n", err)
		return 1
	}
	tokens, err := oidcclient.EnsureFreshTokens(context.Background(), *cfg, accessTokenSkew)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
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
	// Logout wipes the shared tokens.json plus any helper-specific
	// sub-trees we name as extras. "aws-creds" here is the whole
	// per-helper subdir under ~/.config/auth-sso/ — clearing it
	// removes the STS sub-cache in one shot. config.json (shared SSO
	// state, no secrets) stays.
	if err := oidcclient.Logout(appCacheSubdir); err != nil {
		fmt.Fprintf(os.Stderr, "logout: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "auth-aws-creds: logged out (tokens + STS cache cleared)")
	return 0
}

// ── per-role STS credential cache ────────────────────────────────────────────

// loadSTSCache returns the cached credentials for the role slug if they
// have at least stsExpirySkew remaining; otherwise (file missing,
// expired, malformed) returns false so the caller falls through to a
// fresh exchange. Cache path: ~/.config/auth-sso/aws-creds/sts/<slug>.json.
func loadSTSCache(slug string) (*awsCredentialsResponse, bool) {
	dir, err := oidcclient.AppCacheDir(appCacheSubdir)
	if err != nil {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(dir, "sts", oidcclient.SafeFilename(slug)+".json"))
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
	dir, err := oidcclient.AppCacheDir(appCacheSubdir)
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
	return oidcclient.WriteFileAtomic(filepath.Join(stsDir, oidcclient.SafeFilename(slug)+".json"), b, 0o600)
}
