package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/envutil"
)

// serveConfig is the validated, typed form of authd's serve-time environment.
// It is built once, before any database, NATS or worker is opened, so a bad
// value fails startup with an error naming the variable instead of silently
// falling back to a default.
type serveConfig struct {
	Issuer            string
	Addr              string
	AWSAudience       string
	StepUpMFATTL      time.Duration // 0 = package default
	AllowRegistration bool
	TrustedProxies    []*net.IPNet
	AuthRatePerMin    int // 0 = package default
	TokenRatePerMin   int // 0 = package default

	// ProvisionSyncInterval and AWSFedReapInterval of 0 disable the worker.
	ProvisionSyncInterval time.Duration
	AWSFedReapInterval    time.Duration
}

const (
	defaultProvisionSyncInterval = time.Hour
	// 6h is conservative for a typical 1h role lifetime and bounds the
	// aws_revoked_users inline policy growth without thrashing AWS.
	defaultAWSFedReapInterval = 6 * time.Hour
)

// loadServeConfig reads and validates the serve environment, returning every
// problem found (joined) rather than only the first.
func loadServeConfig() (serveConfig, error) {
	var (
		cfg  serveConfig
		errs []error
	)
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	var err error
	cfg.Issuer, err = parseIssuer(os.Getenv("AUTHD_ISSUER"))
	check(err)

	cfg.Addr = envutil.Or("AUTHD_ADDR", ":8443")
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		check(fmt.Errorf("AUTHD_ADDR: %w", err))
	}

	cfg.AWSAudience = os.Getenv("AUTHD_AWS_AUDIENCE")

	cfg.StepUpMFATTL, err = envutil.Duration("AUTHD_STEP_UP_MFA_TTL")
	check(err)
	if cfg.StepUpMFATTL < 0 {
		check(errors.New("AUTHD_STEP_UP_MFA_TTL: must not be negative"))
	}

	cfg.AllowRegistration, err = boolEnv("AUTHD_ALLOW_REGISTRATION")
	check(err)

	cfg.TrustedProxies, err = envutil.CIDRList("AUTHD_TRUSTED_PROXIES")
	check(err)

	cfg.AuthRatePerMin, err = nonNegativeIntEnv("AUTHD_AUTH_RATE_PER_MIN")
	check(err)
	cfg.TokenRatePerMin, err = nonNegativeIntEnv("AUTHD_TOKEN_RATE_PER_MIN")
	check(err)

	cfg.ProvisionSyncInterval, err = intervalEnv("AUTHD_PROVISION_SYNC_INTERVAL", defaultProvisionSyncInterval)
	check(err)
	cfg.AWSFedReapInterval, err = intervalEnv("AUTHD_AWSFED_REAP_INTERVAL", defaultAWSFedReapInterval)
	check(err)

	// Consumed only by the legacy one-shot import, but a typo there would
	// silently become "no timeout"; reject it up front.
	_, err = envutil.Duration("AUTHD_VAULT_SCIM_TIMEOUT")
	check(err)

	check(validateWebAuthnOrigins(os.Getenv("AUTHD_WEBAUTHN_ORIGINS")))

	if len(errs) > 0 {
		return serveConfig{}, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return cfg, nil
}

// parseIssuer requires an absolute http(s) URL with a host and no query or
// fragment (OIDC Discovery §3). The value is returned unchanged.
func parseIssuer(v string) (string, error) {
	if v == "" {
		return "", errors.New("AUTHD_ISSUER is required")
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("AUTHD_ISSUER: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("AUTHD_ISSUER: scheme must be https or http, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("AUTHD_ISSUER: missing host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("AUTHD_ISSUER: must not contain a query or fragment")
	}
	return v, nil
}

// validateWebAuthnOrigins checks the space-separated extra-origin list: each
// entry must be a scheme://host[:port] origin with no path.
func validateWebAuthnOrigins(v string) error {
	for o := range strings.FieldsSeq(v) {
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("AUTHD_WEBAUTHN_ORIGINS: %q is not a scheme://host[:port] origin", o)
		}
	}
	return nil
}

// boolEnv parses key as a strict boolean. Unset or empty is false; anything
// strconv.ParseBool rejects (e.g. "yes") is an error rather than silently off.
func boolEnv(key string) (bool, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean (use true or false)", key, v)
	}
	return b, nil
}

// nonNegativeIntEnv parses key as an int >= 0; unset/empty yields 0, which
// callers map to their default.
func nonNegativeIntEnv(key string) (int, error) {
	n, err := envutil.Int(key)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("%s: must not be negative", key)
	}
	return n, nil
}

// intervalEnv parses key as a duration. Unset/empty yields def; an explicit
// zero or negative value disables the worker (returned as 0); an unparseable
// value is an error.
func intervalEnv(key string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(os.Getenv(key)) == "" {
		return def, nil
	}
	d, err := envutil.Duration(key)
	if err != nil {
		return 0, err
	}
	return max(d, 0), nil
}
