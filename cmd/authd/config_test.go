package main

import (
	"maps"
	"strings"
	"testing"
	"time"
)

// setEnv clears every variable loadServeConfig reads, then applies overrides.
func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range []string{
		"AUTHD_ISSUER", "AUTHD_ADDR", "AUTHD_AWS_AUDIENCE", "AUTHD_STEP_UP_MFA_TTL",
		"AUTHD_ALLOW_REGISTRATION", "AUTHD_TRUSTED_PROXIES", "AUTHD_AUTH_RATE_PER_MIN",
		"AUTHD_TOKEN_RATE_PER_MIN", "AUTHD_PROVISION_SYNC_INTERVAL",
		"AUTHD_AWSFED_REAP_INTERVAL", "AUTHD_VAULT_SCIM_TIMEOUT", "AUTHD_WEBAUTHN_ORIGINS",
	} {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestLoadServeConfig_Defaults(t *testing.T) {
	setEnv(t, map[string]string{"AUTHD_ISSUER": "https://id.example.com"})
	cfg, err := loadServeConfig()
	if err != nil {
		t.Fatalf("loadServeConfig: %v", err)
	}
	if cfg.Addr != ":8443" || cfg.AllowRegistration || cfg.StepUpMFATTL != 0 ||
		cfg.AuthRatePerMin != 0 || cfg.TokenRatePerMin != 0 ||
		cfg.ProvisionSyncInterval != time.Hour || cfg.AWSFedReapInterval != 6*time.Hour {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadServeConfig_ValidValues(t *testing.T) {
	setEnv(t, map[string]string{
		"AUTHD_ISSUER":                  "https://id.example.com",
		"AUTHD_ADDR":                    "127.0.0.1:9000",
		"AUTHD_STEP_UP_MFA_TTL":         "10m",
		"AUTHD_ALLOW_REGISTRATION":      "TRUE",
		"AUTHD_TRUSTED_PROXIES":         "203.0.113.0/24, 198.51.100.7",
		"AUTHD_AUTH_RATE_PER_MIN":       "7",
		"AUTHD_TOKEN_RATE_PER_MIN":      "300",
		"AUTHD_PROVISION_SYNC_INTERVAL": "0",
		"AUTHD_AWSFED_REAP_INTERVAL":    "-1h",
		"AUTHD_WEBAUTHN_ORIGINS":        "https://a.example.com https://b.example.com:8443",
	})
	cfg, err := loadServeConfig()
	if err != nil {
		t.Fatalf("loadServeConfig: %v", err)
	}
	if cfg.StepUpMFATTL != 10*time.Minute || !cfg.AllowRegistration || len(cfg.TrustedProxies) != 2 ||
		cfg.AuthRatePerMin != 7 || cfg.TokenRatePerMin != 300 {
		t.Errorf("parsed config wrong: %+v", cfg)
	}
	if cfg.ProvisionSyncInterval != 0 || cfg.AWSFedReapInterval != 0 {
		t.Errorf("explicit zero/negative must disable workers: %+v", cfg)
	}
}

func TestLoadServeConfig_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string // substring naming the offending variable
	}{
		{"missing issuer", map[string]string{"AUTHD_ISSUER": ""}, "AUTHD_ISSUER"},
		{"issuer scheme", map[string]string{"AUTHD_ISSUER": "ftp://id.example.com"}, "AUTHD_ISSUER"},
		{"issuer no host", map[string]string{"AUTHD_ISSUER": "https://"}, "AUTHD_ISSUER"},
		{"issuer relative", map[string]string{"AUTHD_ISSUER": "id.example.com"}, "AUTHD_ISSUER"},
		{"issuer query", map[string]string{"AUTHD_ISSUER": "https://id.example.com?x=1"}, "AUTHD_ISSUER"},
		{"addr", map[string]string{"AUTHD_ADDR": "8443"}, "AUTHD_ADDR"},
		{"step-up ttl garbage", map[string]string{"AUTHD_STEP_UP_MFA_TTL": "five minutes"}, "AUTHD_STEP_UP_MFA_TTL"},
		{"step-up ttl negative", map[string]string{"AUTHD_STEP_UP_MFA_TTL": "-5m"}, "AUTHD_STEP_UP_MFA_TTL"},
		{"registration", map[string]string{"AUTHD_ALLOW_REGISTRATION": "yes"}, "AUTHD_ALLOW_REGISTRATION"},
		{"proxies", map[string]string{"AUTHD_TRUSTED_PROXIES": "not-a-cidr"}, "AUTHD_TRUSTED_PROXIES"},
		{"auth rate garbage", map[string]string{"AUTHD_AUTH_RATE_PER_MIN": "fast"}, "AUTHD_AUTH_RATE_PER_MIN"},
		{"auth rate negative", map[string]string{"AUTHD_AUTH_RATE_PER_MIN": "-1"}, "AUTHD_AUTH_RATE_PER_MIN"},
		{"token rate negative", map[string]string{"AUTHD_TOKEN_RATE_PER_MIN": "-1"}, "AUTHD_TOKEN_RATE_PER_MIN"},
		{"sync interval", map[string]string{"AUTHD_PROVISION_SYNC_INTERVAL": "hourly"}, "AUTHD_PROVISION_SYNC_INTERVAL"},
		{"reap interval", map[string]string{"AUTHD_AWSFED_REAP_INTERVAL": "6 hours"}, "AUTHD_AWSFED_REAP_INTERVAL"},
		{"scim timeout", map[string]string{"AUTHD_VAULT_SCIM_TIMEOUT": "soon"}, "AUTHD_VAULT_SCIM_TIMEOUT"},
		{"webauthn origin", map[string]string{"AUTHD_WEBAUTHN_ORIGINS": "https://ok.example.com id.example.com"}, "AUTHD_WEBAUTHN_ORIGINS"},
		{"webauthn origin path", map[string]string{"AUTHD_WEBAUTHN_ORIGINS": "https://a.example.com/login"}, "AUTHD_WEBAUTHN_ORIGINS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"AUTHD_ISSUER": "https://id.example.com"}
			maps.Copy(env, tc.env)
			setEnv(t, env)
			_, err := loadServeConfig()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestLoadServeConfig_ReportsAllProblems(t *testing.T) {
	setEnv(t, map[string]string{
		"AUTHD_ISSUER":             "nope",
		"AUTHD_ALLOW_REGISTRATION": "maybe",
	})
	_, err := loadServeConfig()
	if err == nil || !strings.Contains(err.Error(), "AUTHD_ISSUER") || !strings.Contains(err.Error(), "AUTHD_ALLOW_REGISTRATION") {
		t.Fatalf("want both problems reported, got %v", err)
	}
}
