package policy

import (
	"strings"
	"time"
	"unicode"
)

// DefaultPCIRules returns all PCI-DSS v4.0.1 rules relevant to an IdP.
// Load these into an Engine at startup.
func DefaultPCIRules() []Rule {
	return []Rule{
		&PasswordComplexityRule{},
		&PasswordAgeRule{MaxDays: 90},
		&AccountLockoutRule{MaxFailures: 10, LockDuration: 30 * time.Minute},
		&MFARequiredRule{},
		&SessionIdleTimeoutRule{MaxIdle: 15 * time.Minute, CDEScope: "cde"},
		&TokenLifetimeRule{MaxAccess: time.Hour, MaxRefresh: 24 * time.Hour},
		&ClientSecretAgeRule{MaxAge: 365 * 24 * time.Hour},
	}
}

// ── PCI 8.3.6 ─────────────────────────────────────────────────────────────────

// PasswordComplexityRule enforces minimum length and character class diversity.
type PasswordComplexityRule struct{}

func (r *PasswordComplexityRule) ID() string { return "PCI-8.3.6" }
func (r *PasswordComplexityRule) Description() string {
	return "Password must be ≥12 chars with mixed case, digit, and special character"
}

func (r *PasswordComplexityRule) Evaluate(ctx PolicyContext) *PolicyViolation {
	p := ctx.Password
	if p == "" {
		return nil // not a credential-check context
	}
	if len(p) < 12 {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "password must be at least 12 characters"}
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range p {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "password must contain uppercase, lowercase, digit, and special character"}
	}
	return nil
}

// ── PCI 8.3.9 ─────────────────────────────────────────────────────────────────

// PasswordAgeRule blocks login when the password is older than MaxDays and MFA is not enabled.
type PasswordAgeRule struct {
	MaxDays int
}

func (r *PasswordAgeRule) ID() string { return "PCI-8.3.9" }
func (r *PasswordAgeRule) Description() string {
	return "Password must be changed at least every 90 days when MFA is not enabled"
}

func (r *PasswordAgeRule) Evaluate(ctx PolicyContext) *PolicyViolation {
	if ctx.User == nil || ctx.User.MFAEnabled {
		return nil
	}
	age := time.Since(ctx.User.PasswordChangedAt)
	if age > time.Duration(r.MaxDays)*24*time.Hour {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "password has expired; please reset your password"}
	}
	return nil
}

// ── PCI 8.3.4 ─────────────────────────────────────────────────────────────────

// AccountLockoutRule blocks login for locked accounts.
type AccountLockoutRule struct {
	MaxFailures  int
	LockDuration time.Duration
}

func (r *AccountLockoutRule) ID() string { return "PCI-8.3.4" }
func (r *AccountLockoutRule) Description() string {
	return "Account is locked after 10 consecutive failures"
}

func (r *AccountLockoutRule) Evaluate(ctx PolicyContext) *PolicyViolation {
	if ctx.User == nil {
		return nil
	}
	if ctx.User.LockedUntil != nil && time.Now().Before(*ctx.User.LockedUntil) {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "account is temporarily locked; try again later"}
	}
	return nil
}

// ── PCI 8.4.2 ─────────────────────────────────────────────────────────────────

// MFARequiredRule blocks token issuance when MFA has not been verified.
// Exempt: public clients (device flows, SPA) and the "offline_access" scope alone.
type MFARequiredRule struct{}

func (r *MFARequiredRule) ID() string { return "PCI-8.4.2" }
func (r *MFARequiredRule) Description() string {
	return "MFA must be verified before tokens are issued to confidential clients"
}

func (r *MFARequiredRule) Evaluate(ctx PolicyContext) *PolicyViolation {
	if ctx.Client == nil || ctx.Client.Public {
		return nil
	}
	if !ctx.MFAVerified {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "MFA verification required"}
	}
	return nil
}

// ── PCI 8.2.8 — idle timeout ──────────────────────────────────────────────────

// SessionIdleTimeoutRule rejects sessions idle for longer than MaxIdle when the CDE scope is present.
type SessionIdleTimeoutRule struct {
	MaxIdle  time.Duration
	CDEScope string
}

func (r *SessionIdleTimeoutRule) ID() string { return "PCI-8.2.8-idle" }
func (r *SessionIdleTimeoutRule) Description() string {
	return "Sessions accessing CDE must timeout after 15 minutes of inactivity"
}

func (r *SessionIdleTimeoutRule) Evaluate(ctx PolicyContext) *PolicyViolation {
	if !containsScope(ctx.Scopes, r.CDEScope) {
		return nil
	}
	if ctx.LastActivity > r.MaxIdle {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "session has exceeded the 15-minute idle timeout"}
	}
	return nil
}

// ── PCI 8.2.8 — token lifetime ────────────────────────────────────────────────

// TokenLifetimeRule is evaluated at issuance time to set correct expiries.
// It does not block requests but is used by token endpoint to cap durations.
type TokenLifetimeRule struct {
	MaxAccess  time.Duration
	MaxRefresh time.Duration
}

func (r *TokenLifetimeRule) ID() string { return "PCI-8.2.8-lifetime" }
func (r *TokenLifetimeRule) Description() string {
	return "Access tokens max 1h; refresh tokens max 24h"
}

func (r *TokenLifetimeRule) Evaluate(_ PolicyContext) *PolicyViolation { return nil }

func (r *TokenLifetimeRule) AccessTokenDuration() time.Duration  { return r.MaxAccess }
func (r *TokenLifetimeRule) RefreshTokenDuration() time.Duration { return r.MaxRefresh }

// ── PCI 8.6.1 ─────────────────────────────────────────────────────────────────

// ClientSecretAgeRule warns when a machine client's secret is older than MaxAge.
type ClientSecretAgeRule struct {
	MaxAge time.Duration
}

func (r *ClientSecretAgeRule) ID() string { return "PCI-8.6.1" }
func (r *ClientSecretAgeRule) Description() string {
	return "Machine client secrets must be rotated at least every 12 months"
}

func (r *ClientSecretAgeRule) Evaluate(ctx PolicyContext) *PolicyViolation {
	if ctx.Client == nil || ctx.Client.Public {
		return nil
	}
	age := time.Since(ctx.Client.SecretRotatedAt)
	if age > r.MaxAge {
		return &PolicyViolation{RuleID: r.ID(), Description: r.Description(), Message: "client secret has not been rotated in over 12 months"}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}
