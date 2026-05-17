package policy_test

import (
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
)

func TestDefaultPCIRules_Composition(t *testing.T) {
	rules := policy.DefaultPCIRules()
	if len(rules) != 7 {
		t.Fatalf("DefaultPCIRules: want 7, got %d", len(rules))
	}
	wantIDs := []string{
		"PCI-8.3.6",
		"PCI-8.3.9",
		"PCI-8.3.4",
		"PCI-8.4.2",
		"PCI-8.2.8-idle",
		"PCI-8.2.8-lifetime",
		"PCI-8.6.1",
	}
	for i, r := range rules {
		if r.ID() != wantIDs[i] {
			t.Errorf("rule[%d].ID = %q, want %q", i, r.ID(), wantIDs[i])
		}
		if r.Description() == "" {
			t.Errorf("rule[%d] %s has empty Description", i, r.ID())
		}
	}
}

func TestPasswordComplexityRule(t *testing.T) {
	r := &policy.PasswordComplexityRule{}
	cases := []struct {
		name string
		pw   string
		fail bool
	}{
		{"empty skipped", "", false},
		{"too short", "Aa1!aaa", true},
		{"no upper", "abcdefghijk1!", true},
		{"no lower", "ABCDEFGHIJK1!", true},
		{"no digit", "Abcdefghijkl!", true},
		{"no special", "Abcdefghijk12", true},
		{"valid", "Abcdefghij1!", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := r.Evaluate(policy.PolicyContext{Password: c.pw})
			if c.fail && v == nil {
				t.Errorf("password %q: expected violation, got nil", c.pw)
			}
			if !c.fail && v != nil {
				t.Errorf("password %q: expected pass, got %v", c.pw, v)
			}
		})
	}
}

func TestPasswordAgeRule(t *testing.T) {
	r := &policy.PasswordAgeRule{MaxDays: 90}

	if v := r.Evaluate(policy.PolicyContext{User: nil}); v != nil {
		t.Errorf("nil user: expected pass, got %v", v)
	}

	mfaUser := &model.User{MFAEnabled: true, PasswordChangedAt: time.Now().Add(-200 * 24 * time.Hour)}
	if v := r.Evaluate(policy.PolicyContext{User: mfaUser}); v != nil {
		t.Errorf("MFA-enabled user: ancient password should be exempt, got %v", v)
	}

	fresh := &model.User{PasswordChangedAt: time.Now().Add(-30 * 24 * time.Hour)}
	if v := r.Evaluate(policy.PolicyContext{User: fresh}); v != nil {
		t.Errorf("fresh password: expected pass, got %v", v)
	}

	stale := &model.User{PasswordChangedAt: time.Now().Add(-100 * 24 * time.Hour)}
	v := r.Evaluate(policy.PolicyContext{User: stale})
	if v == nil {
		t.Fatal("stale password: expected violation")
	}
	if v.RuleID != "PCI-8.3.9" {
		t.Errorf("RuleID = %q, want PCI-8.3.9", v.RuleID)
	}
}

func TestAccountLockoutRule(t *testing.T) {
	r := &policy.AccountLockoutRule{MaxFailures: 10, LockDuration: 30 * time.Minute}

	if v := r.Evaluate(policy.PolicyContext{User: nil}); v != nil {
		t.Errorf("nil user: expected pass, got %v", v)
	}

	unlocked := &model.User{LockedUntil: nil}
	if v := r.Evaluate(policy.PolicyContext{User: unlocked}); v != nil {
		t.Errorf("unlocked: expected pass, got %v", v)
	}

	past := time.Now().Add(-5 * time.Minute)
	expired := &model.User{LockedUntil: &past}
	if v := r.Evaluate(policy.PolicyContext{User: expired}); v != nil {
		t.Errorf("expired lock: expected pass, got %v", v)
	}

	future := time.Now().Add(5 * time.Minute)
	locked := &model.User{LockedUntil: &future}
	if v := r.Evaluate(policy.PolicyContext{User: locked}); v == nil {
		t.Error("active lock: expected violation, got nil")
	}
}

func TestMFARequiredRule(t *testing.T) {
	r := &policy.MFARequiredRule{}

	publicClient := &model.Client{Public: true}
	if v := r.Evaluate(policy.PolicyContext{Client: publicClient}); v != nil {
		t.Errorf("public client: expected pass, got %v", v)
	}
	if v := r.Evaluate(policy.PolicyContext{Client: nil}); v != nil {
		t.Errorf("nil client: expected pass, got %v", v)
	}

	conf := &model.Client{Public: false}

	enrolled := &model.User{MFAEnabled: true}
	if v := r.Evaluate(policy.PolicyContext{Client: conf, User: enrolled, Password: "pw"}); v != nil {
		t.Errorf("credential phase + MFA enrolled: expected pass, got %v", v)
	}

	noMFA := &model.User{MFAEnabled: false}
	v := r.Evaluate(policy.PolicyContext{Client: conf, User: noMFA, Password: "pw"})
	if v == nil {
		t.Error("credential phase + no MFA: expected violation, got nil")
	}

	if v := r.Evaluate(policy.PolicyContext{Client: conf, MFAVerified: true}); v != nil {
		t.Errorf("token phase + MFAVerified: expected pass, got %v", v)
	}
	if v := r.Evaluate(policy.PolicyContext{Client: conf, MFAVerified: false}); v == nil {
		t.Error("token phase + MFA missing: expected violation, got nil")
	}
}

func TestSessionIdleTimeoutRule(t *testing.T) {
	r := &policy.SessionIdleTimeoutRule{MaxIdle: 15 * time.Minute, CDEScope: "cde"}

	if v := r.Evaluate(policy.PolicyContext{Scopes: []string{"openid"}, LastActivity: time.Hour}); v != nil {
		t.Errorf("non-CDE scope: idle should not matter, got %v", v)
	}

	if v := r.Evaluate(policy.PolicyContext{Scopes: []string{"CDE"}, LastActivity: 5 * time.Minute}); v != nil {
		t.Errorf("CDE scope, fresh: expected pass, got %v", v)
	}

	if v := r.Evaluate(policy.PolicyContext{Scopes: []string{"cde"}, LastActivity: 30 * time.Minute}); v == nil {
		t.Error("CDE scope, idle 30m: expected violation")
	}
}

func TestTokenLifetimeRule(t *testing.T) {
	r := &policy.TokenLifetimeRule{MaxAccess: time.Hour, MaxRefresh: 24 * time.Hour}
	if v := r.Evaluate(policy.PolicyContext{}); v != nil {
		t.Errorf("TokenLifetimeRule never violates; got %v", v)
	}
	if r.AccessTokenDuration() != time.Hour {
		t.Errorf("AccessTokenDuration: want 1h, got %v", r.AccessTokenDuration())
	}
	if r.RefreshTokenDuration() != 24*time.Hour {
		t.Errorf("RefreshTokenDuration: want 24h, got %v", r.RefreshTokenDuration())
	}
}

func TestClientSecretAgeRule(t *testing.T) {
	r := &policy.ClientSecretAgeRule{MaxAge: 365 * 24 * time.Hour}

	if v := r.Evaluate(policy.PolicyContext{Client: nil}); v != nil {
		t.Errorf("nil client: expected pass, got %v", v)
	}
	if v := r.Evaluate(policy.PolicyContext{Client: &model.Client{Public: true}}); v != nil {
		t.Errorf("public client: expected pass, got %v", v)
	}

	fresh := &model.Client{SecretRotatedAt: time.Now().Add(-30 * 24 * time.Hour)}
	if v := r.Evaluate(policy.PolicyContext{Client: fresh}); v != nil {
		t.Errorf("fresh secret: expected pass, got %v", v)
	}

	stale := &model.Client{SecretRotatedAt: time.Now().Add(-400 * 24 * time.Hour)}
	if v := r.Evaluate(policy.PolicyContext{Client: stale}); v == nil {
		t.Error("stale secret: expected violation")
	}
}

func TestEngine_EvaluateAndFirst(t *testing.T) {
	e := policy.New(&policy.PasswordComplexityRule{}, &policy.AccountLockoutRule{})

	// All-pass: empty password + nil user → both rules return nil.
	if vs := e.Evaluate(policy.PolicyContext{}); len(vs) != 0 {
		t.Errorf("all-pass: expected no violations, got %d", len(vs))
	}
	if v := e.First(policy.PolicyContext{}); v != nil {
		t.Errorf("all-pass: First should be nil, got %v", v)
	}

	// Trip both at once.
	locked := time.Now().Add(time.Hour)
	ctx := policy.PolicyContext{
		Password: "short",
		User:     &model.User{LockedUntil: &locked},
	}
	vs := e.Evaluate(ctx)
	if len(vs) != 2 {
		t.Errorf("expected 2 violations, got %d (%v)", len(vs), vs)
	}
	if v := e.First(ctx); v == nil {
		t.Fatal("First should report the password violation")
	} else if v.RuleID != "PCI-8.3.6" {
		t.Errorf("First.RuleID = %q, want PCI-8.3.6", v.RuleID)
	}
}

func TestEngine_AddRule(t *testing.T) {
	e := policy.New()
	if vs := e.Evaluate(policy.PolicyContext{Password: "short"}); len(vs) != 0 {
		t.Errorf("empty engine: expected 0 violations, got %d", len(vs))
	}
	e.AddRule(&policy.PasswordComplexityRule{})
	if vs := e.Evaluate(policy.PolicyContext{Password: "short"}); len(vs) != 1 {
		t.Errorf("after AddRule: expected 1 violation, got %d", len(vs))
	}
}

func TestPolicyViolation_Error(t *testing.T) {
	v := policy.PolicyViolation{RuleID: "PCI-X", Message: "boom"}
	if got := v.Error(); got != "PCI-X: boom" {
		t.Errorf("Error() = %q, want %q", got, "PCI-X: boom")
	}
}
