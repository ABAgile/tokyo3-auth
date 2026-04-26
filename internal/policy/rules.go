// Package policy provides a pluggable rule engine for access control.
package policy

import (
	"net/http"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
)

// PolicyContext carries all data available at evaluation time.
type PolicyContext struct {
	User         *model.User
	Client       *model.Client
	Scopes       []string
	Password     string // plaintext only during credential check; cleared after evaluation
	Request      *http.Request
	MFAVerified  bool
	SessionAge   time.Duration
	LastActivity time.Duration
}

// PolicyViolation describes a single rule failure.
type PolicyViolation struct {
	RuleID      string
	Description string
	Message     string
}

func (v PolicyViolation) Error() string { return v.RuleID + ": " + v.Message }

// Rule is a single evaluatable policy constraint.
type Rule interface {
	ID() string
	Description() string
	Evaluate(ctx PolicyContext) *PolicyViolation
}
