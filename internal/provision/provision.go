// Package provision defines the outbound user/group provisioning interface
// that the auth Server fans out to whenever an authoritative user mutation
// occurs (SCIM ingest, admin API, self-registration, portal admin actions).
//
// Implementations are best-effort: errors are logged via Set but never
// propagated to the originating request, since the source of truth (auth's
// users/scim_groups tables) has already been updated when User/Group is
// called. A failed downstream sync is recoverable via the `authd admin sync`
// backfill command.
package provision

import (
	"context"
	"log/slog"

	"github.com/abagile/tokyo3-auth/internal/model"
)

// Op describes the lifecycle event being fanned out.
type Op int

const (
	OpCreate Op = iota
	OpUpdate
	OpDeactivate
	OpDelete
)

func (o Op) String() string {
	switch o {
	case OpCreate:
		return "create"
	case OpUpdate:
		return "update"
	case OpDeactivate:
		return "deactivate"
	case OpDelete:
		return "delete"
	}
	return "unknown"
}

// Provisioner fans out user and group lifecycle events to a downstream system
// (AWS IAM, vault SCIM, etc.). Name() identifies the target in audit + logs.
type Provisioner interface {
	Name() string
	User(ctx context.Context, op Op, u *model.User, groups []string) error
	Group(ctx context.Context, op Op, g *model.SCIMGroup, members []*model.User) error
}

// Set fans out an event to its slice of provisioners and logs any errors.
// A nil *Set is a valid no-op so handler code can call methods unconditionally.
type Set struct {
	Provisioners []Provisioner
	Log          *slog.Logger
}

// User invokes Provisioner.User on each target. Errors are logged, never returned.
func (s *Set) User(ctx context.Context, op Op, u *model.User, groups []string) {
	if s == nil || u == nil {
		return
	}
	for _, p := range s.Provisioners {
		if err := p.User(ctx, op, u, groups); err != nil && s.Log != nil {
			s.Log.Error("provision user",
				"target", p.Name(), "op", op, "user", u.Email, "err", err)
		}
	}
}

// Group invokes Provisioner.Group on each target. Errors are logged, never returned.
func (s *Set) Group(ctx context.Context, op Op, g *model.SCIMGroup, members []*model.User) {
	if s == nil || g == nil {
		return
	}
	for _, p := range s.Provisioners {
		if err := p.Group(ctx, op, g, members); err != nil && s.Log != nil {
			s.Log.Error("provision group",
				"target", p.Name(), "op", op, "group", g.DisplayName, "err", err)
		}
	}
}
