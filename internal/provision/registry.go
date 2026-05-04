package provision

import (
	"context"
	"sync"

	"github.com/abagile/tokyo3-auth/internal/model"
)

// Registry is a hot-reloadable wrapper around Set. The HTTP server holds a
// single Registry; when an admin saves an integration via the portal, handler
// code calls Reload to rebuild the in-memory Set from the store. User and
// Group calls take an RLock so concurrent requests see a consistent snapshot
// of provisioners — never a partially built Set.
//
// A nil *Registry is a valid no-op so callers can fan out unconditionally,
// matching the contract on *Set.
type Registry struct {
	mu    sync.RWMutex
	set   *Set
	build func(ctx context.Context) (*Set, error)
}

// NewRegistry returns an unloaded Registry. Call Reload at startup before
// serving traffic so the first User/Group call sees the configured provisioners.
// build is invoked under the write lock — keep it free of long-running I/O
// beyond the store reads needed to construct Provisioner instances.
func NewRegistry(build func(ctx context.Context) (*Set, error)) *Registry {
	return &Registry{set: &Set{}, build: build}
}

// Reload rebuilds the underlying Set. The previous Set is discarded only
// after the new one is fully constructed, so a failed Reload leaves the
// Registry serving the old configuration unchanged.
func (r *Registry) Reload(ctx context.Context) error {
	if r == nil {
		return nil
	}
	next, err := r.build(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.set = next
	r.mu.Unlock()
	return nil
}

// User fans out a user lifecycle event under a read lock.
func (r *Registry) User(ctx context.Context, op Op, u *model.User, groups []string) {
	if r == nil {
		return
	}
	r.mu.RLock()
	set := r.set
	r.mu.RUnlock()
	set.User(ctx, op, u, groups)
}

// Group fans out a group lifecycle event under a read lock.
func (r *Registry) Group(ctx context.Context, op Op, g *model.SCIMGroup, members []*model.User) {
	if r == nil {
		return
	}
	r.mu.RLock()
	set := r.set
	r.mu.RUnlock()
	set.Group(ctx, op, g, members)
}
