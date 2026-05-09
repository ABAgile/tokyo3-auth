package provision

import (
	"context"
	"log/slog"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

// SyncStore is the minimum store surface SyncAll needs. Both *postgres.DB and
// the test in-memory store satisfy this — no provision-package dependency on
// the concrete store implementation.
type SyncStore interface {
	ListUsers(ctx context.Context) ([]*model.User, error)
	ListGroups(ctx context.Context) ([]*model.SCIMGroup, error)
}

// SyncAll iterates every user and group in the store and pushes them through a
// single Provisioner as OpCreate. The downstream's User/Group implementations
// are expected to be idempotent (PATCH-or-POST on users, full-list PUT on
// groups) so re-running is safe and is in fact the point — drift recovery, new
// integration backfill, and periodic full-sync all share this path.
//
// Counts of successes and failures are returned per kind. Per-row failures are
// logged at error level and accumulated into the failure count; SyncAll never
// aborts mid-run.
func SyncAll(ctx context.Context, store SyncStore, prov Provisioner, log *slog.Logger) (userOK, userFail, groupOK, groupFail int) {
	users, err := store.ListUsers(ctx)
	if err != nil {
		if log != nil {
			log.Error("provision sync — list users", "target", prov.Name(), "err", err)
		}
		return
	}
	usersByID := make(map[uuid.UUID]*model.User, len(users))
	for _, u := range users {
		usersByID[u.ID] = u
		if err := prov.User(ctx, OpCreate, u, nil); err != nil {
			if log != nil {
				log.Error("provision sync — user", "target", prov.Name(), "email", u.Email, "err", err)
			}
			userFail++
			continue
		}
		userOK++
	}
	groups, err := store.ListGroups(ctx)
	if err != nil {
		if log != nil {
			log.Error("provision sync — list groups", "target", prov.Name(), "err", err)
		}
		return
	}
	for _, g := range groups {
		members := make([]*model.User, 0, len(g.Members))
		for _, mid := range g.Members {
			if m, ok := usersByID[mid]; ok {
				members = append(members, m)
			}
		}
		if err := prov.Group(ctx, OpCreate, g, members); err != nil {
			if log != nil {
				log.Error("provision sync — group", "target", prov.Name(), "displayName", g.DisplayName, "err", err)
			}
			groupFail++
			continue
		}
		groupOK++
	}
	return
}
