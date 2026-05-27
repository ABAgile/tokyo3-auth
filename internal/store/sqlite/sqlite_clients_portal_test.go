package sqlite

import (
	"context"
	"slices"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/google/uuid"
)

// TestListPortalClientsForUser exercises every visibility branch of the
// join query — hidden by default, group-scoped match, group-scoped miss,
// visible-to-all override. The query's correctness is the load-bearing
// guarantee for the /portal/apps page's authorization model, so each
// case lives as its own assertion.
func TestListPortalClientsForUser(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)

	hash, _ := creds.HashPassword("pw0rd-very-strong-123!")
	alice, err := db.CreateUser(ctx, "alice@example.com", hash, "Alice")
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	bob, err := db.CreateUser(ctx, "bob@example.com", hash, "Bob")
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	engGroup, err := db.CreateGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := db.AddGroupMember(ctx, engGroup.ID, alice.ID); err != nil {
		t.Fatalf("AddGroupMember alice/engineering: %v", err)
	}
	// bob is intentionally NOT in engineering.

	// Helper to create a client with all the portal knobs set in one shot.
	mkClient := func(name string, showInPortal, visibleToAll bool, launchURL string) uuid.UUID {
		c, err := db.CreateClient(ctx, name+"-cid", creds.HashToken("sec"), name,
			[]string{"http://localhost/cb"}, []string{"openid"}, false, nil)
		if err != nil {
			t.Fatalf("CreateClient %s: %v", name, err)
		}
		if err := db.UpdateClientPortalConfig(ctx, c.ID, showInPortal, launchURL, "", "", visibleToAll); err != nil {
			t.Fatalf("UpdateClientPortalConfig %s: %v", name, err)
		}
		return c.ID
	}

	hiddenID := mkClient("hidden-client", false, false, "https://hidden.example/login")
	engOnlyID := mkClient("eng-only-client", true, false, "https://eng.example/login")
	everyoneID := mkClient("everyone-client", true, true, "https://everyone.example/login")

	if err := db.ReplaceClientVisibility(ctx, engOnlyID, []uuid.UUID{engGroup.ID}); err != nil {
		t.Fatalf("ReplaceClientVisibility eng-only: %v", err)
	}

	// Alice (in engineering) should see eng-only-client AND everyone-client; never hidden-client.
	aliceTiles, err := db.ListPortalClientsForUser(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListPortalClientsForUser alice: %v", err)
	}
	aliceIDs := tileIDs(aliceTiles)
	if !contains(aliceIDs, engOnlyID) {
		t.Errorf("alice missing eng-only-client (group match): got %v", aliceIDs)
	}
	if !contains(aliceIDs, everyoneID) {
		t.Errorf("alice missing everyone-client (visible_to_all): got %v", aliceIDs)
	}
	if contains(aliceIDs, hiddenID) {
		t.Errorf("alice got hidden-client (show_in_portal=false): got %v", aliceIDs)
	}

	// Bob (no groups) should see ONLY everyone-client.
	bobTiles, err := db.ListPortalClientsForUser(ctx, bob.ID)
	if err != nil {
		t.Fatalf("ListPortalClientsForUser bob: %v", err)
	}
	bobIDs := tileIDs(bobTiles)
	if contains(bobIDs, engOnlyID) {
		t.Errorf("bob got eng-only-client without group membership: got %v", bobIDs)
	}
	if !contains(bobIDs, everyoneID) {
		t.Errorf("bob missing everyone-client (visible_to_all should override group filter): got %v", bobIDs)
	}
	if contains(bobIDs, hiddenID) {
		t.Errorf("bob got hidden-client: got %v", bobIDs)
	}

	// Sanity: ListClientVisibility returns exactly engGroup for eng-only-client.
	vis, err := db.ListClientVisibility(ctx, engOnlyID)
	if err != nil {
		t.Fatalf("ListClientVisibility: %v", err)
	}
	if len(vis) != 1 || vis[0] != engGroup.ID {
		t.Errorf("ListClientVisibility(eng-only) = %v, want [%s]", vis, engGroup.ID)
	}
}

// TestListPortalClientsForUser_NoDuplicatesOnMultipleGroupMatch guards
// the DISTINCT in the join query: a user in two groups that both link
// to the same client must see one tile, not two.
func TestListPortalClientsForUser_NoDuplicatesOnMultipleGroupMatch(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)

	hash, _ := creds.HashPassword("pw0rd-very-strong-123!")
	u, _ := db.CreateUser(ctx, "alice@example.com", hash, "Alice")
	g1, _ := db.CreateGroup(ctx, "g1")
	g2, _ := db.CreateGroup(ctx, "g2")
	_ = db.AddGroupMember(ctx, g1.ID, u.ID)
	_ = db.AddGroupMember(ctx, g2.ID, u.ID)

	c, _ := db.CreateClient(ctx, "shared-cid", creds.HashToken("sec"), "shared",
		[]string{"http://localhost/cb"}, []string{"openid"}, false, nil)
	_ = db.UpdateClientPortalConfig(ctx, c.ID, true, "https://shared.example/login", "", "", false)
	_ = db.ReplaceClientVisibility(ctx, c.ID, []uuid.UUID{g1.ID, g2.ID})

	tiles, err := db.ListPortalClientsForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListPortalClientsForUser: %v", err)
	}
	count := 0
	for _, t := range tiles {
		if t.ID == c.ID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 tile for the doubly-linked client, got %d", count)
	}
}

// TestReplaceClientVisibility_RemovesPriorRows asserts that the
// "replace" semantics actually replace — passing a shorter list shrinks
// the visibility set rather than additively unioning.
func TestReplaceClientVisibility_RemovesPriorRows(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)
	c, _ := db.CreateClient(ctx, "test-cid", creds.HashToken("sec"), "test",
		[]string{"http://localhost/cb"}, []string{"openid"}, false, nil)
	g1, _ := db.CreateGroup(ctx, "g1")
	g2, _ := db.CreateGroup(ctx, "g2")

	_ = db.ReplaceClientVisibility(ctx, c.ID, []uuid.UUID{g1.ID, g2.ID})
	if got, _ := db.ListClientVisibility(ctx, c.ID); len(got) != 2 {
		t.Fatalf("initial set has %d entries, want 2", len(got))
	}
	// Shrink to just g1.
	_ = db.ReplaceClientVisibility(ctx, c.ID, []uuid.UUID{g1.ID})
	got, _ := db.ListClientVisibility(ctx, c.ID)
	if len(got) != 1 || got[0] != g1.ID {
		t.Errorf("after shrink: got %v, want [%s]", got, g1.ID)
	}
}

func tileIDs(cs []*model.Client) []uuid.UUID {
	out := make([]uuid.UUID, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

func contains(ids []uuid.UUID, target uuid.UUID) bool {
	return slices.Contains(ids, target)
}
