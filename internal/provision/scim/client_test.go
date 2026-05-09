package scim_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	scimprov "github.com/abagile/tokyo3-auth/internal/provision/scim"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// memStore is an in-memory IDStore stub used in client tests.
type memStore struct {
	mu  sync.Mutex
	ids map[string]string // key = provider+":"+userID
}

func newMemStore() *memStore { return &memStore{ids: map[string]string{}} }

func (m *memStore) GetExternalID(_ context.Context, provider string, userID uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.ids[provider+":"+userID.String()]; ok {
		return v, nil
	}
	return "", store.ErrNotFound
}

func (m *memStore) SetExternalID(_ context.Context, provider string, userID uuid.UUID, externalID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ids[provider+":"+userID.String()] = externalID
	return nil
}

func (m *memStore) DeleteExternalID(_ context.Context, provider string, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ids, provider+":"+userID.String())
	return nil
}

// fakeVault stands in for vault's SCIM endpoint. Each handler is a closure;
// tests provide whichever subset they need.
type fakeVault struct {
	t        *testing.T
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc // key: METHOD path-prefix
	server   *httptest.Server
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	fv := &fakeVault{t: t, handlers: map[string]http.HandlerFunc{}}
	fv.server = httptest.NewServer(http.HandlerFunc(fv.dispatch))
	t.Cleanup(fv.server.Close)
	return fv
}

func (fv *fakeVault) on(method, prefix string, h http.HandlerFunc) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.handlers[method+" "+prefix] = h
}

func (fv *fakeVault) URL() string { return fv.server.URL }

func (fv *fakeVault) dispatch(w http.ResponseWriter, r *http.Request) {
	fv.mu.Lock()
	handlers := maps.Clone(fv.handlers)
	fv.mu.Unlock()
	for key, h := range handlers {
		parts := strings.SplitN(key, " ", 2)
		if parts[0] == r.Method && strings.HasPrefix(r.URL.Path, parts[1]) {
			h(w, r)
			return
		}
	}
	http.Error(w, "no handler for "+r.Method+" "+r.URL.Path, http.StatusNotFound)
}

// helpers --------------------------------------------------------------------

func newClient(t *testing.T, fv *fakeVault, st *memStore) *scimprov.Provisioner {
	t.Helper()
	return scimprov.New(scimprov.Config{
		BaseURL: fv.URL(),
		Token:   "test-token",
		Store:   st,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func newUser(email string) *model.User {
	return &model.User{ID: uuid.New(), Email: email, Name: email, Active: true}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func authzOK(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
	}
}

// ── User: create ──────────────────────────────────────────────────────────────

func TestUserCreate_PostsAndCachesID(t *testing.T) {
	fv := newFakeVault(t)
	fv.on(http.MethodPost, "/Users", func(w http.ResponseWriter, r *http.Request) {
		authzOK(t, r)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["userName"] != "alice@example.com" {
			t.Errorf("userName = %v", body["userName"])
		}
		if body["externalId"] == "" {
			t.Error("externalId missing")
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": "vault-uuid-1"})
	})

	st := newMemStore()
	p := newClient(t, fv, st)
	u := newUser("alice@example.com")

	if err := p.User(context.Background(), provision.OpCreate, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}

	got, _ := st.GetExternalID(context.Background(), "vault", u.ID)
	if got != "vault-uuid-1" {
		t.Errorf("cached external id = %q, want vault-uuid-1", got)
	}
}

// ── User: update via PATCH on cache hit ───────────────────────────────────────

func TestUserUpdate_CacheHitPatches(t *testing.T) {
	fv := newFakeVault(t)
	patched := false
	var ops []map[string]any
	fv.on(http.MethodPatch, "/Users/", func(w http.ResponseWriter, r *http.Request) {
		patched = true
		if r.URL.Path != "/Users/vault-existing" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var body struct {
			Operations []map[string]any `json:"Operations"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ops = body.Operations
		writeJSON(w, http.StatusOK, map[string]any{"id": "vault-existing"})
	})

	st := newMemStore()
	u := newUser("bob@example.com")
	_ = st.SetExternalID(context.Background(), "vault", u.ID, "vault-existing")

	p := newClient(t, fv, st)
	if err := p.User(context.Background(), provision.OpUpdate, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}
	if !patched {
		t.Error("expected PATCH, got nothing")
	}
	// Body must include a Replace externalId op so a JIT'd downstream row gets
	// scim_external_id backfilled even when the cached path skips POST.
	var sawExtID bool
	for _, op := range ops {
		if strings.EqualFold(asString(op["op"]), "Replace") && strings.EqualFold(asString(op["path"]), "externalId") {
			sawExtID = true
			if got, want := asString(op["value"]), u.ID.String(); got != want {
				t.Errorf("externalId op value = %q, want %q", got, want)
			}
		}
	}
	if !sawExtID {
		t.Errorf("PATCH body missing Replace externalId op; got ops = %+v", ops)
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ── User: 404 self-heal — PATCH falls through to POST ─────────────────────────

func TestUserUpdate_404SelfHealsViaPost(t *testing.T) {
	fv := newFakeVault(t)
	posted := false
	fv.on(http.MethodPatch, "/Users/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	fv.on(http.MethodPost, "/Users", func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		writeJSON(w, http.StatusCreated, map[string]any{"id": "vault-fresh"})
	})

	st := newMemStore()
	u := newUser("carol@example.com")
	_ = st.SetExternalID(context.Background(), "vault", u.ID, "vault-stale")

	p := newClient(t, fv, st)
	if err := p.User(context.Background(), provision.OpUpdate, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}
	if !posted {
		t.Error("expected fall-through POST after 404")
	}
	got, _ := st.GetExternalID(context.Background(), "vault", u.ID)
	if got != "vault-fresh" {
		t.Errorf("cache = %q, want vault-fresh after self-heal", got)
	}
}

// ── User: deactivate via PATCH on cache miss → resolves via filter ────────────

func TestUserDeactivate_CacheMissResolvesViaFilter(t *testing.T) {
	fv := newFakeVault(t)
	var filterCalled, patchCalled bool

	fv.on(http.MethodGet, "/Users", func(w http.ResponseWriter, r *http.Request) {
		filterCalled = true
		f := r.URL.Query().Get("filter")
		if !strings.Contains(f, `externalId eq`) {
			t.Errorf("filter = %q", f)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"Resources":    []map[string]any{{"id": "vault-by-filter"}},
			"totalResults": 1,
		})
	})
	fv.on(http.MethodPatch, "/Users/vault-by-filter", func(w http.ResponseWriter, r *http.Request) {
		patchCalled = true
		var body struct {
			Operations []struct {
				Path  string
				Value bool
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Operations) != 1 || body.Operations[0].Path != "active" || body.Operations[0].Value {
			t.Errorf("PATCH ops = %+v", body.Operations)
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "vault-by-filter"})
	})

	st := newMemStore()
	u := newUser("dave@example.com")
	p := newClient(t, fv, st)

	if err := p.User(context.Background(), provision.OpDeactivate, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}
	if !filterCalled || !patchCalled {
		t.Errorf("filterCalled=%v patchCalled=%v, want both true", filterCalled, patchCalled)
	}
	if got, _ := st.GetExternalID(context.Background(), "vault", u.ID); got != "vault-by-filter" {
		t.Errorf("cache = %q, want vault-by-filter", got)
	}
}

// ── User: deactivate when downstream user doesn't exist is a no-op ────────────

func TestUserDeactivate_NotInDownstreamIsNoOp(t *testing.T) {
	fv := newFakeVault(t)
	fv.on(http.MethodGet, "/Users", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"Resources": []map[string]any{}, "totalResults": 0})
	})
	// No PATCH handler registered: any PATCH call would 404 from the dispatcher
	// (and propagate into errStatusNotFound). The test passes when no PATCH is made.

	p := newClient(t, newFakeVault(t), newMemStore()) // unused; placate compiler
	_ = p
	st := newMemStore()
	u := newUser("erin@example.com")
	p2 := newClient(t, fv, st)
	if err := p2.User(context.Background(), provision.OpDeactivate, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}
}

// ── User: delete invalidates cache ────────────────────────────────────────────

func TestUserDelete_RemovesCache(t *testing.T) {
	fv := newFakeVault(t)
	fv.on(http.MethodDelete, "/Users/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	st := newMemStore()
	u := newUser("frank@example.com")
	_ = st.SetExternalID(context.Background(), "vault", u.ID, "vault-frank")

	p := newClient(t, fv, st)
	if err := p.User(context.Background(), provision.OpDelete, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}
	if _, err := st.GetExternalID(context.Background(), "vault", u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cache = should be cleared, got err=%v", err)
	}
}

// ── User: delete on already-gone resource returns nil ─────────────────────────

func TestUserDelete_404IsTreatedAsSuccess(t *testing.T) {
	fv := newFakeVault(t)
	fv.on(http.MethodDelete, "/Users/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	st := newMemStore()
	u := newUser("gina@example.com")
	_ = st.SetExternalID(context.Background(), "vault", u.ID, "vault-stale")

	p := newClient(t, fv, st)
	if err := p.User(context.Background(), provision.OpDelete, u, nil); err != nil {
		t.Fatalf("User: %v", err)
	}
	if _, err := st.GetExternalID(context.Background(), "vault", u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cache should still be cleared after 404, got err=%v", err)
	}
}

// ── User: server error surfaces ───────────────────────────────────────────────

func TestUserCreate_ServerErrorReturned(t *testing.T) {
	fv := newFakeVault(t)
	fv.on(http.MethodPost, "/Users", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	p := newClient(t, fv, newMemStore())
	err := p.User(context.Background(), provision.OpCreate, newUser("hank@example.com"), nil)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want one mentioning 500", err)
	}
}

// ── Group: PUT addresses the group by its auth-side UUID ──────────────────────

func TestGroupUpsert_PutsByGroupUUIDWithExternalID(t *testing.T) {
	fv := newFakeVault(t)
	gID := uuid.New()
	var (
		put     map[string]any
		putPath string
	)
	fv.on(http.MethodPut, "/Groups/", func(w http.ResponseWriter, r *http.Request) {
		putPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&put)
		writeJSON(w, http.StatusOK, map[string]any{"id": gID.String()})
	})

	st := newMemStore()
	m1 := newUser("ivy@example.com")
	m2 := newUser("jack@example.com")
	_ = st.SetExternalID(context.Background(), "vault", m1.ID, "vault-ivy")
	_ = st.SetExternalID(context.Background(), "vault", m2.ID, "vault-jack")

	p := newClient(t, fv, st)
	g := &model.SCIMGroup{ID: gID, DisplayName: "Engineering"}

	if err := p.Group(context.Background(), provision.OpCreate, g, []*model.User{m1, m2}); err != nil {
		t.Fatalf("Group: %v", err)
	}
	if want := "/Groups/" + gID.String(); putPath != want {
		t.Errorf("put path = %q, want %q", putPath, want)
	}
	if put["externalId"] != gID.String() {
		t.Errorf("externalId = %v, want %s", put["externalId"], gID)
	}
	if put["displayName"] != "Engineering" {
		t.Errorf("displayName = %v", put["displayName"])
	}
	mems, _ := put["members"].([]any)
	if len(mems) != 2 {
		t.Fatalf("members = %v, want 2", mems)
	}
}

// ── Group: PUT 404 falls through to POST /Groups ──────────────────────────────

func TestGroupUpsert_404FallsThroughToPost(t *testing.T) {
	fv := newFakeVault(t)
	gID := uuid.New()
	fv.on(http.MethodPut, "/Groups/"+gID.String(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	posted := false
	fv.on(http.MethodPost, "/Groups", func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		writeJSON(w, http.StatusCreated, map[string]any{"id": gID.String()})
	})

	p := newClient(t, fv, newMemStore())
	g := &model.SCIMGroup{ID: gID, DisplayName: "Marketing"}
	if err := p.Group(context.Background(), provision.OpUpdate, g, nil); err != nil {
		t.Fatalf("Group: %v", err)
	}
	if !posted {
		t.Error("expected POST after PUT 404")
	}
}

// ── Group: delete addresses the group by its auth-side UUID ───────────────────

func TestGroupDelete_DeletesByGroupUUID(t *testing.T) {
	fv := newFakeVault(t)
	gID := uuid.New()
	deletedPath := ""
	fv.on(http.MethodDelete, "/Groups/", func(w http.ResponseWriter, r *http.Request) {
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	p := newClient(t, fv, newMemStore())
	g := &model.SCIMGroup{ID: gID, DisplayName: "Sales"}
	if err := p.Group(context.Background(), provision.OpDelete, g, nil); err != nil {
		t.Fatalf("Group: %v", err)
	}
	if want := "/Groups/" + gID.String(); deletedPath != want {
		t.Errorf("delete path = %q, want %q", deletedPath, want)
	}
}

// ── Provisioner.Name ──────────────────────────────────────────────────────────

func TestName_Default(t *testing.T) {
	p := scimprov.New(scimprov.Config{Store: newMemStore()})
	if p.Name() != "vault-scim" {
		t.Errorf("Name = %q", p.Name())
	}
}
