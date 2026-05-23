package awsfed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/google/uuid"
)

// fakeIAM captures the most recent Put/Delete call shape so tests can
// assert exactly what would have been sent to AWS.
type fakeIAM struct {
	mu          sync.Mutex
	putCalls    []iam.PutRolePolicyInput
	deleteCalls []iam.DeleteRolePolicyInput
	failPut     bool
	failDelete  bool
}

func (f *fakeIAM) GetRolePolicy(_ context.Context, _ *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return nil, &iamtypes.NoSuchEntityException{}
}
func (f *fakeIAM) PutRolePolicy(_ context.Context, in *iam.PutRolePolicyInput, _ ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPut {
		return nil, errors.New("put boom")
	}
	f.putCalls = append(f.putCalls, *in)
	return &iam.PutRolePolicyOutput{}, nil
}
func (f *fakeIAM) DeleteRolePolicy(_ context.Context, in *iam.DeleteRolePolicyInput, _ ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete {
		return nil, errors.New("delete boom")
	}
	f.deleteCalls = append(f.deleteCalls, *in)
	return &iam.DeleteRolePolicyOutput{}, nil
}

// memStore is an in-memory Store implementation for tests.
type memStore struct {
	roles   []*model.AWSRole
	revoked map[uuid.UUID]map[string]time.Time
}

func newMemStore(roles ...*model.AWSRole) *memStore {
	return &memStore{roles: roles, revoked: map[uuid.UUID]map[string]time.Time{}}
}
func (m *memStore) ListAWSRoles(_ context.Context) ([]*model.AWSRole, error) { return m.roles, nil }
func (m *memStore) GetAWSRole(_ context.Context, id uuid.UUID) (*model.AWSRole, error) {
	for _, r := range m.roles {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *memStore) AddAWSRevokedUser(_ context.Context, roleID uuid.UUID, sub string) error {
	if m.revoked[roleID] == nil {
		m.revoked[roleID] = map[string]time.Time{}
	}
	m.revoked[roleID][sub] = time.Now()
	return nil
}
func (m *memStore) ListAWSRevokedUsers(_ context.Context, roleID uuid.UUID) ([]*model.AWSRevokedUser, error) {
	out := []*model.AWSRevokedUser{}
	for s, t := range m.revoked[roleID] {
		out = append(out, &model.AWSRevokedUser{RoleID: roleID, SubUUID: s, RevokedAt: t})
	}
	return out, nil
}
func (m *memStore) ListAWSRevokedUsersOlderThan(_ context.Context, cutoff time.Time) ([]*model.AWSRevokedUser, error) {
	var out []*model.AWSRevokedUser
	for rid, subs := range m.revoked {
		for s, t := range subs {
			if t.Before(cutoff) {
				out = append(out, &model.AWSRevokedUser{RoleID: rid, SubUUID: s, RevokedAt: t})
			}
		}
	}
	return out, nil
}
func (m *memStore) DeleteAWSRevokedUser(_ context.Context, roleID uuid.UUID, sub string) error {
	if subs := m.revoked[roleID]; subs != nil {
		delete(subs, sub)
	}
	return nil
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRoleNameFromARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::111111111111:role/PlatformAdmin": "PlatformAdmin",
		"arn:aws:iam::111111111111:role/path/Nested":   "Nested",
		"": "",
		"arn:aws:iam::111111111111:user/notarole":            "notarole", // permissive — caller still validates
		"arn:aws:iam::111111111111:role/with-dashes-allowed": "with-dashes-allowed",
	}
	for in, want := range cases {
		if got := RoleNameFromARN(in); got != want {
			t.Errorf("RoleNameFromARN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildRevocationPolicy_DeterministicShape(t *testing.T) {
	subs := []string{"a-uuid", "b-uuid", "c-uuid"}
	doc, err := BuildRevocationPolicy(subs)
	if err != nil {
		t.Fatalf("BuildRevocationPolicy: %v", err)
	}
	// Parse the JSON back so we can inspect the structure precisely without
	// brittle substring matching.
	var parsed struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string   `json:"Sid"`
			Effect    string   `json:"Effect"`
			Action    []string `json:"Action"`
			Resource  []string `json:"Resource"`
			Condition struct {
				StringEquals map[string][]string `json:"StringEquals"`
			} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Version != "2012-10-17" {
		t.Errorf("Version = %q, want 2012-10-17", parsed.Version)
	}
	if len(parsed.Statement) != 1 {
		t.Fatalf("Statement count = %d, want 1", len(parsed.Statement))
	}
	st := parsed.Statement[0]
	if st.Effect != "Deny" {
		t.Errorf("Effect = %q, want Deny", st.Effect)
	}
	if st.Sid != "AuthRevokedUsers" {
		t.Errorf("Sid = %q, want AuthRevokedUsers", st.Sid)
	}
	if len(st.Action) != 1 || st.Action[0] != "*" {
		t.Errorf("Action = %v, want [*]", st.Action)
	}
	gotSubs := st.Condition.StringEquals["aws:PrincipalTag/sub"]
	if len(gotSubs) != 3 {
		t.Fatalf("subs len = %d, want 3", len(gotSubs))
	}
	for i, want := range subs {
		if gotSubs[i] != want {
			t.Errorf("subs[%d] = %q, want %q", i, gotSubs[i], want)
		}
	}
}

func TestBuildRevocationPolicy_EmptyIsError(t *testing.T) {
	if _, err := BuildRevocationPolicy(nil); err == nil {
		t.Error("empty subs should return error so caller deletes the policy instead")
	}
}

func TestUser_DeactivatePushesToEveryRole(t *testing.T) {
	roleA := &model.AWSRole{ID: uuid.New(), RoleARN: "arn:aws:iam::111:role/A", MaxSessionDurationSec: 3600}
	roleB := &model.AWSRole{ID: uuid.New(), RoleARN: "arn:aws:iam::111:role/B", MaxSessionDurationSec: 3600}
	st := newMemStore(roleA, roleB)
	fake := &fakeIAM{}
	p := NewWithClient("test", fake, st, discardLog())

	u := &model.User{ID: uuid.New(), Email: "alice@example.com"}
	if err := p.User(context.Background(), provision.OpDeactivate, u, nil); err != nil {
		t.Fatalf("User(OpDeactivate): %v", err)
	}
	if len(fake.putCalls) != 2 {
		t.Fatalf("PutRolePolicy calls = %d, want 2", len(fake.putCalls))
	}
	// Each call must carry the sub UUID in the policy doc.
	for _, c := range fake.putCalls {
		if c.PolicyName == nil || *c.PolicyName != RevocationPolicyName {
			t.Errorf("PolicyName = %v, want %q", c.PolicyName, RevocationPolicyName)
		}
		if c.PolicyDocument == nil || !strings.Contains(*c.PolicyDocument, u.ID.String()) {
			t.Errorf("PolicyDocument missing sub UUID: %v", c.PolicyDocument)
		}
	}
}

func TestUser_OpCreateAndUpdateAreNoOps(t *testing.T) {
	st := newMemStore(&model.AWSRole{ID: uuid.New(), RoleARN: "arn:aws:iam::111:role/X", MaxSessionDurationSec: 3600})
	fake := &fakeIAM{}
	p := NewWithClient("test", fake, st, discardLog())
	u := &model.User{ID: uuid.New(), Email: "bob@example.com"}
	for _, op := range []provision.Op{provision.OpCreate, provision.OpUpdate} {
		if err := p.User(context.Background(), op, u, nil); err != nil {
			t.Errorf("User(%v): %v", op, err)
		}
	}
	if len(fake.putCalls) != 0 {
		t.Errorf("expected no PutRolePolicy calls for Create/Update, got %d", len(fake.putCalls))
	}
}

func TestUser_DeleteRevokes(t *testing.T) {
	role := &model.AWSRole{ID: uuid.New(), RoleARN: "arn:aws:iam::111:role/A", MaxSessionDurationSec: 3600}
	st := newMemStore(role)
	fake := &fakeIAM{}
	p := NewWithClient("test", fake, st, discardLog())
	u := &model.User{ID: uuid.New(), Email: "deleted@example.com"}
	if err := p.User(context.Background(), provision.OpDelete, u, nil); err != nil {
		t.Fatalf("User(OpDelete): %v", err)
	}
	if len(fake.putCalls) != 1 {
		t.Errorf("PutRolePolicy calls = %d, want 1", len(fake.putCalls))
	}
}

func TestReapExpired_DeletesPolicyWhenAllExpired(t *testing.T) {
	role := &model.AWSRole{
		ID:                    uuid.New(),
		RoleARN:               "arn:aws:iam::111:role/Old",
		MaxSessionDurationSec: 60, // tiny so we can synthesise an expired entry
	}
	st := newMemStore(role)
	st.revoked[role.ID] = map[string]time.Time{"old-sub": time.Now().Add(-2 * time.Hour)}
	fake := &fakeIAM{}
	p := NewWithClient("test", fake, st, discardLog())

	if err := p.ReapExpired(context.Background(), time.Now()); err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if len(fake.deleteCalls) != 1 {
		t.Errorf("DeleteRolePolicy calls = %d, want 1 (set reaped to empty)", len(fake.deleteCalls))
	}
	if got := fake.deleteCalls[0].PolicyName; got == nil || *got != RevocationPolicyName {
		t.Errorf("DeleteRolePolicy.PolicyName = %v, want %q", got, RevocationPolicyName)
	}
	if _, still := st.revoked[role.ID]["old-sub"]; still {
		t.Errorf("expected old-sub to be deleted from store after reap")
	}
}

func TestReapExpired_RepushesShorterList(t *testing.T) {
	role := &model.AWSRole{
		ID:                    uuid.New(),
		RoleARN:               "arn:aws:iam::111:role/Mixed",
		MaxSessionDurationSec: 60,
	}
	st := newMemStore(role)
	st.revoked[role.ID] = map[string]time.Time{
		"old-sub":   time.Now().Add(-2 * time.Hour), // past cutoff → reaped
		"fresh-sub": time.Now(),                     // future cutoff → retained
	}
	fake := &fakeIAM{}
	p := NewWithClient("test", fake, st, discardLog())

	if err := p.ReapExpired(context.Background(), time.Now()); err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	// Should re-push the policy with just the fresh sub.
	if len(fake.putCalls) != 1 {
		t.Fatalf("PutRolePolicy calls = %d, want 1", len(fake.putCalls))
	}
	if doc := fake.putCalls[0].PolicyDocument; doc == nil ||
		!strings.Contains(*doc, "fresh-sub") ||
		strings.Contains(*doc, "old-sub") {
		t.Errorf("doc shape unexpected: %s", *doc)
	}
}
