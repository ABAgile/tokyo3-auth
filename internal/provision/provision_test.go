package provision_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/google/uuid"
)

type recorder struct {
	name      string
	userCalls []provision.Op
	groupCall []provision.Op
	userErr   error
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) User(_ context.Context, op provision.Op, _ *model.User, _ []string) error {
	r.userCalls = append(r.userCalls, op)
	return r.userErr
}
func (r *recorder) Group(_ context.Context, op provision.Op, _ *model.SCIMGroup, _ []*model.User) error {
	r.groupCall = append(r.groupCall, op)
	return nil
}

func TestSet_NilReceiverIsNoOp(t *testing.T) {
	var s *provision.Set
	s.User(context.Background(), provision.OpCreate, &model.User{}, nil)
	s.Group(context.Background(), provision.OpCreate, &model.SCIMGroup{}, nil)
}

func TestSet_FansOutToEveryProvisioner(t *testing.T) {
	a := &recorder{name: "a"}
	b := &recorder{name: "b"}
	s := &provision.Set{
		Provisioners: []provision.Provisioner{a, b},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	u := &model.User{ID: uuid.New(), Email: "alice@example.com"}
	s.User(context.Background(), provision.OpCreate, u, nil)
	s.User(context.Background(), provision.OpDeactivate, u, nil)

	if got := []provision.Op{provision.OpCreate, provision.OpDeactivate}; !equalOps(a.userCalls, got) {
		t.Errorf("a.userCalls = %v, want %v", a.userCalls, got)
	}
	if got := []provision.Op{provision.OpCreate, provision.OpDeactivate}; !equalOps(b.userCalls, got) {
		t.Errorf("b.userCalls = %v, want %v", b.userCalls, got)
	}
}

func TestSet_LogsErrorAndContinues(t *testing.T) {
	a := &recorder{name: "a", userErr: errors.New("boom")}
	b := &recorder{name: "b"}
	s := &provision.Set{
		Provisioners: []provision.Provisioner{a, b},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	u := &model.User{Email: "x@y.z"}
	s.User(context.Background(), provision.OpCreate, u, nil)

	if len(b.userCalls) != 1 {
		t.Errorf("b should still have been called even though a failed; got %d calls", len(b.userCalls))
	}
}

func TestSet_NilUserOrGroupSkips(t *testing.T) {
	a := &recorder{name: "a"}
	s := &provision.Set{
		Provisioners: []provision.Provisioner{a},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s.User(context.Background(), provision.OpCreate, nil, nil)
	s.Group(context.Background(), provision.OpCreate, nil, nil)
	if len(a.userCalls) != 0 || len(a.groupCall) != 0 {
		t.Errorf("expected no calls; got user=%d group=%d", len(a.userCalls), len(a.groupCall))
	}
}

func TestOpString(t *testing.T) {
	cases := map[provision.Op]string{
		provision.OpCreate:     "create",
		provision.OpUpdate:     "update",
		provision.OpDeactivate: "deactivate",
		provision.OpDelete:     "delete",
		provision.Op(99):       "unknown",
	}
	for op, want := range cases {
		if got := op.String(); got != want {
			t.Errorf("Op(%d).String() = %q, want %q", op, got, want)
		}
	}
}

func equalOps(a, b []provision.Op) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
