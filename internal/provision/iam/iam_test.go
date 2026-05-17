package iam

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
)

func newTestProvisioner(name string) *Provisioner {
	// client is left nil deliberately — every test below exercises a code
	// path that returns before any AWS call.
	return &Provisioner{
		name:     name,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		GroupMap: map[string]string{"engineers": "eng-iam"},
	}
}

func TestName_Configured(t *testing.T) {
	p := newTestProvisioner("acme-iam")
	if p.Name() != "acme-iam" {
		t.Errorf("Name() = %q, want acme-iam", p.Name())
	}
}

func TestUser_UnknownOpReturnsError(t *testing.T) {
	p := newTestProvisioner("aws-iam")
	u := &model.User{Email: "alice@example.com"}
	err := p.User(context.Background(), provision.Op(99), u, nil)
	if err == nil {
		t.Error("unknown op should error")
	}
}

func TestGroup_OpsOtherThanCreateAreNoOps(t *testing.T) {
	p := newTestProvisioner("aws-iam")
	g := &model.SCIMGroup{DisplayName: "engineers"}

	// Update / Deactivate / Delete return nil without touching the IAM client.
	for _, op := range []provision.Op{provision.OpUpdate, provision.OpDeactivate, provision.OpDelete} {
		if err := p.Group(context.Background(), op, g, nil); err != nil {
			t.Errorf("Group(%v) should be no-op, got %v", op, err)
		}
	}
}
