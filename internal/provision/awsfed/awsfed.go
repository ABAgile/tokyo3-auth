// Package awsfed is the AWS OIDC federation revocation provisioner. Unlike
// `iam`, it does NOT create AWS IAM users — the federation model is
// credential-less and identity-less in AWS (every login produces a fresh STS
// session, no per-user IAM row). The provisioner's only job is to update each
// federation role's "AuthRevokedUsers" inline policy so STS sessions for a
// deactivated user immediately fail their next API call (≤30s policy
// propagation), rather than waiting up to MaxSessionDuration for natural
// expiry.
//
// Required IAM permissions on the principal authd runs as:
//
//	iam:GetRolePolicy   on each managed role
//	iam:PutRolePolicy   on each managed role
//	iam:DeleteRolePolicy on each managed role  (only when the list shrinks to empty)
//
// Credentials come from the AWS SDK's default chain (instance profile, IRSA,
// task role, IAM Roles Anywhere) — never static keys. The provisioner picks
// up whichever credential source the deployment platform attaches.
package awsfed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/google/uuid"
)

// RevocationPolicyName is the inline-policy name auth manages on each
// federation role. Distinct from any other inline policies the role may
// carry, so operators can edit those independently.
const RevocationPolicyName = "AuthRevokedUsers"

// SessionTagKey is the session-tag key carried via AssumeRoleWithWebIdentity
// that the role's revocation policy keys on. Matching value is the user's
// auth-side UUID, set by the federation handler at AssumeRole time.
const SessionTagKey = "sub"

// Store is the subset of store.Store the provisioner needs at runtime.
// Lifting it to an interface keeps the package independent of the concrete
// backend and makes unit testing straightforward.
type Store interface {
	ListAWSRoles(ctx context.Context) ([]*model.AWSRole, error)
	GetAWSRole(ctx context.Context, id uuid.UUID) (*model.AWSRole, error)
	AddAWSRevokedUser(ctx context.Context, roleID uuid.UUID, subUUID string) error
	ListAWSRevokedUsers(ctx context.Context, roleID uuid.UUID) ([]*model.AWSRevokedUser, error)
	ListAWSRevokedUsersOlderThan(ctx context.Context, cutoff time.Time) ([]*model.AWSRevokedUser, error)
	DeleteAWSRevokedUser(ctx context.Context, roleID uuid.UUID, subUUID string) error
}

// IAMAPI is the minimal IAM client surface the provisioner uses. Matches
// what iam.Client exposes — defining it as an interface allows mock-driven
// tests without bringing up real AWS.
type IAMAPI interface {
	GetRolePolicy(ctx context.Context, in *iam.GetRolePolicyInput, opts ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	PutRolePolicy(ctx context.Context, in *iam.PutRolePolicyInput, opts ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error)
	DeleteRolePolicy(ctx context.Context, in *iam.DeleteRolePolicyInput, opts ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error)
}

// Provisioner implements provision.Provisioner for AWS OIDC federation.
type Provisioner struct {
	name   string
	client IAMAPI
	store  Store
	log    *slog.Logger
}

// New constructs a Provisioner using the SDK's default credential chain.
// Pass empty name for the default "aws-federation". The IAM client is
// configured once at construction; credential refresh is handled by the
// SDK transparently (IMDS / IRSA token rotation, etc.).
func New(ctx context.Context, name string, st Store, log *slog.Logger) (*Provisioner, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if name == "" {
		name = "aws-federation"
	}
	return &Provisioner{
		name:   name,
		client: iam.NewFromConfig(cfg),
		store:  st,
		log:    log,
	}, nil
}

// NewWithClient is the test seam: inject a mock IAMAPI directly.
func NewWithClient(name string, client IAMAPI, st Store, log *slog.Logger) *Provisioner {
	if name == "" {
		name = "aws-federation"
	}
	return &Provisioner{name: name, client: client, store: st, log: log}
}

// Name implements provision.Provisioner.
func (p *Provisioner) Name() string { return p.name }

// User implements provision.Provisioner. Only OpDeactivate and OpDelete do
// work — federation never creates AWS-side identities. OpUpdate is a no-op:
// the user's session tags will pick up new attributes (email, name, groups)
// on the next AssumeRoleWithWebIdentity, nothing to push.
func (p *Provisioner) User(ctx context.Context, op provision.Op, u *model.User, _ []string) error {
	switch op {
	case provision.OpCreate, provision.OpUpdate:
		return nil
	case provision.OpDeactivate, provision.OpDelete:
		return p.RevokeUser(ctx, u.ID.String())
	}
	return fmt.Errorf("awsfed: unknown op %v", op)
}

// RevokeUser pushes subUUID onto every managed role's AuthRevokedUsers
// inline policy. Exported so admin handlers can trigger per-user
// revocation independently of the full deactivation fan-out — the
// "Revoke AWS sessions" portal button calls this directly without
// flipping User.Active or invoking any other provisioner. The semantic
// is "kick current STS sessions"; the user can re-authenticate to auth
// and federate again immediately, which is the right behaviour for
// lost-laptop scenarios where you want to invalidate stale credentials
// but not lock the account.
//
// Idempotent on the bookkeeping side: re-revoking a user just refreshes
// their revoked_at timestamp, restarting the reaper's window.
func (p *Provisioner) RevokeUser(ctx context.Context, subUUID string) error {
	return p.revokeAcrossAllRoles(ctx, subUUID)
}

// Group implements provision.Provisioner. Federation has no group-shaped
// AWS state — group → role mapping is auth-side (aws_role_assignments),
// queried at federation time. Nothing to fan out.
func (p *Provisioner) Group(ctx context.Context, op provision.Op, g *model.SCIMGroup, _ []*model.User) error {
	return nil
}

// revokeAcrossAllRoles adds subUUID to every managed role's
// AuthRevokedUsers Deny statement. Per-role failures are logged and the
// loop continues — best-effort to maximise the kill surface. The store-side
// record is added first; if AWS PutRolePolicy fails the reaper will retry
// on the next periodic sweep (it walks store rows, not AWS state).
func (p *Provisioner) revokeAcrossAllRoles(ctx context.Context, subUUID string) error {
	roles, err := p.store.ListAWSRoles(ctx)
	if err != nil {
		return fmt.Errorf("awsfed: list roles: %w", err)
	}
	var firstErr error
	for _, role := range roles {
		if err := p.revokeOneRole(ctx, role, subUUID); err != nil {
			if p.log != nil {
				p.log.Error("awsfed: revoke user",
					"role", role.RoleARN, "sub", subUUID, "err", err)
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if p.log != nil {
			p.log.Info("awsfed: revoked user",
				"role", role.RoleARN, "sub", subUUID)
		}
	}
	return firstErr
}

// revokeOneRole adds subUUID to the role's AuthRevokedUsers inline policy
// and persists the bookkeeping entry. Idempotent: re-revoking is safe.
func (p *Provisioner) revokeOneRole(ctx context.Context, role *model.AWSRole, subUUID string) error {
	if err := p.store.AddAWSRevokedUser(ctx, role.ID, subUUID); err != nil {
		return fmt.Errorf("persist revocation: %w", err)
	}
	subs, err := p.collectActiveRevokedSubs(ctx, role.ID)
	if err != nil {
		return err
	}
	policyDoc, err := BuildRevocationPolicy(subs)
	if err != nil {
		return err
	}
	roleName := RoleNameFromARN(role.RoleARN)
	if roleName == "" {
		return fmt.Errorf("invalid role_arn %q (cannot extract role name)", role.RoleARN)
	}
	_, err = p.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(RevocationPolicyName),
		PolicyDocument: aws.String(policyDoc),
	})
	if err != nil {
		return fmt.Errorf("iam:PutRolePolicy %s: %w", role.RoleARN, err)
	}
	return nil
}

// collectActiveRevokedSubs returns the sorted set of revoked subs for a
// role. Sorted so re-running with the same input produces byte-identical
// policy documents — important for change detection and audit clarity.
func (p *Provisioner) collectActiveRevokedSubs(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	rows, err := p.store.ListAWSRevokedUsers(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("list revoked users: %w", err)
	}
	subs := make([]string, 0, len(rows))
	for _, r := range rows {
		subs = append(subs, r.SubUUID)
	}
	sort.Strings(subs)
	return subs, nil
}

// ReapExpired removes revocation entries whose age exceeds the role's
// MaxSessionDurationSec — by then every session blocked by the Deny
// statement has expired naturally, so the entry's only effect is cluttering
// the inline policy (and bumping it toward IAM's 10 KB inline-policy size
// limit). For each role whose list shrinks, the inline policy is re-pushed;
// when the list reaches empty the policy is deleted entirely. Safe to call
// concurrently with User(OpDeactivate) — the underlying store ops are
// independent.
func (p *Provisioner) ReapExpired(ctx context.Context, now time.Time) error {
	roles, err := p.store.ListAWSRoles(ctx)
	if err != nil {
		return fmt.Errorf("awsfed: reap list roles: %w", err)
	}
	for _, role := range roles {
		// MaxSessionDurationSec defaults to 3600 in the schema; tolerate 0
		// defensively (treat as 1h).
		dur := time.Duration(role.MaxSessionDurationSec) * time.Second
		if dur <= 0 {
			dur = time.Hour
		}
		cutoff := now.Add(-dur)
		expired, err := p.store.ListAWSRevokedUsers(ctx, role.ID)
		if err != nil {
			if p.log != nil {
				p.log.Error("awsfed: reap list revoked", "role", role.RoleARN, "err", err)
			}
			continue
		}
		removed := 0
		for _, e := range expired {
			if e.RevokedAt.Before(cutoff) {
				if err := p.store.DeleteAWSRevokedUser(ctx, role.ID, e.SubUUID); err != nil {
					if p.log != nil {
						p.log.Warn("awsfed: reap delete row",
							"role", role.RoleARN, "sub", e.SubUUID, "err", err)
					}
					continue
				}
				removed++
			}
		}
		if removed == 0 {
			continue
		}
		// Re-collect the trimmed set and push (or delete the policy if empty).
		subs, err := p.collectActiveRevokedSubs(ctx, role.ID)
		if err != nil {
			if p.log != nil {
				p.log.Error("awsfed: reap rebuild policy", "role", role.RoleARN, "err", err)
			}
			continue
		}
		roleName := RoleNameFromARN(role.RoleARN)
		if roleName == "" {
			continue
		}
		if len(subs) == 0 {
			_, err := p.client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(RevocationPolicyName),
			})
			// NoSuchEntity is acceptable — the policy may already be gone
			// (e.g. operator deleted it manually).
			var nseErr *iamtypes.NoSuchEntityException
			if err != nil && !errors.As(err, &nseErr) {
				if p.log != nil {
					p.log.Error("awsfed: reap delete policy", "role", role.RoleARN, "err", err)
				}
				continue
			}
			if p.log != nil {
				p.log.Info("awsfed: reap emptied policy", "role", role.RoleARN, "removed", removed)
			}
			continue
		}
		policyDoc, err := BuildRevocationPolicy(subs)
		if err != nil {
			if p.log != nil {
				p.log.Error("awsfed: reap build policy", "role", role.RoleARN, "err", err)
			}
			continue
		}
		_, err = p.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			RoleName:       aws.String(roleName),
			PolicyName:     aws.String(RevocationPolicyName),
			PolicyDocument: aws.String(policyDoc),
		})
		if err != nil {
			if p.log != nil {
				p.log.Error("awsfed: reap put policy", "role", role.RoleARN, "err", err)
			}
			continue
		}
		if p.log != nil {
			p.log.Info("awsfed: reap pruned policy",
				"role", role.RoleARN, "removed", removed, "remaining", len(subs))
		}
	}
	return nil
}

// ── policy + ARN helpers ──────────────────────────────────────────────────────

// BuildRevocationPolicy returns an IAM policy document JSON denying all
// actions for sessions whose `sub` session tag is in subs. Sorted-input,
// deterministic-output — the same set of subs always produces the same
// document byte-for-byte so AWS PutRolePolicy is a true no-op when the set
// hasn't changed (avoids spurious CloudTrail noise).
//
// Empty subs returns an empty document — the caller is expected to delete
// the inline policy instead of pushing an empty-list document, since an
// empty `StringEquals` value would match nothing and be confusing in audit.
func BuildRevocationPolicy(subs []string) (string, error) {
	if len(subs) == 0 {
		return "", fmt.Errorf("awsfed: empty revocation set (caller should DeleteRolePolicy instead)")
	}
	type cond struct {
		StringEquals map[string][]string `json:"StringEquals"`
	}
	type stmt struct {
		Sid       string   `json:"Sid"`
		Effect    string   `json:"Effect"`
		Action    []string `json:"Action"`
		Resource  []string `json:"Resource"`
		Condition cond     `json:"Condition"`
	}
	type doc struct {
		Version   string `json:"Version"`
		Statement []stmt `json:"Statement"`
	}
	d := doc{
		Version: "2012-10-17",
		Statement: []stmt{{
			Sid:      "AuthRevokedUsers",
			Effect:   "Deny",
			Action:   []string{"*"},
			Resource: []string{"*"},
			Condition: cond{
				StringEquals: map[string][]string{
					"aws:PrincipalTag/" + SessionTagKey: subs,
				},
			},
		}},
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("marshal revocation policy: %w", err)
	}
	return string(b), nil
}

// RoleNameFromARN extracts the trailing role name from a role ARN like
// arn:aws:iam::123456789012:role/PlatformAdmin. Returns empty on malformed
// input; callers treat empty as a hard error and skip the AWS call.
func RoleNameFromARN(arn string) string {
	// Cheap split: roleName is everything after the last '/'. Avoids pulling
	// in arn.Parse for a one-line operation.
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == '/' {
			return arn[i+1:]
		}
	}
	return ""
}
