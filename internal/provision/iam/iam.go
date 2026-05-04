// Package iam is the AWS IAM provisioner. It implements provision.Provisioner
// by mapping auth's users/groups to IAM users/groups, tagging managed users,
// and revoking access keys + group memberships on deactivation.
package iam

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
)

// Provisioner provisions AWS IAM users and manages group membership.
type Provisioner struct {
	name     string
	client   *iam.Client
	log      *slog.Logger
	GroupMap map[string]string // SCIM group display name → IAM group name
}

// New returns a Provisioner using the default AWS credential chain. name is
// surfaced via Name() and identifies the integration row in audit/log output;
// pass empty for the default "aws-iam".
func New(ctx context.Context, name string, groupMap map[string]string, log *slog.Logger) (*Provisioner, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if name == "" {
		name = "aws-iam"
	}
	return &Provisioner{
		name:     name,
		client:   iam.NewFromConfig(cfg),
		log:      log,
		GroupMap: groupMap,
	}, nil
}

// Name implements provision.Provisioner.
func (p *Provisioner) Name() string { return p.name }

// User implements provision.Provisioner. IAM usernames are the local-part of
// the user's email (everything before the first '@').
func (p *Provisioner) User(ctx context.Context, op provision.Op, u *model.User, groups []string) error {
	username := strings.SplitN(u.Email, "@", 2)[0]
	switch op {
	case provision.OpCreate:
		return p.createUser(ctx, username, groups)
	case provision.OpUpdate:
		return p.updateUser(ctx, username)
	case provision.OpDeactivate:
		return p.deactivateUser(ctx, username)
	case provision.OpDelete:
		return p.deleteUser(ctx, username)
	}
	return fmt.Errorf("iam: unknown op %v", op)
}

// Group implements provision.Provisioner. IAM has no concept of "delete a
// group of users" — only EnsureGroup on create is meaningful here. Membership
// changes flow through User() with the groups slice.
func (p *Provisioner) Group(ctx context.Context, op provision.Op, g *model.SCIMGroup, _ []*model.User) error {
	if op != provision.OpCreate {
		return nil
	}
	return p.EnsureGroup(ctx, g.DisplayName)
}

// createUser creates an IAM user and adds them to the mapped groups.
func (p *Provisioner) createUser(ctx context.Context, username string, scimGroups []string) error {
	_, err := p.client.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String(username),
		Tags:     []types.Tag{{Key: aws.String("ManagedBy"), Value: aws.String("tokyo3-auth")}},
	})
	if err != nil {
		return fmt.Errorf("iam create user %s: %w", username, err)
	}
	for _, g := range scimGroups {
		if err := p.addToGroup(ctx, username, g); err != nil {
			p.log.Error("iam add to group", "user", username, "group", g, "err", err)
		}
	}
	return nil
}

// updateUser re-applies tags (username is immutable in IAM).
func (p *Provisioner) updateUser(ctx context.Context, username string) error {
	_, err := p.client.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String(username),
		Tags:     []types.Tag{{Key: aws.String("ManagedBy"), Value: aws.String("tokyo3-auth")}},
	})
	if err != nil {
		return fmt.Errorf("iam tag user %s: %w", username, err)
	}
	return nil
}

// deactivateUser revokes all access keys and removes the user from all groups.
func (p *Provisioner) deactivateUser(ctx context.Context, username string) error {
	if err := p.revokeAccessKeys(ctx, username); err != nil {
		return err
	}
	return p.removeFromAllGroups(ctx, username)
}

// deleteUser deactivates and then deletes the IAM user.
func (p *Provisioner) deleteUser(ctx context.Context, username string) error {
	_ = p.deactivateUser(ctx, username)
	_, err := p.client.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(username)})
	if err != nil {
		return fmt.Errorf("iam delete user %s: %w", username, err)
	}
	return nil
}

// EnsureGroup creates the IAM group if it does not already exist.
func (p *Provisioner) EnsureGroup(ctx context.Context, groupName string) error {
	_, err := p.client.CreateGroup(ctx, &iam.CreateGroupInput{GroupName: aws.String(groupName)})
	// EntityAlreadyExists is acceptable.
	if err != nil {
		p.log.Info("iam ensure group (may already exist)", "group", groupName, "err", err)
	}
	return nil
}

func (p *Provisioner) addToGroup(ctx context.Context, username, scimGroup string) error {
	iamGroup, ok := p.GroupMap[scimGroup]
	if !ok {
		return nil
	}
	_, err := p.client.AddUserToGroup(ctx, &iam.AddUserToGroupInput{
		UserName:  aws.String(username),
		GroupName: aws.String(iamGroup),
	})
	return err
}

func (p *Provisioner) revokeAccessKeys(ctx context.Context, username string) error {
	out, err := p.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(username)})
	if err != nil {
		return fmt.Errorf("iam list access keys for %s: %w", username, err)
	}
	for _, k := range out.AccessKeyMetadata {
		if _, err := p.client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName:    aws.String(username),
			AccessKeyId: k.AccessKeyId,
		}); err != nil {
			p.log.Error("iam delete access key", "user", username, "key", aws.ToString(k.AccessKeyId), "err", err)
		}
	}
	return nil
}

func (p *Provisioner) removeFromAllGroups(ctx context.Context, username string) error {
	out, err := p.client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: aws.String(username)})
	if err != nil {
		return fmt.Errorf("iam list groups for %s: %w", username, err)
	}
	for _, g := range out.Groups {
		if _, err := p.client.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{
			UserName:  aws.String(username),
			GroupName: g.GroupName,
		}); err != nil {
			p.log.Error("iam remove from group", "user", username, "group", aws.ToString(g.GroupName), "err", err)
		}
	}
	return nil
}
