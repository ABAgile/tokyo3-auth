// Package aws handles AWS IAM user and group provisioning triggered by SCIM events.
package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAMProvisioner provisions AWS IAM users and manages group membership.
type IAMProvisioner struct {
	client   *iam.Client
	log      *slog.Logger
	GroupMap map[string]string // SCIM group display name → IAM group name
}

// NewIAMProvisioner creates a provisioner using the default AWS credential chain.
func NewIAMProvisioner(ctx context.Context, groupMap map[string]string, log *slog.Logger) (*IAMProvisioner, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return &IAMProvisioner{
		client:   iam.NewFromConfig(cfg),
		log:      log,
		GroupMap: groupMap,
	}, nil
}

// CreateUser creates an IAM user and adds them to the mapped groups.
func (p *IAMProvisioner) CreateUser(ctx context.Context, username string, scimGroups []string) error {
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

// UpdateUser re-applies tags (username is immutable in IAM).
func (p *IAMProvisioner) UpdateUser(ctx context.Context, username string) error {
	_, err := p.client.TagUser(ctx, &iam.TagUserInput{
		UserName: aws.String(username),
		Tags:     []types.Tag{{Key: aws.String("ManagedBy"), Value: aws.String("tokyo3-auth")}},
	})
	if err != nil {
		return fmt.Errorf("iam tag user %s: %w", username, err)
	}
	return nil
}

// DeactivateUser revokes all access keys and removes the user from all groups.
func (p *IAMProvisioner) DeactivateUser(ctx context.Context, username string) error {
	if err := p.revokeAccessKeys(ctx, username); err != nil {
		return err
	}
	return p.removeFromAllGroups(ctx, username)
}

// DeleteUser deactivates and then deletes the IAM user.
func (p *IAMProvisioner) DeleteUser(ctx context.Context, username string) error {
	_ = p.DeactivateUser(ctx, username)
	_, err := p.client.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(username)})
	if err != nil {
		return fmt.Errorf("iam delete user %s: %w", username, err)
	}
	return nil
}

// EnsureGroup creates the IAM group if it does not already exist.
func (p *IAMProvisioner) EnsureGroup(ctx context.Context, groupName string) error {
	_, err := p.client.CreateGroup(ctx, &iam.CreateGroupInput{GroupName: aws.String(groupName)})
	// EntityAlreadyExists is acceptable.
	if err != nil {
		p.log.Info("iam ensure group (may already exist)", "group", groupName, "err", err)
	}
	return nil
}

func (p *IAMProvisioner) addToGroup(ctx context.Context, username, scimGroup string) error {
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

func (p *IAMProvisioner) revokeAccessKeys(ctx context.Context, username string) error {
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

func (p *IAMProvisioner) removeFromAllGroups(ctx context.Context, username string) error {
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
