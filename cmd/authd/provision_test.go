package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
)

func TestBuildProvisionerSupportedProviders(t *testing.T) {
	// Construction must not depend on a developer's AWS profile or metadata.
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, provider := range []string{model.AppIntegrationProviderSCIM, model.AppIntegrationProviderAWSFederation} {
		t.Run(provider, func(t *testing.T) {
			row := &model.AppIntegration{
				Name: provider, Provider: provider,
				Config: model.AppIntegrationConfig{BaseURL: "https://scim.example/scim/v2", AuthMode: model.AppIntegrationAuthMTLS},
			}
			p, err := buildProvisioner(context.Background(), row, nil, nil, &tls.Config{MinVersion: tls.VersionTLS12}, log)
			if err != nil {
				t.Fatal(err)
			}
			if p == nil || p.Name() != row.Name {
				t.Fatalf("supported provider %q was not constructed", provider)
			}
		})
	}
}

func TestBuildProvisionerRejectsRetiredIAM(t *testing.T) {
	row := &model.AppIntegration{Name: "retired", Provider: "aws_iam"}
	p, err := buildProvisioner(context.Background(), row, nil, nil, nil, nil)
	if p != nil || err == nil || !strings.Contains(err.Error(), `unknown provider "aws_iam"`) {
		t.Fatalf("retired provider: provisioner = %v, error = %v", p, err)
	}
}
