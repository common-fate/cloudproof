//go:build integration

package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

func TestOrgIntegration(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orgClient := organizations.NewFromConfig(cfg)
	res, err := orgClient.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Organization == nil {
		t.Fatal("organization was nil")
	}

	proof, err := NewOrgProof(ctx, WithConfig(&cfg))
	if err != nil {
		t.Fatal(err)
	}

	org, err := proof.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if org.ARN != *res.Organization.Arn {
		t.Errorf("expected %v, got %v", *res.Organization.Arn, org.ARN)
	}
	if org.ID != *res.Organization.Id {
		t.Errorf("expected %v, got %v", *res.Organization.Id, org.ID)
	}
}
