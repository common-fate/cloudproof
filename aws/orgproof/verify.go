package orgproof

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Organization is an attestation about the organization
// of a role in AWS
type Organization struct {
	ARN                  string
	ID                   string
	AvailablePolicyTypes []AvailablePolicyType
	FeatureSet           string
	MainAccountARN       string
	MainAccountEmail     string
	MainAccountID        string
}

type AvailablePolicyType struct {
	Status string
	Type   string
}

// OrganizationProof is created by a claimant who wishes
// to prove their AWS organization to a prover.
type OrganizationProof struct {
	// Signature is the AWS Signature Version 4 Authorization header (https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html).
	Signature string `json:"signature"`
	// Time is the time that the signature was created.
	Time time.Time `json:"time"`
	// SecurityToken is the AWS Session Token associated with the signature.
	SecurityToken string `json:"security_token"`
}

type VerifyOpts struct {
	Client http.Client
	// The URL to call for verification.
	// If not provided, "https://organizations.us-east-1.amazonaws.com/" is used.
	URL string
}

// Verify calls the AWS STS API to verify the contents of the identity proof provided by the claimant.
// If successful, a verified Identity object is returned.
func (op OrganizationProof) Verify(ctx context.Context) (*Organization, error) {
	return op.VerifyWithOpts(ctx, VerifyOpts{})
}

// VerifyWithOpts calls the AWS STS API to verify the contents of the identity proof provided by the claimant.
// It allows additional options to be provided.
// If successful, a verified Identity object is returned.
func (op OrganizationProof) VerifyWithOpts(ctx context.Context, opts VerifyOpts) (*Organization, error) {
	if opts.URL == "" {
		opts.URL = "https://sts.amazonaws.com/"
	}

	userAgent := "cloudproof-go/0.1.0"

	req, _ := http.NewRequest("POST", opts.URL, nil)

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.DescribeOrganization")
	req.Header.Set("X-Amz-Security-Token", op.SecurityToken)
	req.Header.Set("X-Amz-Date", op.Time.UTC().Format("20060102T150405Z"))
	req.Header.Set("Authorization", op.Signature)
	req.Header.Del("Transfer-Encoding")

	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resbody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error while reading response body from failed API call (code %d): %s", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("AWS Organizations API call failed with code %d: %s", resp.StatusCode, resbody)
	}

	// a struct type which matches the JSON structure of the AWS STS response
	var res struct {
		Organization struct {
			Arn                  string `json:"Arn"`
			AvailablePolicyTypes []struct {
				Status string `json:"Status"`
				Type   string `json:"Type"`
			} `json:"AvailablePolicyTypes"`
			FeatureSet         string `json:"FeatureSet"`
			ID                 string `json:"Id"`
			MasterAccountArn   string `json:"MasterAccountArn"`
			MasterAccountEmail string `json:"MasterAccountEmail"`
			MasterAccountID    string `json:"MasterAccountId"`
		} `json:"Organization"`
	}

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	var apts []AvailablePolicyType
	for _, a := range res.Organization.AvailablePolicyTypes {
		apts = append(apts, AvailablePolicyType{Status: a.Status, Type: a.Type})
	}
	id := Organization{
		ARN:                  res.Organization.Arn,
		ID:                   res.Organization.ID,
		AvailablePolicyTypes: apts,
		FeatureSet:           res.Organization.FeatureSet,
		MainAccountARN:       res.Organization.MasterAccountArn,
		MainAccountEmail:     res.Organization.MasterAccountEmail,
		MainAccountID:        res.Organization.MasterAccountID,
	}

	return &id, nil
}
