package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

// NewOrgProof creates a proof of AWS organisation to be verified.
// The proof consists of an AWS Signature V4 over the DescribeOrganization API call.
// A verifier can then use the signature to call the AWS Organizations API and determine the identity of the claimant.
func NewOrgProof(ctx context.Context, opts ...ProofOption) (*OrganisationProof, error) {
	var o ProveOptions

	// by default set the time to be now
	o.time = time.Now()
	o.useragent = "commonfate-cloudattest/0.1.0"

	for _, opt := range opts {
		opt(&o)
	}

	// create a default config if it hasn't been provided by the WithConfig() option
	if o.cfg == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		o.cfg = &cfg
	}

	// build the AWS API call to sign over.
	req, _ := http.NewRequest("POST", "https://organizations.us-east-1.amazonaws.com/", nil)

	req.Header.Set("User-Agent", o.useragent)

	creds, err := o.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	payloadHash := hex.EncodeToString(h.Sum(nil))
	s := signer.NewSigner()
	err = s.SignHTTP(ctx, creds, req, payloadHash, "organizations", "us-east-1", o.time)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.DescribeOrganization")
	req.Header.Del("Transfer-Encoding")

	proof := OrganisationProof{
		Signature:     req.Header.Get("Authorization"),
		Time:          o.time,
		SecurityToken: req.Header.Get("X-Amz-Security-Token"),
	}

	return &proof, nil
}
