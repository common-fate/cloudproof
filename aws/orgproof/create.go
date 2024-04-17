package orgproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

type Opts struct {
	// AWSConfig allows the AWS config to be overridden.
	// If not specified, the New() method will call
	// 'config.LoadDefaultConfig()' to obtain the default
	// AWS config.
	AWSConfig *aws.Config
	// Time allows the current time to be overridden.
	// If left unspecified the current time is used.
	// This is used for testing, so most of the time
	// you shouldn't need to change this.
	Time time.Time
}

// NewWithOpts creates a proof of AWS organisation to be verified, allowing additional options to be provided.
// The proof consists of an AWS Signature V4 over the DescribeOrganization API call.
// A verifier can then use the signature to call the AWS Organizations API and determine the identity of the claimant.
func New(ctx context.Context) (*OrganizationProof, error) {
	return NewWithOpts(ctx, Opts{})
}

// NewWithOpts creates a proof of AWS organisation to be verified, allowing additional options to be provided.
// The proof consists of an AWS Signature V4 over the DescribeOrganization API call.
// A verifier can then use the signature to call the AWS Organizations API and determine the identity of the claimant.
func NewWithOpts(ctx context.Context, opts Opts) (*OrganizationProof, error) {
	if opts.Time.IsZero() {
		opts.Time = time.Now()
	}

	userAgent := "cloudproof-go/0.1.0"

	// create a default config if it hasn't been provided by the WithConfig() option
	if opts.AWSConfig == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		opts.AWSConfig = &cfg
	}

	// build the AWS API call to sign over.
	req, _ := http.NewRequest("POST", "https://organizations.us-east-1.amazonaws.com/", nil)

	req.Header.Set("User-Agent", userAgent)

	creds, err := opts.AWSConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	payloadHash := hex.EncodeToString(h.Sum(nil))
	s := signer.NewSigner()
	err = s.SignHTTP(ctx, creds, req, payloadHash, "organizations", "us-east-1", opts.Time)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.DescribeOrganization")
	req.Header.Del("Transfer-Encoding")

	proof := OrganizationProof{
		Signature:     req.Header.Get("Authorization"),
		Time:          opts.Time,
		SecurityToken: req.Header.Get("X-Amz-Security-Token"),
	}

	return &proof, nil
}
