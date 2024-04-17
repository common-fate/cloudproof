package stsproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

// New creates a proof of AWS identity to be verified.
// The proof consists of an AWS Signature V4 over the STS GetCallerIdentity API call.
// A verifier can then use the signature to call the AWS STS API and determine the identity of the claimant.
func New(ctx context.Context) (*Proof, error) {
	return NewWithOpts(ctx, Opts{})
}

// NewWithOpts creates a proof of AWS identity to be verified, allowing additional options to be specified.
// The proof consists of an AWS Signature V4 over the STS GetCallerIdentity API call.
// A verifier can then use the signature to call the AWS STS API and determine the identity of the claimant.
func NewWithOpts(ctx context.Context, opts Opts) (*Proof, error) {
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

	// build the AWS STS API call to sign over.
	data := url.Values{}
	data.Set("Action", "GetCallerIdentity")
	data.Set("Version", "2011-06-15")

	req, _ := http.NewRequest("POST", "https://sts.amazonaws.com/", strings.NewReader(data.Encode()))

	req.Header.Set("User-Agent", userAgent)

	creds, err := opts.AWSConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	_, _ = io.Copy(h, strings.NewReader(data.Encode()))
	payloadHash := hex.EncodeToString(h.Sum(nil))
	s := signer.NewSigner()
	err = s.SignHTTP(ctx, creds, req, payloadHash, "sts", "us-east-1", opts.Time)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Del("Transfer-Encoding")

	proof := Proof{
		Signature:     req.Header.Get("Authorization"),
		Time:          opts.Time,
		SecurityToken: req.Header.Get("X-Amz-Security-Token"),
	}

	return &proof, nil
}
