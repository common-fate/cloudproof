package aws

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

type ProveOptions struct {
	cfg       *aws.Config
	time      time.Time
	useragent string
}

type ProofOption = func(*ProveOptions)

// NewIdentityProof creates a proof of AWS identity to be verified.
// The proof consists of an AWS Signature V4 over the STS GetCallerIdentity API call.
// A verifier can then use the signature to call the AWS STS API and determine the identity of the claimant.
func NewIdentityProof(ctx context.Context, opts ...ProofOption) (*IdentityProof, error) {
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

	// build the AWS STS API call to sign over.
	data := url.Values{}
	data.Set("Action", "GetCallerIdentity")
	data.Set("Version", "2011-06-15")

	req, _ := http.NewRequest("POST", "https://sts.amazonaws.com/", strings.NewReader(data.Encode()))

	req.Header.Set("User-Agent", o.useragent)

	creds, err := o.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	_, _ = io.Copy(h, strings.NewReader(data.Encode()))
	payloadHash := hex.EncodeToString(h.Sum(nil))
	s := signer.NewSigner()
	err = s.SignHTTP(ctx, creds, req, payloadHash, "sts", "us-east-1", o.time)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Del("Transfer-Encoding")

	proof := IdentityProof{
		Signature:     req.Header.Get("Authorization"),
		Time:          o.time,
		SecurityToken: req.Header.Get("X-Amz-Security-Token"),
	}

	return &proof, nil
}

// WithConfig allows overriding the default AWS config
func WithConfig(cfg *aws.Config) func(p *ProveOptions) {
	return func(p *ProveOptions) {
		p.cfg = cfg
	}
}

// WithTime allows a custom signature time to be provided
func WithTime(t time.Time) func(p *ProveOptions) {
	return func(p *ProveOptions) {
		p.time = t
	}
}

// WithUserAgent allows a custom user agent to be provided.
func WithUserAgent(ua string) func(p *ProveOptions) {
	return func(p *ProveOptions) {
		p.useragent = ua
	}
}
