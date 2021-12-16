package aws

import (
	"context"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Identity is an attestation about the identity
// of a role in AWS.
type Identity struct {
	ARN     string
	UserID  string
	Account string
}

// IdentityProof is created by a claimant who wishes
// to prove their AWS identity to a prover.
type IdentityProof struct {
	// AuthHeader is the AWS Signature Version 4 Authorization header (https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html).
	AuthHeader string `json:"authHeader"`
	// Time is the time that the signature was created.
	Time time.Time `json:"time"`
	// SecurityToken is the AWS Session Token associated with the signature.
	SecurityToken string `json:"securityToken"`
}

// httpClient is satisfied by http.Client
type httpClient interface {
	Do(r *http.Request) (*http.Response, error)
}

type IdentityVerifyOptions struct {
	client    httpClient
	useragent string
}

type IdentityVerifyOption = func(*IdentityVerifyOptions)

// Verify calls the AWS STS API to verify the contents of the identity proof provided by the claimant.
// If successful, a verified Identity object is returned.
func (ip IdentityProof) Verify(ctx context.Context, opts ...IdentityVerifyOption) (*Identity, error) {
	var o IdentityVerifyOptions
	o.useragent = "commonfate-cloudproof/0.1.0"
	o.client = &http.Client{}

	for _, opt := range opts {
		opt(&o)
	}

	data := url.Values{}
	data.Set("Action", "GetCallerIdentity")
	data.Set("Version", "2011-06-15")

	req, _ := http.NewRequest("POST", "https://sts.amazonaws.com/", strings.NewReader(data.Encode()))

	req.Header.Set("User-Agent", o.useragent)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Set("X-Amz-Security-Token", ip.SecurityToken)
	req.Header.Set("X-Amz-Date", ip.Time.UTC().Format("20060102T150405Z"))
	req.Header.Set("Authorization", ip.AuthHeader)
	req.Header.Del("Transfer-Encoding")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// a struct type which matches the XML structure of the AWS STS response
	var res struct {
		GetCallerIdentityResult struct {
			ARN     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
		}
		ResponseMetadata struct {
			RequestID string `xml:"RequestId"`
		}
	}

	err = xml.Unmarshal(resbody, &res)
	if err != nil {
		return nil, err
	}

	id := Identity{
		ARN:     res.GetCallerIdentityResult.ARN,
		UserID:  res.GetCallerIdentityResult.UserID,
		Account: res.GetCallerIdentityResult.Account,
	}

	return &id, nil
}

// WithClient allows a custom HTTP client to be provided
func WithClient(c httpClient) func(*IdentityVerifyOptions) {
	return func(ivo *IdentityVerifyOptions) {
		ivo.client = c
	}
}

// WithVerifierUserAgent allows a custom user agent to be provided.
func WithVerifierUserAgent(ua string) func(*IdentityVerifyOptions) {
	return func(ivo *IdentityVerifyOptions) {
		ivo.useragent = ua
	}
}
