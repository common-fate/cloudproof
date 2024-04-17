package stsproof

import (
	"context"
	"encoding/xml"
	"io"
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
type Proof struct {
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
	// If not provided, "https://sts.amazonaws.com/" is used.
	URL string
}

// Verify calls the AWS STS API to verify the contents of the identity proof provided by the claimant.
// If successful, a verified Identity object is returned.
func (ip Proof) Verify(ctx context.Context) (*Identity, error) {
	return ip.VerifyWithOpts(ctx, VerifyOpts{})
}

// Verify calls the AWS STS API to verify the contents of the identity proof provided by the claimant.
// If successful, a verified Identity object is returned.
func (ip Proof) VerifyWithOpts(ctx context.Context, opts VerifyOpts) (*Identity, error) {
	if opts.URL == "" {
		opts.URL = "https://sts.amazonaws.com/"
	}

	userAgent := "cloudproof-go/0.1.0"

	data := url.Values{}
	data.Set("Action", "GetCallerIdentity")
	data.Set("Version", "2011-06-15")

	req, _ := http.NewRequest("POST", opts.URL, strings.NewReader(data.Encode()))

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Set("X-Amz-Security-Token", ip.SecurityToken)
	req.Header.Set("X-Amz-Date", ip.Time.UTC().Format("20060102T150405Z"))
	req.Header.Set("Authorization", ip.Signature)
	req.Header.Del("Transfer-Encoding")

	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resbody, err := io.ReadAll(resp.Body)
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
