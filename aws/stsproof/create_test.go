package stsproof

import (
	"context"
	"testing"
	"time"

	"github.com/common-fate/cloudproof/cptest"
)

func TestCreateProof(t *testing.T) {
	cfg := cptest.Config()
	ctx := context.Background()

	proof, err := NewWithOpts(ctx, Opts{
		Time:      time.Unix(1, 0),
		AWSConfig: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}

	expected := "AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/sts/aws4_request, SignedHeaders=content-length;host;x-amz-date;x-amz-security-token, Signature=03fabf0e4a4900cea295f8462baa5684d9a5645d7f8bc2ba4caa67bee322a134"
	if proof.Signature != expected {
		t.Errorf("expected %v, got %v", expected, proof.Signature)
	}
}
