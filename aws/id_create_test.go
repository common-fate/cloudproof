package aws

import (
	"context"
	"testing"
	"time"

	"github.com/common-fate/cloudproof/cptest"
)

func TestCreateProof(t *testing.T) {
	cfg := cptest.Config()

	ctx := context.Background()
	proof, err := NewIdentityProof(ctx, WithTime(time.Unix(0, 0)), WithConfig(&cfg))
	if err != nil {
		t.Fatal(err)
	}

	expected := "AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/sts/aws4_request, SignedHeaders=content-length;host;x-amz-date;x-amz-security-token, Signature=d154575f065814e849ddedecca60086221043973e620076fd561fb70dd440320"
	if proof.AuthHeader != expected {
		t.Errorf("expected %v, got %v", expected, proof.AuthHeader)
	}
}
