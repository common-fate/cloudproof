package stsproof

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerify(t *testing.T) {
	ip := Proof{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/test-role/test-session</Arn>
    <UserId>ABCDEFG12345:user-name</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>00000</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
		`
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(body))
	}))

	ctx := context.Background()
	id, err := ip.VerifyWithOpts(ctx, VerifyOpts{
		URL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	arn := "arn:aws:sts::123456789012:assumed-role/test-role/test-session"
	uid := "ABCDEFG12345:user-name"
	acc := "123456789012"

	if id.ARN != arn {
		t.Errorf("expected %v, got %v", arn, id.ARN)
	}
	if id.UserID != uid {
		t.Errorf("expected %v, got %v", arn, id.ARN)
	}
	if id.Account != acc {
		t.Errorf("expected %v, got %v", arn, id.ARN)
	}
}
