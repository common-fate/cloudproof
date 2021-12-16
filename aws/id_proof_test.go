package aws

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return &http.Response{}, nil
}

func TestVerify(t *testing.T) {
	ip := IdentityProof{}

	mc := MockClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
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
			header := http.Header{}
			header.Set("Content-Type", "application/xml")

			res := &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     header,
			}
			return res, nil
		},
	}

	ctx := context.Background()
	id, err := ip.Verify(ctx, WithClient(&mc))
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
