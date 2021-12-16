// Package cptest contains helpers for tests in cloudproof.
package cptest

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func init() {
	config = aws.Config{}
	config.Region = "mock-region"
	config.Credentials = StubCredentialsProvider{}
}

// StubCredentialsProvider provides a stub credential provider that returns
// static credentials that never expire.
type StubCredentialsProvider struct{}

// Retrieve satisfies the CredentialsProvider interface. Returns stub
// credential value, and never error.
func (StubCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "SESSION",
		Source: "unit test credentials",
	}, nil
}

var config aws.Config

// Config returns a copy of the mock configuration for unit tests.
func Config() aws.Config { return config.Copy() }
