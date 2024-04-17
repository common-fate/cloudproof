# cloudproof

[![Go Reference](https://pkg.go.dev/badge/github.com/common-fate/cloudproof.svg)](https://pkg.go.dev/github.com/common-fate/cloudproof)

A Go library for verifying cloud identities.

## Install

```bash
go get github.com/common-fate/cloudproof
```

## Supported proofs

### AWS STS

The claimant generates a signed AWS STS `GetCallerIdentity` API call and constructs a proof consisting of the timestamp, signature, and session token.

The verifier verifies the proof by **calling** the AWS STS API with the timestamp, signature and session token provided by the claimant. AWS STS returns the claimant's identity.

The proved identity consists of an `ARN`, a `UserID`, and an `Account`.

### AWS Organization

The claimant generates a signed AWS Organizations `DescribeOrganization` API call and constructs a proof consisting of the timestamp, signature, and session token.

The verifier verifies the proof by **calling** the AWS Organizations API with the timestamp, signature and session token provided by the claimant. AWS returns the claimant's organization details.

## Usage

```go
import (
	"fmt"
	"log"
	"github.com/common-fate/cloudproof/aws/stsproof"
)


func main() {
	ctx := context.TODO()

	// construct a proof
	proof, err := stsproof.New(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// verify the proof (usually you'd do this elsewhere, like on a server)
	identity := proof.Verify(ctx)

	fmt.Printf("verified account ID is: %s\n", identity.Account)
}
```
