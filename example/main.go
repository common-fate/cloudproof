package main

import (
	"context"
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
	identity, err := proof.Verify(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("verified account ID is: %s\n", identity.Account)
}
