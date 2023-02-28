package attestation

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	verify, err := Verify(context.Background(), []string{"ttl.sh/picante:1h"}, "/Users/tommytroen/ws/nav/picante/internal/attestation/testdata/cosign.pub")
	assert.NoError(t, err)
	fmt.Printf("verify: %v\n", verify)
}
