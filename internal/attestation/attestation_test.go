package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/in-toto/in-toto-golang/in_toto"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	verify, err := Verify(context.Background(), []string{"ttl.sh/picante:6h"}, "testdata/cosign.pub")
	assert.NoError(t, err)
	for _, v := range verify {
		fmt.Printf("statement: %v\n", v)
	}
}

func TestParsePayload(t *testing.T) {
	attPath := "testdata/cyclonedx-dsse.json"
	dsse, err := os.ReadFile(attPath)
	assert.NoError(t, err)

	got, err := parseEnvelope(dsse)
	assert.NoError(t, err)

	att, err := os.ReadFile("testdata/cyclonedx-attestation.json")
	assert.NoError(t, err)

	var want *in_toto.CycloneDXStatement
	err = json.Unmarshal(att, &want)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}
