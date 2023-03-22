package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"os"
	"picante/internal/pod"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	testCases := []struct {
		desc   string
		keyRef string
		tLog   bool
	}{
		{
			desc:   "key ref options should match",
			keyRef: "testdata/cosign.pub",
			tLog:   true,
		},
		{
			desc:   "keyless options should match",
			keyRef: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			co := &VerifyAttestationOpts{
				VerifyCmd: &verify.VerifyAttestationCommand{
					KeyRef:     tc.keyRef,
					IgnoreTlog: tc.tLog,
				},
			}
			result, err := co.options(context.Background(), "")
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.tLog, result.IgnoreTlog)
			assert.Equal(t, tc.keyRef != "", result.SigVerifier != nil)
			assert.Equal(t, tc.keyRef == "", result.RootCerts != nil)
			assert.Equal(t, tc.keyRef == "", result.IntermediateCerts != nil)

		})
	}
}

func TestVerifyKeyless(t *testing.T) {
	image := "ttl.sh/salsa/gogoogletestapp:1h"
	p := &pod.Info{
		ContainerImages: []string{image},
		Verify:          false,
	}

	co := &VerifyAttestationOpts{
		VerifyCmd: &verify.VerifyAttestationCommand{
			IgnoreTlog: false,
			KeyRef:     "",
			LocalImage: false,
			RekorURL:   "",
		},
		ProjectID: "plattformsikkerhet-dev-496e",
		Issuer:    "https://accounts.google.com",
	}

	verify, err := co.Verify2(context.Background(), p)
	assert.NoError(t, err)
	for _, v := range verify {
		fmt.Printf("statement: %v\n", v.Statement)
		fmt.Printf("image: %s\n", v.Image)
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
