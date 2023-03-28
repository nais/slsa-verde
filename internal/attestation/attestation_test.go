package attestation

import (
	"encoding/json"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	"os"
	"picante/internal/pod"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	testCases := []struct {
		desc    string
		keyRef  string
		tLog    bool
		podInfo *pod.Info
	}{
		{
			desc:   "key ref options should match",
			keyRef: "testdata/cosign.pub",
			tLog:   true,
			podInfo: &pod.Info{
				Verifier: &pod.Verifier{
					KeyRef: "true",
				},
			},
		},
		{
			desc:   "keyless options should match",
			keyRef: "",
			podInfo: &pod.Info{
				Verifier: &pod.Verifier{
					KeyRef: "",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			v := &verify.VerifyAttestationCommand{
				KeyRef:     tc.keyRef,
				IgnoreTlog: tc.tLog,
			}
			co := &VerifyAttestationOpts{
				Logger: log.WithFields(log.Fields{
					"test-app": "picante",
				}),
				VerifyCmd: v,
			}

			co.WithOptions(tc.podInfo)
			assert.Equal(t, tc.tLog, co.VerifyCmd.IgnoreTlog)
			assert.Equal(t, tc.keyRef, co.VerifyCmd.KeyRef)
		})
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
