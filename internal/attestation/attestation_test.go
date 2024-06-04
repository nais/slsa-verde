package attestation

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"slsa-verde/internal/github"
)

func TestBuildCertificateIdentities(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		keyRef        string
		team          string
		tLog          bool
		wantIssuerUrl string
	}{
		{
			desc:          "keyless is enabled, build certificate identity with github",
			keyRef:        "",
			tLog:          true,
			team:          "github-yolo",
			wantIssuerUrl: "https://token.actions.githubusercontent.com",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			g := github.NewCertificateIdentity([]string{"yolo"})

			co := &VerifyAttestationOpts{
				StaticKeyRef: tc.keyRef,
				Identities:   g.GetIdentities(),
				Logger: log.WithFields(log.Fields{
					"test-app": "picante",
				}),

				VerifyAttestationCommand: &verify.VerifyAttestationCommand{
					KeyRef:     tc.keyRef,
					IgnoreTlog: tc.tLog,
				},
			}

			assert.NotEmpty(t, co.Identities)
			assert.Equal(t, tc.tLog, co.IgnoreTlog)
			assert.Equal(t, tc.keyRef, co.StaticKeyRef)
			for _, id := range co.Identities {
				assert.Equal(t, tc.wantIssuerUrl, id.Issuer)
				assert.NotEmpty(t, id.SubjectRegExp)
			}
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
