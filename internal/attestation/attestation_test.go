package attestation

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"

	"picante/internal/config"
	"picante/internal/github"
	"picante/internal/pod"
	"picante/internal/team"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/stretchr/testify/assert"
)

func TestCosignOptions(t *testing.T) {
	err := os.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", "testdata/ct_log.pub")
	assert.NoError(t, err)

	for _, tc := range []struct {
		desc      string
		keyRef    string
		tLog      bool
		ignoreSCT bool
		podInfo   *pod.Info
	}{
		{
			desc:   "key ref cosign options should match",
			keyRef: "testdata/cosign.pub",
			tLog:   true,
			podInfo: &pod.Info{
				Verifier: &pod.Verifier{
					KeyRef: "true",
				},
			},
		},
		{
			desc:   "keyless cosign options should match",
			keyRef: "",
			podInfo: &pod.Info{
				Verifier: &pod.Verifier{
					KeyRef: "",
				},
			},
		},

		{
			desc:   "configured with tlog",
			keyRef: "",
			podInfo: &pod.Info{
				Verifier: &pod.Verifier{
					KeyRef:     "",
					IgnoreTLog: "false",
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			v := &verify.VerifyAttestationCommand{
				KeyRef:     tc.keyRef,
				IgnoreTlog: tc.tLog,
				IgnoreSCT:  tc.ignoreSCT,
			}
			co := &VerifyAttestationOpts{
				StaticKeyRef: tc.keyRef,
				Logger: log.WithFields(log.Fields{
					"test-app": "picante",
				}),
				VerifyAttestationCommand: v,
			}

			g := github.NewCertificateIdentity([]string{"google-yolo"})
			_, err := co.cosignOptions(context.Background(), tc.podInfo, g)
			assert.NoError(t, err)
			assert.Equal(t, tc.tLog, co.IgnoreTlog)
			assert.Equal(t, tc.keyRef, co.KeyRef)
			assert.Equal(t, tc.keyRef, co.StaticKeyRef)
			assert.Equal(t, "", co.RekorURL)
		})
	}
}

func TestBuildCertificateIdentities(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		keyRef        string
		team          string
		tLog          bool
		wantIssuerUrl string
	}{
		{
			desc:          "keyless is enabled, build certificate identity with google",
			keyRef:        "",
			tLog:          true,
			team:          "google-yolo",
			wantIssuerUrl: "https://google-provider-yolo.com",
		},
		{
			desc:          "keyless is enabled, build certificate identity with github",
			keyRef:        "",
			tLog:          true,
			team:          "github-yolo",
			wantIssuerUrl: "https://token.actions.githubusercontent.com",
		},
		{
			desc:          "static key is enabled, no certificate identity",
			keyRef:        "testdata/cosign.pub",
			tLog:          false,
			team:          "static-team-yolo",
			wantIssuerUrl: "https://static-provider-yolo.com",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var teamIdentity *team.CertificateIdentity
			var g *github.CertificateIdentity
			var static []cosign.Identity

			if tc.team == "google-yolo" {
				teamIdentity = &team.CertificateIdentity{
					Domain: "some-project.iam.gserviceaccount.com",
					Issuer: tc.wantIssuerUrl,
				}
			}

			if tc.team == "github-yolo" {
				g = github.NewCertificateIdentity([]string{"yolo"})
			}

			if tc.team == "static-team-yolo" {
				cfg := config.Config{
					PreConfiguredSaIdentities: []config.Identity{
						{
							Issuer:  tc.wantIssuerUrl,
							Subject: "static-team-yolo",
						},
					},
				}
				static = cfg.GetPreConfiguredIdentities()
			}

			co := &VerifyAttestationOpts{
				StaticKeyRef: tc.keyRef,
				Identities:   static,
				Logger: log.WithFields(log.Fields{
					"test-app": "picante",
				}),

				TeamIdentity: teamIdentity,
				VerifyAttestationCommand: &verify.VerifyAttestationCommand{
					KeyRef:     tc.keyRef,
					IgnoreTlog: tc.tLog,
				},
			}

			ids := co.BuildCertificateIdentities(tc.team, g)
			assert.NotEmpty(t, ids)
			assert.Equal(t, tc.tLog, co.IgnoreTlog)
			assert.Equal(t, tc.keyRef, co.StaticKeyRef)
			for _, id := range ids {
				if tc.team == "github-yolo" {
					assert.Equal(t, tc.wantIssuerUrl, id.Issuer)
					assert.NotEmpty(t, id.SubjectRegExp)
				} else {
					assert.Equal(t, tc.wantIssuerUrl, id.Issuer)
					assert.NotEmpty(t, id.Subject)
				}
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
