package attestation

import (
	"context"
	"encoding/json"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"
	"os"
	"picante/internal/config"
	"picante/internal/github"
	"picante/internal/pod"
	"picante/internal/team"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	for _, tc := range []struct {
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
	} {
		t.Run(tc.desc, func(t *testing.T) {
			v := &verify.VerifyAttestationCommand{
				KeyRef:     tc.keyRef,
				IgnoreTlog: tc.tLog,
			}
			co := &VerifyAttestationOpts{
				KeyRef: tc.keyRef,
				Logger: log.WithFields(log.Fields{
					"test-app": "picante",
				}),
				VerifyCmd: v,
			}

			_, err := co.options(context.Background(), tc.podInfo, nil)
			assert.NoError(t, err)
			assert.Equal(t, tc.tLog, co.VerifyCmd.IgnoreTlog)
			assert.Equal(t, tc.keyRef, co.VerifyCmd.KeyRef)
		})
	}
}

func TestBuildCertificateIdentities(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		keyRef        string
		labels        map[string]string
		serverUrl     string
		team          string
		tLog          bool
		wantIssuerUrl string
		wantSubject   string
		workFlowRef   string
	}{
		{
			desc:          "keyless is enabled, build certificate identity with google",
			keyRef:        "",
			tLog:          true,
			team:          "google-yolo",
			wantIssuerUrl: "https://google-provider-yolo.com",
			labels:        map[string]string{},
			wantSubject:   "gar-google-yolo-b974@some-project.iam.gserviceaccount.com",
		},
		{
			desc:          "keyless is enabled, build certificate identity with github",
			keyRef:        "",
			tLog:          true,
			team:          "github-yolo",
			wantIssuerUrl: "https://token.actions.githubusercontent.com",
			serverUrl:     "https://github.com",
			labels: map[string]string{
				github.ImageWorkflowRefLabelKey: "yolo/bolo/.github/workflows/picante.yaml@main",
			},
			wantSubject: "https://github.com/yolo/bolo/.github/workflows/picante.yaml@main",
		},
		{
			desc:          "static key is enabled, no certificate identity",
			keyRef:        "testdata/cosign.pub",
			tLog:          false,
			team:          "static-team-yolo",
			wantIssuerUrl: "https://static-provider-yolo.com",
			labels:        map[string]string{},
			wantSubject:   "static-subject-yolo",
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
					Prefix: "gar",
				}
			}

			if tc.team == "github-yolo" {
				g = &github.CertificateIdentity{
					ServerUrl:   tc.serverUrl,
					WorkFlowRef: tc.labels[github.ImageWorkflowRefLabelKey],
				}
			}

			if tc.team == "static-team-yolo" {
				cfg := config.Config{
					PreConfiguredSaIdentities: []config.Identity{
						{
							Issuer:  tc.wantIssuerUrl,
							Subject: tc.wantSubject,
						},
					},
				}
				static = cfg.GetPreConfiguredIdentities()
			}

			co := &VerifyAttestationOpts{
				KeyRef:     tc.keyRef,
				Identities: static,
				Logger: log.WithFields(log.Fields{
					"test-app": "picante",
				}),

				TeamIdentity: teamIdentity,
				VerifyCmd: &verify.VerifyAttestationCommand{
					KeyRef:     tc.keyRef,
					IgnoreTlog: tc.tLog,
				},
			}

			ids := co.BuildCertificateIdentities(tc.team, g)
			assert.Equal(t, tc.tLog, co.VerifyCmd.IgnoreTlog)
			assert.Equal(t, tc.keyRef, co.VerifyCmd.KeyRef)
			assert.Equal(t, tc.wantIssuerUrl, ids[0].Issuer)
			assert.Equal(t, tc.wantSubject, ids[0].Subject)
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
