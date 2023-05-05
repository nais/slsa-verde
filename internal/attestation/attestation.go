package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/signature"
	log "github.com/sirupsen/logrus"
	"picante/internal/github"
	"picante/internal/pod"
	"picante/internal/team"
)

type ImageMetadata struct {
	BundleVerified bool                        `json:"bundleVerified"`
	Image          string                      `json:"image"`
	Statement      *in_toto.CycloneDXStatement `json:"statement"`
}

type Verifier interface {
	Verify(ctx context.Context, pod *pod.Info) ([]*ImageMetadata, error)
}

type VerifyAttestationOpts struct {
	*verify.VerifyAttestationCommand
	GithubOrganizations []string
	Identities          []cosign.Identity
	StaticKeyRef        string
	Logger              *log.Entry
	TeamIdentity        *team.CertificateIdentity
}

func NewVerifyAttestationOpts(verifyCmd *verify.VerifyAttestationCommand, organizations []string, identities []cosign.Identity, teamIdentity *team.CertificateIdentity, keyRef string) *VerifyAttestationOpts {
	return &VerifyAttestationOpts{
		GithubOrganizations:      organizations,
		Identities:               identities,
		StaticKeyRef:             keyRef,
		Logger:                   log.WithFields(log.Fields{"package": "attestation"}),
		TeamIdentity:             teamIdentity,
		VerifyAttestationCommand: verifyCmd,
	}
}

func (vao *VerifyAttestationOpts) certificateIdentityPreConfiguredEnabled() bool {
	return vao.Identities != nil && len(vao.Identities) > 0
}

func (vao *VerifyAttestationOpts) certificateIdentityTeamEnabled(team string) bool {
	return vao.TeamIdentity != nil && team != ""
}

func (vao *VerifyAttestationOpts) BuildCertificateIdentities(team string, gCertId *github.CertificateIdentity) []cosign.Identity {
	var result []cosign.Identity
	if vao.certificateIdentityPreConfiguredEnabled() {
		result = append(result, vao.Identities...)
	}

	if vao.certificateIdentityTeamEnabled(team) {
		result = append(result, vao.TeamIdentity.GetAccountIdEmailAddress(team))
	}

	if gCertId != nil {
		id := gCertId.GetIdentities()
		result = append(result, id...)
	}

	vao.Logger.WithFields(log.Fields{"identities": result}).Debug("Identities")

	return result
}

func (vao *VerifyAttestationOpts) cosignOptions(ctx context.Context, pod *pod.Info, gCertId *github.CertificateIdentity) (*cosign.CheckOpts, error) {
	co := &cosign.CheckOpts{}

	var err error
	if !co.IgnoreSCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if !pod.IgnoreTLog() {
		if vao.RekorURL != "" {
			rekorClient, err := rekor.NewClient(vao.RekorURL)
			if err != nil {
				return nil, fmt.Errorf("creating Rekor client: %w", err)
			}
			co.RekorClient = rekorClient
		}
		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}

	if pod.KeylessVerification() {
		// This performs an online fetch of the Fulcio roots. This is needed
		// for verifying keyless certificates (both online and offline).
		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
		co.Identities = vao.BuildCertificateIdentities(pod.Team, gCertId)

		vao.Logger.Debugf("enabled keyless verification")
		// ensure that the public key is not used
		vao.StaticKeyRef = ""
	}

	if !pod.KeylessVerification() {
		// ensure that the static public key is used
		vao.KeyRef = vao.StaticKeyRef
		co.SigVerifier, err = signature.PublicKeyFromKeyRef(ctx, vao.StaticKeyRef)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		co.IgnoreTlog = pod.IgnoreTLog()
		vao.Logger.Debugf("enabled static public key verification")
	}

	return co, nil
}

func (vao *VerifyAttestationOpts) Verify(ctx context.Context, pod *pod.Info) ([]*ImageMetadata, error) {
	metadata := make([]*ImageMetadata, 0)
	for _, image := range pod.ContainerImages {
		ref, err := name.ParseReference(image)

		gCertId := github.NewCertificateIdentity(vao.GithubOrganizations)

		opts, err := vao.cosignOptions(ctx, pod, gCertId)
		if err != nil {
			return nil, fmt.Errorf("get options: %v", err)
		}

		var verified []oci.Signature
		var bVerified bool
		var statement *in_toto.CycloneDXStatement

		vao.Logger.WithFields(log.Fields{
			"pod":   pod.Name,
			"image": image,
		}).Infof("verifying image attestations")

		if vao.LocalImage {
			verified, bVerified, err = cosign.VerifyLocalImageAttestations(ctx, image, opts)
			if err != nil {
				return nil, err
			}
		} else {
			verified, bVerified, err = cosign.VerifyImageAttestations(ctx, ref, opts)
			if err != nil {
				if strings.Contains(err.Error(), "no matching attestations") {
					vao.Logger.WithFields(log.Fields{
						"image": image,
						"msg":   err.Error(),
					}).Warnf("no matching attestations found")
					continue
				}
				return nil, err
			}
		}

		att := verified[len(verified)-1]

		env, err := att.Payload()
		if err != nil {
			return nil, fmt.Errorf("get payload: %v", err)
		}
		statement, err = parseEnvelope(env)
		if err != nil {
			return nil, fmt.Errorf("parse payload: %v", err)
		}

		vao.Logger.WithFields(log.Fields{
			"predicate-type": statement.PredicateType,
			"statement-type": statement.Type,
			"ref":            image,
		}).Info("attestation verified and parsed statement")

		metadata = append(metadata, &ImageMetadata{
			Statement:      statement,
			Image:          ref.String(),
			BundleVerified: bVerified,
		})
	}
	return metadata, nil
}

func parseEnvelope(dsseEnvelope []byte) (*in_toto.CycloneDXStatement, error) {
	env := ssldsse.Envelope{}
	err := json.Unmarshal(dsseEnvelope, &env)
	if err != nil {
		return nil, err
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	stat := &in_toto.CycloneDXStatement{}
	err = json.Unmarshal(decodedPayload, &stat)
	if err != nil {
		return nil, err
	}
	return stat, nil
}
