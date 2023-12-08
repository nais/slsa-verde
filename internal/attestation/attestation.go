package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"picante/internal/workload"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	ociremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	gh "github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/signature"
	log "github.com/sirupsen/logrus"
	"picante/internal/github"
)

type ImageMetadata struct {
	BundleVerified bool                        `json:"bundleVerified"`
	Image          string                      `json:"image"`
	ContainerName  string                      `json:"containerName"`
	Statement      *in_toto.CycloneDXStatement `json:"statement"`
	Digest         string                      `json:"digest"`
}

type Verifier interface {
	Verify(ctx context.Context, container workload.Container) (*ImageMetadata, error)
}

var _ Verifier = &VerifyAttestationOpts{}

type VerifyAttestationOpts struct {
	*verify.VerifyAttestationCommand
	CheckOpts           *cosign.CheckOpts
	GithubOrganizations []string
	Identities          []cosign.Identity
	StaticKeyRef        string
	Logger              *log.Entry
}

func NewVerifyAttestationOpts(
	verifyCmd *verify.VerifyAttestationCommand,
	organizations []string,
	identities []cosign.Identity,
	keyRef string,
) (*VerifyAttestationOpts, error) {
	gCertId := github.NewCertificateIdentity(organizations)
	ids := BuildCertificateIdentities(gCertId, identities)
	opts, err := CosignOptions(context.Background(), keyRef, ids)
	if err != nil {
		return nil, err
	}

	return &VerifyAttestationOpts{
		CheckOpts:                opts,
		GithubOrganizations:      organizations,
		Identities:               ids,
		StaticKeyRef:             keyRef,
		Logger:                   log.WithFields(log.Fields{"package": "attestation"}),
		VerifyAttestationCommand: verifyCmd,
	}, nil
}

func certificateIdentityPreConfiguredEnabled(identities []cosign.Identity) bool {
	return len(identities) > 0
}

func BuildCertificateIdentities(gCertId *github.CertificateIdentity, identities []cosign.Identity) []cosign.Identity {
	var result []cosign.Identity
	if certificateIdentityPreConfiguredEnabled(identities) {
		result = append(result, identities...)
	}

	if gCertId != nil {
		id := gCertId.GetIdentities()
		result = append(result, id...)
	}

	return result
}

func CosignOptions(ctx context.Context, staticKeyRef string, identities []cosign.Identity) (*cosign.CheckOpts, error) {
	co := &cosign.CheckOpts{}

	var err error
	if !co.IgnoreSCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if staticKeyRef == "" {
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
		co.Identities = identities

		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}

	if staticKeyRef != "" {
		// ensure that the static public key is used
		// vao.KeyRef = vao.StaticKeyRef
		co.SigVerifier, err = signature.PublicKeyFromKeyRef(ctx, staticKeyRef)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		co.IgnoreTlog = true
	}

	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		gh.Keychain,
	)

	co.RegistryClientOpts = []remote.Option{
		remote.WithRemoteOptions(ociremote.WithAuthFromKeychain(keychain)),
	}

	return co, nil
}

func (vao *VerifyAttestationOpts) Verify(ctx context.Context, container workload.Container) (*ImageMetadata, error) {
	ref, err := name.ParseReference(container.Image)

	opts := vao.CheckOpts

	if opts.SigVerifier != nil {
		vao.KeyRef = vao.StaticKeyRef
	}

	if err != nil {
		return nil, fmt.Errorf("get options: %v", err)
	}

	var verified []oci.Signature
	var bVerified bool
	var statement *in_toto.CycloneDXStatement

	vao.Logger.WithFields(log.Fields{
		"image":          container.Image,
		"container-name": container.Name,
	}).Infof("verifying image attestations")

	if vao.LocalImage {
		verified, bVerified, err = cosign.VerifyLocalImageAttestations(ctx, container.Image, opts)
		if err != nil {
			return nil, err
		}
	} else {
		verified, bVerified, err = cosign.VerifyImageAttestations(ctx, ref, opts)
		if err != nil {
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

	digest, err := att.Digest()
	if err != nil {
		return nil, fmt.Errorf("get digest: %v", err)
	}

	vao.Logger.WithFields(log.Fields{
		"predicate-type": statement.PredicateType,
		"statement-type": statement.Type,
		"ref":            container.Image,
	}).Info("attestation verified and parsed statement")

	return &ImageMetadata{
		Statement:      statement,
		Image:          ref.String(),
		BundleVerified: bVerified,
		ContainerName:  container.Name,
		Digest:         digest.String(),
	}, nil
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
