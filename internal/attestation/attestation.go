package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	ociremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	"slsa-verde/internal/github"

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
)

const (
	ErrNoAttestation = "no matching attestations"
)

type ImageMetadata struct {
	BundleVerified bool                        `json:"bundleVerified"`
	Image          string                      `json:"image"`
	ContainerName  string                      `json:"containerName"`
	Statement      *in_toto.CycloneDXStatement `json:"statement"`
	Digest         string                      `json:"digest"`
	RekorMetadata  *Rekor                      `json:"rekorMetadata"`
}

type Verifier interface {
	Verify(ctx context.Context, image string) (*ImageMetadata, error)
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
	keyRef string,
) (*VerifyAttestationOpts, error) {
	ids := github.NewCertificateIdentity(organizations).GetIdentities()
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

func (vao *VerifyAttestationOpts) Verify(ctx context.Context, image string) (*ImageMetadata, error) {
	ref, err := name.ParseReference(image)

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
		"image": image,
	}).Debug("verifying image attestations")

	if vao.LocalImage {
		verified, bVerified, err = cosign.VerifyLocalImageAttestations(ctx, image, opts)
		if err != nil {
			return nil, err
		}
	} else {
		verified, bVerified, err = cosign.VerifyImageAttestations(ctx, ref, opts)
		if err != nil {
			l := vao.Logger.Logger.WithFields(log.Fields{
				"ref": ref.String(),
			})
			if strings.Contains(err.Error(), ErrNoAttestation) {
				l.Debug("no attestations found")
				return nil, err
			}
			l.Warn("verifying image attestations")
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

	imageMetadata := &ImageMetadata{
		Statement:      statement,
		Image:          ref.String(),
		BundleVerified: bVerified,
		ContainerName:  image,
	}

	// Find the digest of the image that was attested
	for _, s := range statement.Subject {
		if s.Name == ref.Context().Name() {
			imageMetadata.Digest = s.Digest["sha256"]
		}
	}

	rekorBundle, err := att.Bundle()
	if err != nil {
		log.Errorf("get bundle: %v", err)
	}

	if rekorBundle != nil {
		rekorMetadata, err := GetRekorMetadata(rekorBundle)
		if err != nil {
			log.Errorf("get rekor metadata: %v", err)
		}
		imageMetadata.RekorMetadata = rekorMetadata
	}

	return imageMetadata, nil
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
