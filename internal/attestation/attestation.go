package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"picante/internal/identity"
	"picante/internal/pod"

	"github.com/in-toto/in-toto-golang/in_toto"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	log "github.com/sirupsen/logrus"
)

type ImageMetadata struct {
	Statement *in_toto.CycloneDXStatement `json:"statement"`
	Image     string                      `json:"image"`
}

type VerifyAttestationOpts struct {
	Issuer    string
	ProjectID string
	VerifyCmd *verify.VerifyAttestationCommand
}

func (vao *VerifyAttestationOpts) options(ctx context.Context, team string) (*cosign.CheckOpts, error) {
	co := &cosign.CheckOpts{
		IgnoreTlog: vao.VerifyCmd.IgnoreTlog,
		IgnoreSCT:  vao.VerifyCmd.IgnoreSCT,
	}

	var err error
	if !co.IgnoreSCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if !co.IgnoreTlog {
		if vao.VerifyCmd.RekorURL != "" {
			rekorClient, err := rekor.NewClient(vao.VerifyCmd.RekorURL)
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

	if keylessVerification(vao.VerifyCmd.KeyRef) {
		println("keyless verification")
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

		co.Identities = identity.GetIdentities(vao.ProjectID, vao.Issuer, team)
	}

	if vao.VerifyCmd.KeyRef != "" {
		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, vao.VerifyCmd.KeyRef)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		co.IgnoreTlog = vao.VerifyCmd.IgnoreTlog
	}

	return co, nil
}

func keylessVerification(keyRef string) bool {
	if keyRef != "" {
		return false
	}
	return true
}

func (vao *VerifyAttestationOpts) Verify(ctx context.Context, pod *pod.Info) ([]*ImageMetadata, error) {
	metadata := make([]*ImageMetadata, 0)
	for _, image := range pod.ContainerImages {
		ref, err := name.ParseReference(image)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reference: %v", err)
		}

		opts, err := vao.options(ctx, pod.Team)
		if err != nil {
			return nil, fmt.Errorf("failed to get options: %v", err)
		}

		var verified []oci.Signature
		var bVerified bool
		var statement *in_toto.CycloneDXStatement

		if vao.VerifyCmd.LocalImage {
			verified, bVerified, err = cosign.VerifyLocalImageAttestations(ctx, image, opts)
			if err != nil {
				return nil, err
			}
		} else {
			verified, bVerified, err = cosign.VerifyImageAttestations(ctx, ref, opts)
			if err != nil {
				return nil, err
			}
		}

		log.Infof("bundleVerified: %v", bVerified)

		att := verified[len(verified)-1]

		log.Infof("attestation: %s", att)
		env, err := att.Payload()
		if err != nil {
			return nil, fmt.Errorf("failed to get payload: %v", err)
		}
		statement, err = parseEnvelope(env)
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload: %v", err)
		}

		metadata = append(metadata, &ImageMetadata{
			Statement: statement,
			Image:     ref.String(),
		})
	}
	return metadata, nil
}

func parseEnvelope(dsseEnvelope []byte) (*in_toto.CycloneDXStatement, error) {
	var env = ssldsse.Envelope{}
	err := json.Unmarshal(dsseEnvelope, &env)
	if err != nil {
		return nil, err
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	var stat = &in_toto.CycloneDXStatement{}
	err = json.Unmarshal(decodedPayload, &stat)
	if err != nil {
		return nil, err
	}
	return stat, nil
}
