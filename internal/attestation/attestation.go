package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/oci"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/google/go-containerregistry/pkg/name"
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

func options(ctx context.Context, keyRef string, rekorUrl string, co *cosign.CheckOpts) (*cosign.CheckOpts, error) {
	var err error
	if !co.IgnoreSCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if !co.IgnoreTlog {
		if rekorUrl != "" {
			rekorClient, err := rekor.NewClient(rekorUrl)
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

	if keylessVerification(keyRef) {
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
	}

	if keyRef != "" {
		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		co.IgnoreTlog = true
	}

	return co, nil
}

func keylessVerification(keyRef string) bool {
	if keyRef != "" {
		return false
	}
	return true
}

func Verify(
	ctx context.Context,
	containers []string,
	keyRef string,
	localImage bool,
	rekorUrl string,
	cosOpts *cosign.CheckOpts,
) ([]*ImageMetadata, error) {
	metadata := make([]*ImageMetadata, 0)
	for _, imageRef := range containers {
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reference: %v", err)
		}
		opts, err := options(ctx, keyRef, rekorUrl, cosOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to get options: %v", err)
		}

		var verified []oci.Signature
		var bVerified bool
		var statement *in_toto.CycloneDXStatement

		if localImage {
			verified, bVerified, err = cosign.VerifyLocalImageAttestations(ctx, imageRef, opts)
			if err != nil {
				return nil, err
			}
		} else {
			println("remote image verification")
			verified, bVerified, err = cosign.VerifyImageAttestations(ctx, ref, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to verify image attestations: %v", err)
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
