package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	log "github.com/sirupsen/logrus"
)

type ImageMetadata struct {
	Statement *in_toto.CycloneDXStatement `json:"statement"`
	Image     string                      `json:"image"`
}

func options(ctx context.Context, keyRef string) (*cosign.CheckOpts, error) {
	co := &cosign.CheckOpts{}
	verifier, err := sigs.PublicKeyFromKeyRef(ctx, keyRef)
	if err != nil {
		return nil, fmt.Errorf("loading public key: %w", err)
	}
	co.SigVerifier = verifier
	pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
	if ok {
		defer pkcs11Key.Close()
	}
	co.IgnoreTlog = true
	return co, nil
}

func Verify(ctx context.Context, containers []string, keyRef string) ([]*ImageMetadata, error) {
	metadata := make([]*ImageMetadata, 0)
	for _, c := range containers {
		ref, err := name.ParseReference(c)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reference: %v", err)
		}
		opts, err := options(ctx, keyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to get options: %v", err)
		}

		atts, bVerified, err := cosign.VerifyImageAttestations(ctx, ref, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to verify image attestations: %v", err)
		}
		log.Infof("bundleVerified: %v", bVerified)

		att := atts[len(atts)-1]

		log.Infof("attestation: %s", att)
		env, err := att.Payload()
		if err != nil {
			return nil, fmt.Errorf("failed to get payload: %v", err)
		}
		statement, err := parseEnvelope(env)
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

type Envelope struct {
	Payload string `json:"payload"`
}

func parseEnvelope(dsseEnvelope []byte) (*in_toto.CycloneDXStatement, error) {
	var env = Envelope{}
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
