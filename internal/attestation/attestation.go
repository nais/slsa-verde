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

func Verify(ctx context.Context, containers []string, keyRef string) ([]*in_toto.CycloneDXStatement, error) {
	ref, err := name.ParseReference(containers[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %v", err)
	}
	opts, err := options(ctx, keyRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get options: %v", err)
	}

	att, bVerified, err := cosign.VerifyImageAttestations(ctx, ref, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify image attestations: %v", err)
	}
	log.Infof("bundleVerified: %v", bVerified)

	var attestations []*in_toto.CycloneDXStatement
	for _, a := range att {
		log.Infof("attestation: %s", a)
		stat, err := a.Payload()
		if err != nil {
			return nil, fmt.Errorf("failed to get payload: %v", err)
		}
		payload, err := parseEnvelope(stat)
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload: %v", err)
		}
		attestations = append(attestations, payload)
	}
	return attestations, nil
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
