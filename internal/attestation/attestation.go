package attestation

import (
	"context"
	"fmt"

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
	return co, nil
}

func Verify(ctx context.Context, containers []string, keyRef string) (any, error) {
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
	for _, a := range att {
		log.Infof("attestation: %s", a)
	}
	return nil, nil
}
