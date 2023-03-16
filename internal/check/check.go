package check

import (
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"picante/internal/config"
	"picante/internal/identity"
)

type VerifyAttestationOpts struct {
	CosignCheckOpts *cosign.CheckOpts
	IgnoreTLog      bool
	KeyRef          string
	LocalImage      bool
	RekorURL        string
}

func AttestationOpts(cfg *config.Config) *VerifyAttestationOpts {
	return &VerifyAttestationOpts{
		IgnoreTLog: cfg.IgnoreTLog,
		LocalImage: cfg.LocalImage,
		KeyRef:     cfg.KeyRef,
		CosignCheckOpts: &cosign.CheckOpts{
			Identities: identity.NewClaim(cfg.ProjectId, cfg.Issuer),
			IgnoreTlog: cfg.IgnoreTLog,
		},
		RekorURL: cfg.RekorURL,
	}
}
