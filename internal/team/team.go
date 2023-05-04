package team

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sigstore/cosign/v2/pkg/cosign"
)

const (
	IdentityTeamMaxLength = 30
	DefaultTeamPrefix     = "gar"
)

type CertificateIdentity struct {
	Domain string
	Issuer string
}

func NewCertificateIdentity(domain, issuer string) *CertificateIdentity {
	return &CertificateIdentity{
		Domain: domain,
		Issuer: issuer,
	}
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}

func (i *CertificateIdentity) teamHashPrefixTruncate(team string, maxLength int) string {
	hasher := sha256.New()
	hasher.Write([]byte(DefaultTeamPrefix))

	prefixLength := len(DefaultTeamPrefix)
	hashLength := 4
	teamLength := maxLength - prefixLength - hashLength - 2 // 2 becasue we join parts with '-'

	parts := []string{
		DefaultTeamPrefix,
		strings.TrimSuffix(truncate(team, teamLength), "-"),
		truncate(hex.EncodeToString(hasher.Sum(nil)), hashLength),
	}

	return strings.Join(parts, "-")
}

func (i *CertificateIdentity) GetAccountIdEmailAddress(team string) cosign.Identity {
	emailAddress := fmt.Sprintf("%s@%s", i.teamHashPrefixTruncate(team, IdentityTeamMaxLength), i.Domain)
	return cosign.Identity{
		Issuer:  i.Issuer,
		Subject: emailAddress,
	}
}
