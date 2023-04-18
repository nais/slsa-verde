package team

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"strings"
)

const (
	IdentityTeamMaxLength = 30
)

type CertificateIdentity struct {
	Prefix string
	Domain string
	Issuer string
}

func NewCertificateIdentity(prefix, domain, issuer string) *CertificateIdentity {
	return &CertificateIdentity{
		Prefix: prefix,
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
	hasher.Write([]byte(i.Prefix))

	prefixLength := len(i.Prefix)
	hashLength := 4
	teamLength := maxLength - prefixLength - hashLength - 2 // 2 becasue we join parts with '-'

	parts := []string{
		i.Prefix,
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
