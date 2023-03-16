package identity

import (
	"fmt"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

const (
	GoogleServiceAccountSuffix = ".iam.gserviceaccount.com"
)

type Claim struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
}

func NewClaim(projectID, iss string) []cosign.Identity {
	return []cosign.Identity{
		{
			Issuer:        iss,
			SubjectRegExp: toSubjectRegexSuffix(projectID),
		},
	}
}

func toSubjectRegexSuffix(projectID string) string {
	return fmt.Sprintf(".*@%s%s", projectID, GoogleServiceAccountSuffix)
}
