package identity

import (
	"fmt"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

const (
	GoogleServiceAccountSuffix = ".iam.gserviceaccount.com"
)

func GetIdentities(projectID, issuer, team string) []cosign.Identity {
	return []cosign.Identity{
		{
			Issuer:        issuer,
			SubjectRegExp: ToSubject(projectID, team),
		},
	}
}

func ToSubject(projectID string, team string) string {
	return fmt.Sprintf("@%s%s", projectID, GoogleServiceAccountSuffix)
}
