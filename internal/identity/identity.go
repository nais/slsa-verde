package identity

import (
	"fmt"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

const (
	GoogleServiceAccountSuffix = ".iam.gserviceaccount.com"
)

func Get(issuer, projectID, team string) []cosign.Identity {
	return []cosign.Identity{
		{
			Issuer:        issuer,
			SubjectRegExp: toSubject(projectID, team),
		},
	}
}

func toSubject(projectID string, team string) string {
	return fmt.Sprintf("@%s%s", projectID, GoogleServiceAccountSuffix)
}
