package identity

import (
	"fmt"
)

const (
	GoogleServiceAccountSuffix = ".iam.gserviceaccount.com"
)

func ToSubject(projectID string, team string) string {
	return fmt.Sprintf("@%s%s", projectID, GoogleServiceAccountSuffix)
}
