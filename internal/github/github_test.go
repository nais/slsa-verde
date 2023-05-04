package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCertificateIdentity(t *testing.T) {
	defaultPattern := "^https:\\/\\/github\\.com\\/nais\\/[a-zA-Z0-9_.-]+?\\/.github\\/workflows\\/[a-zA-Z0-9_-]+?(?:.yaml|.yml)@refs\\/heads\\/[a-zA-Z0-9_-]+?$"

	for _, tt := range []struct {
		name             string
		enabled          bool
		serverUrl        string
		orgs             []string
		workFlowRef      string
		wantValidPattern bool
		wantEqualPattern bool
	}{
		{
			name:             "GitHub Cert Authz is enabled and matches pattern and identity",
			enabled:          true,
			serverUrl:        "https://github.com",
			orgs:             []string{"nais"},
			workFlowRef:      "nais/yolo-bolo/.github/workflows/main.yml@refs/heads/master",
			wantValidPattern: true,
			wantEqualPattern: true,
		},
		{
			name:             "GitHub Cert Authz is disabled",
			wantValidPattern: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id := NewCertificateIdentity(tt.orgs)
			idPattern := id.GetIdentities()
			for _, pattern := range idPattern {
				assert.Equal(t, IssuerUrl, pattern.Issuer, "issuer should be empty")
				assert.Equal(t, defaultPattern, pattern.SubjectRegExp, "pattern should be equal")
			}
		})
	}
}
