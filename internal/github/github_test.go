package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCertificateIdentity(t *testing.T) {
	for _, tt := range []struct {
		name        string
		enabled     bool
		serverUrl   string
		orgs        []string
		workFlowRef string
	}{
		{
			name:        "GitHub Cert Authz is enabled and matches pattern and identity",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"nais"},
			workFlowRef: "nais/yolo-bolo/.github/workflows/.main.yml@refs/heads/master",
		},

		{
			name:        "GitHub Cert Authz is enabled and matches pattern and identity",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"navikt"},
			workFlowRef: "navikt/yolo-bolo/.github/workflows/.build.yaml@refs/pull/1575/merge",
		},
		{
			name: "GitHub Cert Authz is disabled",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id := NewCertificateIdentity(tt.orgs)
			idPattern := id.GetIdentities()
			for _, pattern := range idPattern {
				assert.Regexp(t, pattern.SubjectRegExp, tt.serverUrl+"/"+tt.workFlowRef)
			}
		})
	}
}
