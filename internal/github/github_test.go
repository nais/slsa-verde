package github

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewCertificateIdentity(t *testing.T) {
	defaultPattern := "https://github.com/nais/yolo-bolo/.github/workflows/main.yml@refs/heads/master"

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
			var enabledConfig map[string]string

			if tt.enabled {
				enabledConfig = map[string]string{
					"org.opencontainers.image.server.url":   tt.serverUrl,
					"org.opencontainers.image.workflow.ref": tt.workFlowRef,
				}
			}

			id := NewCertificateIdentity(tt.orgs, enabledConfig)
			assert.Equal(t, tt.enabled, id.Enabled(), "enabled should be equal")
			valid := id.IsValid()
			assert.Equal(t, tt.wantValidPattern, valid, "pattern should be valid")
			idPattern := id.GetIdentity()
			if valid {
				// if pattern is valid, the pattern should be equal (cosign does this check)
				assert.Equal(t, defaultPattern, idPattern.Subject, "pattern should be equal")
			}
		})
	}
}
