package team

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCertificateIdentity(t *testing.T) {
	for _, tt := range []struct {
		name        string
		domain      string
		issuer      string
		team        string
		wantSubject string
	}{
		{
			name:        "Generate certificate same identity base on specific inputs and algorithm",
			domain:      "test.com",
			issuer:      "test-provider.com",
			wantSubject: "gar--b974@test.com",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := NewCertificateIdentity(tt.domain, tt.issuer)
			emailCertId := result.GetAccountIdEmailAddress(tt.team)
			assert.Equal(t, tt.wantSubject, emailCertId.Subject)
			assert.Equal(t, tt.issuer, emailCertId.Issuer)
		})
	}
}
