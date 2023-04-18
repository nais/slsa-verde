package team

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewCertificateIdentity(t *testing.T) {
	for _, tt := range []struct {
		name        string
		prefix      string
		domain      string
		issuer      string
		team        string
		wantSubject string
	}{
		{
			name:        "Generate certificate same identity base on specific inputs and algorithm",
			prefix:      "test-yolo",
			domain:      "test.com",
			issuer:      "test-provider.com",
			wantSubject: "test-yolo--1bf9@test.com",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := NewCertificateIdentity(tt.prefix, tt.domain, tt.issuer)
			emailCertId := result.GetAccountIdEmailAddress(tt.team)
			assert.Equal(t, tt.wantSubject, emailCertId.Subject)
			assert.Equal(t, tt.issuer, emailCertId.Issuer)
		})
	}
}
