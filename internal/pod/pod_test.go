package pod

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetInfo(t *testing.T) {
	for _, tt := range []struct {
		name              string
		predicateType     string
		keyRef            string
		tlog              string
		wantPredicateType string
		wantKeyless       bool
		wantTlog          bool
	}{
		{
			name:              "Get basic info from pod for keyRef verification",
			keyRef:            "",
			predicateType:     "",
			tlog:              "true",
			wantPredicateType: "cyclonedx",
			wantTlog:          true,
			wantKeyless:       true,
		},
		{
			name:              "Get basic info from pod for keyRef verification with custom input predicateType",
			keyRef:            "",
			predicateType:     "yolo-custom",
			tlog:              "false",
			wantPredicateType: "yolo-custom",
			wantKeyless:       true,
		},
		{
			name:              "Get basic info from pod for static verification",
			keyRef:            "true",
			predicateType:     "",
			tlog:              "false",
			wantPredicateType: "cyclonedx",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pInfo := &Info{
				Verifier: &Verifier{
					KeyRef:        tt.keyRef,
					PredicateType: tt.predicateType,
					IgnoreTLog:    tt.tlog,
				},
			}
			assert.Equal(t, tt.wantPredicateType, pInfo.GetPredicateType(), "predicate type should match")
			assert.Equal(t, tt.wantKeyless, pInfo.KeylessVerification(), "keyRef should match")
			assert.Equal(t, tt.wantTlog, pInfo.IgnoreTLog(), "tlog should match")
		})
	}
}
