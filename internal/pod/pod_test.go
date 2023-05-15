package pod

import (
	"testing"

	"picante/internal/test"

	"github.com/stretchr/testify/assert"
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
			l := make(map[string]string)
			l[SalsaPredicateLabelKey] = tt.predicateType
			l[SalsaKeyRefLabelKey] = tt.keyRef
			l[IgnoreTransparencyLogLabelKey] = tt.tlog
			p := test.CreatePod("team1", "pod1", l, "nginx:latest")

			inf := GetInfo(p)
			assert.Equal(t, tt.wantPredicateType, inf.GetPredicateType(), "predicate type should match")
			assert.Equal(t, tt.wantKeyless, inf.KeylessVerification(), "keyRef should match")
			assert.Equal(t, tt.wantTlog, inf.IgnoreTLog(), "tlog should match")
			assert.Equal(t, "pod1", inf.PodName, "pod name should match")
			assert.Equal(t, "team1", inf.Team, "team name should match")
			assert.Equal(t, "pod1", inf.Name, "name should match")
			assert.Equal(t, "team1", inf.Namespace, "namespace should match")
			assert.Equal(t, "nginx:latest", inf.ContainerImages[0].Image, "image should match")
			assert.Equal(t, "pod1", inf.ContainerImages[0].Name, "name should match")
		})
	}
}
