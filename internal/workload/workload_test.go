package workload

import (
	"testing"

	v1 "k8s.io/api/core/v1"

	"picante/internal/test"

	"github.com/stretchr/testify/assert"
)

func TestGetMetadata(t *testing.T) {
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
			name:              "Get basic info from workload for keyRef verification",
			keyRef:            "",
			predicateType:     "",
			tlog:              "true",
			wantPredicateType: "cyclonedx",
			wantTlog:          true,
			wantKeyless:       true,
		},
		{
			name:              "Get basic info from workload for keyRef verification with custom input predicateType",
			keyRef:            "",
			predicateType:     "yolo-custom",
			tlog:              "false",
			wantPredicateType: "yolo-custom",
			wantKeyless:       true,
		},
		{
			name:              "Get basic info from workload for static verification",
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
			w := test.CreateWorkload("team1", "pod1", l, nil, "nginx:latest")

			workload := GetMetadata(w, nil)
			assert.Equal(t, tt.wantPredicateType, GetPredicateType(workload), "predicate type should match")
			assert.Equal(t, tt.wantKeyless, KeylessVerification(workload), "keyRef should match")
			assert.Equal(t, tt.wantTlog, IgnoreTLog(workload), "tlog should match")
			assert.Equal(t, "pod1", workload.GetName(), "workload name should match")
			assert.Equal(t, "team1", workload.GetNamespace(), "namespace should match")
			assert.Equal(t, "nginx:latest", workload.GetContainers()[0].Image, "image should match")
			assert.Equal(t, "pod1", workload.GetContainers()[0].Name, "name should match")
			assert.Equal(t, "team1", workload.GetTeam(), "team should match")
			assert.Equal(t, "ReplicaSet", workload.GetKind(), "kind should match")
			assert.Equal(t, "pod1", workload.GetIdentifier(), "identifier should match")
		})
	}
}

func TestSetContainers(t *testing.T) {
	for _, tt := range []struct {
		name           string
		containers     []v1.Container
		initContainers []v1.Container
		want           []Container
	}{
		{
			name: "Set containers",
			containers: []v1.Container{
				{
					Name:  "nginx",
					Image: "nginx:latest",
				},
			},
			initContainers: []v1.Container{
				{
					Name:  "nginx-init",
					Image: "nginx:latest",
				},
			},
			want: []Container{
				{
					Name:  "nginx",
					Image: "nginx:latest",
				},
				{
					Name:  "nginx-init",
					Image: "nginx:latest",
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := setContainers(tt.containers, tt.initContainers)
			assert.Equal(t, tt.want, got, "containers should match")
		})
	}
}
