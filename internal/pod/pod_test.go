package pod

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"

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
			p := createPod("team1", "pod1", l, "nginx:latest")

			inf := GetInfo(p)
			assert.Equal(t, tt.wantPredicateType, inf.GetPredicateType(), "predicate type should match")
			assert.Equal(t, tt.wantKeyless, inf.KeylessVerification(), "keyRef should match")
			assert.Equal(t, tt.wantTlog, inf.IgnoreTLog(), "tlog should match")
			assert.Equal(t, "pod1", inf.PodName, "pod name should match")
			assert.Equal(t, "team1", inf.Team, "team name should match")
			assert.Equal(t, "pod1", inf.Name, "name should match")
			assert.Equal(t, "team1", inf.Namespace, "namespace should match")
			assert.Equal(t, "nginx:latest", inf.ContainerImages[0].Image, "image should match")
		})
	}
}

func createPod(namespace, name string, labels map[string]string, images ...string) *v1.Pod {
	c := make([]v1.Container, 0)
	for _, image := range images {
		c = append(c, v1.Container{
			Image: image,
		})
	}
	l := merge(map[string]string{
		SalsaKeylessProviderLabelKey:  "cosign",
		SalsaKeyRefLabelKey:           "testdata/cosign.key",
		SalsaPredicateLabelKey:        "cyclonedx",
		TeamLabelKey:                  namespace,
		IgnoreTransparencyLogLabelKey: "true",
		AppK8sIoNameLabelKey:          name,
	}, labels)
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    l,
		},
		Spec: v1.PodSpec{
			Containers: c,
		},
	}
}

func merge(map1, map2 map[string]string) map[string]string {
	mergedMap := make(map[string]string)
	for key, value := range map1 {
		mergedMap[key] = value
	}
	for key, value := range map2 {
		mergedMap[key] = value
	}
	return mergedMap
}
