package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/nais/dependencytrack/pkg/client"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/nais/dependencytrack/pkg/httpclient"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"picante/internal/attestation"
	"picante/internal/pod"

	"github.com/stretchr/testify/assert"
)

func TestConfig_OnAdd(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v)
	p := createPod("team1", "pod1", nil, "nginx:latest")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should attest image and create project", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: false,
				Image:          "nginx:latest",
				Statement:      &statement,
			},
		}, nil)

		c.On("GetProject", mock.Anything, "pod1:nginx", "latest").Return(nil, &httpclient.RequestError{
			StatusCode: 404,
			Err:        errors.New("project not found"),
		})

		c.On("CreateProject", mock.Anything, "pod1:nginx", "latest", "team1", []string{"team1", "pod1"}).Return(nil, nil)

		c.On("UploadProject", mock.Anything, "pod1:nginx", "latest", mock.Anything).Return(nil, nil)

		m.OnAdd(p)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{}, nil)

		m.OnAdd(p)
	})

	t.Run("should not create project if already exists", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: false,
				Image:          "nginx:latest",
				Statement:      &statement,
			},
		}, nil)

		c.On("GetProject", mock.Anything, "pod1:nginx", "latest").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "team",
			Name:       "project1",
			Publisher:  "Team",
			Tags:       []client.Tag{{Name: "team1"}, {Name: "pod1"}},
			Version:    "",
		}, nil)
		m.OnAdd(p)
	})

	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnAdd(nil)
	})
}

func TestConfig_OnDelete(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v)
	p := createPod("team1", "pod1", nil, "nginx:latest")

	t.Run("should delete project", func(t *testing.T) {
		c.On("DeleteProjects", mock.Anything, "pod1:nginx").Return(nil)

		m.OnDelete(p)
	})
	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnDelete(nil)
	})
}

func TestConfig_OnUpdate(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v)
	p := createPod("team1", "pod1", nil, "nginx:latest")
	pLatest := createPod("team1", "pod1", nil, "nginx:laterthenlatest")

	t.Run("should ignore old and new pod with equal container image(s) ", func(t *testing.T) {
		m.OnUpdate(p, p)
	})

	t.Run("should attest image and create project", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{}, nil)
		m.OnUpdate(p, pLatest)
	})

	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnUpdate(nil, p)
	})
	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnUpdate(p, nil)
	})
}

func createPod(namespace, name string, labels map[string]string, images ...string) *v1.Pod {
	c := make([]v1.Container, 0)
	for _, image := range images {
		c = append(c, v1.Container{
			Image: image,
		})
	}
	l := merge(map[string]string{
		pod.SalsaKeylessProviderLabelKey:  "cosign",
		pod.SalsaKeyRefLabelKey:           "testdata/cosign.key",
		pod.SalsaPredicateLabelKey:        "cyclonedx",
		pod.TeamLabelKey:                  namespace,
		pod.IgnoreTransparencyLogLabelKey: "true",
		pod.AppK8sIoNameLabelKey:          name,
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

func TestProjectAndVersion(t *testing.T) {
	image := "ghcr.io/securego/gosec:v2.9.1"
	p, v := projectAndVersion("yolo", image)
	assert.Equal(t, "yolo:ghcr.io/securego/gosec", p)
	assert.Equal(t, "v2.9.1", v)

	image = "europe-north1-docker.pkg.dev/nais-io/nais/images/picante@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5"
	p, v = projectAndVersion("yolo", image)
	assert.Equal(t, "yolo:europe-north1-docker.pkg.dev/nais-io/nais/images/picante", p)
	assert.Equal(t, "sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5", v)

	image = "europe-north1-docker.pkg.dev/nais-io/nais/images/picante:20230504-091909-3efbee3@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5"
	p, v = projectAndVersion("yolo", image)
	assert.Equal(t, "yolo:europe-north1-docker.pkg.dev/nais-io/nais/images/picante", p)
	assert.Equal(t, "20230504-091909-3efbee3@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5", v)
}
