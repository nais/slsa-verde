package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"picante/internal/test"

	"github.com/nais/dependencytrack/pkg/client"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/nais/dependencytrack/pkg/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"picante/internal/attestation"
)

func TestConfig_OnAdd(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	p := test.CreatePod("team1", "pod1", nil, "nginx:latest")

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
				ContainerName:  "pod1",
			},
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, "pod1").Return(nil, &httpclient.RequestError{
			StatusCode: 404,
			Err:        errors.New("project not found"),
		})

		c.On("CreateProject", mock.Anything, "test:pod1", "latest", "team1", []string{"team1", "pod1", "pod1", "test", "nginx:latest"}).Return(nil, nil)

		c.On("UploadProject", mock.Anything, "test:pod1", "latest", mock.Anything).Return(nil, nil)

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

		c.On("GetProjectsByTag", mock.Anything, "pod1").Return([]client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "team",
				Name:       "project1",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: "team1"}, {Name: "pod1"}},
				Version:    "",
			},
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
	m := NewMonitor(context.Background(), c, v, "test")
	p := test.CreatePod("team1", "pod1", nil, "nginx:latest")

	t.Run("should delete project", func(t *testing.T) {
		c.On("DeleteProjects", mock.Anything, "test:pod1").Return(nil)

		m.OnDelete(p)
	})
	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnDelete(nil)
	})
}

func TestConfig_OnUpdate(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	p := test.CreatePod("team1", "pod1", nil, "nginx:latest")
	pLatest := test.CreatePod("team1", "pod1", nil, "nginx:laterthenlatest")

	t.Run("should ignore old and new pod with equal container image(s) ", func(t *testing.T) {
		m.OnUpdate(p, p)
	})

	t.Run("should ignore existing project", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: true,
				Image:          "nginx:laterthenlatest",
				Statement:      nil,
			},
		}, nil)
		c.On("GetProject", mock.Anything, "test:pod1", "laterthenlatest").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "team1",
			Uuid:       "1234",
			Name:       "project1",
			Publisher:  "Team",
			Tags:       []client.Tag{{Name: "team1"}, {Name: "pod1"}},
			Version:    "latest",
		}, nil)

		c.On("UpdateProjectInfo", mock.Anything, "1234", "laterthenlatest", "team1", []string{"team1", "pod1"}).Return(nil, nil)
		m.OnUpdate(p, pLatest)
	})

	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnUpdate(nil, p)
	})
	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnUpdate(p, nil)
	})
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
