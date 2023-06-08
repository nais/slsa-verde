package monitor

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"picante/internal/test"

	"github.com/nais/dependencytrack/pkg/client"

	"github.com/in-toto/in-toto-golang/in_toto"
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
		c.On("GetProject", mock.Anything, "team1:pod1:container1", "latest").Return(nil, nil)

		c.On("GetProjectsByTag", mock.Anything, "team1:pod1:container1").Return([]*client.Project{}, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: false,
				Image:          "nginx:latest",
				Statement:      &statement,
				ContainerName:  "container1",
			},
		}, nil)

		c.On("CreateProject", mock.Anything, "team1:pod1:container1", "latest", "team1", []string{
			"team1:pod1:container1",
			"team1",
			"pod1",
			"container1",
			"nginx:latest",
		}).Return(nil, nil)

		c.On("UploadProject", mock.Anything, "team1:pod1:container1", "latest", mock.Anything).Return(nil, nil)

		m.OnAdd(p)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{}, nil)

		m.OnAdd(p)
	})

	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnAdd(nil)
	})
}

func TestConfig_OnAdd_Exists(t *testing.T) {
	t.Run("should not create project if already exists", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, "test")
		p := test.CreatePod("team1", "pod1", nil, "nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: false,
				Image:          "nginx:latest",
				Statement:      &statement,
				ContainerName:  "container1",
			},
		}, nil)

		c.On("GetProject", mock.Anything, "team1:pod1:container1", "latest").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "team",
			Name:       "team1:pod1:container1",
			Publisher:  "Team",
			Tags:       []client.Tag{{Name: "team1"}, {Name: "pod1"}},
			Version:    "latest",
		}, nil)

		m.OnAdd(p)
	})

	t.Run("should update project if a project with same name already exists", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, "test")
		p := test.CreatePod("team1", "pod1", nil, "nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: false,
				Image:          "nginx:latest",
				Statement:      &statement,
				ContainerName:  "container1",
			},
		}, nil)

		c.On("GetProject", mock.Anything, "team1:pod1:container1", "latest").Return(nil, nil)

		c.On("GetProjectsByTag", mock.Anything, "team1:pod1:container1").Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "team",
				Uuid:       "uuid1",
				Name:       "team1:pod1:container1",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: "team1:pod1:container1"}, {Name: "team1"}, {Name: "pod1"}},
				Version:    "version1",
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "uuid1", "team1:pod1:container1", "latest", "team1", []string{
			"team1:pod1:container1",
			"team1",
			"pod1",
			"container1",
			"nginx:latest",
		}).Return(nil, nil)

		c.On("UploadProject", mock.Anything, "team1:pod1:container1", "latest", mock.Anything).Return(nil, nil)

		m.OnAdd(p)
	})
}

func TestConfig_OnDelete(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	p := test.CreatePod("team1", "pod1", nil, "nginx:latest")

	t.Run("should delete project", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "team1:pod1", "latest").Return(&client.Project{
			Uuid:       "1",
			Classifier: "APPLICATION",
			Group:      "team",
			Name:       "team1:pod1",
			Publisher:  "Team",
			Tags:       []client.Tag{{Name: "team1"}, {Name: "pod1"}},
			Version:    "latest",
		}, nil)
		c.On("DeleteProject", mock.Anything, "1").Return(nil)

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

	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnUpdate(nil, p)
	})
	t.Run("should ignore nil pod object", func(t *testing.T) {
		m.OnUpdate(p, nil)
	})
}

func TestProjectAndVersion(t *testing.T) {
	image := "ghcr.io/securego/gosec:v2.9.1"
	v := version(image)
	assert.Equal(t, "v2.9.1", v)

	image = "europe-north1-docker.pkg.dev/nais-io/nais/images/picante@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5"
	v = version(image)
	assert.Equal(t, "sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5", v)

	image = "europe-north1-docker.pkg.dev/nais-io/nais/images/picante:20230504-091909-3efbee3@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5"
	v = version(image)
	assert.Equal(t, "20230504-091909-3efbee3@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5", v)
}
