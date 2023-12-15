package monitor

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"testing"

	v1 "k8s.io/api/apps/v1"

	"picante/internal/test"

	"github.com/nais/dependencytrack/pkg/client"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"picante/internal/attestation"
)

var cluster = "test"

func TestConfig_OnAdd(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	w := test.CreateWorkload("team1", "pod1", nil, nil, "nginx:latest")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should attest image and create project", func(t *testing.T) {
		c.On("GetProject", mock.Anything, cluster+":team1:pod1", "latest").Return(nil, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "nginx:latest",
			Statement:      &statement,
			ContainerName:  "pod1",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(cluster+":team1:pod1")).Return([]*client.Project{}, nil)

		c.On("CreateProject", mock.Anything, cluster+":team1:pod1", "latest", "team1", []string{
			cluster + ":team1:pod1",
			"team1",
			"pod1",
			"pod1",
			"nginx:latest",
			cluster,
			"latest",
			"digest:",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("UploadProject", mock.Anything, cluster+":team1:pod1", "latest", "uuid1", false, mock.Anything).Return(nil, nil)

		m.OnAdd(w)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{}, nil)

		m.OnAdd(w)
	})

	t.Run("should ignore nil workload object", func(t *testing.T) {
		m.OnAdd(nil)
	})

	t.Run("should not create if a !active workload", func(t *testing.T) {
		w.Status = v1.ReplicaSetStatus{
			Replicas:          1,
			ReadyReplicas:     0,
			AvailableReplicas: 1,
		}
		m.OnAdd(w)
	})
}

func TestConfig_OnAdd_Exists(t *testing.T) {
	t.Run("should not create project if already exists", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		w := test.CreateWorkload("team1", "pod1", nil, nil, "nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, cluster+":team1:pod1", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "team",
			Name:                cluster + ":team1:pod1",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: "test:team1"}, {Name: "pod1"}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		m.OnAdd(w)
	})

	t.Run("should update project if a project with same name already exists", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		p := test.CreateWorkload("team1", "pod1", nil, nil, "nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, cluster+":team1:pod1", "latest").Return(nil, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "nginx:latest",
			Statement:      &statement,
			ContainerName:  "pod1",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(cluster+":team1:pod1")).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "team",
				Uuid:       "uuid1",
				Name:       cluster + ":team1:pod1",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: cluster + ":team1:pod1"}, {Name: "team1"}, {Name: "pod1"}, {Name: "test"}},
				Version:    "version1",
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "uuid1", cluster+":team1:pod1", "latest", "team1", []string{
			cluster + ":team1:pod1",
			"team1",
			"pod1",
			"pod1",
			"nginx:latest",
			cluster,
			"latest",
			"digest:",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("UploadProject", mock.Anything, cluster+":team1:pod1", "latest", "uuid1", false, mock.Anything).Return(nil, nil)

		m.OnAdd(p)
	})
}

func TestConfig_OnDelete(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	p := test.CreateWorkload("team1", "pod1", nil, nil, "nginx:latest")

	t.Run("should delete project", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test:team1:pod1", "latest").Return(&client.Project{
			Uuid:       "1",
			Classifier: "APPLICATION",
			Group:      "team",
			Name:       "team1:pod1",
			Publisher:  "Team",
			Tags:       []client.Tag{{Name: "test:team1"}, {Name: "pod1"}},
			Version:    "latest",
		}, nil)
		c.On("DeleteProject", mock.Anything, "1").Return(nil)

		m.OnDelete(p)
	})
	t.Run("should ignore nil workload object", func(t *testing.T) {
		m.OnDelete(nil)
	})

	t.Run("should not delete if a active workload", func(t *testing.T) {
		p.Status = v1.ReplicaSetStatus{
			Replicas:          1,
			ReadyReplicas:     1,
			AvailableReplicas: 1,
		}
		m.OnDelete(p)
	})

	t.Run("should delete if a !active workload", func(t *testing.T) {
		p.Status = v1.ReplicaSetStatus{
			Replicas:          1,
			ReadyReplicas:     0,
			AvailableReplicas: 1,
		}
		c.On("DeleteProject", mock.Anything, "1").Return(nil)
		m.OnDelete(p)
	})
}

func TestConfig_OnUpdate(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	w := test.CreateWorkload("team1", "pod1", nil, nil, "nginx:latest")
	o := test.CreateWorkload("team1", "pod2", nil, nil, "nginx:old")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should ignore nil workload object", func(t *testing.T) {
		m.OnUpdate(nil, nil)
	})

	t.Run("should not update if both old and new have the same state", func(t *testing.T) {
		m.OnUpdate(o, w)
	})

	t.Run("should not update if new is not active on update", func(t *testing.T) {
		w.Status = v1.ReplicaSetStatus{
			Replicas:          1,
			ReadyReplicas:     1,
			AvailableReplicas: 0,
		}
		m.OnUpdate(o, w)
	})

	t.Run("should try to update if new is active on update but old is not", func(t *testing.T) {
		w.Status = v1.ReplicaSetStatus{
			Replicas:          1,
			ReadyReplicas:     1,
			AvailableReplicas: 1,
		}
		o.Status = v1.ReplicaSetStatus{
			Replicas:          1,
			ReadyReplicas:     1,
			AvailableReplicas: 0,
		}

		c.On("GetProject", mock.Anything, cluster+":team1:pod1", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "team",
			Name:                cluster + ":team1:pod1",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: "test:team1"}, {Name: "pod1"}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		m.OnUpdate(o, w)
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
