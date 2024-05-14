package monitor

import (
	"context"
	"encoding/json"
	v1 "k8s.io/api/apps/v1"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"

	"picante/internal/test"

	"github.com/nais/dependencytrack/pkg/client"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"picante/internal/attestation"
)

var cluster = "test"

func Test_DigestHasChanged(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)

	metadata := &attestation.ImageMetadata{
		Digest: "digest1",
	}

	p := &client.Project{
		Name:    "test:app",
		Tags:    []client.Tag{{Name: "digest:digest1"}, {Name: "test:app"}},
		Uuid:    uuid.New().String(),
		Version: "2021-01-01",
	}

	// We test the case where the digest has not changed
	hasChanged := m.digestHasChanged(metadata, p)
	if hasChanged {
		t.Errorf("Expected false, got %v", hasChanged)
	}

	// We test the case where the digest has changed
	metadata.Digest = "digest2"
	hasChanged = m.digestHasChanged(metadata, p)
	if !hasChanged {
		t.Errorf("Expected true, got %v", hasChanged)
	}
}

func TestConfig_OnAdd(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should attest image and create project", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "nginx", "latest").Return(nil, nil)

		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[0]).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "nginx:latest",
			Statement:      &statement,
			ContainerName:  "nginx",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:"+"nginx")).Return([]*client.Project{}, nil)

		c.On("CreateProject", mock.Anything, "nginx", "latest", "testns", []string{
			"project:nginx",
			"image:nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
			"instance:" + cluster + "-" + "testns" + "-" + "testapp",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("UploadProject", mock.Anything, "nginx", "latest", "uuid1", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{}, nil)

		m.OnAdd(deployment)
	})

	t.Run("should ignore nil workload object", func(t *testing.T) {
		m.OnAdd(nil)
	})
}

func TestConfig_OnAdd_Exists(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should not create project if already exists", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "nginx", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "testns",
			Name:                "nginx",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp"}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		m.OnAdd(deployment)
	})

	t.Run("should delete project if this instance (Deployment) is the last instance and create new project", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		deployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest2")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, "nginx", "latest2").Return(nil, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "nginx:latest2",
			Statement:      &statement,
			ContainerName:  "pod1",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:"+"nginx")).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "nginx",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp"}, {Name: "project:nginx"}},
				Version:    "latest",
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "uuid1").Return(nil)

		c.On("CreateProject", mock.Anything, "nginx", "latest2", "testns", []string{
			"project:nginx",
			"image:nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
			"instance:" + cluster + "-" + "testns" + "-" + "testapp",
		}).Return(&client.Project{
			Uuid: "uuid2",
		}, nil)

		c.On("UploadProject", mock.Anything, "nginx", "latest2", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should update project tags if this instance (Deployment) is a new instance", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		deployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, "nginx", "latest").Return(nil, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "nginx:latest",
			Statement:      &statement,
			ContainerName:  "pod1",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:"+"nginx")).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "nginx",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp2"},
					{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp"},
					{Name: "project:nginx"},
					{Name: "image:nginx:latest2"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
				Version: "latest2",
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "uuid1", "nginx", "latest2", "testns", []string{
			"instance:" + cluster + "-" + "testns" + "-" + "testapp2",
			"project:nginx",
			"image:nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("CreateProject", mock.Anything, "nginx", "latest", "testns", []string{
			"project:nginx",
			"image:nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
			"instance:" + cluster + "-" + "testns" + "-" + "testapp",
		}).Return(&client.Project{
			Uuid: "uuid2",
		}, nil)

		c.On("UploadProject", mock.Anything, "nginx", "latest", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})
}

func TestConfig_OnDelete(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest")

	t.Run("should ignore if not a deployment", func(t *testing.T) {
		m.OnDelete(nil)
	})

	t.Run("project is nil, should ignore", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("instance:"+cluster+"-"+"testns"+"-"+"testapp")).Return(nil, nil)
		m.OnDelete(deployment)

	})

	t.Run("project exists, with more then 1 tag, remove this tag from project", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("instance:"+cluster+"-"+"testns"+"-"+"testapp")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "testns",
				Name:       "nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp"},
					{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp2"},
					{Name: "project:nginx"},
					{Name: "image:nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "1", "nginx", "latest", "testns", []string{
			"instance:" + cluster + "-" + "testns" + "-" + "testapp2",
			"project:nginx",
			"image:nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)
		m.OnDelete(deployment)
	})

	t.Run("project with only this instance tag, delete project", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("instance:"+cluster+"-"+"testns"+"-"+"testapp")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "testns",
				Name:       "nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp"},
					{Name: "project:nginx"},
					{Name: "image:nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "1").Return(nil)
		m.OnDelete(deployment)
	})
}

func TestConfig_OnUpdate(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	newDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest")
	oldDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "nginx:latest")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should ignore none deployment", func(t *testing.T) {
		m.OnUpdate(nil, nil)
	})

	t.Run("should not do anything if conditions not changed", func(t *testing.T) {
		m.OnUpdate(oldDeployment, newDeployment)
	})

	t.Run("should verify deployment if conditions changed and matches", func(t *testing.T) {
		newDeployment.Status.Conditions = []v1.DeploymentCondition{
			{
				Type:   v1.DeploymentProgressing,
				Status: "True",
				Reason: "NewReplicaSetAvailable",
			},
		}

		c.On("GetProject", mock.Anything, "nginx", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "testns",
			Name:                "nginx",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: "instance:" + cluster + "-" + "testns" + "-" + "testapp"}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		m.OnUpdate(oldDeployment, newDeployment)
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
