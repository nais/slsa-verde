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

	"picante/internal/attestation"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var cluster = "test"

func TestConfigOnAdd(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should attest image and create project", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)

		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[0]).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest",
			Statement:      &statement,
			ContainerName:  "test/nginx",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:test/nginx")).Return([]*client.Project{}, nil)

		c.On("CreateProject", mock.Anything, "test/nginx", "latest", "test", []string{
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
			"environment:test",
			"team:testns",
			workload.getTag(cluster),
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("UploadProject", mock.Anything, "test/nginx", "latest", "uuid1", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{}, nil)

		m.OnAdd(deployment)
	})

	t.Run("should ignore nil workload object", func(t *testing.T) {
		m.OnAdd(nil)
	})
}

func TestConfigOnAddSeveralProjectsFromContainers(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest", "test/nginx:latest2")
	workload := NewWorkload(deployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should attest images 2 containers and create 2 projects", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[0]).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest",
			Statement:      &statement,
			ContainerName:  "test/nginx",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:test/nginx")).Return([]*client.Project{}, nil)
		c.On("CreateProject", mock.Anything, "test/nginx", "latest", "test", []string{
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
			"environment:test",
			"team:testns",
			workload.getTag(cluster),
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)
		c.On("UploadProject", mock.Anything, "test/nginx", "latest", "uuid1", false, mock.Anything).Return(nil, nil)

		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(nil, nil)
		c.On("CreateProject", mock.Anything, "test/nginx", "latest2", "test", []string{
			"project:test/nginx",
			"image:test/nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
			"environment:test",
			"team:testns",
			workload.getTag(cluster),
		}).Return(&client.Project{
			Uuid: "uuid2",
		}, nil)

		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[1]).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest2",
			Statement:      &statement,
			ContainerName:  "test/nginx",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)
		c.On("UploadProject", mock.Anything, "test/nginx", "latest2", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{}, nil)

		m.OnAdd(deployment)
	})
}

func TestConfigOnAddExists(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should not create project if already exists", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "test",
			Name:                "test/nginx",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: workload.getTag(cluster)}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		m.OnAdd(deployment)
	})

	t.Run("should delete project if this workload is the last workload and create new project", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest2")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(nil, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest2",
			Statement:      &statement,
			ContainerName:  "pod1",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:test/nginx")).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "test",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: workload.getTag(cluster)}, {Name: "project:test/nginx"}},
				Version:    "latest",
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "uuid1").Return(nil)

		c.On("CreateProject", mock.Anything, "test/nginx", "latest2", "test", []string{
			"project:test/nginx",
			"image:test/nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
			"environment:test",
			"team:testns",
			workload.getTag(cluster),
		}).Return(&client.Project{
			Uuid: "uuid2",
		}, nil)

		c.On("UploadProject", mock.Anything, "test/nginx", "latest2", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should update project tags if this workload is a new workload", func(t *testing.T) {
		c := NewMockClient(t)
		v := attestation.NewMockVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)

		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest",
			Statement:      &statement,
			ContainerName:  "pod1",
			Digest:         "123",
			RekorLogIndex:  "1234",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:test/nginx")).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: WorkloadTagPrefix + cluster + "|" + "testns" + "|app|" + "testapp2"},
					{Name: workload.getTag(cluster)},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest2"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
					{Name: "environment:test"},
					{Name: "team:testns"},
				},
				Version: "latest2",
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "uuid1", "test/nginx", "latest2", "testns", []string{
			WorkloadTagPrefix + cluster + "|testns|app|testapp2",
			"team:testns",
			"environment:test",
			"project:test/nginx",
			"image:test/nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("CreateProject", mock.Anything, "test/nginx", "latest", "test", []string{
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
			"environment:test",
			"team:testns",
			workload.getTag(cluster),
		}).Return(&client.Project{
			Uuid: "uuid2",
		}, nil)

		c.On("UploadProject", mock.Anything, "test/nginx", "latest", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})
}

func TestConfigOnDeleteNotADeployment(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)

	// ok
	t.Run("should ignore if not a deployment", func(t *testing.T) {
		m.OnDelete(nil)
	})
}

func TestConfigOnDeleteProjectIsNil(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")

	// ok
	t.Run("project is nil, should ignore", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest")).Return(nil, nil)
		m.OnDelete(deployment)
	})
}

func TestConfigOnDeleteRemoveTag(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "dev")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")

	t.Run("project exists with more than 1 getTag, remove this getTag from project", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: WorkloadTagPrefix + "dev|testns|app|testapp"},
					{Name: WorkloadTagPrefix + cluster + "|aura|app|testapp"},
					{Name: "environment:" + cluster},
					{Name: "environment:dev"},
					{Name: "team:testns"},
					{Name: "team:aura"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "1", "test/nginx", "latest", "test", []string{
			WorkloadTagPrefix + cluster + "|aura|app|testapp",
			"team:aura",
			"environment:" + cluster,
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)
		m.OnDelete(deployment)
	})
}

func TestConfigOnDeleteDeleteProject(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	t.Run("project with only this workload getTag, delete project", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: workload.getTag(cluster)},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
					{Name: "environment:test"},
					{Name: "team:testns"},
				},
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "1").Return(nil)

		m.OnDelete(deployment)
	})
}

func TestConfigOnDeleteDeleteProjectAndRemoveAllOtherTags(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest", "test/nginx:latest2")
	workload := NewWorkload(deployment)

	t.Run("project with only this workload getTag, delete project, and remove/update other tags associated with this workload", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: workload.getTag(cluster)},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
					{Name: "environment:test"},
					{Name: "team:testns"},
				},
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "1").Return(nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest2")).Return([]*client.Project{
			{
				Uuid:       "2",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest2",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: workload.getTag(cluster)},
					{Name: WorkloadTagPrefix + cluster + "|testns|app|testapp3"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest2"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
					{Name: "environment:test"},
					{Name: "team:testns"},
				},
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "2", "test/nginx", "latest2", "test", []string{
			WorkloadTagPrefix + cluster + "|testns|app|testapp3",
			"team:testns",
			"environment:test",
			"project:test/nginx",
			"image:test/nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)
		m.OnDelete(deployment)
	})
}

func TestConfigOnDeleteRemoveTagFromBothContainerImages(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "dev")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest", "test/nginx:latest2")

	t.Run("project exists with more than 1 getTag, remove this getTag from project and for all containers in the resource", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: WorkloadTagPrefix + "dev|testns|app|testapp"},
					{Name: WorkloadTagPrefix + cluster + "|aura|app|testapp"},
					{Name: "environment:" + cluster},
					{Name: "environment:dev"},
					{Name: "team:testns"},
					{Name: "team:aura"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "1", "test/nginx", "latest", "test", []string{
			WorkloadTagPrefix + cluster + "|aura|app|testapp",
			"team:aura",
			"environment:" + cluster,
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("image:test/nginx:latest2")).Return([]*client.Project{
			{
				Uuid:       "2",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest2",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: WorkloadTagPrefix + "dev|testns|app|testapp"},
					{Name: WorkloadTagPrefix + cluster + "|aura|app|testapp"},
					{Name: "environment:" + cluster},
					{Name: "environment:dev"},
					{Name: "team:testns"},
					{Name: "team:aura"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest2"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		c.On("UpdateProject", mock.Anything, "2", "test/nginx", "latest2", "test", []string{
			WorkloadTagPrefix + cluster + "|aura|app|testapp",
			"team:aura",
			"environment:" + cluster,
			"project:test/nginx",
			"image:test/nginx:latest2",
			"version:latest2",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)
		m.OnDelete(deployment)
	})
}

func TestConfigOnUpdate(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	newDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	oldDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(newDeployment)

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

		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "testns",
			Name:                "test/nginx",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: workload.getTag(cluster)}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)
		m.OnUpdate(oldDeployment, newDeployment)
	})
}

func TestConfigOnUpdateAddWorkloadInOtherNamespace(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	newDeployment := test.CreateDeployment("testns2", "testapp2", nil, nil, "test/nginx:latest")
	oldDeployment := test.CreateDeployment("testns2", "testapp2", nil, nil, "test/nginx:latest")
	workload := NewWorkload(newDeployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should verify deployment if conditions changed and matches", func(t *testing.T) {
		newDeployment.Status.Conditions = []v1.DeploymentCondition{
			{
				Type:   v1.DeploymentProgressing,
				Status: "True",
				Reason: "NewReplicaSetAvailable",
			},
		}

		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier: "APPLICATION",
			Uuid:       "uuid1",
			Group:      "testns",
			Name:       "test/nginx",
			Publisher:  "Team",
			Tags: []client.Tag{
				{Name: WorkloadTagPrefix + cluster + "|" + "testns" + "|app|" + "testapp"},
				{Name: "team:testns"},
				{Name: "environment:test"},
				{Name: "project:test/nginx"},
				{Name: "image:test/nginx:latest"},
				{Name: "version:latest"},
				{Name: "digest:123"},
				{Name: "rekor:1234"},
			},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		c.On("UpdateProject", mock.Anything, "uuid1", "test/nginx", "latest", "testns", []string{
			WorkloadTagPrefix + cluster + "|" + "testns" + "|app|" + "testapp",
			workload.getTag(cluster),
			"team:testns",
			"team:testns2",
			"environment:test",
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		m.OnUpdate(oldDeployment, newDeployment)
	})
}

func TestConfigOnUpdateDeleteTags(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	newDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest2")
	oldDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(newDeployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should verify deployment if conditions changed and matches", func(t *testing.T) {
		newDeployment.Status.Conditions = []v1.DeploymentCondition{
			{
				Type:   v1.DeploymentProgressing,
				Status: "True",
				Reason: "NewReplicaSetAvailable",
			},
		}

		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "testns",
			Name:       "test/nginx",
			Publisher:  "Team",
			Tags: []client.Tag{
				{Name: workload.getTag(cluster)},
				{Name: WorkloadTagPrefix + cluster + "|testns|app|app2"},
			},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		m.OnUpdate(oldDeployment, newDeployment)
	})
}

func TestProjectAndVersion(t *testing.T) {
	image := "ghcr.io/securego/gosec:v2.9.1"
	v := getProjectVersion(image)
	assert.Equal(t, "v2.9.1", v)

	image = "europe-north1-docker.pkg.dev/nais-io/nais/images/picante@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5"
	v = getProjectVersion(image)
	assert.Equal(t, "sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5", v)

	image = "europe-north1-docker.pkg.dev/nais-io/nais/images/picante:20230504-091909-3efbee3@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5"
	v = getProjectVersion(image)
	assert.Equal(t, "20230504-091909-3efbee3@sha256:456d4c3f4b2ae92baf02b2516e025abc44464be9447ea04b163a0c8d091d30b5", v)
}
