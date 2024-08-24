package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"

	mockattestation "slsa-verde/mocks/internal_/attestation"
	mockmonitor "slsa-verde/mocks/internal_/monitor"

	"slsa-verde/internal/test"

	"github.com/nais/dependencytrack/pkg/client"

	"slsa-verde/internal/attestation"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var cluster = "test"

var rekor = &attestation.Rekor{
	OIDCIssuer:               "my-iss",
	GitHubWorkflowName:       "http://localhost",
	GitHubWorkflowRef:        "refs/heads/main",
	GitHubWorkflowSHA:        "1234567890",
	BuildTrigger:             "push",
	RunInvocationURI:         "http://localhost",
	SourceRepositoryOwnerURI: "http://localhost",
	BuildConfigURI:           "http://localhost",
	IntegratedTime:           "1629780000",
	LogIndex:                 "1234",
}

func toRekorTags(rekor *attestation.Rekor) []string {
	var tags []string
	tags = append(tags, client.RekorTagPrefix.With(rekor.LogIndex))
	tags = append(tags, client.RekorBuildTriggerTagPrefix.With(rekor.BuildTrigger))
	tags = append(tags, client.RekorOIDCIssuerTagPrefix.With(rekor.OIDCIssuer))
	tags = append(tags, client.RekorGitHubWorkflowNameTagPrefix.With(rekor.GitHubWorkflowName))
	tags = append(tags, client.RekorGitHubWorkflowRefTagPrefix.With(rekor.GitHubWorkflowRef))
	tags = append(tags, client.RekorGitHubWorkflowSHATagPrefix.With(rekor.GitHubWorkflowSHA))
	tags = append(tags, client.RekorSourceRepositoryOwnerURITagPrefix.With(rekor.SourceRepositoryOwnerURI))
	tags = append(tags, client.RekorBuildConfigURITagPrefix.With(rekor.BuildConfigURI))
	tags = append(tags, client.RekorRunInvocationURITagPrefix.With(rekor.RunInvocationURI))
	tags = append(tags, client.RekorIntegratedTimeTagPrefix.With(rekor.IntegratedTime))
	return tags
}

func TestConfigOnAdd(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	att := &attestation.ImageMetadata{
		BundleVerified: false,
		Image:          "test/nginx:latest",
		Statement:      &statement,
		ContainerName:  "test/nginx",
		Digest:         "123",
		RekorMetadata:  rekor,
	}

	tags := workload.initWorkloadTags(att, cluster, "test/nginx", "latest")

	t.Run("should attest image and create project", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[0].Image).Return(att, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{}, nil)
		c.On("CreateProject", mock.Anything, "test/nginx", "latest", "test", tags).Return(&client.Project{
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

func TestConfigOnAddWereProjectCreatedWithOtherInstance(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	att := &attestation.ImageMetadata{
		BundleVerified: false,
		Image:          "test/nginx:latest",
		Statement:      &statement,
		ContainerName:  "test/nginx",
		Digest:         "123",
		RekorMetadata:  rekor,
	}

	tags := workload.initWorkloadTags(att, cluster, "test/nginx", "latest")

	t.Run("should check attested image and tag project if already created", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil).Once()
		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[0].Image).Return(att, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{}, nil)
		c.On("CreateProject", mock.Anything, "test/nginx", "latest", "test", tags).Return(
			nil,
			errors.New("verify attestation: creating request: status 409: err A project with the specified name already exists."),
		)

		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Uuid:    "uuid1",
			Name:    "test/nginx",
			Group:   "test",
			Version: "latest",
			Tags: []client.Tag{
				{Name: client.WorkloadTagPrefix.String() + "test2|testns|app|testapp"},
				{Name: "project:test/nginx"},
				{Name: "image:test/nginx:latest"},
				{Name: "version:latest"},
				{Name: "digest:123"},
				{Name: "rekor:1234"},
			},
		}, nil).Once()

		c.On("UpdateProject", mock.Anything, "uuid1", "test/nginx", "latest", "test", []string{
			client.WorkloadTagPrefix.String() + "test2|testns|app|testapp",
			workload.getTag(cluster),
			"team:testns",
			"env:test2",
			"env:test",
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)
		m.OnAdd(deployment)
	})
}

func TestConfigOnAddSeveralProjectsFromContainers(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest", "test/nginx:latest2")
	workload := NewWorkload(deployment)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	att := &attestation.ImageMetadata{
		BundleVerified: false,
		Image:          "test/nginx:latest",
		Statement:      &statement,
		ContainerName:  "test/nginx",
		Digest:         "123",
		RekorMetadata:  rekor,
	}
	tags := workload.initWorkloadTags(att, cluster, "test/nginx", "latest")
	t.Run("should attest images 2 containers and create 2 projects", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[0].Image).Return(att, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{}, nil)
		c.On("CreateProject", mock.Anything, "test/nginx", "latest", "test", tags).Return(&client.Project{Uuid: "uuid1"}, nil)
		c.On("UploadProject", mock.Anything, "test/nginx", "latest", "uuid1", false, mock.Anything).Return(nil, nil)
		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(nil, nil)

		att = &attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest2",
			Statement:      &statement,
			ContainerName:  "test/nginx",
			Digest:         "123",
			RekorMetadata:  rekor,
		}
		tags = workload.initWorkloadTags(att, cluster, "test/nginx", "latest2")
		c.On("CreateProject", mock.Anything, "test/nginx", "latest2", "test", tags).Return(&client.Project{Uuid: "uuid2"}, nil)
		v.On("Verify", mock.Anything, deployment.Spec.Template.Spec.Containers[1].Image).Return(att, nil)
		c.On("UploadProject", mock.Anything, "test/nginx", "latest2", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should not create project if no metadata is found", func(t *testing.T) {
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(nil, nil)
		v.On("Verify", mock.Anything, mock.Anything).Return(&attestation.ImageMetadata{}, nil)

		m.OnAdd(deployment)
	})
}

func TestConfigOnAddExistsJob(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	job := test.CreateJobWithImage("testns", "testjob", nil, "test/nginx:latest")
	workload := NewWorkload(job)

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should not delete project if this workload(job) is the last successful workload and the version is the same", func(t *testing.T) {
		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "test",
			Uuid:       "uuid1",
			Name:       "test/nginx",
			Publisher:  "Team",
			Tags: []client.Tag{
				{Name: workload.getTag(cluster)},
				{Name: "project:test/nginx"},
				{Name: "image:test/nginx:latest"},
				{Name: "version:latest"},
				{Name: "digest:123"},
				{Name: "rekor:1234"},
			},
			Version: "latest",
		}, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.ProjectTagPrefix.With("test/nginx"))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "test",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: workload.getTag(cluster)},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
				Version: "latest",
			},
		}, nil)
		m.OnAdd(job)
	})

	t.Run("should ignore failed jobs conditions", func(t *testing.T) {
		job.Object["status"] = "unknown"
		m.OnAdd(job)
	})
}

func TestConfigOnAddExistsJobWithNewVersion(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)

	t.Run("should delete project if this workload(job) is the last workload and have new version", func(t *testing.T) {
		job := test.CreateJobWithImage("testns", "testjob", nil, "test/nginx:latest2")
		workload := NewWorkload(job)
		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		att := &attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest2",
			Statement:      &statement,
			ContainerName:  "pod1",
			Digest:         "123",
			RekorMetadata:  rekor,
		}
		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(nil, nil)
		v.On("Verify", mock.Anything, mock.Anything).Return(att, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{
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

		tags := workload.initWorkloadTags(att, cluster, "test/nginx", "latest2")
		c.On("CreateProject", mock.Anything, "test/nginx", "latest2", "test", tags).Return(&client.Project{Uuid: "uuid2"}, nil)
		c.On("UploadProject", mock.Anything, "test/nginx", "latest2", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(job)
	})
}

func TestConfigOnAddExists(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
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
			Tags:                []client.Tag{{Name: workload.getTag(cluster)}, {Name: "project:test/nginx"}, {Name: "image:test/nginx:latest"}, {Name: "version:latest"}, {Name: "digest:123"}, {Name: "rekor:1234"}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape("project:test/nginx")).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "test",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: workload.getTag(cluster)}, {Name: client.WorkloadTagPrefix.With(cluster + "|testns|app|testapp2")}, {Name: "project:test/nginx"}, {Name: "image:test/nginx:latest"}, {Name: "version:latest"}, {Name: "digest:123"}, {Name: "rekor:1234"}},
				Version:    "latest",
			},
		}, nil)

		m.OnAdd(deployment)
	})

	t.Run("should delete project if this workload is the last workload and create new project", func(t *testing.T) {
		c := mockmonitor.NewClient(t)
		v := mockattestation.NewVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest2")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		att := &attestation.ImageMetadata{
			BundleVerified: false,
			Image:          "test/nginx:latest2",
			Statement:      &statement,
			ContainerName:  "pod1",
			Digest:         "123",
			RekorMetadata:  rekor,
		}
		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(nil, nil)
		v.On("Verify", mock.Anything, mock.Anything).Return(att, nil)
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "test",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Publisher:  "Team",
				Tags:       []client.Tag{{Name: workload.getTag(cluster)}, {Name: "project:test/nginx"}, {Name: "image:test/nginx:latest"}, {Name: "version:latest"}, {Name: "digest:124"}, {Name: "rekor:12345"}},
				Version:    "latest",
			},
		}, nil)
		c.On("DeleteProject", mock.Anything, "uuid1").Return(nil)

		tags := workload.initWorkloadTags(att, cluster, "test/nginx", "latest2")
		c.On("CreateProject", mock.Anything, "test/nginx", "latest2", "test", tags).Return(&client.Project{Uuid: "uuid2"}, nil)
		c.On("UploadProject", mock.Anything, "test/nginx", "latest2", "uuid2", false, mock.Anything).Return(nil, nil)

		m.OnAdd(deployment)
	})

	t.Run("should update project tags if this workload is a new workload", func(t *testing.T) {
		c := mockmonitor.NewClient(t)
		v := mockattestation.NewVerifier(t)
		m := NewMonitor(context.Background(), c, v, cluster)
		deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")

		var statement in_toto.CycloneDXStatement
		file, err := os.ReadFile("testdata/sbom.json")
		assert.NoError(t, err)
		err = json.Unmarshal(file, &statement)
		assert.NoError(t, err)

		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "testns",
			Uuid:       "uuid1",
			Name:       "test/nginx",
			Publisher:  "Team",
			Tags: []client.Tag{
				{Name: client.WorkloadTagPrefix.String() + cluster + "|" + "testns" + "|app|" + "testapp2"},
				// {Name: workload.getTag(cluster)},
				{Name: "project:test/nginx"},
				{Name: "image:test/nginx:latest2"},
				{Name: "version:latest2"},
				{Name: "digest:123"},
				{Name: "rekor:1234"},
				{Name: "env:test"},
				{Name: "team:testns"},
				{Name: "build-trigger:push"},
				{Name: "oidc-issuer:my-iss"},
				{Name: "workflow-name:http://localhost"},
				{Name: "workflow-ref:refs/heads/main"},
				{Name: "workflow-sha:1234567890"},
				{Name: "source-repo-owner-uri:http://localhost"},
				{Name: "build-config-uri:http://localhost"},
				{Name: "run-invocation-uri:http://localhost"},
				{Name: "integrated-time:1629780000"},
			},
			Version: "latest2",
		}, nil)

		updateRetTags := []string{
			client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp2",
			workload.getTag(cluster),
			"team:testns",
			"env:test",
			"project:test/nginx",
			"image:test/nginx:latest2",
			"version:latest2",
			"digest:123",
		}
		updateRetTags = append(updateRetTags, toRekorTags(rekor)...)
		c.On("UpdateProject", mock.Anything, "uuid1", "test/nginx", "latest2", "testns", updateRetTags).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.ProjectTagPrefix.With("test/nginx"))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + cluster + "|" + "testns" + "|app|" + "testapp2"},
					{Name: workload.getTag(cluster)},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest2"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
					{Name: "env:test"},
					{Name: "team:testns"},
					{Name: "build-trigger:push"},
					{Name: "oidc-issuer:my-iss"},
					{Name: "workflow-name:http://localhost"},
					{Name: "workflow-ref:refs/heads/main"},
					{Name: "workflow-sha:1234567890"},
					{Name: "source-repo-owner-uri:http://localhost"},
					{Name: "build-config-uri:http://localhost"},
					{Name: "run-invocation-uri:http://localhost"},
					{Name: "integrated-time:1629780000"},
				},
				Version: "latest2",
			},
		}, nil)

		m.OnAdd(deployment)
	})
}

func TestConfigOnDeleteNotADeployment(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)

	// ok
	t.Run("should ignore if not a deployment", func(t *testing.T) {
		m.OnDelete(nil)
	})
}

func TestConfigOnDeleteProjectIsNil(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	// ok
	t.Run("project is nil, should ignore", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return(nil, nil)
		m.OnDelete(deployment)
	})
}

func TestConfigOnDeleteRemoveTag(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, "dev")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")

	t.Run("project exists with more than 1 tag, remove this tag from project", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.WorkloadTagPrefix.String()+"dev|testns|app|testapp")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + "dev|testns|app|testapp"},
					{Name: client.WorkloadTagPrefix.String() + cluster + "|aura|app|testapp"},
					{Name: "env:" + cluster},
					{Name: "env:dev"},
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
			client.WorkloadTagPrefix.String() + cluster + "|aura|app|testapp",
			"team:aura",
			"env:" + cluster,
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
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(deployment)

	t.Run("project with only this workload tag, delete project", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{
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
					{Name: "env:test"},
					{Name: "team:testns"},
				},
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "1").Return(nil)

		m.OnDelete(deployment)
	})
}

func TestConfigOnDeleteDeleteProjectAndRemoveAllOtherTags(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest", "test/nginx:latest2")
	workload := NewWorkload(deployment)

	t.Run("project with only this workload tag, delete project and update if other container ad workload is present", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(workload.getTag(cluster))).Return([]*client.Project{
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
					{Name: "env:test"},
					{Name: "team:testns"},
				},
			},
			{
				Uuid:       "2",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest2",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: workload.getTag(cluster)},
					{Name: client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp3"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest2"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
					{Name: "env:test"},
					{Name: "team:testns"},
				},
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "1").Return(nil)

		c.On("UpdateProject", mock.Anything, "2", "test/nginx", "latest2", "test", []string{
			client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp3",
			"team:testns",
			"env:test",
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
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, "dev")
	deployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest", "test/nginx:latest2")

	t.Run("project exists with more than 1 getTag, remove this tag from project and for all containers in the resource", func(t *testing.T) {
		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.WorkloadTagPrefix.String()+"dev|testns|app|testapp")).Return([]*client.Project{
			{
				Uuid:       "1",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + "dev|testns|app|testapp"},
					{Name: client.WorkloadTagPrefix.String() + cluster + "|aura|app|testapp"},
					{Name: "env:" + cluster},
					{Name: "env:dev"},
					{Name: "team:testns"},
					{Name: "team:aura"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
			{
				Uuid:       "2",
				Group:      "test",
				Name:       "test/nginx",
				Publisher:  "Team",
				Version:    "latest2",
				Classifier: "APPLICATION",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + "dev|testns|app|testapp"},
					{Name: client.WorkloadTagPrefix.String() + cluster + "|aura|app|testapp"},
					{Name: "env:" + cluster},
					{Name: "env:dev"},
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

		c.On("UpdateProject", mock.Anything, "1", "test/nginx", "latest", "test", []string{
			client.WorkloadTagPrefix.String() + cluster + "|aura|app|testapp",
			"team:aura",
			"env:" + cluster,
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)

		c.On("UpdateProject", mock.Anything, "2", "test/nginx", "latest2", "test", []string{
			client.WorkloadTagPrefix.String() + cluster + "|aura|app|testapp",
			"team:aura",
			"env:" + cluster,
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
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	newDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	pastDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(newDeployment)

	t.Run("should ignore none deployment", func(t *testing.T) {
		m.OnUpdate(nil, nil)
	})

	t.Run("should not do anything if condition is not satisfied", func(t *testing.T) {
		replicas := int32(2)
		newDeployment.Spec.Replicas = &replicas
		m.OnUpdate(nil, newDeployment)
	})

	t.Run("should verify deployment if conditions changed and matches", func(t *testing.T) {
		replicas := int32(1)
		pastReplicas := int32(2)
		newDeployment.Spec.Replicas = &replicas
		pastDeployment.Spec.Replicas = &pastReplicas
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier:          "APPLICATION",
			Group:               "testns",
			Name:                "test/nginx",
			Publisher:           "Team",
			Tags:                []client.Tag{{Name: workload.getTag(cluster)}, {Name: "project:test/nginx"}, {Name: "image:test/nginx:latest"}, {Name: "version:latest"}, {Name: "digest:123"}, {Name: "rekor:1234"}},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.ProjectTagPrefix.With("test/nginx"))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Version:    "latest",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + cluster + "|" + "testns" + "|app|" + "testapp"},
					{Name: workload.getTag(cluster)},
					{Name: "team:testns"},
					{Name: "env:test"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)
		m.OnUpdate(pastDeployment, newDeployment)
	})
}

func TestConfigOnUpdateAddWorkloadInOtherNamespace(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, cluster)
	newDeployment := test.CreateDeployment("testns2", "testapp2", nil, nil, "test/nginx:latest")
	pastDeployment := test.CreateDeployment("testns2", "testapp2", nil, nil, "test/nginx:latest")
	workload := NewWorkload(newDeployment)

	t.Run("should verify deployment if conditions changed and matches", func(t *testing.T) {
		replicas := int32(2)
		pastDeployment.Spec.Replicas = &replicas
		c.On("GetProject", mock.Anything, "test/nginx", "latest").Return(&client.Project{
			Classifier: "APPLICATION",
			Uuid:       "uuid1",
			Group:      "testns",
			Name:       "test/nginx",
			Publisher:  "Team",
			Tags: []client.Tag{
				{Name: client.WorkloadTagPrefix.String() + cluster + "|" + "testns" + "|app|" + "testapp"},
				{Name: "team:testns"},
				{Name: "env:test"},
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
			client.WorkloadTagPrefix.String() + cluster + "|" + "testns" + "|app|" + "testapp",
			workload.getTag(cluster),
			"team:testns",
			"team:testns2",
			"env:test",
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest",
			"digest:123",
			"rekor:1234",
		}).Return(&client.Project{
			Uuid: "uuid1",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.ProjectTagPrefix.With("test/nginx"))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Version:    "latest",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + cluster + "|" + "testns" + "|app|" + "testapp"},
					{Name: workload.getTag(cluster)},
					{Name: "team:testns"},
					{Name: "env:test"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		m.OnUpdate(pastDeployment, newDeployment)
	})
}

func TestConfigOnUpdateDeleteTags(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	newDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest2")
	pastDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	workload := NewWorkload(newDeployment)

	t.Run("should ignore deployment if the condition not fulfilled", func(t *testing.T) {
		replicas := int32(2)
		newDeployment.Spec.Replicas = &replicas
		m.OnUpdate(pastDeployment, newDeployment)
	})

	t.Run("should verify deployment if conditions changed and matches", func(t *testing.T) {
		replicas := int32(1)
		newDeployment.Spec.Replicas = &replicas
		pastReplicas := int32(2)
		pastDeployment.Spec.Replicas = &pastReplicas

		c.On("GetProject", mock.Anything, "test/nginx", "latest2").Return(&client.Project{
			Classifier: "APPLICATION",
			Group:      "testns",
			Name:       "test/nginx",
			Publisher:  "Team",
			Tags: []client.Tag{
				{Name: workload.getTag(cluster)},
				{Name: client.WorkloadTagPrefix.String() + cluster + "|testns|app|app2"},
				{Name: "team:testns"},
				{Name: "env:test"},
				{Name: "project:test/nginx"},
				{Name: "image:test/nginx:latest2"},
				{Name: "version:latest"},
				{Name: "digest:123"},
				{Name: "rekor:1234"},
			},
			Version:             "latest",
			LastBomImportFormat: "CycloneDX 1.4",
		}, nil)

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.ProjectTagPrefix.With("test/nginx"))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Version:    "latest",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: workload.getTag(cluster)},
					{Name: client.WorkloadTagPrefix.String() + cluster + "|testns|app|app2"},
					{Name: "team:testns"},
					{Name: "env:test"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest2"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		m.OnUpdate(pastDeployment, newDeployment)
	})
}

func TestConfigOnUpdateDeploymentScaledDown(t *testing.T) {
	c := mockmonitor.NewClient(t)
	v := mockattestation.NewVerifier(t)
	m := NewMonitor(context.Background(), c, v, "test")
	newDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")
	pastDeployment := test.CreateDeployment("testns", "testapp", nil, nil, "test/nginx:latest")

	t.Run("should identify a scale down, where the workload is removed from/ or delete all found projects", func(t *testing.T) {
		replicas := int32(0)
		newDeployment.Status.Replicas = 0
		newDeployment.Spec.Replicas = &replicas
		newDeployment.Status.ReadyReplicas = 0
		newDeployment.Status.AvailableReplicas = 0
		pastReplicas := int32(2)
		pastDeployment.Spec.Replicas = &pastReplicas

		c.On("GetProjectsByTag", mock.Anything, url.QueryEscape(client.WorkloadTagPrefix.With(cluster+"|testns|app|testapp"))).Return([]*client.Project{
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid1",
				Name:       "test/nginx",
				Version:    "latest",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp"},
					{Name: "team:testns"},
					{Name: "env:test"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
			{
				Classifier: "APPLICATION",
				Group:      "testns",
				Uuid:       "uuid2",
				Name:       "test/nginx",
				Version:    "latest2",
				Publisher:  "Team",
				Tags: []client.Tag{
					{Name: client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp2"},
					{Name: client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp"},
					{Name: "team:testns"},
					{Name: "env:test"},
					{Name: "project:test/nginx"},
					{Name: "image:test/nginx:latest"},
					{Name: "version:latest2"},
					{Name: "digest:123"},
					{Name: "rekor:1234"},
				},
			},
		}, nil)

		c.On("DeleteProject", mock.Anything, "uuid1").Return(nil)

		c.On("UpdateProject", mock.Anything, "uuid2", "test/nginx", "latest2", "testns", []string{
			client.WorkloadTagPrefix.String() + cluster + "|testns|app|testapp2",
			"team:testns",
			"env:test",
			"project:test/nginx",
			"image:test/nginx:latest",
			"version:latest2",
			"digest:123",
			"rekor:1234",
		}).Return(nil, nil)

		m.OnUpdate(pastDeployment, newDeployment)
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
