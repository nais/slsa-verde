package monitor

import (
	"slices"
	"testing"

	"slsa-verde/internal/attestation"
	"slsa-verde/internal/test"
)

func TestNewWorkload(t *testing.T) {
	d := test.CreateDeployment("my-namespace", "my-app", nil, nil, "test/my-app:1.0.0")
	workload := NewWorkload(d)
	if workload.Type != "app" {
		t.Errorf("NewWorkload() = %v, want 'app'", workload.Type)
	}
	if workload.Name != "my-app" {
		t.Errorf("NewWorkload() = %v, want 'my-app'", workload.Name)
	}

	j := test.CreateJob("my-namespace", "my-job", nil)
	workload = NewWorkload(j)
	if workload.Type != "job" {
		t.Errorf("NewWorkload() = %v, want 'job'", workload.Type)
	}
	if workload.Name != "my-job" {
		t.Errorf("NewWorkload() = %v, want 'my-job'", workload.Name)
	}
}

func TestInitWorkloadTags(t *testing.T) {
	d := test.CreateDeployment("my-namespace", "my-app", nil, nil, "")
	workloadRekor := &attestation.Rekor{
		OIDCIssuer:               "my-iss",
		GitHubWorkflowName:       "my-workflow",
		GitHubWorkflowRef:        "refs/heads/main",
		BuildTrigger:             "push",
		RunInvocationURI:         "http://localhost",
		SourceRepositoryOwnerURI: "http://localhost",
		BuildConfigURI:           "http://localhost",
		IntegratedTime:           "1629780000",
		LogIndex:                 "10001",
		GitHubWorkflowSHA:        "1234567890",
	}
	meta := &attestation.ImageMetadata{
		RekorMetadata: workloadRekor,
		Image:         "my-app:1.0.0",
		Digest:        "sha256:1234567890",
	}
	workload := NewWorkload(d)
	tags := workload.initWorkloadTags(meta, "my-cluster", "dp-project", "1.0.0")

	if !slices.Contains(tags, "image:my-app:1.0.0") {
		t.Errorf("initTags() = %v, want 'image:my-app:1.0.0' in tags", tags)
	}
	if !slices.Contains(tags, "version:1.0.0") {
		t.Errorf("initTags() = %v, want 'version:1.0.0' in tags", tags)
	}
	if !slices.Contains(tags, "digest:sha256:1234567890") {
		t.Errorf("initTags() = %v, want 'digest:sha256:1234567890' in tags", tags)
	}
	if !slices.Contains(tags, "rekor:10001") {
		t.Errorf("initTags() = %v, want 'rekor:10001' in tags", tags)
	}
	if !slices.Contains(tags, "env:my-cluster") {
		t.Errorf("initTags() = %v, want 'env:my-cluster' in tags", tags)
	}
	if !slices.Contains(tags, "team:my-namespace") {
		t.Errorf("initTags() = %v, want 'team:my-namespace' in tags", tags)
	}
	if !slices.Contains(tags, "workload:my-cluster|my-namespace|app|my-app") {
		t.Errorf("initTags() = %v, want 'workload:my-cluster|my-namespace|app|my-app' in tags", tags)
	}
	if !slices.Contains(tags, "build-trigger:push") {
		t.Errorf("initTags() = %v, want 'build-trigger:push' in tags", tags)
	}
	if !slices.Contains(tags, "workflow-name:my-workflow") {
		t.Errorf("initTags() = %v, want 'workflow-name:my-workflow' in tags", tags)
	}
	if !slices.Contains(tags, "workflow-ref:refs/heads/main") {
		t.Errorf("initTags() = %v, want 'workflow-ref:refs/heads/main' in tags", tags)
	}
	if !slices.Contains(tags, "source-repo-owner-uri:http://localhost") {
		t.Errorf("initTags() = %v, want 'source-repo-owner-uri:http://localhost' in tags", tags)
	}
	if !slices.Contains(tags, "build-config-uri:http://localhost") {
		t.Errorf("initTags() = %v, want 'build-config-uri:http://localhost' in tags", tags)
	}
	if !slices.Contains(tags, "oidc-issuer:my-iss") {
		t.Errorf("initTags() = %v, want 'oidc-issuer:my-iss' in tags", tags)
	}
	if !slices.Contains(tags, "run-invocation-uri:http://localhost") {
		t.Errorf("initTags() = %v, want 'run-invocation-uri:http://localhost' in tags", tags)
	}
	if !slices.Contains(tags, "integrated-time:1629780000") {
		t.Errorf("initTags() = %v, want 'integrated-time:1629780000' in tags", tags)
	}
	if !slices.Contains(tags, "workflow-sha:1234567890") {
		t.Errorf("initTags() = %v, want 'workflow-sha:1234567890' in tags", tags)
	}
}

func TestJobName(t *testing.T) {
	j := test.CreateJob("my-namespace", "my-job", map[string]string{"app": "my-job"})
	name := jobName(j)
	if name != "my-job" {
		t.Errorf("jobName() = %v, want 'my-job'", name)
	}

	j = test.CreateJob("my-namespace", "my-job-20123", nil)
	name = jobName(j)
	if name != "my-job" {
		t.Errorf("jobName() = %v, want 'my-job'", name)
	}
}
