package monitor

import (
	"slices"
	"testing"

	"github.com/nais/dependencytrack/pkg/client"

	"picante/internal/attestation"
	"picante/internal/test"
)

func TestNewTags(t *testing.T) {
	tags := NewTags()

	if tags == nil {
		t.Errorf("NewTags() = %v, want non-nil", tags)
	}
}

func TestInitTags(t *testing.T) {
	d := test.CreateDeployment("my-namespace", "my-app", nil, nil, "")
	meta := &attestation.ImageMetadata{
		RekorLogIndex: "10001",
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
	if !slices.Contains(tags, "environment:my-cluster") {
		t.Errorf("initTags() = %v, want 'environment:my-cluster' in tags", tags)
	}
	if !slices.Contains(tags, "team:my-namespace") {
		t.Errorf("initTags() = %v, want 'team:my-namespace' in tags", tags)
	}
	if !slices.Contains(tags, "workload:my-cluster|my-namespace|app|my-app") {
		t.Errorf("initTags() = %v, want 'workload:my-cluster|my-namespace|app|my-app' in tags", tags)
	}
}

func TestArrangeByPrefix(t *testing.T) {
	workloadTags := NewTags()
	clientTags := []client.Tag{
		{
			Name: "workload:my-cluster|my-namespace|app|my-app",
		},
		{
			Name: "team:my-namespace",
		},
		{
			Name: "environment:my-cluster",
		},
		{
			Name: "other:getTag",
		},
	}

	workloadTags.ArrangeByPrefix(clientTags)

	if !slices.Contains(workloadTags.WorkloadTags, "workload:my-cluster|my-namespace|app|my-app") {
		t.Errorf("ArrangeByPrefix() = %v, want 'workload:my-cluster|my-namespace|app|my-app' in WorkloadTags", workloadTags.WorkloadTags)
	}
	if !slices.Contains(workloadTags.TeamTags, "team:my-namespace") {
		t.Errorf("ArrangeByPrefix() = %v, want 'team:my-namespace' in TeamTags", workloadTags.TeamTags)
	}
	if !slices.Contains(workloadTags.EnvironmentTags, "environment:my-cluster") {
		t.Errorf("ArrangeByPrefix() = %v, want 'environment:my-cluster' in EnvironmentTags", workloadTags.EnvironmentTags)
	}
	if !slices.Contains(workloadTags.OtherTags, "other:getTag") {
		t.Errorf("ArrangeByPrefix() = %v, want 'other:getTag' in OtherTags", workloadTags.OtherTags)
	}

	if len(workloadTags.getAllTags()) != 4 {
		t.Errorf("ArrangeByPrefix() = %v, want 4 tags", workloadTags.getAllTags())
	}

	workloadTags.deleteWorkloadTag("workload:my-cluster|my-namespace|app|my-app")
	if len(workloadTags.WorkloadTags) != 0 {
		t.Errorf("deleteWorkloadTag() = %v, want 0 tags", workloadTags.WorkloadTags)
	}

	workloadTags.addWorkloadTag("workload:my-cluster|my-namespace|app|my-app")
	if len(workloadTags.WorkloadTags) != 1 {
		t.Errorf("addWorkloadTag() = %v, want 1 tags", workloadTags.WorkloadTags)
	}
}
