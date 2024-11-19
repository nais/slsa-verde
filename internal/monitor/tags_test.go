package monitor

import (
	"slices"
	"testing"

	"github.com/nais/dependencytrack/pkg/client"
)

func TestNewTags(t *testing.T) {
	tags := NewTags()

	if tags == nil {
		t.Errorf("NewTags() = %v, want non-nil", tags)
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
			Name: "env:my-cluster",
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
	if !slices.Contains(workloadTags.EnvironmentTags, "env:my-cluster") {
		t.Errorf("ArrangeByPrefix() = %v, want 'env:my-cluster' in EnvironmentTags", workloadTags.EnvironmentTags)
	}
	if !slices.Contains(workloadTags.OtherTags, "other:getTag") {
		t.Errorf("ArrangeByPrefix() = %v, want 'other:getTag' in OtherTags", workloadTags.OtherTags)
	}

	if len(workloadTags.GetAllTags()) != 4 {
		t.Errorf("ArrangeByPrefix() = %v, want 4 tags", workloadTags.GetAllTags())
	}

	workloadTags.DeleteWorkloadTag("workload:my-cluster|my-namespace|app|my-app")
	if len(workloadTags.WorkloadTags) != 0 {
		t.Errorf("DeleteWorkloadTag() = %v, want 0 tags", workloadTags.WorkloadTags)
	}

	workloadTags.addWorkloadTag("workload:my-cluster|my-namespace|app|my-app")
	if len(workloadTags.WorkloadTags) != 1 {
		t.Errorf("addWorkloadTag() = %v, want 1 tags", workloadTags.WorkloadTags)
	}

	workloadTags.addWorkloadTag("workload:my-cluster2|my-namespace2|app|my-app")
	if len(workloadTags.WorkloadTags) != 2 {
		t.Errorf("addWorkloadTag() = %v, want 2 tags", workloadTags.WorkloadTags)
	}

	workloadTags.verifyTags()
	if len(workloadTags.EnvironmentTags) != 2 {
		t.Errorf("verifyTags() = %v, want 2 tags", workloadTags.EnvironmentTags)
	}

	if len(workloadTags.TeamTags) != 2 {
		t.Errorf("verifyTags() = %v, want 2 tags", workloadTags.TeamTags)
	}

	if len(workloadTags.OtherTags) != 1 {
		t.Errorf("verifyTags() = %v, want 1 tags", workloadTags.OtherTags)
	}
}

func TestContainsAllTags(t *testing.T) {
	tags := []client.Tag{
		{
			Name: "workload:my-cluster|my-namespace|app|my-app",
		},
		{
			Name: "team:my-namespace",
		},
		{
			Name: "env:my-cluster",
		},
	}

	if !containsAllTags(tags, "workload:my-cluster|my-namespace|app|my-app", "team:my-namespace", "env:my-cluster") {
		t.Errorf("ContainsAllTags() = false, want true")
	}
}
