package monitor

import (
	"picante/internal/attestation"
	"picante/internal/test"
	"slices"
	"testing"
)

func TestNewTags(t *testing.T) {
	tags := NewTags()

	if tags == nil {
		t.Errorf("NewTags() = %v, want non-nil", tags)
	}
}

func TestInitTags(t *testing.T) {
	d := test.CreateDeployment("my-cluster", "my-namespace", nil, nil, "my-app")
	meta := &attestation.ImageMetadata{
		RekorLogIndex: "10001",
		Image:         "my-app:1.0.0",
		Digest:        "sha256:1234567890",
	}

	tags := initTags(d.GetObjectMeta(), meta, "my-cluster", "dp-project", "1.0.0")

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
	if !slices.Contains(tags, "workload:my-cluster|my-namespace|app|my-namespace") {
		t.Errorf("initTags() = %v, want 'workload:my-cluster|my-namespace|app|my-namespace' in tags", tags)
	}

}
