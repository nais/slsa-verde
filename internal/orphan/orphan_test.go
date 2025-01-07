package orphan

import (
	"context"
	"testing"

	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"k8s.io/apimachinery/pkg/runtime"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mockmonitor "slsa-verde/mocks/internal_/monitor"

	"github.com/nais/dependencytrack/pkg/client"
)

func TestTidyWorkloadProject(t *testing.T) {
	mockClient := mockmonitor.NewClient(t)

	props := New(context.Background(), mockClient, nil, "test-cluster", log.WithField("system", "test"))

	project := &client.Project{
		Name: "test-project",
		Uuid: "test-uuid",
		Tags: []client.Tag{{Name: "workload:cluster|namespace|type|name"}},
	}

	workloadTag := "workload:cluster|namespace|type|name"

	t.Run("Successful project deletion", func(t *testing.T) {
		mockClient.On("DeleteProject", mock.Anything, "test-uuid").Return(nil)

		err := props.TidyWorkloadProject(project, workloadTag, false)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		mockClient.AssertCalled(t, "DeleteProject", mock.Anything, "test-uuid")
	})
}

func TestRunWithFakeK8sClient(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = nais_io_v1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
	}
	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(deployment).Build()
	mockClient := mockmonitor.NewClient(t)

	logger := log.WithField("system", "test")
	props := New(context.Background(), mockClient, fakeK8sClient, "test-cluster", logger)

	mockClient.On("GetProjectsByTag", mock.Anything, "env:test-cluster").
		Return([]*client.Project{
			{
				Name:    "test-project",
				Uuid:    "test-uuid",
				Version: "latest",
				Group:   "test-group",
				Tags: []client.Tag{
					{Name: "workload:test-cluster|default|type|test-deployment"},
					{Name: "workload:test-cluster|namespace|type|name"},
					{Name: "team:default"},
					{Name: "image:latest"},
					{Name: "env:test-cluster"},
					{Name: "rekor:1010"},
					{Name: "digest:sha256:123"},
				},
			},
		}, nil)

	mockClient.On("UpdateProject", mock.Anything, "test-uuid", "test-project", "latest", "test-group", []string{
		"workload:test-cluster|default|type|test-deployment",
		"team:default",
		"env:test-cluster",
		"image:latest",
		"rekor:1010",
		"digest:sha256:123",
	}).Return(&client.Project{}, nil)

	err := props.Run(false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	mockClient.AssertCalled(t, "GetProjectsByTag", mock.Anything, "env:test-cluster")
	mockClient.AssertCalled(t, "UpdateProject", mock.Anything, "test-uuid", "test-project", "latest", "test-group", []string{
		"workload:test-cluster|default|type|test-deployment",
		"team:default",
		"env:test-cluster",
		"image:latest",
		"rekor:1010",
		"digest:sha256:123",
	})
}
