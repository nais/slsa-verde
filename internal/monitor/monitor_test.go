package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/nais/dependencytrack/pkg/httpclient"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"picante/internal/attestation"
	"picante/internal/pod"

	"github.com/stretchr/testify/assert"
)

func TestConfig_OnAdd(t *testing.T) {
	c := NewMockClient(t)
	v := attestation.NewMockVerifier(t)
	m := NewMonitor(context.Background(), c, v)
	pod := createPod("team1", "pod1", nil, "nginx:latest")

	var statement in_toto.CycloneDXStatement
	file, err := os.ReadFile("testdata/sbom.json")
	assert.NoError(t, err)
	err = json.Unmarshal(file, &statement)
	assert.NoError(t, err)

	t.Run("should attest image and create project", func(t *testing.T) {
		v.On("Verify", mock.Anything, mock.Anything).Return([]*attestation.ImageMetadata{
			{
				BundleVerified: false,
				Image:          "nginx:latest",
				Statement:      &statement,
			},
		}, nil)

		c.On("GetProject", mock.Anything, "pod1:nginx", "latest").Return(nil, &httpclient.RequestError{
			StatusCode: 404,
			Err:        errors.New("project not found"),
		})

		c.On("CreateProject", mock.Anything, "pod1:nginx", "latest", "team1", []string{"team1"}).Return(nil, nil)

		c.On("UploadProject", mock.Anything, "pod1:nginx", "latest", mock.Anything).Return(nil, nil)

		m.OnAdd(pod)
	})
}

func createPod(namespace, name string, labels map[string]string, images ...string) *v1.Pod {
	c := make([]v1.Container, 0)
	for _, image := range images {
		c = append(c, v1.Container{
			Image: image,
		})
	}
	l := merge(map[string]string{
		pod.SalsaKeylessProviderLabelKey:  "cosign",
		pod.SalsaKeyRefLabelKey:           "testdata/cosign.key",
		pod.SalsaPredicateLabelKey:        "cyclonedx",
		pod.TeamLabelKey:                  namespace,
		pod.IgnoreTransparencyLogLabelKey: "true",
	}, labels)
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    l,
		},
		Spec: v1.PodSpec{
			Containers: c,
		},
	}
}

func merge(map1, map2 map[string]string) map[string]string {
	mergedMap := make(map[string]string)
	for key, value := range map1 {
		mergedMap[key] = value
	}
	for key, value := range map2 {
		mergedMap[key] = value
	}
	return mergedMap
}

//func TestEnsureAttested(t *testing.T) {
//	ctx := context.Background()
//
//	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Header().Set("Content-Type", "application/json")
//		_, err := fmt.Fprintf(w, "{\"token\":\"token1\"}\n")
//		assert.NoError(t, err)
//	}))
//	defer server.Close()
//
//	dockerRegistryUserID := "ttl.sh/nais/picante"
//	tagName := "1h"
//	tag := dockerRegistryUserID + ":" + tagName
//	dCli, err := DockerBuild(dockerRegistryUserID, "testdata", "Dockerfile", tagName)
//	assert.NoError(t, err)
//
//	err = DockerPush(dCli, dockerRegistryUserID, tagName)
//	assert.NoError(t, err)
//
//	attCommand := attest.AttestCommand{
//		KeyOpts: options.KeyOpts{
//			StaticKeyRef: "testdata/cosign.key",
//		},
//		RegistryOptions: options.RegistryOptions{},
//		PredicatePath:   "testdata/sbom.json",
//		PredicateType:   "cyclonedx",
//		TlogUpload:      false,
//	}
//
//	err = attCommand.Exec(ctx, tag)
//	assert.NoError(t, err)
//
//	sorageClient := storage.NewClient(server.URL+"/api/v1/bom", "token1")
//	opts := &attestation.VerifyAttestationOpts{
//		VerifyCmd: &verify.VerifyAttestationCommand{
//			IgnoreTlog:    true,
//			StaticKeyRef:        "testdata/cosign.pub",
//			PredicateType: "cyclonedx",
//		},
//	}
//	cfg := NewMonitor(ctx, sorageClient, opts)
//
//	err = cfg.ensureAttested(context.Background(), &pod.Info{
//		Name:            "app2",
//		ContainerImages: []string{tag},
//	})
//	assert.NoError(t, err)
//}

func TestProjectAndVersion(t *testing.T) {
	image := "ghcr.io/securego/gosec:v2.9.1"
	p, v := projectAndVersion("yolo", image)
	assert.Equal(t, "yolo:ghcr.io/securego/gosec", p)
	assert.Equal(t, "v2.9.1", v)
}
