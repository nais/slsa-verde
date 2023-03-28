package monitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
//			KeyRef: "testdata/cosign.key",
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
//			KeyRef:        "testdata/cosign.pub",
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
	assert.Equal(t, "bolo:yolo:ghcr.io/securego/gosec", p)
	assert.Equal(t, "v2.9.1", v)
}
