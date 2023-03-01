package monitor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"picante/internal/storage"
)

func TestEnsureAttested(t *testing.T) {
	cfg := New(storage.New("http://localhost:8888/api/v1/bom", "BjaW3EoqJbKKGBzc1lcOkBijjsC5rL2O"), "testdata/cosign.pub")
	err := cfg.ensureAttested(context.Background(), &podInfo{
		name:            "app2",
		containerImages: []string{"ttl.sh/picante:6h"},
	})
	assert.NoError(t, err)
}

func TestProjectAndVersion(t *testing.T) {
	image := "ghcr.io/securego/gosec:v2.9.1"
	println(projectAndVersion("foobar", image))
}
