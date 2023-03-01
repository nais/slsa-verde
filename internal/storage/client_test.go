package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
)

func TestUploadSbom(t *testing.T) {
	att, err := os.ReadFile("testdata/attestation.json")
	assert.NoError(t, err)
	var a *in_toto.CycloneDXStatement
	err = json.Unmarshal(att, &a)
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		err := requestIsValid(t, r)
		assert.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")

		_, err = fmt.Fprintf(w, "{\"token\":\"66c6c8f0-f826-40b9-acbf-ce99c0b8d2af\"}\n")
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := Client{
		url:    server.URL + "/api/v1/bom", //"http://localhost:8888/api/v1/bom",
		apiKey: "BjaW3EoqJbKKGBzc1lcOkBijjsC5rL2O",
	}

	err = cfg.UploadSbom("test", "1.0.1", a)
	assert.NoError(t, err)
}

func requestIsValid(t *testing.T, r *http.Request) error {
	assert.Equal(t, r.Header.Get("Content-Type"), "application/json")
	assert.NotEmpty(t, r.Header.Get("X-API-Key"), "X-API-Key header is empty")
	assert.Equal(t, r.Method, "PUT")
	assert.Equal(t, r.URL.Path, "/api/v1/bom")
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("reading request body: %w", err)
	}
	var p payload
	err = json.Unmarshal(b, &p)
	if err != nil {
		return fmt.Errorf("unmarshalling request body: %w", err)
	}
	assert.NotEmpty(t, p.ProjectName)
	assert.NotEmpty(t, p.ProjectVersion)
	assert.Equal(t, p.AutoCreate, true)
	assert.NotEmpty(t, p.Bom)
	return nil
}
