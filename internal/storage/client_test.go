package storage

import (
	"encoding/json"
	"fmt"
	"github.com/in-toto/in-toto-golang/in_toto"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUploadSbom(t *testing.T) {
	att, err := os.ReadFile("testdata/attestation.json")
	assert.NoError(t, err)
	var a *in_toto.CycloneDXStatement
	err = json.Unmarshal(att, &a)
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		switch r.Method {
		case "GET":
			err := requestIsValid(t, r, "GET", "/api/v1/project/lookup")
			_, err = fmt.Fprintf(w, "{\"name\":\"project1\", \"uuid\":\"1234\", \"version\":\"1.0.1\"}\n")
			assert.NoError(t, err)
		case "PUT":
			err = requestIsValid(t, r, "PUT", "/api/v1/bom")
			assert.NoError(t, err)
		default:
			err = requestIsValid(t, r, "PATCH", "/api/v1/project/1234")
			assert.NoError(t, err)
		}

		w.Header().Set("Content-Type", "application/json")

		//_, err = fmt.Fprintf(w, "{\"token\":\"66c6c8f0-f826-40b9-acbf-ce99c0b8d2af\"}\n")
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := Client{
		url:    server.URL + "/api/v1",
		apiKey: "BjaW3EoqJbKKGBzc1lcOkBijjsC5rL2O",
		logger: log.WithFields(log.Fields{"test-component": "storage"}),
	}

	err = cfg.UploadSbom("project1", "1.0.1", "team1", a)
	assert.NoError(t, err)
}

func requestIsValid(t *testing.T, r *http.Request, expectedMethod, expectedURL string) error {
	assert.Equal(t, r.Header.Get("Content-Type"), "application/json")
	assert.NotEmpty(t, r.Header.Get("X-API-Key"), "X-API-Key header is empty")
	assert.Equal(t, expectedMethod, r.Method)
	assert.Equal(t, expectedURL, r.URL.Path)
	if expectedMethod != "GET" {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("reading request body: %w", err)
		}
		if expectedMethod == "PUT" {
			var p payload
			err = json.Unmarshal(b, &p)
			if err != nil {
				return fmt.Errorf("unmarshalling request body: %w", err)
			}

			assert.NotEmpty(t, p.ProjectName)
			assert.NotEmpty(t, p.ProjectVersion)
			assert.Equal(t, p.AutoCreate, true)
			assert.NotEmpty(t, p.Bom)
		}
		if expectedMethod == "PATCH" {
			var tag Tags
			err = json.Unmarshal(b, &tag)
			if err != nil {
				return fmt.Errorf("unmarshalling request body: %w", err)
			}
			assert.NotEmpty(t, tag.Tags)
		}
	}
	return nil
}
