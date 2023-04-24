package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/in-toto/in-toto-golang/in_toto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUploadSbom(t *testing.T) {
	ctx := context.Background()
	att, err := os.ReadFile("testdata/attestation.json")
	assert.NoError(t, err)
	var a *in_toto.CycloneDXStatement
	err = json.Unmarshal(att, &a)
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			println(r.URL.Path)
			switch r.URL.Path {
			case "/api/v1/project/lookup":
				p, err := json.Marshal(Project{
					Name:    "project1",
					Uuid:    "1234",
					Version: "1.0.1",
				})
				_, err = fmt.Fprintf(w, string(p))
				assert.NoError(t, err)
			case "/api/v1/team":
				tt, err := json.Marshal([]Team{
					{
						Name: "Administrators",
						Uuid: "1234",
						Apikeys: []ApiKey{
							{
								Key: "key",
							},
						},
					},
				})
				assert.NoError(t, err)
				_, err = fmt.Fprintf(w, string(tt))
				assert.NoError(t, err)
			}
		case http.MethodPut:
			err = requestIsValid(t, r, http.MethodPut, "/api/v1/bom")
			assert.NoError(t, err)
		case http.MethodPost:
			err = requestIsValid(t, r, http.MethodPost, "/api/v1/user/login")
		case http.MethodPatch:
			err = requestIsValid(t, r, http.MethodPatch, "/api/v1/project/1234")
			assert.NoError(t, err)
		default:
		}

		w.Header().Set("Content-Type", "application/json")

		// _, err = fmt.Fprintf(w, "{\"token\":\"66c6c8f0-f826-40b9-acbf-ce99c0b8d2af\"}\n")
		assert.NoError(t, err)
	}))
	defer server.Close()

	client := NewClient(ctx, server.URL, "admin", "admin", "Administrators")
	err = client.UploadProject("project1", "1.0.1", "team1", "namespace", a)
	assert.NoError(t, err)
}

func requestIsValid(t *testing.T, r *http.Request, expectedMethod, expectedURL string) error {
	switch expectedMethod {
	case http.MethodPost:
		if expectedURL == "api/v1/user/login" {
			b, err := io.ReadAll(r.Body)
			var a Auth
			err = json.Unmarshal(b, &a)
			if err != nil {
				assert.Error(t, err)
			}

			fmt.Println(r.URL.Path)

			assert.NotEmpty(t, a.username, "username is empty")
			assert.NotEmpty(t, a.password, "password is empty")
			assert.Equal(t, expectedMethod, r.Method, "request method is not POST")
			assert.Equal(t, expectedURL, r.URL.Host, "request URL is not /api/v1/user/login")
			assert.Equal(t, r.Header.Get("Content-Type"), "application/json")
		}

	case http.MethodGet:
		assert.Equal(t, expectedMethod, r.Method)
		assert.Equal(t, expectedURL, r.URL.Path)
		assert.Equal(t, r.Header.Get("Content-Type"), "application/json")
		if expectedURL == "api/v1/user/login" {
			assert.NotEmpty(t, r.Header.Get("X-Api-Key"), "X-Api-Key header is empty")
		} else {
			assert.NotEmpty(t, r.Header.Get("Authorization"), "Authorization header is empty")
		}
	case http.MethodPut:
		b, err := io.ReadAll(r.Body)
		var p BomSubmitRequest
		err = json.Unmarshal(b, &p)
		if err != nil {
			assert.Error(t, err)
		}
		assert.Equal(t, expectedMethod, r.Method)
		assert.Equal(t, expectedURL, r.URL.Path)
		assert.Equal(t, r.Header.Get("Content-Type"), "application/json")
		assert.NotEmpty(t, p.ProjectName)
		assert.NotEmpty(t, p.ProjectVersion)
		assert.Equal(t, p.AutoCreate, true)
		assert.NotEmpty(t, p.Bom)
	case http.MethodPatch:
		var tag Tags
		b, err := io.ReadAll(r.Body)
		err = json.Unmarshal(b, &tag)
		if err != nil {
			assert.Error(t, err, "unmarshalling request body")
		}
		assert.Equal(t, expectedMethod, r.Method)
		assert.Equal(t, expectedURL, r.URL.Path)
		assert.NotEmpty(t, tag.Tags)
		assert.Equal(t, r.Header.Get("Content-Type"), "application/json")
		assert.NotEmpty(t, r.Header.Get("X-Api-Key"), "Authorization header is empty")
	}
	return nil
}

func TestClient_ApiKey(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		switch r.Method {
		case http.MethodPost:
			if r.URL.Path == "api/v1/user/login" {
				_, err := fmt.Fprintf(w, "{\"token\":\"66c6c8f0-f826-40b9-acbf-ce99c0b8d2af\"}\n")
				assert.NoError(t, err)
			}
		case http.MethodGet:
			if r.URL.Path == "/api/v1/team" {
				tt, err := json.Marshal([]Team{
					{
						Name: "Administrators",
						Uuid: "1234",
						Apikeys: []ApiKey{
							{
								Key: "key",
							},
						},
					},
				})
				assert.NoError(t, err)
				_, err = fmt.Fprintf(w, string(tt))
				assert.NoError(t, err)
			}
		case http.MethodPut:
			if r.URL.Path == "team/1234/key" {
				_, err := fmt.Fprintf(w, "{\"key\":\"key\"}")
				assert.NoError(t, err)
			}
		}
	}))
	defer server.Close()

	client := NewClient(context.Background(), server.URL, "admin", "admin", "Administrators")
	apiKey, err := client.ApiKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, apiKey)
	assert.Equal(t, apiKey, "key")
}
