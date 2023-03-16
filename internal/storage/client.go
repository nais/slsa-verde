package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/in-toto/in-toto-golang/in_toto"
)

type Client struct {
	url    string
	apiKey string
}

type payload struct {
	ProjectName    string `json:"projectName"`
	ProjectVersion string `json:"projectVersion"`
	AutoCreate     bool   `json:"autoCreate"`
	Bom            string `json:"bom"`
}

func NewClient(url string, apiKey string) *Client {
	return &Client{
		url:    url,
		apiKey: apiKey,
	}
}

func (c *Client) UploadSbom(projectName string, projectVersion string, statement *in_toto.CycloneDXStatement) error {
	p, err := createPayload(projectName, projectVersion, statement)
	if err != nil {
		return fmt.Errorf("creating payload: %w", err)
	}

	req, err := http.NewRequest("PUT", c.url, bytes.NewReader(p))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	if resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}
		return fmt.Errorf("unexpected status code: %d, with body:\n%s\n", resp.StatusCode, string(b))
	}
	return nil
}

func createPayload(projectName string, projectVersion string, statement *in_toto.CycloneDXStatement) ([]byte, error) {
	b, err := json.Marshal(statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("marshalling statement.predicate: %w", err)
	}
	bom := base64.StdEncoding.EncodeToString(b)
	p := &payload{
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		AutoCreate:     true,
		Bom:            bom,
	}
	return json.Marshal(p)
}
