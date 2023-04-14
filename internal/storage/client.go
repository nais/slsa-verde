package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"

	"github.com/in-toto/in-toto-golang/in_toto"
)

const (
	ProjectPath = "/project"
	BomPath     = "/bom"
	ApiVersion1 = "/api/v1"
)

type Client struct {
	baseUrl string
	apiKey  string
	logger  *log.Entry
}

type BomSubmitRequest struct {
	ProjectName    string `json:"projectName"`
	ProjectVersion string `json:"projectVersion"`
	AutoCreate     bool   `json:"autoCreate"`
	Bom            string `json:"bom"`
}

type Project struct {
	Active    bool   `json:"active"`
	Author    string `json:"author"`
	Group     string `json:"group"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Tags      []Tag  `json:"tags"`
	Uuid      string `json:"uuid"`
	Version   string `json:"version"`
}

type Tag struct {
	Name string `json:"name"`
}

type Tags struct {
	Tags []Tag `json:"tags"`
}

func NewClient(url string, apiKey string) *Client {
	return &Client{
		baseUrl: url + ApiVersion1,
		apiKey:  apiKey,
		logger:  log.WithFields(log.Fields{"component": "storage", "url": url}),
	}
}

func (c *Client) UploadSbom(projectName, projectVersion, team, namespace string, statement *in_toto.CycloneDXStatement) error {
	c.logger.WithFields(log.Fields{
		"projectName":    projectName,
		"projectVersion": projectVersion,
	}).Info("uploading sbom")

	p, err := createBomSubmitRequest(projectName, projectVersion, statement)
	if err != nil {
		return fmt.Errorf("creating payload: %w", err)
	}

	req, err := c.createRequest(http.MethodPut, BomPath, bytes.NewReader(p))
	c.withHeaders(req, nil)

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	c.logger.Info("sbom uploaded")

	project, err := c.GetProject(projectName, projectVersion)
	if err != nil {
		return fmt.Errorf("getting project: %w", err)
	}

	err = c.addAdditionalInfoToProject(project.Uuid, projectVersion, team, namespace)
	if err != nil {
		return fmt.Errorf("updating project: %w", err)
	}
	return nil
}

func (c *Client) addAdditionalInfoToProject(projectUuid, projectVersion, team, namespace string) error {
	c.logger.WithFields(log.Fields{
		"projectUuid": projectUuid,
		"team":        team,
		"namespace":   namespace,
	}).Debug("adding additional info to project")

	body, err := c.createProjectBody(projectVersion, team, namespace)
	if err != nil {
		return fmt.Errorf("creating project body: %w", err)
	}

	req, err := c.createRequest(http.MethodPatch, ProjectPath+"/"+projectUuid, body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	c.withHeaders(req, map[string]string{"Accept": "application/json"})
	_, err = do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	c.logger.Debug("additional info added to project")

	return nil
}

func (c *Client) createProjectBody(projectVersion, team, namespace string) (*bytes.Buffer, error) {
	body, err := json.Marshal(Project{
		Publisher: "picante",
		Active:    true,
		Version:   projectVersion,
		Group:     namespace,
		Tags: []Tag{
			{
				Name: team,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling project: %w", err)
	}
	return bytes.NewBuffer(body), nil
}

func createBomSubmitRequest(projectName string, projectVersion string, statement *in_toto.CycloneDXStatement) ([]byte, error) {
	b, err := json.Marshal(statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("marshalling statement.predicate: %w", err)
	}
	bom := base64.StdEncoding.EncodeToString(b)
	p := &BomSubmitRequest{
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		AutoCreate:     true,
		Bom:            bom,
	}
	return json.Marshal(p)
}

func (c *Client) GetProject(name string, version string) (*Project, error) {
	req, err := c.createRequest(http.MethodGet, ProjectPath+"/lookup?name="+name+"&version="+version, nil)
	c.withHeaders(req, nil)

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resBody, err := do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var dtrackProject Project
	if err = json.Unmarshal(resBody, &dtrackProject); err != nil {
		return nil, fmt.Errorf("unmarshalling response body: %w", err)
	}

	return &dtrackProject, nil
}

func (c *Client) CleanUpProjects(name string) error {
	req, err := c.createRequest(http.MethodGet, ProjectPath+"?name="+name+"&excludeInactive=false", nil)
	c.withHeaders(req, nil)

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resBody, err := do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	var dtrackProjects []Project
	if err = json.Unmarshal(resBody, &dtrackProjects); err != nil {
		return fmt.Errorf("unmarshalling response body: %w", err)
	}

	for _, project := range dtrackProjects {
		err = c.DeleteProject(project.Uuid)
		if err != nil {
			return fmt.Errorf("deleting project: %w", err)
		}
	}

	return nil
}

func (c *Client) DeleteProject(uuid string) error {
	req, err := c.createRequest(http.MethodDelete, ProjectPath+"/"+uuid, nil)
	c.withHeaders(req, nil)

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	return nil
}

func (c *Client) createRequest(method string, path string, body io.Reader) (*http.Request, error) {
	c.logger.WithFields(log.Fields{
		"method": method,
		"url":    path,
	}).Info("creating request")
	req, err := http.NewRequest(method, c.baseUrl+path, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return req, nil
}

func (c *Client) withHeaders(req *http.Request, headers map[string]string) {
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
}

func do(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	if resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		return nil, fmt.Errorf("unexpected status code: %d, with body:\n%s\n", resp.StatusCode, string(b))
	}
	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return resBody, nil
}
