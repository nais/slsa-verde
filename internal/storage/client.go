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
	Active  bool   `json:"active"`
	Name    string `json:"name"`
	Uuid    string `json:"uuid"`
	Version string `json:"version"`
	Tags    []Tag  `json:"tags"`
}

func NewClient(url string, apiKey string) *Client {
	return &Client{
		baseUrl: url,
		apiKey:  apiKey,
		logger:  log.WithFields(log.Fields{"component": "storage", "url": url}),
	}
}

func (c *Client) UploadSbom(projectName string, projectVersion string, team string, statement *in_toto.CycloneDXStatement) error {
	c.logger.WithFields(log.Fields{
		"projectName":    projectName,
		"projectVersion": projectVersion,
	}).Info("uploading sbom")

	p, err := createBomSubmitRequest(projectName, projectVersion, statement)
	if err != nil {
		return fmt.Errorf("creating payload: %w", err)
	}

	req, err := c.createRequest("PUT", BomPath, bytes.NewReader(p))
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

	err = c.UpdateProjectTags(project.Uuid, []Tag{
		{
			Name: team,
		},
	})
	if err != nil {
		return fmt.Errorf("updating project tags: %w", err)
	}
	return nil
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

type Tag struct {
	Name string `json:"name"`
}

type Tags struct {
	Tags []Tag `json:"tags"`
}

func tagArray(tags []Tag) ([]byte, error) {
	body, err := json.Marshal(Tags{tags})
	if err != nil {
		return nil, fmt.Errorf("marshalling tags: %w", err)
	}
	return body, nil
}

func (c *Client) UpdateProjectTags(projectUuid string, tags []Tag) error {
	body, err := tagArray(tags)
	if err != nil {
		return err
	}

	req, err := c.createRequest("PATCH", ProjectPath+"/"+projectUuid, bytes.NewBuffer(body))
	c.withHeaders(req, map[string]string{"Accept": "application/json"})

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	return nil
}

func (c *Client) GetProject(name string, version string) (*Project, error) {
	req, err := c.createRequest("GET", ProjectPath+"/lookup?name="+name+"&version="+version, nil)
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
	req, err := c.createRequest("GET", ProjectPath+"?name="+name+"&excludeInactive=false", nil)
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
	req, err := c.createRequest("DELETE", ProjectPath+"/"+uuid, nil)
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

//func (c *Client) PatchProject(project Project) error {
//	patchBody, err := CreatePatchBody()
//	if err != nil {
//		return fmt.Errorf("creating patch body: %w", err)
//	}
//
//	req, err := request.New("PATCH", c.baseUrl+ProjectPath+"/"+project.Uuid, bytes.NewBuffer(patchBody))
//	request.withHeaders(req, map[string]string{
//		"X-API-Key": c.apiKey,
//	})
//
//	if err != nil {
//		return fmt.Errorf("creating request: %w", err)
//	}
//
//	_, err = request.do(req)
//	if err != nil {
//		return fmt.Errorf("sending request: %w", err)
//	}
//
//	return nil
//}
//
//func CreatePatchBody() ([]byte, error) {
//	body, err := json.Marshal(Project{
//		Active: false,
//	})
//	if err != nil {
//		return nil, fmt.Errorf("marshalling project: %w", err)
//	}
//	return body, nil
//}
