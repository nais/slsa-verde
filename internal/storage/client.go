package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"picante/internal/request"

	"github.com/in-toto/in-toto-golang/in_toto"
)

type Client struct {
	url    string
	apiKey string
	logger *log.Entry
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
		logger: log.WithFields(log.Fields{"component": "storage"}),
	}
}

func (c *Client) UploadSbom(projectName string, projectVersion string, team string, statement *in_toto.CycloneDXStatement) error {
	c.logger.WithFields(log.Fields{
		"projectName":    projectName,
		"projectVersion": projectVersion,
	}).Info("uploading sbom")

	p, err := createPayload(projectName, projectVersion, statement)
	if err != nil {
		return fmt.Errorf("creating payload: %w", err)
	}

	req, err := request.New("PUT", c.url+"/bom", bytes.NewReader(p))
	request.WithHeaders(req, map[string]string{
		"X-Api-Key": c.apiKey,
	})

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = request.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	c.logger.WithFields(log.Fields{
		"api-url": c.url + "bom",
	}).Info("sbom uploaded")

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

	req, err := request.New("PATCH", c.url+"/project/"+projectUuid, bytes.NewBuffer(body))
	request.WithHeaders(req, map[string]string{
		"X-API-Key": c.apiKey,
		"Accept":    "application/json",
	})

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = request.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	return nil
}

type Project struct {
	Name    string `json:"name"`
	Uuid    string `json:"uuid"`
	Version string `json:"version"`
}

func (c *Client) GetProject(name string, version string) (*Project, error) {
	req, err := request.New("GET", c.url+"/project/lookup?name="+name+"&version="+version, nil)
	request.WithHeaders(req, map[string]string{
		"X-API-Key": c.apiKey,
	})

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resBody, err := request.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var dtrackProject Project
	if err = json.Unmarshal(resBody, &dtrackProject); err != nil {
		return nil, fmt.Errorf("unmarshalling response body: %w", err)
	}

	return &dtrackProject, nil
}
