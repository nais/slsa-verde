package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/avast/retry-go/v4"
	"github.com/in-toto/in-toto-golang/in_toto"
	log "github.com/sirupsen/logrus"
)

const (
	ProjectPath          = "/project"
	BomPath              = "/bom"
	ApiVersion1          = "/api/v1"
	DefaultRetryAttempts = 5
)

type Client struct {
	Auth      *Auth
	baseUrl   string
	client    *http.Client
	ctx       context.Context
	logger    *log.Entry
	retryOpts []retry.Option
}

type BomSubmitRequest struct {
	ProjectName    string `json:"projectName"`
	ProjectVersion string `json:"projectVersion"`
	AutoCreate     bool   `json:"autoCreate"`
	Bom            string `json:"bom"`
}

type Purl struct {
	Scheme    string `json:"scheme"`
	Type      string `json:"type"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type Project struct {
	Active     bool   `json:"active"`
	Author     string `json:"author"`
	Classifier string `json:"classifier"`
	Group      string `json:"group"`
	Name       string `json:"name"`
	Publisher  string `json:"publisher"`
	Tags       []Tag  `json:"tags"`
	Purl       Purl   `json:"purl"`
	Uuid       string `json:"uuid"`
	Version    string `json:"version"`
}

type Tag struct {
	Name string `json:"name"`
}

type Tags struct {
	Tags []Tag `json:"tags"`
}

func NewClient(ctx context.Context, client *http.Client, baseUrl, username, password, team string) *Client {
	return &Client{
		Auth: &Auth{
			username: username,
			password: password,
			team:     team,
		},
		baseUrl: baseUrl + ApiVersion1,
		client:  client,
		ctx:     ctx,
		logger:  log.WithFields(log.Fields{"package": "storage"}),
		retryOpts: []retry.Option{
			retry.Attempts(DefaultRetryAttempts),
			retry.LastErrorOnly(true),
			retry.Context(ctx),
		},
	}
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

func (c *Client) UploadProject(projectName, projectVersion, team, namespace string, statement *in_toto.CycloneDXStatement) error {
	c.logger.WithFields(log.Fields{
		"projectName":    projectName,
		"projectVersion": projectVersion,
	}).Info("uploading sbom")

	apiKey, err := c.ApiKey()
	if err != nil {
		return fmt.Errorf("getting apiKey: %w", err)
	}

	p, err := createBomSubmitRequest(projectName, projectVersion, statement)
	if err != nil {
		return fmt.Errorf("creating payload: %w", err)
	}

	req, err := c.createRequest(http.MethodPut, BomPath, p)
	c.withHeaders(req, map[string]string{"X-Api-Key": apiKey, "Content-Type": "application/json"})

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = c.do(req)
	if err != nil {
		return err
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

	apiKey, err := c.ApiKey()
	if err != nil {
		return fmt.Errorf("getting apiKey: %w", err)
	}

	body, err := c.patchProjectBody(projectVersion, team, namespace)
	if err != nil {
		return fmt.Errorf("creating project body: %w", err)
	}

	req, err := c.createRequest(http.MethodPatch, ProjectPath+"/"+projectUuid, body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	c.withHeaders(req, map[string]string{"Accept": "application/json", "X-Api-Key": apiKey, "Content-Type": "application/json"})
	_, err = c.do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	c.logger.Info("additional info added to project")

	return nil
}

func (c *Client) patchProjectBody(projectVersion, team, namespace string) ([]byte, error) {
	body, err := json.Marshal(Project{
		Publisher:  "picante",
		Active:     true,
		Classifier: "APPLICATION",
		Version:    projectVersion,
		Group:      namespace,
		Tags: []Tag{
			{
				Name: team,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling project: %w", err)
	}
	return body, nil
}

func (c *Client) GetProject(name string, version string) (*Project, error) {
	apiKey, err := c.ApiKey()
	if err != nil {
		return nil, fmt.Errorf("getting apiKey: %w", err)
	}

	req, err := c.createRequest(http.MethodGet, ProjectPath+"/lookup?name="+name+"&version="+version, nil)
	c.withHeaders(req, map[string]string{"X-Api-Key": apiKey, "Content-Type": "application/json"})

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resBody, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	if len(resBody) == 0 {
		return nil, nil
	}

	var dtrackProject Project
	if err = json.Unmarshal(resBody, &dtrackProject); err != nil {
		return nil, fmt.Errorf("unmarshalling response body: %w", err)
	}

	return &dtrackProject, nil
}

func (c *Client) CleanUpProjects(name string) error {
	apiKey, err := c.ApiKey()
	if err != nil {
		return fmt.Errorf("getting apiKey: %w", err)
	}

	req, err := c.createRequest(http.MethodGet, ProjectPath+"?name="+name+"&excludeInactive=false", nil)
	c.withHeaders(req, map[string]string{"X-Api-Key": apiKey, "Content-Type": "application/json"})

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resBody, err := c.do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	var dtrackProjects []Project
	if err = json.Unmarshal(resBody, &dtrackProjects); err != nil {
		return fmt.Errorf("unmarshalling response body: %w", err)
	}

	if len(dtrackProjects) == 0 {
		return nil
	}

	for _, project := range dtrackProjects {
		err = c.DeleteProject(project.Uuid)
		if err != nil {
			return fmt.Errorf("deleting project: %w", err)
		}
		log.Info(log.Fields{
			"project": project.Name,
			"version": project.Version,
		}, "project deleted")
	}

	return nil
}

func (c *Client) DeleteProject(uuid string) error {
	apiKey, err := c.ApiKey()
	if err != nil {
		return fmt.Errorf("getting apiKey: %w", err)
	}

	req, err := c.createRequest(http.MethodDelete, ProjectPath+"/"+uuid, nil)
	c.withHeaders(req, map[string]string{"X-Api-Key": apiKey, "Content-Type": "application/json"})

	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	_, err = c.do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	return nil
}

func (c *Client) createRequest(method string, path string, body []byte) (*http.Request, error) {
	c.logger.WithFields(log.Fields{
		"method": method,
		"url":    path,
	}).Info("creating request")

	req, err := http.NewRequestWithContext(c.ctx, method, c.baseUrl+path, bytes.NewReader(body))
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
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	var resBody []byte
	err := retry.Do(func() error {
		resp, err := c.client.Do(req)
		if err != nil {
			return fmt.Errorf("sending request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound && strings.Contains(req.URL.Path, "lookup") {
			return nil
		}

		if resp.StatusCode > 299 {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("reading response body: %w", err)
			}
			return fmt.Errorf("unexpected status code: %d, with body:\n%s\n", resp.StatusCode, string(b))
		}
		resBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}
		return nil
	}, c.retryOpts...)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	return resBody, nil
}
