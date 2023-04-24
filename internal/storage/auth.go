package storage

import (
	"encoding/json"
	"fmt"
	"github.com/avast/retry-go/v4"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
)

const (
	UserLoginPath = "/user/login"
	TeamPath      = "/team"
)

type Auth struct {
	accessToken string
	apiKey      string
	username    string
	password    string
	team        string
}

type Team struct {
	Uuid    string   `json:"uuid"`
	Name    string   `json:"name"`
	Apikeys []ApiKey `json:"apikeys"`
}

type ApiKey struct {
	Key string `json:"key"`
}

func (c *Client) getApiKey(uuid, token string) (string, error) {
	request, err := c.createRequest(http.MethodPut, TeamPath+"/"+uuid+"/key", nil)
	c.withHeaders(request, map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	})

	if err != nil {
		return "", err
	}

	authOpt := []retry.Option{
		retry.Attempts(1),
	}

	resp, err := do(request, authOpt)
	if err != nil {
		return "", err
	}

	var apikey ApiKey
	err = json.Unmarshal(resp, &apikey)
	if err != nil {
		return "", err
	}

	return apikey.Key, nil
}

func (c *Client) getTeam(token string) (Team, error) {
	request, err := c.createRequest(http.MethodGet, TeamPath, nil)
	c.withHeaders(request, map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	})

	var tt Team
	if err != nil {
		return tt, err
	}

	authOpt := []retry.Option{
		retry.Attempts(1),
	}

	resp, err := do(request, authOpt)
	if err != nil {
		return tt, err
	}

	var teams []Team
	err = json.Unmarshal(resp, &teams)
	if err != nil {
		return tt, err
	}

	for _, t := range teams {
		if t.Name != c.Auth.team {
			continue
		}
		tt = t
		break
	}

	return tt, nil
}

func (c *Client) updateApiKey(token string) (string, error) {
	log.Debugf("apiKey not set")
	team, err := c.getTeam(token)
	if err != nil {
		return "", fmt.Errorf("getting team: %v", err)
	}

	if len(team.Apikeys) > 0 {
		log.Debugf("using existing apiKey")
		c.Auth.apiKey = team.Apikeys[0].Key
		return c.Auth.apiKey, nil
	}

	log.Debugf("getting new apiKey")
	key, err := c.getApiKey(team.Uuid, token)
	if err != nil {
		return "", fmt.Errorf("getting apiKey: %v", err)
	}
	return key, nil
}

func (c *Client) login() (string, error) {
	data := url.Values{
		"username": {c.Auth.username},
		"password": {c.Auth.password},
	}
	request, err := c.createRequest(http.MethodPost, UserLoginPath, []byte(data.Encode()))
	c.withHeaders(request, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "text/plain",
	})

	if err != nil {
		return "", err
	}

	authOpt := []retry.Option{
		retry.Attempts(1),
	}

	token, err := do(request, authOpt)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func (c *Client) isExpired() (bool, error) {
	if c.Auth.accessToken == "" {
		return true, nil
	}
	parseOpts := []jwt.ParseOption{
		jwt.WithVerify(false),
	}
	token, err := jwt.ParseString(c.Auth.accessToken, parseOpts...)
	if err != nil {
		log.Errorf("error parsing accessToken: %v", err)
		return true, err
	}
	if token.Expiration().Before(time.Now().Add(-1 * time.Minute)) {
		return true, nil
	}
	return false, err
}

func (c *Client) ApiKey() (string, error) {
	expired, err := c.isExpired()
	if err != nil {
		return "", err
	}

	if c.Auth.accessToken == "" || expired || c.Auth.apiKey == "" {
		log.Debugf("accessToken expired, getting new one")
		token, err := c.login()
		if err != nil {
			return "", err
		}
		c.Auth.accessToken = token

		var apiKey string
		if c.Auth.apiKey == "" {
			apiKey, err = c.updateApiKey(token)
			if err != nil {
				return "", fmt.Errorf("updating apiKey: %v", err)
			}
		}
		c.Auth.apiKey = apiKey
	}
	return c.Auth.apiKey, nil
}
