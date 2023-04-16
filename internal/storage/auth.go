package storage

import (
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
)

const (
	UserLoginPath = "/user/login"
)

type Auth struct {
	accessToken string
	username    string
	password    string
}

func (c *Client) Token() (string, error) {
	if c.Auth.accessToken == "" || c.isExpired() {
		log.Debugf("accessToken expired, getting new one")
		token, err := c.login()
		if err != nil {
			return "", err
		}
		c.Auth.accessToken = token
	}
	return c.Auth.accessToken, nil
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

	token, err := do(request)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func (c *Client) isExpired() bool {
	if c.Auth.accessToken == "" {
		return true
	}
	parseOpts := []jwt.ParseOption{
		jwt.WithVerify(false),
	}
	token, err := jwt.ParseString(c.Auth.accessToken, parseOpts...)
	if err != nil {
		log.Errorf("error parsing accessToken: %v", err)
		return true
	}
	if token.Expiration().Before(time.Now().Add(-1 * time.Minute)) {
		return true
	}
	return false
}
