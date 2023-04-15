package storage

import (
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
)

const (
	UserLoginPath = "/user/login"
)

func (c *Client) Token() (string, error) {
	if c.accessToken == "" || c.isExpired() {
		log.Debugf("accessToken expired, getting new one")
		token, err := c.login()
		if err != nil {
			return "", err
		}
		c.accessToken = token
	}
	return c.accessToken, nil
}

func (c *Client) login() (string, error) {
	request, err := c.createRequest(http.MethodPost, c.baseUrl+UserLoginPath, []byte("username="+c.username+"&password="+c.password))
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
	if c.accessToken == "" {
		return true
	}
	parseOpts := []jwt.ParseOption{
		jwt.WithVerify(false),
	}
	token, err := jwt.ParseString(c.accessToken, parseOpts...)
	if err != nil {
		log.Errorf("error parsing accessToken: %v", err)
		return true
	}
	if token.Expiration().Before(time.Now().Add(-1 * time.Minute)) {
		return true
	}
	return false
}
