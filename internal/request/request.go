package request

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
)

func New(method string, url string, body io.Reader) (*http.Request, error) {
	log.WithFields(log.Fields{
		"method": method,
		"url":    url,
	}).Info("creating request")
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return req, nil
}

func WithHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	req.Header.Set("Content-Type", "application/json")
}

func Do(req *http.Request) ([]byte, error) {
	log.WithFields(log.Fields{
		"method": req.Method,
		"url":    req.URL,
	}).Info("sending request")
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
