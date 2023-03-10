package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type Config struct {
	HTTPClient           *http.Client
	ConsoleQueryEndpoint string
	ApiKey               string
}

func NewConfig(apikey string) *Config {
	return &Config{
		HTTPClient:           http.DefaultClient,
		ConsoleQueryEndpoint: "http://console-backend/query",
		ApiKey:               apikey,
	}
}

type User struct {
	Email string `json:"email"`
}

type Members struct {
	User User `json:"user"`
}

type Teams struct {
	Slug    string  `json:"slug"`
	Members Members `json:"members"`
}

const query = `query {
	  teams {
	    slug
	    members {
	      user {
	        email
	      }
	    }
	  }
	}
}`

func (c *Config) GetTeams(ctx context.Context) (*Teams, error) {
	q := struct {
		Query string `json:"query"`
	}{
		Query: query,
	}

	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ConsoleQueryEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.ApiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(os.Stdout, resp.Body)
		return nil, fmt.Errorf("console: %v", resp.Status)
	}

	respBody := struct {
		Data struct {
			Teams *Teams `json:"teams"`
		} `json:"data"`
		Errors []map[string]any `json:"errors"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, err
	}

	if len(respBody.Errors) > 0 {
		return nil, fmt.Errorf("console: %v", respBody.Errors)
	}

	return respBody.Data.Teams, nil
}
