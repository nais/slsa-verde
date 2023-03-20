package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"io"
	"time"
)

type ErrorLine struct {
	Error       string      `json:"error"`
	ErrorDetail ErrorDetail `json:"errorDetail"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

func DockerBuild(dockerImageID, srchPath, dockerfile, tagName string) (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	err = imageBuild(dockerImageID, cli, srchPath, dockerfile, tagName)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

func imageBuild(id string, dockerClient *client.Client, path, dockerfile, tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()

	tar, err := archive.Tar(path, archive.Uncompressed)
	if err != nil {
		return err
	}

	opts := types.ImageBuildOptions{
		Dockerfile: dockerfile,
		Tags:       []string{id + ":" + tag},
		Remove:     true,
	}
	res, err := dockerClient.ImageBuild(ctx, tar, opts)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = getInfo(res.Body)

	if err != nil {
		return err
	}

	return nil
}

func getInfo(rd io.Reader) error {
	var lastLine string

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		lastLine = scanner.Text()
		fmt.Println(scanner.Text())
	}

	errLine := &ErrorLine{}
	json.Unmarshal([]byte(lastLine), errLine)
	if errLine.Error != "" {
		return errors.New(errLine.Error)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func DockerPush(dockerClient *client.Client, id, tagName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()

	tag := id + ":" + tagName
	rd, err := dockerClient.ImagePush(ctx, tag, types.ImagePushOptions{
		All:           false,
		RegistryAuth:  "test",
		PrivilegeFunc: nil,
		Platform:      "",
	})
	if err != nil {
		return err
	}

	defer rd.Close()

	err = getInfo(rd)
	if err != nil {
		return err
	}

	return nil
}
