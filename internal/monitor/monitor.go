package monitor

import (
	"context"
	"fmt"
	"strings"

	"picante/internal/storage"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"picante/internal/attestation"
)

type Config struct {
	*storage.Client
	keyRef string
}

func New(client *storage.Client, keyRef string) *Config {
	return &Config{client, keyRef}
}

func (c *Config) OnDelete(obj any) {
	log.Infof("pod deleted: %s, do nothing", obj)
}

// TODO: compare to check if image is updated
func (c *Config) OnUpdate(obj any, obj2 any) {
	p := pod(obj)
	if err := c.ensureAttested(context.Background(), p); err != nil {
		log.Errorf("failed to attest pod %s: %v", p.name, err)
	}
}

func (c *Config) OnAdd(obj any) {
	p := pod(obj)
	if err := c.ensureAttested(context.Background(), p); err != nil {
		log.Errorf("failed to attest pod %s: %v", p.name, err)
	}
}

func (c *Config) ensureAttested(ctx context.Context, p *podInfo) error {

	if p.name != "picanteapp1" {
		log.Infof("not ready to attest any other apps than picanteapp1")
		return nil
	}

	metadata, err := attestation.Verify(ctx, p.containerImages, c.keyRef)
	if err != nil {
		return fmt.Errorf("failed to verify attestation: %v", err)
	}

	for _, m := range metadata {
		project, version := projectAndVersion(p.name, m.Image)
		if err := c.UploadSbom(project, version, m.Statement); err != nil {
			return fmt.Errorf("failed to upload sbom: %v", err)
		}
	}
	return nil
}

func projectAndVersion(name, image string) (project string, version string) {
	//foobar:ghcr.io/securego/gosec:v2.9.1
	image = name + ":" + image
	i := strings.LastIndex(image, ":")
	version = image[i+1 : len(image)]
	project = image[0:i]
	return
}

func pod(obj any) *podInfo {
	pod := obj.(*v1.Pod)
	name := pod.Labels["app.kubernetes.io/name"]
	c := make([]string, 0)
	for _, container := range pod.Spec.Containers {
		log.Debugf("pod %s", container.Image)
		c = append(c, container.Image)
	}
	return &podInfo{
		name:            name,
		containerImages: c,
	}
}

type podInfo struct {
	name            string
	containerImages []string
}
