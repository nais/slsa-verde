package picante

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"picante/internal/attestation"
)

type Config struct {
	SbomApi string
}

func New(sbomApi string) *Config {
	return &Config{
		SbomApi: sbomApi,
	}
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
	att, err := attestation.Verify(ctx, p.containers, "")
	if err != nil {
		return fmt.Errorf("failed to verify attestation: %v", err)
	}
	if err = c.persistSbom(att); err != nil {
		return fmt.Errorf("failed to persist sbom: %v", err)
	}
	return nil
}

func (c *Config) persistSbom(att any) error {
	return nil
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
		name:       name,
		containers: c,
	}
}

type podInfo struct {
	name       string
	containers []string
}
