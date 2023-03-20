package monitor

import (
	"context"
	"fmt"
	"picante/internal/pod"
	"strings"

	"picante/internal/storage"

	log "github.com/sirupsen/logrus"
	"picante/internal/attestation"
)

type Config struct {
	*storage.Client
	verifyAttestOpts *attestation.VerifyAttestationOpts
}

func NewMonitor(client *storage.Client, opts *attestation.VerifyAttestationOpts) *Config {
	return &Config{
		Client:           client,
		verifyAttestOpts: opts,
	}
}

func (c *Config) OnDelete(obj any) {
	log.Infof("podd deleted: %s, do nothing", obj)
}

// TODO: compare to check if image is updated
func (c *Config) OnUpdate(obj any, obj2 any) {
	p := pod.GetInfo(obj)
	if err := c.ensureAttested(context.Background(), p); err != nil {
		log.Errorf("failed to attest pod %s: %v", p.Name, err)
	}
}

func (c *Config) OnAdd(obj any) {
	p := pod.GetInfo(obj)
	if p == nil {
		log.Infof("ignoring pod %s", p.Name)
		return
	}

	if !p.Verify {
		log.Infof("ignoring pod %s", p.Name)
		return
	}

	if err := c.ensureAttested(context.Background(), p); err != nil {
		log.Errorf("failed to attest pod %s: %v", p.Name, err)
	}
}

func (c *Config) ensureAttested(ctx context.Context, p *pod.Info) error {
	metadata, err := c.verifyAttestOpts.Verify(ctx, p)
	if err != nil {
		return fmt.Errorf("failed to verify attestation: %v", err)
	}

	for _, m := range metadata {
		project, version := projectAndVersion(p.Team, p.Name, m.Image)
		if err := c.UploadSbom(project, version, m.Statement); err != nil {
			return fmt.Errorf("failed to upload sbom: %v", err)
		}
	}
	return nil
}

func projectAndVersion(team, name, image string) (project string, version string) {
	//team:foobar:ghcr.io/securego/gosec:v2.9.1
	image = team + ":" + name + ":" + image
	i := strings.LastIndex(image, ":")
	version = image[i+1:]
	project = image[0:i]
	return
}
