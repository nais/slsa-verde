package monitor

import (
	"context"
	log "github.com/sirupsen/logrus"
	"picante/internal/pod"
	"strings"

	"picante/internal/storage"

	"picante/internal/attestation"
)

type Config struct {
	*storage.Client
	verifyAttestOpts *attestation.VerifyAttestationOpts
	logger           *log.Entry
	ctx              context.Context
}

func NewMonitor(ctx context.Context, client *storage.Client, opts *attestation.VerifyAttestationOpts) *Config {
	return &Config{
		Client:           client,
		verifyAttestOpts: opts,
		logger:           log.WithFields(log.Fields{"component": "monitor"}),
		ctx:              ctx,
	}
}

func (c *Config) OnDelete(obj any) {
	c.logger.Info("pod deleted, do nothing")
}

func (c *Config) OnUpdate(old any, new any) {
	c.logger.Debug("pod updated event, check if image needs to be attested")

	p, err := pod.GetInfo(old)
	if err != nil {
		c.logger.Debugf("get pod info: %v", err)
		return
	}

	p2, err := pod.GetInfo(new)
	if err != nil {
		c.logger.Debugf("get pod info: %v", err)
		return
	}

	if equalSlice(p.ContainerImages, p2.ContainerImages) {
		c.logger.Debugf("same tag on image ignoring pod %s", p.PodName)
		return
	}

	if err = c.ensureAttested(c.ctx, p); err != nil {
		c.logger.Errorf("verfy attesation pod %v", err)
	}
}

func (c *Config) OnAdd(obj any) {
	c.logger.Debug("new pod event, check if image needs to be attested")
	p, _ := pod.GetInfo(obj)
	if p == nil {
		c.logger.Debugf("ignoring pod with no team label")
		return
	}

	if err := c.ensureAttested(c.ctx, p); err != nil {
		c.logger.Errorf("verify attestation %v", err)
	}
}

func (c *Config) ensureAttested(ctx context.Context, p *pod.Info) error {
	metadata, err := c.verifyAttestOpts.Verify(ctx, p)
	if err != nil {
		return err
	}

	for _, m := range metadata {
		project, version := projectAndVersion(p.Team, p.Name, m.Image)
		if err = c.UploadSbom(project, version, p.Team, m.Statement); err != nil {
			return err
		}
	}
	return nil
}

func equalSlice(str1, str2 []string) bool {
	if len(str1) != len(str2) {
		return false
	}
	for i, str := range str1 {
		if str != str2[i] {
			return false
		}
	}
	return true
}

func projectAndVersion(team, name, image string) (project string, version string) {
	//team:foobar:ghcr.io/securego/gosec:v2.9.1
	image = team + ":" + name + ":" + image
	i := strings.LastIndex(image, ":")
	version = image[i+1:]
	project = image[0:i]
	return
}
