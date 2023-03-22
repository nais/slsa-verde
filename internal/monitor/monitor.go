package monitor

import (
	"context"
	"fmt"
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

// TODO: compare to check if image is updated
func (c *Config) OnUpdate(newObj any, oldObj any) {
	c.logger.Debug("pod updated")
	p := pod.GetInfo(newObj)

	if p == nil {
		c.logger.Debugf("ignore pod with no team label name")
	}

	p2 := pod.GetInfo(oldObj)
	if p2 == nil {
		c.logger.Debugf("ignore pod with no team label name")
	}

	if !p.Verify {
		c.logger.Debugf("ignore pod with no verify label name %s", p.Name)
		return
	}

	if equalSlice(p.ContainerImages, p2.ContainerImages) {
		c.logger.Debugf("same tag on image ignoring pod %s", p.Name)
		return
	}

	if err := c.ensureAttested(c.ctx, p); err != nil {
		c.logger.Errorf("attest pod %p", err)
	}
}

func (c *Config) OnAdd(obj any) {
	c.logger.Debug("pod added")
	p := pod.GetInfo(obj)
	if p == nil {
		log.Debugf("ignoring pod with no team label")
		return
	}

	if !p.Verify {
		log.Debugf("ignoring pod with no verify label %s", p.Name)
		return
	}

	if err := c.ensureAttested(c.ctx, p); err != nil {
		log.Errorf("attest pod %v", err)
	}
}

func (c *Config) ensureAttested(ctx context.Context, p *pod.Info) error {
	metadata, err := c.verifyAttestOpts.Verify2(ctx, p)
	if err != nil {
		return fmt.Errorf("verify attestation: %v", err)
	}

	for _, m := range metadata {
		project, version := projectAndVersion(p.Team, p.Name, m.Image)
		if err = c.UploadSbom(project, version, m.Statement); err != nil {
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
