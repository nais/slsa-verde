package monitor

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"
	"picante/internal/pod"

	"picante/internal/attestation"
)

type Config struct {
	Client           client.Client
	verifyAttestOpts *attestation.VerifyAttestationOpts
	logger           *log.Entry
	ctx              context.Context
}

func NewMonitor(ctx context.Context, client client.Client, opts *attestation.VerifyAttestationOpts) *Config {
	return &Config{
		Client:           client,
		verifyAttestOpts: opts,
		logger:           log.WithFields(log.Fields{"package": "monitor"}),
		ctx:              ctx,
	}
}

func (c *Config) OnDelete(obj any) {
	p := pod.GetInfo(obj)
	if !p.HasTeamLabel() {
		c.logger.Debugf("ignoring pod with no team label")
		return
	}

	ctx := context.Background()
	for _, m := range p.ContainerImages {
		project, _ := projectAndVersion(p.Name, m)
		if err := c.Client.DeleteProjects(ctx, project); err != nil {
			c.logger.Errorf("clean up projects: %v", err)
			return
		}
	}
}

func (c *Config) OnUpdate(old any, new any) {
	c.logger.Debug("pod updated event, check if image needs to be attested")

	p := pod.GetInfo(old)
	p2 := pod.GetInfo(new)

	if !p.HasTeamLabel() || !p2.HasTeamLabel() {
		c.logger.Debugf("ignoring pod with no team label")
		return
	}

	if equalSlice(p.ContainerImages, p2.ContainerImages) {
		c.logger.Debugf("image has not changed, ignoring pod %s", p.PodName)
		return
	}

	if err := c.ensureAttested(c.ctx, p); err != nil {
		c.logger.Errorf("verfy attesation pod %v", err)
	}
}

func (c *Config) OnAdd(obj any) {
	c.logger.Debug("new pod event, check if image needs to be attested")

	p := pod.GetInfo(obj)
	if !p.HasTeamLabel() {
		c.logger.Debugf("ignoring pod with no team label")
		return
	}

	if err := c.ensureAttested(c.ctx, p); err != nil {
		c.logger.Errorf("verify attestation: %v", err)
	}
}

func (c *Config) ensureAttested(ctx context.Context, p *pod.Info) error {
	metadata, err := c.verifyAttestOpts.Verify(ctx, p)
	if err != nil {
		return err
	}

	if len(metadata) == 0 {
		return nil
	}

	for _, m := range metadata {
		project, version := projectAndVersion(p.Name, m.Image)

		pp, err := c.Client.GetProject(ctx, project, version)
		if err != nil {
			return err
		}

		if pp != nil {
			c.logger.WithFields(log.Fields{
				"project": project,
				"version": version,
				"uuid":    pp.Uuid,
			}).Info("project already exists, skipping")
			continue
		}
		b, err := json.Marshal(m.Statement)
		if err != nil {
			return err
		}

		if err = c.Client.UploadProject(ctx, project, version, b); err != nil {
			return err
		}

		if err = c.Client.UpdateProjectInfo(ctx, pp.Uuid, version, p.Namespace, []string{p.Team}); err != nil {
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

func projectAndVersion(name, image string) (project string, version string) {
	//foobar:ghcr.io/securego/gosec:v2.9.1
	image = name + ":" + image
	i := strings.LastIndex(image, ":")
	version = image[i+1:]
	project = image[0:i]
	return
}
