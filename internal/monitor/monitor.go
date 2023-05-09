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
	Client   client.Client
	verifier attestation.Verifier
	logger   *log.Entry
	ctx      context.Context
}

func NewMonitor(ctx context.Context, client client.Client, verifier attestation.Verifier) *Config {
	return &Config{
		Client:   client,
		verifier: verifier,
		logger:   log.WithFields(log.Fields{"package": "monitor"}),
		ctx:      ctx,
	}
}

func (c *Config) OnDelete(obj any) {
	p := pod.GetInfo(obj)
	if p == nil {
		c.logger.Debug("pod deleted event, but pod is nil")
		return
	}

	for _, container := range p.ContainerImages {
		project, _ := projectAndVersion(p.Name, container.Image)
		if err := c.Client.DeleteProjects(c.ctx, project); err != nil {
			c.logger.Errorf("clean up projects: %v", err)
			return
		}
	}
}

func (c *Config) OnUpdate(old any, new any) {
	c.logger.Debug("pod updated event, check if image needs to be attested")

	p := pod.GetInfo(old)
	if p == nil {
		c.logger.Debug("pod updated event, but pod is nil")
		return
	}

	p2 := pod.GetInfo(new)
	if p2 == nil {
		c.logger.Debug("pod updated event, but pod is nil")
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
	if p == nil {
		c.logger.Debug("pod added event, but pod is nil")
		return
	}

	if err := c.ensureAttested(c.ctx, p); err != nil {
		c.logger.Errorf("verify attestation: %v", err)
	}
}

func (c *Config) ensureAttested(ctx context.Context, p *pod.Info) error {
	metadata, err := c.verifier.Verify(ctx, p)
	if err != nil {
		return err
	}

	if len(metadata) == 0 {
		return nil
	}

	for _, m := range metadata {
		if err := c.createProject(ctx, p, m); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) createProject(ctx context.Context, p *pod.Info, metadata *attestation.ImageMetadata) error {
	project, version := projectAndVersion(p.Name, metadata.Image)

	pp, err := c.Client.GetProject(ctx, project, version)
	if err != nil {
		if !client.IsNotFound(err) {
			return err
		}
	}

	if pp == nil {
		c.logger.WithFields(log.Fields{
			"project":   project,
			"version":   version,
			"pod":       p.PodName,
			"container": metadata.ContainerName,
		}).Info("project does not exist, creating")
		_, err = c.Client.CreateProject(ctx, project, version, p.Namespace, []string{p.Team, p.PodName})
		if err != nil {
			return err
		}
		b, err := json.Marshal(metadata.Statement.Predicate)
		if err != nil {
			return err
		}

		if err = c.Client.UploadProject(ctx, project, version, b); err != nil {
			return err
		}
	}
	return nil
}

func equalSlice(containers1, containers2 []pod.Container) bool {
	if len(containers1) != len(containers2) {
		return false
	}
	for i, c := range containers1 {
		if c.Image != containers2[i].Image {
			return false
		}
	}
	return true
}

func projectAndVersion(name, image string) (project string, version string) {
	if !strings.Contains(image, "@") {
		image = name + ":" + image
		i := strings.LastIndex(image, ":")
		project = image[0:i]
		version = image[i+1:]
		return
	}

	project, version = handleImageDigest(name, image)
	return
}

func handleImageDigest(name, image string) (project string, version string) {
	// format: <image>@<digest>
	imageArray := strings.Split(image, "@")
	i := strings.LastIndex(imageArray[0], ":")
	// format: <image>:<tag>@<digest>
	if i != -1 {
		project = name + ":" + imageArray[0][0:i]
		version = imageArray[0][i+1:] + "@" + imageArray[1]
		return project, version
	}
	project = name + ":" + imageArray[0]
	version = imageArray[1]
	return project, version
}
