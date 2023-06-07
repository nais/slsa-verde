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
	Cluster  string
	verifier attestation.Verifier
	logger   *log.Entry
	ctx      context.Context
}

func NewMonitor(ctx context.Context, client client.Client, verifier attestation.Verifier, cluster string) *Config {
	return &Config{
		Client:   client,
		Cluster:  cluster,
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

	appName := pod.AppName(p.Labels)
	if appName == "" {
		c.logger.Debug("pod deleted event, but no app name found")
		return
	}

	for _, container := range p.ContainerImages {
		project := projectName(p.Namespace, appName, container.Name)
		if err := c.Client.DeleteProjects(c.ctx, project); err != nil {
			c.logger.Errorf("clean up projects: %v", err)
			return
		}
		c.logger.Debugf("clean up project %s", project)
	}
}

func (c *Config) OnUpdate(old any, new any) {
	c.logger.Debug("pod updated event, check if image needs to be attested")

	oldPod := pod.GetInfo(old)
	if oldPod == nil {
		c.logger.Debug("pod updated event, but pod is nil")
		return
	}

	newPod := pod.GetInfo(new)
	if newPod == nil {
		c.logger.Debug("pod updated event, but pod is nil")
		return
	}

	name := pod.AppName(newPod.Labels)
	if name == "" {
		c.logger.Debug("pod updated event, but no app name found")
		return
	}

	if equalSlice(oldPod.ContainerImages, newPod.ContainerImages) {
		c.logger.Debug("pod updated event, but container images are the same")
		return
	}
}

func (c *Config) OnAdd(obj any) {
	c.logger.Debug("new pod event, check if image needs to be attested")

	p := pod.GetInfo(obj)
	if p == nil {
		c.logger.Debug("pod added event, but pod is nil")
		return
	}

	name := pod.AppName(p.Labels)
	if name == "" {
		c.logger.Debug("pod added event, but no app name found")
		return
	}

	metadata, err := c.verifier.Verify(c.ctx, p)
	if err != nil {
		c.logger.Errorf("verify attestation: %v", err)
		return
	}

	if len(metadata) == 0 {
		c.logger.Debugf("no metadata found for pod %s", p.Name)
		return
	}

	for _, m := range metadata {
		if err := c.createProject(c.ctx, p, m); err != nil {
			c.logger.Warnf("verify attestation: %v", err)
		}
	}
}

func (c *Config) createProject(ctx context.Context, p *pod.Info, metadata *attestation.ImageMetadata) error {
	projectVersion := version(metadata.Image)
	appName := pod.AppName(p.Labels)
	project := projectName(p.Namespace, appName, metadata.ContainerName)

	pp, err := c.Client.GetProject(ctx, project, projectVersion)
	if err != nil {
		return err
	}

	if pp == nil {

		projects, err := c.Client.GetProjectsByTag(ctx, project)
		if err != nil {
			return err
		}
		tags := []string{
			project,
			p.Namespace,
			appName,
			metadata.ContainerName,
			metadata.Image,
		}

		if len(projects) > 0 {

			c.logger.WithFields(log.Fields{
				"projectVersion": projectVersion,
				"pod":            p.Name,
				"container":      metadata.ContainerName,
			}).Info("project exist update version")

			_, err = c.Client.UpdateProject(ctx, projects[0].Uuid, project, projectVersion, p.Namespace, tags)
			if err != nil {
				return err
			}

		} else {
			c.logger.WithFields(log.Fields{
				"projectVersion": projectVersion,
				"pod":            p.Name,
				"container":      metadata.ContainerName,
			}).Info("project does not exist, creating")

			_, err = c.Client.CreateProject(ctx, project, projectVersion, p.Namespace, tags)
			if err != nil {
				return err
			}
		}

		b, err := json.Marshal(metadata.Statement.Predicate)
		if err != nil {
			return err
		}

		if err = c.Client.UploadProject(ctx, project, projectVersion, b); err != nil {
			return err
		}
	}
	return nil
}

func projectName(namespace, appName, containerName string) string {
	if appName == containerName {
		return namespace + ":" + appName
	}
	return namespace + ":" + appName + ":" + containerName
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

func version(image string) string {
	if !strings.Contains(image, "@") {
		i := strings.LastIndex(image, ":")
		return image[i+1:]
	}

	return handleImageDigest(image)
}

func handleImageDigest(image string) string {
	// format: <image>@<digest>
	imageArray := strings.Split(image, "@")
	i := strings.LastIndex(imageArray[0], ":")
	// format: <image>:<tag>@<digest>
	if i != -1 {
		return imageArray[0][i+1:] + "@" + imageArray[1]
	}
	return imageArray[1]
}
